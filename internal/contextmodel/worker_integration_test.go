//go:build onnx

package contextmodel

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/saifety-org/sAIfety/pkg/contextscan"
)

// The 9KB fixture exercises real ORT execution offline. It has constant logits
// and is not a trained classifier. CI supplies only the pinned runtime library.
func TestRealWorkerFixture(t *testing.T) {
	library := os.Getenv("SAIFETY_CONTEXT_TEST_LIBRARY")
	if library == "" {
		t.Skip("set SAIFETY_CONTEXT_TEST_LIBRARY for native fixture test")
	}
	const pin = "8572e52ddae09ac37ef40977958cd94f9d6427553e613e32628bfe3601b05b63"
	dir := filepath.Join("testdata", "bundle")
	input, _ := contextscan.Serialize(contextscan.Input{Contract: contextscan.Contract, Task: "Summarize", Documents: []contextscan.Document{{Kind: "mcp", Trust: "untrusted", Text: "hello world русский 中文 café café"}}})
	var requests bytes.Buffer
	enc := json.NewEncoder(&requests)
	for _, r := range []contextscan.Request{{Mode: "info"}, {Mode: "tokens", Text: input}, {Mode: "score", Text: input}} {
		if e := enc.Encode(r); e != nil {
			t.Fatal(e)
		}
	}
	var output bytes.Buffer
	if e := Serve(dir, library, pin, &requests, &output); e != nil {
		t.Fatal(e)
	}
	dec := json.NewDecoder(&output)
	var info, tokens, score contextscan.Response
	for _, r := range []*contextscan.Response{&info, &tokens, &score} {
		if e := dec.Decode(r); e != nil {
			t.Fatal(e, output.String())
		}
		if r.Error != "" {
			t.Fatal(r.Error)
		}
	}
	if info.Info == nil || info.Info.ManifestSHA256 != pin || len(tokens.IDs) == 0 || len(tokens.IDs) > 512 || tokens.IDs[0] != 0 || tokens.IDs[len(tokens.IDs)-1] != 2 || math.Abs(score.Score-1/(1+math.Exp(-1))) > 1e-7 {
		t.Fatalf("bad worker output: %+v %+v %+v", info, tokens, score)
	}
	// Pin failure is observable before model parsing, not a fabricated zero score.
	output.Reset()
	if e := Serve(dir, library, contextscan.V4ManifestSHA256, bytes.NewReader(nil), &output); e != nil {
		t.Fatal(e)
	}
	var failure contextscan.Response
	if e := json.Unmarshal(output.Bytes(), &failure); e != nil || failure.Error == "" {
		t.Fatal("wrong pin accepted", e)
	}
	// Exact overflow policy: counting succeeds, scoring rejects rather than truncates.
	long, _ := contextscan.Serialize(contextscan.Input{Contract: contextscan.Contract, Task: "Summarize", Documents: []contextscan.Document{{Kind: "mcp", Trust: "untrusted", Text: string(bytes.Repeat([]byte("hello "), 600))}}})
	requests.Reset()
	_ = json.NewEncoder(&requests).Encode(contextscan.Request{Mode: "score", Text: long})
	output.Reset()
	if e := Serve(dir, library, pin, &requests, &output); e != nil {
		t.Fatal(e)
	}
	failure = contextscan.Response{}
	if e := json.Unmarshal(output.Bytes(), &failure); e != nil || failure.Error != "token window exceeded; no truncation" {
		t.Fatal("overflow accepted", e, output.String())
	}
}
