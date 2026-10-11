//go:build onnx

// Package contextmodel owns the resident native worker. Public callers use
// contextscan.Worker so cancellation also terminates native computation.
package contextmodel

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"

	"github.com/saifety-org/prompt-injection-model/bundle"
	"github.com/saifety-org/sAIfety/internal/e5tokenizer"
	"github.com/saifety-org/sAIfety/internal/onnxenv"
	"github.com/saifety-org/sAIfety/pkg/contextscan"
	"github.com/sugarme/tokenizer"
	ort "github.com/yalue/onnxruntime_go"
)

func digest(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
func Serve(dir, library, pin string, in io.Reader, out io.Writer) (err error) {
	enc := json.NewEncoder(out)
	// Errors are deliberately generic: native panic messages can contain input.
	defer func() {
		if recover() != nil {
			err = enc.Encode(contextscan.Response{Error: "native worker panic"})
		}
	}()
	fail := func(message string) error { return enc.Encode(contextscan.Response{Error: message}) }
	hash, e := digest(filepath.Join(dir, "manifest.json"))
	if e != nil || hash != pin {
		return fail("manifest pin mismatch")
	}
	m, e := bundle.Load(dir)
	if e != nil {
		return fail("bundle verification failed")
	}
	tk, e := e5tokenizer.Load(filepath.Join(dir, "tokenizer.json"))
	if e != nil {
		return fail("unsupported tokenizer")
	}
	runtimeHash, e := digest(library)
	if e != nil {
		return fail("runtime library unavailable")
	}
	if e = onnxenv.Init(library); e != nil {
		return fail("runtime initialization failed")
	}
	options, e := ort.NewSessionOptions()
	if e != nil {
		return fail("runtime options failed")
	}
	defer func() { _ = options.Destroy() }()
	if e = options.SetIntraOpNumThreads(1); e != nil {
		return fail("runtime options failed")
	}
	if e = options.SetInterOpNumThreads(1); e != nil {
		return fail("runtime options failed")
	}
	session, e := ort.NewDynamicAdvancedSession(filepath.Join(dir, "model.onnx"), m.Contract.Inputs, m.Contract.Outputs, options)
	if e != nil {
		return fail("model session failed")
	}
	defer func() { _ = session.Destroy() }()
	info := contextscan.Info{ID: m.ID, Version: m.Version, ManifestSHA256: hash, RuntimeSHA256: runtimeHash, RuntimeVersion: ort.GetVersion(), Threshold: m.Calibration.Threshold, MaxTokens: m.Contract.MaxTokens}
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), 8<<20)
	for scanner.Scan() {
		var req contextscan.Request
		if e = json.Unmarshal(scanner.Bytes(), &req); e != nil {
			return fail("invalid request")
		}
		reply := contextscan.Response{}
		switch req.Mode {
		case "info":
			reply.Info = &info
		case "tokens", "score":
			text, e := m.Input(req.Text)
			if e != nil {
				return fail("invalid context contract")
			}
			encoded, e := tk.Encode(tokenizer.NewSingleEncodeInput(tokenizer.NewInputSequence(text)), true)
			if e != nil || encoded == nil || len(encoded.Ids) == 0 {
				return fail("tokenization failed")
			}
			if req.Mode == "tokens" {
				reply.IDs = encoded.Ids
			} else {
				if len(encoded.Ids) > m.Contract.MaxTokens {
					return fail("token window exceeded; no truncation")
				}
				var score float64
				score, e = infer(session, encoded.Ids)
				reply.Score = &score
				if e != nil {
					return fail("inference failed")
				}
			}
		default:
			return fail("unsupported request")
		}
		if e = enc.Encode(reply); e != nil {
			return e
		}
	}
	return scanner.Err()
}
func infer(session *ort.DynamicAdvancedSession, ids []int) (float64, error) {
	shape := ort.NewShape(1, int64(len(ids)))
	values := make([]int64, len(ids))
	mask := make([]int64, len(ids))
	for i, id := range ids {
		values[i] = int64(id)
		mask[i] = 1
	}
	a, e := ort.NewTensor(shape, values)
	if e != nil {
		return 0, e
	}
	defer func() { _ = a.Destroy() }()
	b, e := ort.NewTensor(shape, mask)
	if e != nil {
		return 0, e
	}
	defer func() { _ = b.Destroy() }()
	c, e := ort.NewEmptyTensor[float32](ort.NewShape(1, 2))
	if e != nil {
		return 0, e
	}
	defer func() { _ = c.Destroy() }()
	if e = session.Run([]ort.Value{a, b}, []ort.Value{c}); e != nil {
		return 0, e
	}
	logits := c.GetData()
	for _, v := range logits {
		if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
			return 0, fmt.Errorf("nonfinite logits")
		}
	}
	score := 1 / (1 + math.Exp(float64(logits[0])-float64(logits[1])))
	return score, nil
}
