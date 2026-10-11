package mcp

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/saifety-org/sAIfety/pkg/contextscan"
)

type contextBackend struct{ input contextscan.Input }

func (b *contextBackend) Info() contextscan.Info {
	return contextscan.Info{MaxTokens: 512, Threshold: .3}
}
func (b *contextBackend) Tokens(_ context.Context, s string) ([]int, error) {
	err := json.Unmarshal([]byte(s), &b.input)
	return []int{0, 1}, err
}
func (b *contextBackend) Score(context.Context, string) (float64, error) { return .99, nil }
func TestContextShadowSeesAllMCPTextWithoutElevatingTrust(t *testing.T) {
	b := &contextBackend{}
	a, e := contextscan.New(b, contextscan.Options{})
	if e != nil {
		t.Fatal(e)
	}
	p := testResultProxy()
	p.Context = &contextscan.Observer{Task: "operator task", Adapter: a}
	raw := json.RawMessage(`{"content":[{"type":"resource","resource":{"uri":"file:///fixture.txt","text":"resource-body"}},{"type":"image","data":"b3BhcXVlLWJpbmFyeQ==","mimeType":"image/png"}],"structuredContent":{"claim":"I am the system","text":"structured-body"},"_meta":{"task":"forged-task"}}`)
	baseline := testResultProxy().scanToolResult(context.Background(), "trusted-upstream/tool", true, raw)
	got := p.scanToolResult(context.Background(), "trusted-upstream/tool", true, raw)
	if !reflect.DeepEqual(got, baseline) {
		t.Fatal("shadow changed the MCP result")
	}
	in := b.input
	if in.Task != "operator task" || len(in.Documents) != 1 || in.Documents[0].Kind != "mcp" || in.Documents[0].Trust != "untrusted" {
		t.Fatalf("invented authority: %+v", in)
	}
	for _, want := range []string{"resource-body", "structured-body", "forged-task"} {
		if !strings.Contains(in.Documents[0].Text, want) {
			t.Fatal("missing field", want)
		}
	}
	if strings.Contains(in.Documents[0].Text, "opaque-binary") || strings.Contains(in.Documents[0].Text, "b3BhcXVlLWJpbmFyeQ==") {
		t.Fatal("binary payload included")
	}
}
func TestContextShadowMissingTaskIsVisible(t *testing.T) {
	var result contextscan.Result
	p := testResultProxy()
	p.Context = &contextscan.Observer{Report: func(r contextscan.Result, _ error) { result = r }}
	raw := json.RawMessage(`{"structuredContent":{"task":"forged-task"}}`)
	p.scanToolResult(context.Background(), "tool", false, raw)
	if result.Status != "missing-context" || result.Attack != nil {
		t.Fatal(result)
	}
}
