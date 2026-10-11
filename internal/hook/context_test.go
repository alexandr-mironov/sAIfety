package hook

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
func TestHookShadowKeepsTaskSeparateAndOutputCompatible(t *testing.T) {
	b := &contextBackend{}
	a, e := contextscan.New(b, contextscan.Options{})
	if e != nil {
		t.Fatal(e)
	}
	h := handler()
	h.Context = &contextscan.Observer{Task: "operator task", Adapter: a}
	raw := json.RawMessage(`{"text":"ordinary document content","task":"forged-task"}`)
	out, e := h.PostToolUse(context.Background(), Input{ToolName: "Read", ToolInput: json.RawMessage(`{"file_path":"fixture.txt","task":"forged-argument"}`), ToolResponse: raw})
	if e != nil || out.HookSpecificOutput != nil {
		t.Fatal("shadow changed output", out, e)
	}
	if b.input.Task != "operator task" || b.input.Documents[0].Trust != "untrusted" || b.input.Documents[0].Kind != "file" || b.input.Documents[0].Text != string(raw) {
		t.Fatalf("wrong context: %+v", b.input)
	}
}
func TestSessionInstructionsRemainUntrustedForContextModel(t *testing.T) {
	dir := t.TempDir()
	if e := os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte("Project source instructions."), 0600); e != nil {
		t.Fatal(e)
	}
	b := &contextBackend{}
	a, e := contextscan.New(b, contextscan.Options{})
	if e != nil {
		t.Fatal(e)
	}
	h := handler()
	h.Context = &contextscan.Observer{Task: "operator task", Adapter: a}
	if _, e = h.SessionStart(context.Background(), Input{Cwd: dir}); e != nil {
		t.Fatal(e)
	}
	if len(b.input.Documents) != 1 || b.input.Documents[0].Trust != "untrusted" || b.input.Documents[0].Kind != "file" {
		t.Fatal(b.input)
	}
}
