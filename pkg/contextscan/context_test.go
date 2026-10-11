package contextscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

type fakeBackend struct {
	seen []string
	fail bool
	wait bool
}

func (f *fakeBackend) Info() Info {
	return Info{ID: "test", Version: "1", MaxTokens: 512, Threshold: 0.3}
}
func (f *fakeBackend) Tokens(ctx context.Context, s string) ([]int, error) {
	if f.wait {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	f.seen = append(f.seen, s)
	return make([]int, utf8.RuneCountInString(s)+2), nil
}
func (f *fakeBackend) Score(_ context.Context, s string) (float64, error) {
	if f.fail {
		return 0, errors.New("inference unavailable")
	}
	if strings.Contains(s, "MARKER") {
		return .8, nil
	}
	return .1, nil
}
func testInput() Input {
	return Input{Contract: Contract, Task: "Summarize documents", Documents: []Document{{Kind: "file", Trust: "untrusted", Text: "ordinary text", Source: "local"}}}
}
func testAdapter(t *testing.T, f *fakeBackend, opts Options) *Adapter {
	t.Helper()
	a, e := New(f, opts)
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func TestContextBoundariesAndSerialization(t *testing.T) {
	in := testInput()
	in.Task = "<task> Привет"
	in.Documents[0].Text = "& keep\nＡ"
	in.Documents[0].Source = "NEVER_SERIALIZE"
	got, e := Serialize(in)
	if e != nil {
		t.Fatal(e)
	}
	want := `{"contract":"context-json-v2","task":"<task> Привет","documents":[{"kind":"file","trust":"untrusted","text":"& keep\nＡ"}]}`
	if got != want {
		t.Fatalf("serialization mismatch: %s", got)
	}
	a := testAdapter(t, &fakeBackend{}, Options{})
	r, e := a.Analyze(context.Background(), in)
	if e != nil || r.Status != "complete" || r.Coverage != "joint" || r.Attack == nil || *r.Attack || r.Windows[0].Ranges[0].Source != "NEVER_SERIALIZE" {
		t.Fatalf("%+v %v", r, e)
	}
}
func TestRejectMissingAndInvalidContext(t *testing.T) {
	for _, name := range []string{"missing-task", "contract", "trust", "kind", "empty", "utf8", "limit"} {
		t.Run(name, func(t *testing.T) {
			in := testInput()
			opts := Options{}
			switch name {
			case "missing-task":
				in.Task = " "
			case "contract":
				in.Contract = "v1"
			case "trust":
				in.Documents[0].Trust = "trusted"
			case "kind":
				in.Documents[0].Kind = "system"
			case "empty":
				in.Documents = nil
			case "utf8":
				in.Documents[0].Text = "\xff"
			case "limit":
				opts.MaxBytes = 2
			}
			f := &fakeBackend{}
			a := testAdapter(t, f, opts)
			r, e := a.Analyze(context.Background(), in)
			if name == "missing-task" {
				if e != nil || r.Status != "missing-context" {
					t.Fatal(r, e)
				}
			} else if e == nil || r.Status != "error" {
				t.Fatal(r, e)
			}
			if r.Score != nil || r.Attack != nil || len(f.seen) > 0 {
				t.Fatal("invalid input reached inference or produced a clean verdict")
			}
		})
	}
}
func TestSegmentationPreservesSourcesAndLateAttack(t *testing.T) {
	in := testInput()
	in.Documents = []Document{{Kind: "web", Trust: "user-provided", Source: "web", Text: strings.Repeat("界аб ", 300) + "MARKER"}, {Kind: "mcp", Trust: "untrusted", Source: "tool", Text: strings.Repeat("another ", 100)}}
	a := testAdapter(t, &fakeBackend{}, Options{})
	r, e := a.Analyze(context.Background(), in)
	if e != nil || r.Status != "complete" || r.Coverage != "segmented" || r.Attack == nil || !*r.Attack || len(r.Warnings) == 0 {
		t.Fatalf("%+v %v", r, e)
	}
	covered := make([]int, len(in.Documents))
	for _, w := range r.Windows {
		if w.Tokens > 512 {
			t.Fatal("overflow")
		}
		for _, p := range w.Ranges {
			d := in.Documents[p.Document]
			if p.Kind != d.Kind || p.Trust != d.Trust || p.Source != d.Source || p.Start > covered[p.Document] || p.End <= p.Start || !utf8.ValidString(d.Text[p.Start:p.End]) {
				t.Fatal("lost provenance or text coverage", p)
			}
			covered[p.Document] = max(covered[p.Document], p.End)
		}
	}
	for i, d := range in.Documents {
		if covered[i] != len(d.Text) {
			t.Fatal("incomplete coverage")
		}
	}
}
func TestFailuresNeverReturnAggregateDecision(t *testing.T) {
	for _, name := range []string{"window-limit", "long-task", "inference", "timeout"} {
		t.Run(name, func(t *testing.T) {
			in := testInput()
			f := &fakeBackend{}
			opts := Options{}
			switch name {
			case "window-limit":
				in.Documents[0].Text = strings.Repeat("abc ", 500)
				opts.MaxWindows = 1
			case "long-task":
				in.Task = strings.Repeat("task", 200)
			case "inference":
				f.fail = true
			case "timeout":
				f.wait = true
				opts.Timeout = 10 * time.Millisecond
			}
			r, e := testAdapter(t, f, opts).Analyze(context.Background(), in)
			if e == nil || r.Status != "error" || r.Score != nil || r.Attack != nil {
				t.Fatalf("failure treated as verdict: %+v %v", r, e)
			}
			if name == "timeout" && !errors.Is(e, context.DeadlineExceeded) {
				t.Fatal(e)
			}
		})
	}
}
func TestMixedDocumentsJointAndMaxAggregation(t *testing.T) {
	in := testInput()
	in.Documents = append(in.Documents, Document{Kind: "mcp", Trust: "user-provided", Text: "MARKER", Source: "other"})
	f := &fakeBackend{}
	r, e := testAdapter(t, f, Options{}).Analyze(context.Background(), in)
	if e != nil || r.Coverage != "joint" || len(r.Windows) != 1 || len(r.Windows[0].Ranges) != 2 || r.Score == nil || *r.Score != .8 {
		t.Fatal(r, e)
	}
	var parsed Input
	if e = json.Unmarshal([]byte(f.seen[0]), &parsed); e != nil {
		t.Fatal(e)
	}
	if len(parsed.Documents) != 2 || parsed.Documents[1].Trust != "user-provided" {
		t.Fatal(parsed)
	}
}
func ExampleSerialize() {
	text, _ := Serialize(Input{Contract: Contract, Task: "Summarize", Documents: []Document{{Kind: "file", Trust: "untrusted", Text: "Hello"}}})
	fmt.Println(text)
	// Output: {"contract":"context-json-v2","task":"Summarize","documents":[{"kind":"file","trust":"untrusted","text":"Hello"}]}
}

type partialBackend struct {
	fakeBackend
	calls int
}

func (f *partialBackend) Score(context.Context, string) (float64, error) {
	f.calls++
	if f.calls > 1 {
		return 0, errors.New("second window failed")
	}
	return .9, nil
}
func TestPartialScoresCannotBecomeAggregateVerdict(t *testing.T) {
	f := &partialBackend{}
	a, e := New(f, Options{})
	if e != nil {
		t.Fatal(e)
	}
	in := testInput()
	in.Documents[0].Text = strings.Repeat("content ", 150)
	r, e := a.Analyze(context.Background(), in)
	if e == nil || r.Coverage != "partial" || len(r.Windows) != 1 || r.Score != nil || r.Attack != nil || r.Reason != "inference-failed" {
		t.Fatalf("partial result misrepresented: %+v %v", r, e)
	}
}
