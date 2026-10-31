package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/saifety-org/sAIfety/internal/scan/redact"
)

type personNER struct{ fail bool }

func (n personNER) Recognize(s string) []redact.Match { out, _ := n.RecognizeChecked(s); return out }
func (n personNER) RecognizeChecked(s string) ([]redact.Match, error) {
	if n.fail {
		return nil, errors.New("fixture failure")
	}
	var out []redact.Match
	for _, name := range []string{"Шахержон Тахержон", "Shaherzhon Taherzhon", "Ivan Petrov"} {
		if i := strings.Index(s, name); i >= 0 {
			out = append(out, redact.Match{Kind: redact.KindPII, Label: "full_name", Start: i, End: i + len(name)})
		}
	}
	return out, nil
}

func TestMCPOptionalNERMaskingAndFailure(t *testing.T) {
	for _, name := range []string{"Шахержон Тахержон", "Shaherzhon Taherzhon", "Ivan Petrov"} {
		for _, fail := range []bool{false, true} {
			p := piiProxy()
			p.Redact = p.Redact.WithNER(personNER{fail: fail})
			raw := mustJSON(map[string]any{"structuredContent": map[string]string{"contact": name, "mobile": "+79165550132"}})
			output, d := p.inspectToolResult(context.Background(), "fixture/read", false, raw)
			got := string(mustJSON(output))
			if strings.Contains(got, name) || strings.Contains(got, "79165550132") {
				t.Fatal("NER/rule value leaked", got, d)
			}
			if fail {
				assertWithheld(t, []byte(got))
				if d.Reason != "pii_inspection_unavailable" {
					t.Fatal("model failure reported as clean", d)
				}
			} else if !strings.Contains(got, "[REDACTED:full_name]") {
				t.Fatal("no model mask", got)
			}
		}
	}
	p := piiProxy()
	p.Redact = p.Redact.WithNERError(errors.New("initialization failed"))
	output, d := p.inspectToolResult(context.Background(), "fixture/read", false, json.RawMessage(`{"content":[{"type":"text","text":"private unknown entity"}]}`))
	got := mustJSON(output)
	assertWithheld(t, got)
	if strings.Contains(string(got), "private unknown entity") || d.Reason != "pii_inspection_unavailable" {
		t.Fatal("initialization error leaked original", string(got), d)
	}
}
