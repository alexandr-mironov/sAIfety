package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/saifety-org/sAIfety/internal/scan/redact"
)

// These tests extend the MCP personal-data (обезличивание) coverage with three
// boundaries the existing privacy tests do not exercise directly:
//
//  1. operator telemetry must never carry the personal data it describes;
//  2. personal data hidden behind invisible/zero-width runes must not survive
//     the normalization boundary as a usable copy;
//  3. recursive masking of record lists must mask every person in place while
//     leaving benign structure and non-personal fields untouched.

// TestPIIDecisionTelemetryNeverCarriesValues is a privacy regression guard for
// the operator decision log. The agent-facing result is redacted, and the
// JSONL decision stream that an operator tails must describe the decision
// (action/reason/finding metadata) without ever echoing the masked values.
func TestPIIDecisionTelemetryNeverCarriesValues(t *testing.T) {
	const (
		phone      = "79165550132"
		plusPhone  = "+79165550132"
		firstName  = "Иван"
		backupCard = "89165550133"
	)
	var journal bytes.Buffer
	c, _ := startProxyConfigured(t, func(p *Proxy) {
		p.RedactOn, p.Redact = true, redact.DefaultOptions
	}, &journal)

	raw := json.RawMessage(`{"content":[{"type":"text","text":"` + plusPhone + `"}],` +
		`"structuredContent":{"first_name":"` + firstName + `","phone":` + phone + `,"card":` + backupCard + `},` +
		`"_meta":{"copy":"` + plusPhone + `"}}`)
	got := c.call(t, "tools/call", map[string]any{
		"name":      "fake__echo",
		"arguments": map[string]any{"result": raw},
	})

	// Sanity: the value really was personal data, so the result had to change.
	for _, v := range []string{phone, plusPhone, firstName, backupCard} {
		if strings.Contains(string(got), v) {
			t.Fatalf("personal data leaked to the agent: %q in %s", v, got)
		}
	}
	if !strings.Contains(string(got), "[REDACTED:") {
		t.Fatalf("expected a redacted result, got %s", got)
	}

	// The decision journal must carry no trace of the values it acted on.
	for _, v := range []string{phone, plusPhone, firstName, backupCard, "Иван", "REDACTED"} {
		if strings.Contains(journal.String(), v) {
			t.Fatalf("decision telemetry leaked personal data: %q in %s", v, journal.String())
		}
	}

	var d Decision
	if err := json.Unmarshal(bytes.TrimSpace(journal.Bytes()), &d); err != nil {
		t.Fatalf("decision log is not valid JSONL: %v (%s)", err, journal.String())
	}
	if d.Delivery != "transformed" || d.Reason != "redacted" || d.RequestSHA256 == "" {
		t.Fatalf("expected a redaction decision with a request hash, got %+v", d)
	}
}

// TestPIIZeroWidthSplitDoesNotSurviveNormalization covers the normalization
// boundary inside a tool result: a mobile number split by an invisible
// zero-width space does not match the raw phone pattern, but the normalized
// form does. The value must be hidden wholesale (never partially), so no
// reassemblable digit run reaches the agent.
func TestPIIZeroWidthSplitDoesNotSurviveNormalization(t *testing.T) {
	const zwsp = "​"
	// A phone and a Russian full name, each cut by an invisible rune.
	raw := json.RawMessage(`{"structuredContent":{` +
		`"contact":"+7916` + zwsp + `5550132",` +
		`"name":"Ива` + zwsp + `н Петров"}}`)
	p := piiProxy()
	out, d := p.inspectToolResult(context.Background(), "fixture/read", false, raw)
	got := string(mustJSON(out))

	// Neither the digit run nor any trailing fragment of it may survive.
	for _, leak := range []string{"79165550132", "5550132", "916", "Петров"} {
		if strings.Contains(got, leak) {
			t.Fatalf("invisible-split personal data survived: %q in %s", leak, got)
		}
	}
	if !strings.Contains(got, "[REDACTED:") {
		t.Fatalf("invisible-split personal data was not masked: %s (%+v)", got, d)
	}
}

// TestPIIEmailMaskedInToolResult covers email, a direct personal identifier in
// corporate results, across a textual field, a structured field and an
// invisible-split copy. Non-email tokens that merely contain an "@" (package
// refs, bare user@host without a TLD) must survive so ordinary output is kept.
func TestPIIEmailMaskedInToolResult(t *testing.T) {
	const zwsp = "​"
	raw := json.RawMessage(`{"content":[{"type":"text","text":"Написал demo.person@corp.example по вопросу."}],` +
		`"structuredContent":{"email":"user+tag@corp.example.com","split":"hidden` + zwsp + `.person@corp.example","ref":"@scope/pkg","host":"deploy@buildserver"}}`)
	p := piiProxy()
	out, d := p.inspectToolResult(context.Background(), "fixture/read", false, raw)
	got := string(mustJSON(out))

	for _, leak := range []string{"demo.person@corp.example", "user+tag@corp.example.com", "hidden.person@corp.example"} {
		if strings.Contains(got, leak) {
			t.Fatalf("email leaked to the agent: %q in %s (%+v)", leak, got, d)
		}
	}
	if !strings.Contains(got, "[REDACTED:") {
		t.Fatalf("expected a redacted result, got %s", got)
	}
	// Non-email "@" tokens are not personal data and must be preserved.
	for _, keep := range []string{"@scope/pkg", "deploy@buildserver"} {
		if !strings.Contains(got, keep) {
			t.Fatalf("benign @-token wrongly removed: want %q in %s", keep, got)
		}
	}
}

// TestPIIRecordListMaskedInPlacePreservingStructure checks recursive masking
// through an array of person objects (a realistic "list customers" result).
// Every name and phone is masked using its field context, while the JSON shape
// and non-personal fields (ids, status) are preserved so the tool's structured
// contract still holds.
func TestPIIRecordListMaskedInPlacePreservingStructure(t *testing.T) {
	raw := json.RawMessage(`{"structuredContent":{"customers":[` +
		`{"id":"c-1","first_name":"Иван","last_name":"Петров","phone":"+79165550132","status":"active"},` +
		`{"id":"c-2","first_name":"Пётр","last_name":"Смирнов","phone":"+7 916 555-01-33","status":"blocked"}` +
		`]}}`)
	p := piiProxy()
	out, d := p.inspectToolResult(context.Background(), "fixture/read", false, raw)
	got := string(mustJSON(out))

	for _, leak := range []string{"Иван", "Петров", "Пётр", "Смирнов", "79165550132", "555-01-33"} {
		if strings.Contains(got, leak) {
			t.Fatalf("record-list personal data leaked: %q in %s", leak, got)
		}
	}
	// Benign fields survive, and the result stays structured (not downgraded to
	// a text blob), so ids/status remain machine-readable.
	for _, keep := range []string{`"c-1"`, `"c-2"`, `"status":"active"`, `"status":"blocked"`} {
		if !strings.Contains(got, keep) {
			t.Fatalf("benign structure lost: want %q in %s (%+v)", keep, got, d)
		}
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("masked result is not valid JSON: %v", err)
	}
	if _, ok := decoded["structuredContent"].(map[string]any); !ok {
		t.Fatalf("structuredContent should remain a structured object, got %s", got)
	}
}
