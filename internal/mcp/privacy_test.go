package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/saifety-org/sAIfety/internal/policy"
	"github.com/saifety-org/sAIfety/internal/scan"
	"github.com/saifety-org/sAIfety/internal/scan/detect"
	"github.com/saifety-org/sAIfety/internal/scan/redact"
)

func piiProxy() *Proxy {
	p := testResultProxy()
	p.RedactOn, p.Redact = true, redact.DefaultOptions
	p.Scanner = scan.New(append(detect.Default(), detect.Redaction{Opts: p.Redact}),
		policy.New(policy.Default), scan.Options{})
	return p
}

func TestPIIEncodedCopyCannotSurvivePlaintextRedaction(t *testing.T) {
	contact := "+79165550132"
	encoded := base64.StdEncoding.EncodeToString([]byte("Contact record: " + contact))
	p := piiProxy()
	raw := mustJSON(map[string]any{"structuredContent": map[string]string{
		"contact": contact, "encoded_copy": encoded,
	}})
	output, decision := p.inspectToolResult(context.Background(), "fixture/read", false, raw)
	got := mustJSON(output)
	assertWithheld(t, got)
	if strings.Contains(string(got), contact) || strings.Contains(string(got), encoded) ||
		decision.Reason != "encoded_sensitive_data" {
		t.Fatal("encoded alternate representation survived", string(got), decision)
	}
}

func TestPIIResultsValuesAndFields(t *testing.T) {
	for name, tc := range map[string]struct {
		raw    string
		values []string
	}{
		"numbers": {`{"structuredContent":{"phone":79165550132,"backup":89165550133}}`,
			[]string{"79165550132", "89165550133"}},
		"number-array": {`{"structuredContent":{"values":[79165550132,89165550133]}}`,
			[]string{"79165550132", "89165550133"}},
		"number-spellings": {`{"structuredContent":{"values":[7.9165550132e10,89165550133.0]}}`,
			[]string{"7.9165550132e10", "89165550133"}},
		"split-name": {`{"structuredContent":{"first_name":"Иван","last_name":"Петров","patronymic":"Иванович"}}`,
			[]string{"Иван", "Петров", "Иванович"}},
		"prefix-spoof": {`{"structuredContent":{"first_name":"[REDACTED:full_name] Иван","last_name":"Петров"}}`,
			[]string{"Иван", "Петров"}},
		"copies": {`{"content":[{"type":"text","text":"+79165550132"}],"structuredContent":{"contact":"+79165550132"},"_meta":{"copy":"+79165550132"}}`,
			[]string{"79165550132", "+79165550132"}},
		"resource": {`{"content":[{"type":"resource","resource":{"uri":"file:///fixture","text":"Иван Петров, +7 916 555-01-32"}}]}`,
			[]string{"Иван", "Петров", "916", "555"}},
	} {
		t.Run(name, func(t *testing.T) {
			p := piiProxy()
			got := string(mustJSON(p.scanToolResult(context.Background(), "fixture/read", false, json.RawMessage(tc.raw))))
			for _, value := range tc.values {
				if strings.Contains(got, value) {
					t.Fatalf("PII leaked: %q in %s", value, got)
				}
			}
			if !strings.Contains(got, "[REDACTED:") {
				t.Fatal("expected masked values", got)
			}
		})
	}
}

func TestPIINumbersDoNotChangeDeclaredJSONTypes(t *testing.T) {
	p := piiProxy()
	got := mustJSON(p.scanToolResult(context.Background(), "fixture/read", false,
		json.RawMessage(`{"structuredContent":{"phone":79165550132,"amount":9007199254740993}}`)))
	assertWithheld(t, got)
	if strings.Contains(string(got), "79165550132") || !strings.Contains(string(got), "9007199254740993") {
		t.Fatal("masked number leaked or ordinary large integer lost", string(got))
	}
}

func TestPIIProtectedKeysAndProtocolValuesWithholdOriginal(t *testing.T) {
	for _, raw := range []string{
		`{"structuredContent":{"+79165550132":"value","[REDACTED:phone]":"other"}}`,
		`{"content":[{"type":"resource_link","uri":"https://example.invalid/+79165550132","name":"fixture"}]}`,
		`{"structuredContent":{"first_name":{"Иван":"value"}}}`,
	} {
		p := piiProxy()
		got := mustJSON(p.scanToolResult(context.Background(), "fixture/read", false, json.RawMessage(raw)))
		assertWithheld(t, got)
		if strings.Contains(string(got), "79165550132") || strings.Contains(string(got), "+79165550132") {
			t.Fatal("protected value leaked through fallback", string(got))
		}
	}
}

func TestPIIOpaqueDefaultAndExplicitException(t *testing.T) {
	raw := json.RawMessage(`{"content":[{"type":"resource","resource":{"uri":"file:///fixture","blob":"ZGVtby5wZXJzb25AZXhhbXBsZS5pbnZhbGlk"}}]}`)
	p := piiProxy()
	output, decision := p.inspectToolResult(context.Background(), "fixture/read", false, raw)
	got := mustJSON(output)
	assertWithheld(t, got)
	if decision.Reason != "opaque_pii_unavailable" || strings.Contains(string(got), "ZGVtby") {
		t.Fatal("opaque data delivered as inspected", decision, string(got))
	}
	p.AllowOpaque = true
	if got := mustJSON(p.scanToolResult(context.Background(), "fixture/read", false, raw)); string(got) != string(raw) {
		t.Fatal("explicit opaque exception ignored")
	}
	p.AllowOpaque, p.RedactOn = false, false
	if got := mustJSON(p.scanToolResult(context.Background(), "fixture/read", false, raw)); string(got) != string(raw) {
		t.Fatal("explicit disabled redaction ignored")
	}
}

func TestPIIPreservesCleanNumbersAndControls(t *testing.T) {
	p := piiProxy()
	raw := json.RawMessage(`{"structuredContent":{"id":1234567890,"count":9007199254740993,"ratio":1.00,"huge":1e1000000000,"tiny":1e-1000000000,"ok":true,"empty":null},"content":[{"type":"text","text":"2026-10-30 12:34:56; Order #1234567890"}]}`)
	if got := mustJSON(p.scanToolResult(context.Background(), "fixture/read", false, raw)); string(got) != string(raw) {
		t.Fatal("clean controls or exact numbers changed", string(got))
	}
}

func TestPIIToolSchemaAnnotationsAndConstraints(t *testing.T) {
	p := piiProxy()
	tool := Tool{Name: "fixture", Description: "Contact +79165550132",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"contact":{"type":"string","default":"+79165550132","examples":["+79165550132"]},"phone":{"type":"integer","default":79165550132},"count":{"type":"integer","default":42}},"required":["contact"]}`)}
	got, ok := p.redactTool(context.Background(), tool)
	if !ok {
		t.Fatal("safe schema could not be redacted")
	}
	encoded := string(mustJSON(got))
	if strings.Contains(encoded, "79165550132") || strings.Contains(encoded, "+79165550132") || strings.Contains(encoded, "79165550132") {
		t.Fatal("tool metadata PII leaked", encoded)
	}
	if !strings.Contains(encoded, `"required":["contact"]`) || !strings.Contains(encoded, `"default":42`) {
		t.Fatal("clean constraints/default changed", encoded)
	}
	for _, schema := range []string{
		`{"type":"object","properties":{"contact":{"enum":["+79165550132"]}}}`,
		`{"type":"object","properties":{"first_name":{"const":"Иван"}}}`,
		`{"type":"object","properties":{"+79165550132":{"type":"string"}}}`,
		`{"type":"object","x-extension":{"contact":"+79165550132"}}`,
		`{"type":"object","x-extension":{"first_name":"Иван"}}`,
	} {
		tool.InputSchema = json.RawMessage(schema)
		if _, ok := p.redactTool(context.Background(), tool); ok {
			t.Fatal("sensitive constraints rewritten or leaked", schema)
		}
	}
	tool.InputSchema = json.RawMessage(`{"type":"object","properties":{"contacts":{"type":"array","items":{"type":"object","properties":{"first_name":{"type":"string"},"phone":{"type":"integer"}}}}}}`)
	if _, ok := p.redactTool(context.Background(), tool); !ok {
		t.Fatal("ordinary nested schemas treated as sensitive data")
	}
}

func TestProxyPIIEndToEnd(t *testing.T) {
	c, bl := startProxyConfigured(t, func(p *Proxy) {
		p.RedactOn, p.Redact = true, redact.DefaultOptions
		spec := p.Specs["fake"]
		spec.Env["SAIFETY_FAKE_PII"] = "1"
		p.Specs["fake"] = spec
	})
	tools := c.call(t, "tools/list", map[string]any{})
	if strings.Contains(string(tools), "79165550132") || strings.Contains(string(tools), "+79165550132") ||
		strings.Contains(string(tools), "pii_enum") || !strings.Contains(string(tools), "pii_default") {
		t.Fatal("tool schema/description PII leaked or constraints widened", string(tools))
	}
	raw := json.RawMessage(`{"content":[{"type":"text","text":"+79165550132"}],"structuredContent":{"first_name":"Иван","phone":79165550132,"card":89165550133},"_meta":{"copy":"+79165550132"}}`)
	got := c.call(t, "tools/call", map[string]any{"name": "fake__echo", "arguments": map[string]any{"result": raw}})
	for _, value := range []string{"79165550132", "+79165550132", "Иван", "79165550132", "89165550133"} {
		if strings.Contains(string(got), value) {
			t.Fatalf("PII crossed real stdio proxy: %s", got)
		}
	}
	if bl.Blocked("fake/echo") {
		t.Fatal("PII-only response permanently quarantined the tool")
	}
	response := c.exchange(t, "tools/call", map[string]any{"name": "fake__echo", "arguments": map[string]any{
		"error": &RPCError{Code: -32000, Message: "+79165550132",
			Data: json.RawMessage(`{"phone":79165550132}`)},
	}})
	encoded := string(mustJSON(response))
	if response.Error == nil || strings.Contains(encoded, "+79165550132") || strings.Contains(encoded, "79165550132") ||
		response.Error.Data != nil {
		t.Fatal("upstream error details leaked", encoded)
	}
}
