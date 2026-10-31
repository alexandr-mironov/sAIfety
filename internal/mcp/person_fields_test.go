package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestPersonFieldDataAndContainers(t *testing.T) {
	for _, raw := range []string{
		`{"structuredContent":{"full_name":"Шахержон Тахержон","count":7}}`,
		`{"structuredContent":{"first_name":"Shaherzhon","last_name":"Taherzhon"}}`,
		`{"structuredContent":{"full_name":["Ivan Petrov","Li Bo"]}}`,
		`{"structuredContent":{"full_name":{"value":"Ivan Petrov","lang":"en"}}}`,
		`{"structuredContent":{"person_name":{"parts":["Ivan","Petrov"],"locale":"en"}}}`,
		`{"content":[{"type":"resource","resource":{"uri":"file:///fixture","text":"{\"full_name\":\"Shaherzhon Taherzhon\"}"}}]}`,
	} {
		p := piiProxy()
		out, d := p.inspectToolResult(context.Background(), "fixture/read", false, json.RawMessage(raw))
		got := string(mustJSON(out))
		for _, value := range []string{"Шахержон", "Тахержон", "Shaherzhon", "Taherzhon", "Ivan", "Petrov", "Li Bo"} {
			if strings.Contains(got, value) {
				t.Fatalf("field leaked %q: %s (%+v)", value, got, d)
			}
		}
		if !strings.Contains(got, "[REDACTED:full_name]") {
			t.Fatal("data needlessly withheld instead of masked", got, d)
		}
	}
}

func TestPersonFieldSchemaAndConfigurationPreserved(t *testing.T) {
	for _, raw := range []string{
		`{"structuredContent":{"first_name":{"type":"string","maxLength":60},"last_name":{"type":"string","required":true}}}`,
		`{"structuredContent":{"full_name":{"type":["string","null"],"title":"Full name","x-widget":"input","readOnly":false}}}`,
		`{"structuredContent":{"first_name":{"enabled":true,"visible":false,"widget":"text","label":"Given name"}}}`,
		`{"structuredContent":{"first_name":{"value":"String","lang":"en"},"full_name":{"type":"string","default":"String","enum":["String","None"]}}}`,
		`{"structuredContent":{"first_name":null,"last_name":"не указано","full_name":12345,"name":"Release Overview","title":"План Поставки"}}`,
	} {
		p := piiProxy()
		out, d := p.inspectToolResult(context.Background(), "fixture/read", false, json.RawMessage(raw))
		var want, got any
		if err := json.Unmarshal([]byte(raw), &want); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(mustJSON(out), &got); err != nil {
			t.Fatal(err)
		}
		if string(mustJSON(want)) != string(mustJSON(got)) {
			t.Errorf("safe schema/config changed: %s => %s (%+v)", raw, mustJSON(out), d)
		}
	}
}

func TestPersonFieldSchemaPrivateAnnotationsAndConstraints(t *testing.T) {
	p := piiProxy()
	raw := json.RawMessage(`{"structuredContent":{"full_name":{"type":"string","default":"Shaherzhon Taherzhon","examples":["Ivan Petrov"],"maxLength":80}}}`)
	out, _ := p.inspectToolResult(context.Background(), "fixture/read", false, raw)
	got := string(mustJSON(out))
	if strings.Contains(got, "Shaherzhon") || strings.Contains(got, "Ivan") || strings.Contains(got, `"default"`) || strings.Contains(got, `"examples"`) || !strings.Contains(got, `"maxLength":80`) {
		t.Fatal("schema annotation leaked or clean constraint lost", got)
	}
	for _, raw := range []string{
		`{"structuredContent":{"full_name":{"type":"string","enum":["Ivan Petrov"],"widget":"text"}}}`,
		`{"structuredContent":{"full_name":{"const":"Shaherzhon Taherzhon"}}}`,
		`{"structuredContent":{"first_name":{"Shaherzhon":"private key"}}}`,
	} {
		p := piiProxy()
		out, _ := p.inspectToolResult(context.Background(), "fixture/read", false, json.RawMessage(raw))
		got := mustJSON(out)
		assertWithheld(t, got)
		if strings.Contains(string(got), "Shaherzhon") || strings.Contains(string(got), "Ivan") {
			t.Fatal("private constraint/key leaked", string(got))
		}
	}
	tool := Tool{Name: "fixture", InputSchema: json.RawMessage(`{"type":"object","properties":{"full_name":{"type":"string","default":"Shaherzhon Taherzhon"}},"required":["full_name"]}`)}
	clean, ok := p.redactTool(context.Background(), tool)
	if !ok || strings.Contains(string(mustJSON(clean)), "Shaherzhon") || !strings.Contains(string(mustJSON(clean)), `"required":["full_name"]`) {
		t.Fatal("tool schema annotation handling changed", clean, ok)
	}
	tool.InputSchema = json.RawMessage(`{"type":"object","properties":{"full_name":{"const":"Shaherzhon Taherzhon"}}}`)
	if _, ok := p.redactTool(context.Background(), tool); ok {
		t.Fatal("tool constraint silently widened")
	}
}
