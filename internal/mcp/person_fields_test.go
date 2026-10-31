package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestPersonMetadataCannotHideNames(t *testing.T) {
	for _, key := range []string{"widget", "label", "language", "lang", "locale", "encoding", "description", "title", "enabled", "visible", "hidden", "disabled", "editable"} {
		for _, name := range []string{"John Smith", "Шахержон Тахержон", "晓岚 沈"} {
			for _, typed := range []bool{false, true} {
				for _, sibling := range []bool{false, true} {
					value := map[string]any{key: name}
					if typed {
						value["type"] = "string"
					}
					if sibling {
						value["value"] = "Ivan Petrov"
					}
					raw := mustJSON(map[string]any{"structuredContent": map[string]any{"full_name": value}})
					out, d := piiProxy().inspectToolResult(context.Background(), "fixture/read", false, raw)
					got := string(mustJSON(out))
					if strings.Contains(got, name) || strings.Contains(got, "Ivan Petrov") {
						t.Errorf("metadata %s, typed=%v sibling=%v: %s (%+v)", key, typed, sibling, got, d)
					}
				}
			}
		}
	}
	for _, value := range []any{[]any{"John Smith", "Шахержон Тахержон"}, map[string]any{"en": "John Smith"}} {
		raw := mustJSON(map[string]any{"structuredContent": map[string]any{"full_name": map[string]any{"label": value}}})
		out, _ := piiProxy().inspectToolResult(context.Background(), "fixture/read", false, raw)
		if got := string(mustJSON(out)); strings.Contains(got, "John Smith") || strings.Contains(got, "Шахержон") {
			t.Fatal("nested metadata leaked", got)
		}
	}
	for _, value := range []string{"en-x-john-smith", "en-John-US", "en John Smith", "en\u200bJohnSmith"} {
		if personMetadataValue("lang", value) {
			t.Errorf("person content accepted as locale: %q", value)
		}
	}
}

func TestKnownPersonMetadataPreserved(t *testing.T) {
	for key, values := range map[string][]any{
		"lang":     {"en", "eng", "ru-RU", "zh-Hant-TW", "sr_Latn", "C"},
		"locale":   {"en_US", "de-DE", "es-419", "POSIX"},
		"encoding": {"UTF-8", "utf-16le", "base64", "ascii"},
		"widget":   {"input", "text", "textarea", "autocomplete"},
		"label":    {"Given name", "ФИО", "User field"},
		"visible":  {true, false},
	} {
		for _, value := range values {
			raw := mustJSON(map[string]any{"structuredContent": map[string]any{"full_name": map[string]any{key: value, "value": "String"}}})
			out, d := piiProxy().inspectToolResult(context.Background(), "fixture/read", false, raw)
			if string(mustJSON(out)) != string(raw) {
				t.Errorf("safe metadata %s=%v changed: %s (%+v)", key, value, mustJSON(out), d)
			}
		}
	}
	// Custom UI prose cannot be distinguished from a person's name without a
	// stronger source contract. The conservative fallback must remain explicit.
	raw := json.RawMessage(`{"structuredContent":{"full_name":{"label":"Public display label"}}}`)
	out, _ := piiProxy().inspectToolResult(context.Background(), "fixture/read", false, raw)
	if strings.Contains(string(mustJSON(out)), "Public display label") {
		t.Fatal("unknown metadata silently exempted")
	}
}

func TestSchemaChangeSignal(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		changed   bool
	}{
		{"clean", `{"type":"object","properties":{"full_name":{"type":"string","title":"Full name"}}}`, false},
		{"default", `{"type":"object","properties":{"full_name":{"type":"string","default":"John Smith"}}}`, true},
		{"examples", `{"type":"object","properties":{"full_name":{"type":"string","examples":["John Smith"]}}}`, true},
		{"description", `{"type":"object","description":"Call +79165550132"}`, true},
		{"person title", `{"type":"object","properties":{"full_name":{"type":"string","title":"John Smith"}}}`, true},
		{"numeric annotation", `{"type":"object","properties":{"full_name":{"type":"string","title":79165550132}}}`, true},
		{"nested array", `{"allOf":[{"$defs":{"Person":{"properties":{"full_name":{"type":"string","example":"John Smith"}}}}}]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, err := parseJSONObject(json.RawMessage(tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			before := string(mustJSON(value))
			change := privacyChange{}
			if err := piiProxy().redactSchema(context.Background(), value, "", &change); err != nil {
				t.Fatal(err)
			}
			if change.changed != tc.changed || change.changed != (before != string(mustJSON(value))) || change.protected || change.numeric {
				t.Fatalf("mutation signal mismatch: %+v, %s => %s", change, before, mustJSON(value))
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	change := privacyChange{}
	if err := piiProxy().redactSchema(ctx, map[string]any{}, "", &change); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}

func TestPersonConstraintTracksOnlyItsOwnChanges(t *testing.T) {
	// An earlier sibling's mask must not make an unchanged enum look modified.
	value := map[string]any{"const": "String", "value": "John Smith"}
	change := privacyChange{changed: true}
	_, err := piiProxy().redactValue(context.Background(), value, resultOther, "full_name", &change)
	if err != nil || change.protected || !change.changed {
		t.Fatal("clean constraint inherited sibling mutation", change, err)
	}
}

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
