package mcp

import (
	"context"
	"strings"
	"testing"
)

func TestComposedPersonUIDescriptorsPreserved(t *testing.T) {
	for _, text := range []string{
		"Shipping details", "Optional profile input", "Введите значение", "Public display label", "Profile caption",
		"Required account name", "Please enter your family name", "Additional shipping information",
		"Подпись поля профиля", "Ваше имя и фамилия", "Подсказка для заполнения поля", "Данные учётной записи",
	} {
		for _, key := range []string{"label", "title", "description"} {
			for _, typed := range []bool{false, true} {
				value := map[string]any{key: text}
				if typed {
					value["type"] = "string"
				}
				raw := mustJSON(map[string]any{"structuredContent": map[string]any{"full_name": value}})
				out, d := piiProxy().inspectToolResult(context.Background(), "fixture/read", false, raw)
				if string(mustJSON(out)) != string(raw) {
					t.Errorf("UI metadata changed: %s => %s (%+v)", raw, mustJSON(out), d)
				}
			}
		}
	}
}

func TestUIDescriptorWordsCannotExemptPersonalData(t *testing.T) {
	for _, name := range []string{"John Smith", "Шахержон Тахержон", "ivan petrov", "Li Wei", "A. Field", "A Field", "An Field", "И. Поля", "Mark Field", "Will Read", "松本 美咲"} {
		for _, prefix := range []string{"", "Public display label for ", "Введите имя ", "Shipping details: "} {
			for _, key := range []string{"label", "title", "description"} {
				value := map[string]any{key: prefix + name, "type": "string"}
				raw := mustJSON(map[string]any{"structuredContent": map[string]any{"full_name": value}})
				out, d := piiProxy().inspectToolResult(context.Background(), "fixture/read", false, raw)
				if strings.Contains(string(mustJSON(out)), name) {
					t.Errorf("UI prefix hid a name: %s => %s (%+v)", raw, mustJSON(out), d)
				}
			}
		}
	}
	for _, key := range []string{"first_name", "full_name", "value", "text", "parts", "widget", "encoding", "lang"} {
		value := "Public display label"
		raw := mustJSON(map[string]any{"structuredContent": map[string]any{"full_name": map[string]any{key: value}}})
		out, _ := piiProxy().inspectToolResult(context.Background(), "fixture/read", false, raw)
		if strings.Contains(string(mustJSON(out)), value) {
			t.Errorf("UI exception escaped descriptor metadata via %s", key)
		}
	}
	for _, text := range []string{
		"Public display label John\u200b Smith", "Your name J\u043ehn Smith", "Public label 姓名",
		strings.Repeat("Public field ", 100) + "John Smith", "A. Field", "name name",
	} {
		if personUIDescriptor(text) {
			t.Errorf("unsafe descriptor accepted: %q", text)
		}
	}
}

func TestUIDescriptorsStillCheckCustomKeywordsAndPhones(t *testing.T) {
	for _, tc := range []struct{ text, hidden string }{
		{"Please enter your full name 79036842719", "79036842719"},
		{"Public display label", "display"},
	} {
		if !personUIDescriptor(tc.text) {
			t.Fatal("test did not exercise an approved descriptor", tc.text)
		}
		p := piiProxy()
		p.Redact.Keywords = []string{"display"}
		raw := mustJSON(map[string]any{"structuredContent": map[string]any{"full_name": map[string]any{"label": tc.text}}})
		out, _ := p.inspectToolResult(context.Background(), "fixture/read", false, raw)
		if strings.Contains(string(mustJSON(out)), tc.hidden) {
			t.Fatal("descriptor bypassed independent redaction", tc, string(mustJSON(out)))
		}
	}
}
