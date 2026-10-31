package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestRussianPIIPreservesNonpersonalResults(t *testing.T) {
	for _, raw := range []string{
		`{"content":[{"type":"text","text":"Release Overview"}]}`,
		`{"content":[{"type":"text","text":"План Поставки"}]}`,
		`{"content":[{"type":"text","text":"first_name: String\nlast_name: String"}]}`,
		`{"structuredContent":{"account":{"status":"active","plan":"team"},"phone":{"type":"string"},"first_name":{"type":"string"}}}`,
		`{"structuredContent":{"order_number":79165550132,"order_id":"89165550132","amount":79165550132.25,"negative":-79165550132}}`,
		`{"structuredContent":{"order_number":"12379165550132","foreign_phone":"+1 (415) 555-0132","card":"4111111111111111"}}`,
		`{"content":[{"type":"text","text":"Номер заказа: 79165550132"}],"structuredContent":{"id":9007199254740993}}`,
		`{"content":[{"type":"resource","resource":{"uri":"file:///fixture","text":"План Поставки"}}],"_meta":{"account":{"status":"ok"}}}`,
	} {
		p := piiProxy()
		output, d := p.inspectToolResult(context.Background(), "fixture/read", false, json.RawMessage(raw))
		var want, got any
		if err := json.Unmarshal([]byte(raw), &want); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(mustJSON(output), &got); err != nil {
			t.Fatal(err)
		}
		if string(mustJSON(want)) != string(mustJSON(got)) {
			t.Errorf("safe result changed: %s => %s (%+v)", raw, mustJSON(output), d)
		}
	}
}

func TestOrderContextDoesNotSuppressContact(t *testing.T) {
	p := piiProxy()
	raw := json.RawMessage(`{"structuredContent":{"order_number":79165550132,"phone":"+79165550133","first_name":"Иван","last_name":"Петров"}}`)
	got := string(mustJSON(p.scanToolResult(context.Background(), "fixture/read", false, raw)))
	if !strings.Contains(got, "79165550132") || strings.Contains(got, "79165550133") || strings.Contains(got, "Иван") || strings.Contains(got, "Петров") {
		t.Fatal("order exception affected contact", got)
	}
}

func TestShortEncodedRussianPIICopies(t *testing.T) {
	for _, value := range []string{"+79165550132", "Иван Петров"} {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding} {
			encoded := enc.EncodeToString([]byte(value))
			p := piiProxy()
			raw := mustJSON(map[string]any{"structuredContent": map[string]string{"encoded_copy": encoded}})
			output, d := p.inspectToolResult(context.Background(), "fixture/read", false, raw)
			if strings.Contains(string(mustJSON(output)), encoded) || d.Reason != "encoded_sensitive_data" {
				t.Fatal("encoded contact leaked", string(mustJSON(output)), d)
			}
		}
	}
}
