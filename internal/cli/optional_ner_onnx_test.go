//go:build onnx

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/saifety-org/sAIfety/internal/scan/redact"
)

func TestCachedNERStillNeedsOptInAndUsesNativeFixture(t *testing.T) {
	lib := os.Getenv("SAIFETY_CONTEXT_TEST_LIBRARY")
	if lib == "" {
		t.Skip("set SAIFETY_CONTEXT_TEST_LIBRARY for native NER fixture")
	}
	cache := t.TempDir()
	t.Setenv("SAIFETY_CACHE", cache)
	t.Setenv("SAIFETY_ORT_LIB", lib)
	for dst, src := range map[string]string{"pii-model.onnx": "ner-fixture.onnx", "pii-tokenizer.json": "ner-tokenizer.json", "pii-config.json": "ner-config.json"} {
		raw, err := os.ReadFile(filepath.Join("..", "scan", "redact", "testdata", src))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cache, dst), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	const name = "Shaherzhon Taherzhon"
	for _, cfg := range []Config{{}, {Redact: RedactConfig{NER: true, NoModel: true}}, {Redact: RedactConfig{NERLabels: []string{"PER"}}}} {
		opts := RedactOptions(cfg, true)
		got, err := redact.Text(name, opts)
		if err != nil || got != name {
			t.Fatal("valid cache activated a disabled model", got, err)
		}
	}
	for _, deep := range []bool{false, true} {
		opts := RedactOptions(Config{Redact: RedactConfig{NER: true}}, deep)
		for _, value := range []string{name, "Шахержон Тахержон", "Ivan Petrov"} {
			got, err := redact.Text(value, opts)
			if err != nil || got != "[REDACTED:full_name]" {
				t.Fatal("explicit NER not wired to native fixture", value, got, err)
			}
		}
		if err := opts.CloseNER(); err != nil {
			t.Fatal(err)
		}
	}
	// The graph assigns fixed logits to vocabulary IDs, not learned name scores.
}
