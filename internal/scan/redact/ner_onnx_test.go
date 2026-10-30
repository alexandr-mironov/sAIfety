//go:build onnx

package redact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestONNXNERCompleteWindowedFixture(t *testing.T) {
	lib := os.Getenv("SAIFETY_CONTEXT_TEST_LIBRARY")
	if lib == "" {
		home, _ := os.UserHomeDir()
		lib = filepath.Join(home, ".cache", "saifety", "libonnxruntime.dylib")
		if _, err := os.Stat(lib); err != nil {
			t.Skip("native test runtime unavailable; set SAIFETY_CONTEXT_TEST_LIBRARY")
		}
	}
	recognizer, err := NewONNXNER(NERConfig{
		LibraryPath: lib, ModelPath: "testdata/ner-fixture.onnx",
		TokenizerPath: "testdata/ner-tokenizer.json", ConfigPath: "testdata/ner-config.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	n := recognizer.(*onnxNER)
	t.Cleanup(func() { _ = n.session.Destroy() })
	for _, entity := range []string{"entity", "иван петров", "张伟"} {
		t.Run(entity, func(t *testing.T) {
			text := strings.Repeat("plain ", 600) + entity
			matches, err := n.RecognizeChecked(text)
			if err != nil {
				t.Fatal(err)
			}
			if len(matches) != 1 || text[matches[0].Start:matches[0].End] != entity {
				t.Fatalf("late entity missing or original Unicode offsets wrong: %+v", matches)
			}
			out, err := Text(text, DefaultOptions.WithNER(n))
			if err != nil || strings.Contains(out, entity) {
				t.Fatal("entity beyond first window leaked", out, err)
			}
		})
	}
	if matches, err := n.RecognizeChecked(strings.Repeat("plain ", nerMaxSeq*(nerMaxWindows+1))); err == nil || matches != nil {
		t.Fatal("over-limit native NER returned a clean prefix")
	}
}

func TestONNXNERRecognizesNames(t *testing.T) {
	cache := os.Getenv("SAIFETY_CACHE")
	if cache == "" {
		home, _ := os.UserHomeDir()
		cache = filepath.Join(home, ".cache", "saifety")
	}
	cfg := NERConfig{
		LibraryPath:   filepath.Join(cache, "libonnxruntime.dylib"),
		ModelPath:     filepath.Join(cache, "pii-model.onnx"),
		TokenizerPath: filepath.Join(cache, "pii-tokenizer.json"),
		ConfigPath:    filepath.Join(cache, "pii-config.json"),
	}
	for _, p := range []string{cfg.LibraryPath, cfg.ModelPath, cfg.TokenizerPath, cfg.ConfigPath} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("pii model not present (%s); run `saifety model pull`", p)
		}
	}
	ner, err := NewONNXNER(cfg)
	if err != nil {
		t.Fatalf("NewONNXNER: %v", err)
	}
	// A name with no patronymic and no nearby contact — heuristics miss it,
	// the model should catch it.
	text := "The report was prepared by Jonathan Whitfield last quarter."
	ms := ner.Recognize(text)
	found := false
	for _, m := range ms {
		val := text[m.Start:m.End]
		if strings.Contains("Jonathan Whitfield", val) && m.Kind == KindPII {
			found = true
		}
	}
	if !found {
		t.Fatalf("NER did not flag the name: %+v", ms)
	}
	// Full Find with NER attached masks it.
	out := Mask(text, Find(text, DefaultOptions.WithNER(ner)))
	if strings.Contains(out, "Jonathan") {
		t.Fatalf("name not masked with NER: %q", out)
	}

	// Multilingual: a Russian name (not in the model's training languages)
	// is still caught via the multilingual base.
	ru := "Отчёт подготовил Иван Петров вчера."
	if len(ner.Recognize(ru)) == 0 {
		t.Errorf("multilingual NER found no entity in Russian text: %q", ru)
	}
}
