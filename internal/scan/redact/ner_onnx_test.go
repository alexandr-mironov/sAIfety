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
	t.Cleanup(func() { _ = n.Close() })
	for _, entity := range []string{"entity", "иван петров", "张伟", "Шахержон Тахержон", "Shaherzhon Taherzhon", "Ivan Petrov"} {
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
