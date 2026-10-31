package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saifety-org/sAIfety/internal/model"
	"github.com/saifety-org/sAIfety/internal/scan/redact"
)

func TestNERRequiresExplicitOptInEvenWithCorruptCache(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("SAIFETY_CACHE", cache)
	for _, name := range []string{"pii-model.onnx", "pii-tokenizer.json", "pii-config.json", "libonnxruntime.dylib", "libonnxruntime.so"} {
		if err := os.WriteFile(filepath.Join(cache, name), []byte("broken fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []RedactConfig{{}, {NoModel: false}, {NERLabels: []string{"PER", "ORG"}}, {NER: true, NoModel: true}, {NER: true, Disabled: true}}
	for _, redaction := range cases {
		called := false
		opts := redactOptionsWithNER(Config{Redact: redaction}, func(redact.NERConfig) (redact.NER, error) { called = true; return nil, errors.New("must not load") })
		got, err := redact.Text("Иван Петров", opts)
		if called || err != nil || got != "[REDACTED:full_name]" {
			t.Fatal("implicit NER activation", redaction, called, got, err)
		}
	}
	for _, deep := range []bool{false, true} {
		opts := RedactOptions(Config{}, deep)
		if _, err := redact.FindChecked("Release Overview", opts); err != nil {
			t.Fatal("cache/deep flag activated NER", err)
		}
	}
}

type controlledNER struct{ closed bool }

func (*controlledNER) Recognize(s string) []redact.Match {
	const name = "Shaherzhon Taherzhon"
	if i := strings.Index(s, name); i >= 0 {
		return []redact.Match{{Kind: redact.KindPII, Label: "full_name", Start: i, End: i + len(name)}}
	}
	return nil
}
func (n *controlledNER) Close() error { n.closed = true; return nil }

func TestNEROptInWiresCachedArtifactsAndCloses(t *testing.T) {
	if _, err := model.PIIBundle(); err != nil {
		t.Skip(err)
	}
	cache := t.TempDir()
	t.Setenv("SAIFETY_CACHE", cache)
	runtime := filepath.Join(cache, "operator-runtime")
	t.Setenv("SAIFETY_ORT_LIB", runtime)
	called := 0
	recognizer := &controlledNER{}
	cfg := Config{Redact: RedactConfig{NER: true, NERLabels: []string{"PER"}}}
	opts := redactOptionsWithNER(cfg, func(c redact.NERConfig) (redact.NER, error) {
		called++
		if c.LibraryPath != runtime || c.ModelPath != filepath.Join(cache, "pii-model.onnx") || c.TokenizerPath != filepath.Join(cache, "pii-tokenizer.json") || c.ConfigPath != filepath.Join(cache, "pii-config.json") || len(c.Entities) != 1 || c.Entities[0] != "PER" {
			t.Fatalf("wrong NER wiring: %+v", c)
		}
		return recognizer, nil
	})
	got, err := redact.Text("Shaherzhon Taherzhon", opts)
	if called != 1 || err != nil || got != "[REDACTED:full_name]" {
		t.Fatal("explicit NER not applied", called, got, err)
	}
	if err := opts.CloseNER(); err != nil || !recognizer.closed {
		t.Fatal("owned recognizer not closed", err)
	}
}

func TestExplicitNERMissingDoesNotDownloadOrFallBack(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("SAIFETY_CACHE", cache)
	cfg := Config{Redact: RedactConfig{NER: true}}
	for _, deep := range []bool{false, true} {
		opts := RedactOptions(cfg, deep)
		if _, err := redact.Text("uninspected contact", opts); err == nil {
			t.Fatal("missing explicitly enabled model silently fell back")
		}
	}
	entries, err := os.ReadDir(cache)
	if err != nil || len(entries) != 0 {
		t.Fatal("runtime attempted provisioning", entries, err)
	}
	if _, err := scanPaths(context.Background(), []string{t.TempDir()}, cfg, scanOpts{}, io.Discard); err == nil {
		t.Fatal("scan reported success with unavailable enabled NER")
	}
}

func TestOptionalPIIBundleIsSeparateFromInjection(t *testing.T) {
	pii, err := model.PIIBundle()
	if err != nil {
		t.Skip(err)
	}
	injection, err := model.DefaultBundle()
	if err != nil {
		t.Fatal(err)
	}
	if pii.Model.Name == injection.Model.Name || pii.Tokenizer.Name == injection.Tokenizer.Name || pii.Config.Name == "" {
		t.Fatal("PII provisioning overwrites injection artifacts")
	}
}
