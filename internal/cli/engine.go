package cli

import (
	"fmt"
	"os"

	"github.com/saifety-org/sAIfety/internal/model"
	"github.com/saifety-org/sAIfety/internal/policy"
	"github.com/saifety-org/sAIfety/internal/scan"
	"github.com/saifety-org/sAIfety/internal/scan/classify"
	"github.com/saifety-org/sAIfety/internal/scan/detect"
	"github.com/saifety-org/sAIfety/internal/scan/redact"
)

// newScannerAndPolicyWithRedact shares one optional recognizer between
// detection and output masking. The instruction classifier is independent.
func newScannerAndPolicyWithRedact(cfg Config, useModel bool, opts redact.Options) (*scan.Scanner, scan.Policy) {
	profile := policy.Strict
	if cfg.Policy == "balanced" || cfg.Policy == "default" {
		profile = policy.Default
	}
	pol := policy.New(profile)
	detectors := append(detect.Default(), classify.Detector{C: classifierFor(cfg, useModel)})
	detectors = append(detectors, detect.Redaction{Opts: opts})
	return scan.New(detectors, pol, scan.Options{MaxDecodeDepth: cfg.MaxDecodeDepth}), pol
}

// NewDescScanner builds a scanner for MCP tool DESCRIPTIONS. Descriptions are
// short, static, and numerous (hundreds across servers), so it always uses
// the fast lexical classifier — never the transformer — regardless of the
// configured classifier. The heavy model is reserved for tool-call results.
func NewDescScanner(cfg Config) *scan.Scanner {
	return newDescScannerWithRedact(cfg, RedactOptions(cfg, false))
}

func newDescScannerWithRedact(cfg Config, opts redact.Options) *scan.Scanner {
	profile := policy.Strict
	if cfg.Policy == "balanced" || cfg.Policy == "default" {
		profile = policy.Default
	}
	pol := policy.New(profile)
	detectors := append(detect.Default(), classify.Detector{C: classify.Lexical{}})
	detectors = append(detectors, detect.Redaction{Opts: opts})
	return scan.New(detectors, pol, scan.Options{MaxDecodeDepth: cfg.MaxDecodeDepth})
}

// RedactOptions attaches NER only after explicit configuration. It never
// downloads files. The old deep/useModel flag cannot activate NER on its own.
func RedactOptions(cfg Config, _ bool) redact.Options {
	return redactOptionsWithNER(cfg, redact.NewONNXNER)
}

func redactOptionsWithNER(cfg Config, load func(redact.NERConfig) (redact.NER, error)) redact.Options {
	opts := redact.Options{Keywords: cfg.Redact.Keywords, Allowlist: cfg.Redact.Allowlist,
		MinEntropy: cfg.Redact.MinEntropy}
	if !cfg.Redact.NER || cfg.Redact.NoModel || cfg.Redact.Disabled {
		return opts
	}
	bundle, err := model.PIIBundle()
	if err != nil {
		return opts.WithNERError(err)
	}
	lib := model.RuntimeLibPath()
	if override := os.Getenv("SAIFETY_ORT_LIB"); override != "" {
		lib = override
	}
	ner, err := load(redact.NERConfig{LibraryPath: lib,
		ModelPath: model.Path(bundle.Model), TokenizerPath: model.Path(bundle.Tokenizer),
		ConfigPath: model.Path(bundle.Config), Entities: cfg.Redact.NERLabels})
	if err != nil {
		return opts.WithNERError(err)
	}
	if ner == nil {
		return opts.WithNERError(fmt.Errorf("PII NER loader returned no recognizer"))
	}
	return opts.WithNER(ner)
}

// RedactEnabled reports whether output masking should run.
func RedactEnabled(cfg Config) bool { return !cfg.Redact.Disabled }

// classifierFor picks the instruction classifier from config. It falls back
// to the lexical model whenever the transformer is unavailable (not built
// in, or the model has not been pulled), printing one line to stderr so the
// choice is visible but never fatal.
func classifierFor(cfg Config, useModel bool) classify.Classifier {
	explicit := cfg.Classifier != ""
	mode := cfg.Classifier
	if mode == "" {
		mode = "trained" // default: our embedded attack-on-agent model (fast, no download)
	}
	switch mode {
	case "trained":
		if c, err := classify.NewTrained(); err == nil {
			return c
		}
		return classify.Lexical{}
	case "lexical":
		return classify.Lexical{}
	case "onnx", "auto":
		if !classify.Built {
			if explicit && mode == "onnx" {
				fmt.Fprintln(os.Stderr, "saifety: this binary has no transformer (build with -tags onnx or `make build`); using lexical")
			}
			return classify.Lexical{}
		}
		b, err := model.DefaultBundle()
		if err != nil {
			fmt.Fprintln(os.Stderr, "saifety: no model bundle for this platform, using lexical:", err)
			return classify.Lexical{}
		}
		// onnx: download the model on first use. auto: only
		// use a model that is already present, never block on a download.
		if !b.Present() {
			if mode == "auto" {
				return classify.Lexical{}
			}
			fmt.Fprintln(os.Stderr, "saifety: provisioning transformer classifier (first run, ~738MB)...")
			if err := b.Pull(os.Stderr, false); err != nil {
				fmt.Fprintln(os.Stderr, "saifety: model download failed, using lexical:", err)
				return classify.Lexical{}
			}
		}
		lib := model.RuntimeLibPath()
		if env := os.Getenv("SAIFETY_ORT_LIB"); env != "" {
			lib = env
		}
		c, err := classify.NewONNX(classify.ONNXConfig{
			LibraryPath:    lib,
			ModelPath:      model.Path(b.Model),
			TokenizerPath:  model.Path(b.Tokenizer),
			InjectionIndex: b.InjectionIndex,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "saifety: onnx classifier unavailable, using lexical (rebuild with -tags onnx):", err)
			return classify.Lexical{}
		}
		return c
	default:
		fmt.Fprintln(os.Stderr, "saifety: unknown classifier", mode, "- using lexical")
		return classify.Lexical{}
	}
}
