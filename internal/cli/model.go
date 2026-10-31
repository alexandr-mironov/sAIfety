package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/saifety-org/sAIfety/internal/model"
)

func runModel(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	sub := "status"
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	b, err := model.DefaultBundle()
	if sub == "pull-pii" {
		b, err = model.PIIBundle()
	}
	if err != nil {
		fmt.Fprintln(stderr, "model:", err)
		return ExitError
	}
	switch sub {
	case "pull", "pull-pii":
		force := len(args) > 0 && (args[0] == "-force" || args[0] == "--force")
		fmt.Fprintf(stdout, "provisioning models into %s\n", model.CacheDir())
		if err := b.Pull(stdout, force); err != nil {
			fmt.Fprintln(stderr, "pull:", err)
			return ExitError
		}
		fmt.Fprintln(stdout, "done. ONNX models require a -tags onnx build; PII NER also requires redact.ner=true.")
		return ExitClean
	case "status":
		fmt.Fprintf(stdout, "cache: %s\n", model.CacheDir())
		arts := []model.Artifact{b.Runtime, b.Tokenizer, b.Model}
		for _, a := range arts {
			state := "missing"
			if fi, err := os.Stat(model.Path(a)); err == nil {
				state = fmt.Sprintf("%d bytes", fi.Size())
			}
			fmt.Fprintf(stdout, "  %-20s %s\n", a.Name, state)
		}
		fmt.Fprintf(stdout, "injection ready: %v\n", b.Present())
		if pii, err := model.PIIBundle(); err == nil {
			for _, a := range []model.Artifact{pii.Tokenizer, pii.Config, pii.Model} {
				state := "missing"
				if fi, err := os.Stat(model.Path(a)); err == nil {
					state = fmt.Sprintf("%d bytes", fi.Size())
				}
				fmt.Fprintf(stdout, "  %-20s %s\n", a.Name, state)
			}
			fmt.Fprintf(stdout, "pii cached: %v (NER disabled unless redact.ner=true)\n", pii.Present())
		}
		return ExitClean
	case "path":
		fmt.Fprintln(stdout, model.Path(b.Model))
		fmt.Fprintln(stdout, model.Path(b.Tokenizer))
		fmt.Fprintln(stdout, model.RuntimeLibPath())
		return ExitClean
	default:
		fmt.Fprintln(stderr, "usage: saifety model <pull|pull-pii|status|path>")
		return ExitUsage
	}
}
