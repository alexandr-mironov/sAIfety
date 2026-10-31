package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/saifety-org/sAIfety/internal/report"
	"github.com/saifety-org/sAIfety/internal/scan"
	"github.com/saifety-org/sAIfety/internal/scan/aggregate"
	"github.com/saifety-org/sAIfety/internal/scan/extract"
	"github.com/saifety-org/sAIfety/internal/stats"
	"github.com/saifety-org/sAIfety/internal/walk"
)

func runScan(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text | json | sarif")
	verbose := fs.Bool("v", false, "show excerpts and detector notes")
	cfgPath := fs.String("config", DefaultConfigPath(), "config file")
	failOn := fs.String("fail-on", "base", "exit non-zero from this level: base | medium | critical")
	ocr := fs.Bool("ocr", false, "run OCR on raster images (needs tesseract in PATH)")
	deep := fs.Bool("deep", false, "compatibility flag; PII uses model-free Russian name/mobile rules")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	paths := fs.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "config:", err)
		return ExitError
	}
	threshold, ok := scan.ParseLevel(*failOn)
	if !ok {
		fmt.Fprintln(stderr, "bad -fail-on value")
		return ExitUsage
	}

	sum, err := scanPaths(ctx, paths, cfg, scanOpts{OCR: *ocr, Deep: *deep}, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitError
	}

	switch *format {
	case "json":
		if err := report.JSON(stdout, sum); err != nil {
			return ExitError
		}
	case "sarif":
		if err := report.SARIF(stdout, sum); err != nil {
			return ExitError
		}
	default:
		report.Text(stdout, sum, *verbose)
	}
	if sum.Level >= threshold && sum.Level > scan.LevelNone {
		return int(sum.Level)
	}
	return ExitClean
}

func listEntries(p string, cfg Config) ([]walk.Entry, error) {
	info, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []walk.Entry{{Path: p, Kind: walk.Classify(filepath.Base(p)), Size: info.Size()}}, nil
	}
	return walk.Files(p, walk.Options{MaxFileSize: cfg.MaxFileSize})
}

type scanOpts struct {
	OCR  bool
	Deep bool
}

// scanPaths scans files and directories, then runs the cross-file
// aggregate pass, and returns the combined summary.
func scanPaths(ctx context.Context, paths []string, cfg Config, opts scanOpts, stderr io.Writer) (*report.Summary, error) {
	redaction := RedactOptions(cfg, opts.Deep)
	defer func() { _ = redaction.CloseNER() }()
	if err := redaction.NERError(); err != nil {
		return nil, fmt.Errorf("enabled PII NER unavailable: %w", err)
	}
	sc, pol := newScannerAndPolicyWithRedact(cfg, opts.Deep, redaction)
	agg := aggregate.New(sc, pol)
	st, _ := stats.Load(stats.ScopePath("scan"))
	var ocr extract.OCR
	if opts.OCR {
		t := extract.Tesseract{}
		if t.Available() {
			ocr = t
		} else {
			fmt.Fprintln(stderr, "ocr: tesseract not found in PATH, skipping pixels")
		}
	}
	// Gather every entry first so progress can show N/total.
	var entries []walk.Entry
	for _, p := range paths {
		es, err := listEntries(p, cfg)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		entries = append(entries, es...)
	}
	prog := newScanProgress(stderr, len(entries))

	sum := &report.Summary{}
	for _, e := range entries {
		prog.step(e.Path)
		{
			raw, err := os.ReadFile(e.Path)
			if err != nil {
				prog.clear()
				fmt.Fprintf(stderr, "skip %s: %v\n", e.Path, err)
				continue
			}
			var doc *scan.Document
			if e.Kind == scan.KindImage {
				text, ok := extract.ImageText(e.Path, raw)
				if ocr != nil {
					if t, err := ocr.Recognize(ctx, e.Path, raw); err == nil && strings.TrimSpace(t) != "" {
						text += "\nocr: " + t
						ok = true
					}
				}
				if !ok {
					sum.Scanned++
					continue
				}
				doc = &scan.Document{Source: e.Path, Kind: scan.KindImage, Raw: text}
			} else {
				doc = &scan.Document{Source: e.Path, Kind: e.Kind, Raw: string(raw)}
			}
			v := sc.Scan(ctx, doc)
			agg.Add(doc, v)
			sum.Add(v)
			st.Record(v)
		}
	}
	prog.done()
	for _, v := range agg.Finish(ctx) {
		sum.Add(v)
		sum.Scanned-- // repo-level verdicts are not files
		st.Record(v)
	}
	return sum, nil
}
