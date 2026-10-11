package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/saifety-org/sAIfety/internal/contextmodel"
	"github.com/saifety-org/sAIfety/pkg/contextscan"
)

// ContextConfig enables advisory inference, separately from the production
// classifier. Task is only accepted from command-line flags, never tool data.
type ContextConfig struct {
	Mode           string `json:"mode"`
	Bundle         string `json:"bundle"`
	Library        string `json:"library"`
	ManifestSHA256 string `json:"manifestSHA256"`
	TimeoutMS      int    `json:"timeoutMS"`
	MaxWindows     int    `json:"maxWindows"`
}

func contextOptions(c ContextConfig) (contextscan.Options, error) {
	if c.MaxWindows < 0 || c.MaxWindows > 32 {
		return contextscan.Options{}, fmt.Errorf("context maxWindows must be 0..32")
	}
	if c.TimeoutMS < 0 || c.TimeoutMS > 60000 {
		return contextscan.Options{}, fmt.Errorf("context timeoutMS must be 0..60000")
	}
	return contextscan.Options{Timeout: time.Duration(c.TimeoutMS) * time.Millisecond, MaxWindows: c.MaxWindows}, nil
}
func openContext(ctx context.Context, c ContextConfig) (*contextscan.Adapter, *contextscan.Worker, error) {
	opts, err := contextOptions(c)
	if err != nil {
		return nil, nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	pin := c.ManifestSHA256
	if pin == "" {
		pin = contextscan.V4ManifestSHA256
	}
	startup, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	w, err := contextscan.Open(startup, contextscan.WorkerConfig{Executable: exe, Bundle: c.Bundle, Library: c.Library, ManifestSHA256: pin})
	if err != nil {
		return nil, nil, err
	}
	a, err := contextscan.New(w, opts)
	if err != nil {
		_ = w.Close()
		return nil, nil, err
	}
	return a, w, nil
}
func contextObserver(ctx context.Context, c ContextConfig, task string, stderr io.Writer) (*contextscan.Observer, func(), error) {
	if c.Mode == "" || c.Mode == "off" {
		return nil, func() {}, nil
	}
	if c.Mode != "shadow" {
		return nil, nil, fmt.Errorf("experimentalContext.mode must be off or shadow")
	}
	if _, err := contextOptions(c); err != nil {
		return nil, nil, err
	}
	var mu sync.Mutex
	o := &contextscan.Observer{Task: task, Report: func(r contextscan.Result, err error) {
		// Only status, scores and artifact identity; no task, ranges or document text.
		value := struct {
			Status   string           `json:"status"`
			Reason   string           `json:"reason"`
			Model    contextscan.Info `json:"model"`
			Coverage string           `json:"coverage"`
			Score    *float64         `json:"score,omitempty"`
			Attack   *bool            `json:"attack,omitempty"`
			Windows  int              `json:"windows"`
			Warnings []string         `json:"warnings,omitempty"`
		}{r.Status, r.Reason, r.Model, r.Coverage, r.Score, r.Attack, len(r.Windows), r.Warnings}
		mu.Lock()
		defer mu.Unlock()
		b, e := json.Marshal(value)
		if e == nil {
			fmt.Fprintln(stderr, "experimental-context:", string(b))
		}
	}}
	if strings.TrimSpace(task) == "" {
		o.Task = ""
		return o, func() {}, nil
	}
	a, w, err := openContext(ctx, c)
	if err != nil {
		// Advisory startup failure must not skip the existing protection path.
		o.Report(contextscan.Result{Status: "error", Reason: "backend-unavailable", Experimental: true, Coverage: "none"}, err)
		return o, func() {}, nil
	}
	o.Adapter = a
	return o, func() { _ = w.Close() }, nil
}
func runContext(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("context", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", DefaultConfigPath(), "config with experimentalContext local artifacts")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if len(fs.Args()) != 0 {
		return ExitUsage
	}
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "config:", err)
		return ExitError
	}
	if cfg.ExperimentalContext.Mode != "shadow" {
		fmt.Fprintln(stderr, "context requires experimentalContext.mode=shadow")
		return ExitUsage
	}
	var in contextscan.Input
	dec := json.NewDecoder(io.LimitReader(stdin, 8<<20))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&in); err != nil {
		fmt.Fprintln(stderr, "invalid context JSON")
		return ExitUsage
	}
	if dec.Decode(new(any)) != io.EOF {
		fmt.Fprintln(stderr, "trailing or oversized context JSON")
		return ExitUsage
	}
	// Missing task is observable without loading hundreds of MB of model assets.
	if strings.TrimSpace(in.Task) == "" {
		if err = json.NewEncoder(stdout).Encode(contextscan.Result{Status: "missing-context", Reason: "missing-user-task", Experimental: true, Coverage: "none"}); err != nil {
			return ExitError
		}
		return ExitError
	}
	a, w, err := openContext(ctx, cfg.ExperimentalContext)
	if err != nil {
		fmt.Fprintln(stderr, "context:", err)
		return ExitError
	}
	defer func() { _ = w.Close() }()
	result, err := a.Analyze(ctx, in)
	if e := json.NewEncoder(stdout).Encode(result); e != nil {
		return ExitError
	}
	if err != nil {
		return ExitError
	}
	return ExitClean // advisory attack does not change process threat level
}
func runContextWorker(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("context-worker", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("bundle", "", "local bundle")
	library := fs.String("library", "", "local ORT library")
	pin := fs.String("manifest-sha256", "", "manifest pin")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if err := contextmodel.Serve(*dir, *library, *pin, stdin, stdout); err != nil {
		return ExitError
	}
	return ExitClean
}
