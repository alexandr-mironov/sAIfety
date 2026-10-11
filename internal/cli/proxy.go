package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"

	"github.com/saifety-org/sAIfety/internal/mcp"
	"github.com/saifety-org/sAIfety/internal/policy"
	"github.com/saifety-org/sAIfety/internal/stats"
)

func runProxy(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	task := fs.String("task", "", "operator-supplied user task for experimental contextual shadow inference")
	cfgPath := fs.String("config", DefaultConfigPath(), "config with mcpServers (compatible with .mcp.json)")
	statePath := fs.String("state", policy.DefaultBlocklistPath(), "blocklist state file")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "config:", err)
		return ExitError
	}
	if len(cfg.MCPServers) == 0 {
		fmt.Fprintln(stderr, "no mcpServers in", *cfgPath)
		return ExitUsage
	}
	observer, closeContext, err := contextObserver(ctx, cfg.ExperimentalContext, *task, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "context:", err)
		return ExitError
	}
	defer closeContext()
	bl, err := policy.LoadBlocklist(*statePath)
	if err != nil {
		fmt.Fprintln(stderr, "state:", err)
		return ExitError
	}
	pins, err := policy.LoadPins(policy.DefaultPinsPath())
	if err != nil {
		fmt.Fprintln(stderr, "pins:", err)
		pins = nil
	}
	st, _ := stats.Load(stats.ScopePath("proxy"))
	trusted := map[string]bool{}
	for _, t := range cfg.TrustedSources {
		trusted[t] = true
	}
	p := &mcp.Proxy{
		Context:     observer,
		Scanner:     newScanner(cfg, true),
		DescScanner: NewDescScanner(cfg),
		Specs:       cfg.MCPServers,
		Trusted:     trusted,
		Blocklist:   bl,
		Log:         log.New(stderr, "saifety: ", log.Ltime), // stdout is the protocol channel
		Redact:      RedactOptions(cfg, true),
		RedactOn:    RedactEnabled(cfg),
		Pins:        pins,
		Stats:       st,
	}
	if err := p.Serve(ctx, stdin, stdout); err != nil {
		fmt.Fprintln(stderr, "proxy:", err)
		return ExitError
	}
	return ExitClean
}
