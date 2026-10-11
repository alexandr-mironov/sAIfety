package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/saifety-org/sAIfety/internal/hook"
	"github.com/saifety-org/sAIfety/internal/policy"
	"github.com/saifety-org/sAIfety/internal/stats"
)

func runHook(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	fs.SetOutput(stderr)
	task := fs.String("task", "", "operator-supplied user task for experimental contextual shadow inference")
	cfgPath := fs.String("config", DefaultConfigPath(), "config file")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	args = fs.Args()
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: saifety hook [-config f] <session-start|pre-tool-use|post-tool-use>")
		return ExitUsage
	}
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "config:", err)
		return ExitError
	}
	bl, err := policy.LoadBlocklist(policy.DefaultBlocklistPath())
	if err != nil {
		fmt.Fprintln(stderr, "state:", err)
		if args[0] == "pre-tool-use" {
			if err := json.NewEncoder(stdout).Encode(hook.DenyUnavailableBlocklist(err)); err != nil {
				return ExitError
			}
			return ExitClean
		}
		return ExitError
	}
	st, _ := stats.Load(stats.ScopePath("hook"))
	h := &hook.Handler{Scanner: newScanner(cfg, true), Blocklist: bl, Redact: RedactOptions(cfg, true), RedactOn: RedactEnabled(cfg), Stats: st}

	var in hook.Input
	if err := json.NewDecoder(stdin).Decode(&in); err != nil {
		fmt.Fprintln(stderr, "hook input:", err)
		return ExitError
	}
	// PreToolUse is enforced independently of the optional observer. A broken
	// shadow configuration/backend must never turn blocking into a hook error.
	if args[0] == "session-start" || args[0] == "post-tool-use" {
		observer, closeContext, contextErr := contextObserver(ctx, cfg.ExperimentalContext, *task, stderr)
		if contextErr != nil {
			fmt.Fprintln(stderr, "context:", contextErr)
		} else {
			h.Context = observer
			defer closeContext()
		}
	}
	var out hook.Output
	switch args[0] {
	case "session-start":
		out, err = h.SessionStart(ctx, in)
	case "pre-tool-use":
		out, err = h.PreToolUse(ctx, in)
	case "post-tool-use":
		out, err = h.PostToolUse(ctx, in)
	default:
		fmt.Fprintln(stderr, "unknown hook event", args[0])
		return ExitUsage
	}
	if err != nil {
		fmt.Fprintln(stderr, "hook:", err)
		return ExitError // non-blocking error: Claude Code shows stderr, continues
	}
	if out.HookSpecificOutput == nil {
		return ExitClean // no output = no decision
	}
	if err := json.NewEncoder(stdout).Encode(out); err != nil {
		return ExitError
	}
	return ExitClean
}
