// Package cli dispatches saifety subcommands. Every subcommand is a thin
// adapter over the shared analysis library in internal/scan.
package cli

import (
	"context"
	"fmt"
	"io"
	"runtime/debug"

	injectionmodel "github.com/saifety-org/prompt-injection-model"
)

// Exit codes. scan and launch return the maximum threat level found so the
// binary can gate other tools (CI, launch wrappers).
const (
	ExitClean    = 0
	ExitBase     = 1
	ExitMedium   = 2
	ExitCritical = 3
	ExitUsage    = 64
	ExitError    = 70
)

const usage = `saifety — предварительный анализ вводных данных для агентов

Usage:
  saifety context [-config f]         experimental contextual JSON from stdin
  saifety scan   [flags] [path...]      scan files or directories
  saifety proxy  [flags]                run MCP aggregating proxy over stdio
  saifety hook   <event>                Claude Code hook adapter (stdin JSON)
  saifety launch [flags] [dir] [-- args] scan, then start claude safely
  saifety model  <pull|status|path>     manage optional injection and PII models
  saifety statistics [scan|proxy|hook] [-json] [-reset]  detected-threat counters
  saifety install   <claude-code|claude-desktop|cursor|windsurf|vscode|all> [-dry-run]
  saifety uninstall <same targets>
  saifety version

Run "saifety <command> -h" for command flags.
`

// Run executes the CLI and returns the process exit code.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "context":
		return runContext(ctx, rest, stdin, stdout, stderr)
	case "context-worker":
		return runContextWorker(rest, stdin, stdout, stderr)
	case "scan":
		return runScan(ctx, rest, stdout, stderr)
	case "proxy":
		return runProxy(ctx, rest, stdin, stdout, stderr)
	case "hook":
		return runHook(ctx, rest, stdin, stdout, stderr)
	case "launch":
		return runLaunch(ctx, rest, stdout, stderr)
	case "model":
		return runModel(ctx, rest, stdout, stderr)
	case "install":
		return runInstall(ctx, rest, stdout, stderr, false)
	case "uninstall":
		return runInstall(ctx, rest, stdout, stderr, true)
	case "statistics", "stats":
		return runStatistics(ctx, rest, stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, "saifety", Version)
		fmt.Fprintln(stdout, "prompt-injection-model", promptInjectionModelVersion())
		fmt.Fprintln(stdout, "weights-sha256", injectionmodel.EmbeddedSHA256())
		fmt.Fprintln(stdout, "feature-schema", injectionmodel.FeatureSchema)
		return ExitClean
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return ExitClean
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return ExitUsage
	}
}

// Version is set at build time via -ldflags "-X .../internal/cli.Version=...".
var Version = "dev"

// promptInjectionModelVersion reports the model revision actually linked into
// this binary. Local workspaces are identified separately from release pins.
func promptInjectionModelVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path != "github.com/saifety-org/prompt-injection-model" {
				continue
			}
			if dep.Replace != nil {
				if dep.Replace.Version == "" {
					return "local"
				}
				return dep.Replace.Version
			}
			return dep.Version
		}
	}
	return "unknown"
}
