// Package contextscan provides experimental, offline contextual inference.
// Results are advisory and never replace scanner policy or sanitization.
package contextscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"
)

const Contract = "context-json-v2"
const V4ManifestSHA256 = "a749100810cd6cd689bafdd97623d714fbb10aa969f000be514c8da5eddcd73d"

// Source is application metadata; it is not serialized into model input.
// Trust describes provenance, never instruction authority.
type Document struct {
	Kind   string `json:"kind"`
	Trust  string `json:"trust"`
	Text   string `json:"text"`
	Source string `json:"source,omitempty"`
}
type Input struct {
	Contract  string     `json:"contract"`
	Task      string     `json:"task"`
	Documents []Document `json:"documents"`
}
type Info struct {
	ID             string  `json:"id"`
	Version        string  `json:"version"`
	ManifestSHA256 string  `json:"manifest_sha256"`
	RuntimeSHA256  string  `json:"runtime_sha256"`
	RuntimeVersion string  `json:"runtime_version"`
	Threshold      float64 `json:"threshold"`
	MaxTokens      int     `json:"max_tokens"`
}

// Backend accepts serialized context-json-v2 WITHOUT the trained query prefix.
// Implementations must respect cancellation and must never truncate or fall back.
type Backend interface {
	Info() Info
	Tokens(context.Context, string) ([]int, error)
	Score(context.Context, string) (float64, error)
}
type Options struct {
	Timeout      time.Duration
	MaxBytes     int
	MaxDocuments int
	MaxWindows   int
}
type Adapter struct {
	backend Backend
	options Options
}

func New(backend Backend, opts Options) (*Adapter, error) {
	if backend == nil {
		return nil, fmt.Errorf("missing contextual backend")
	}
	info := backend.Info()
	if info.MaxTokens != 512 || math.IsNaN(info.Threshold) || math.IsInf(info.Threshold, 0) || info.Threshold < 0 || info.Threshold > 1 {
		return nil, fmt.Errorf("unsupported contextual backend")
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.MaxBytes == 0 {
		opts.MaxBytes = 1 << 20
	}
	if opts.MaxDocuments == 0 {
		opts.MaxDocuments = 128
	}
	if opts.MaxWindows == 0 {
		opts.MaxWindows = 32
	}
	if opts.Timeout < 0 || opts.Timeout > 60*time.Second || opts.MaxBytes < 1 || opts.MaxBytes > 1<<20 || opts.MaxDocuments < 1 || opts.MaxDocuments > 128 || opts.MaxWindows < 1 || opts.MaxWindows > 32 {
		return nil, fmt.Errorf("invalid contextual limits")
	}
	return &Adapter{backend, opts}, nil
}

// Range is a half-open UTF-8 byte range in the ORIGINAL document, not a model
// attribution. Source strings are never included in diagnostics or model input.
type Range struct {
	Document int    `json:"document"`
	Source   string `json:"source,omitempty"`
	Kind     string `json:"kind"`
	Trust    string `json:"trust"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
}
type Window struct {
	Ranges []Range `json:"ranges"`
	Tokens int     `json:"tokens"`
	Score  float64 `json:"score"`
	Attack bool    `json:"attack"`
}
type Result struct {
	Status       string   `json:"status"`
	Reason       string   `json:"reason"`
	Experimental bool     `json:"experimental"`
	Model        Info     `json:"model"`
	Coverage     string   `json:"coverage"`
	Score        *float64 `json:"score,omitempty"`
	Attack       *bool    `json:"attack,omitempty"`
	Windows      []Window `json:"windows,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}
type planned struct {
	input  Input
	ranges []Range
	tokens int
}

// Serialize renders the same compact ordered JSON as the training corpus.
// It preserves text verbatim; Source is deliberately excluded.
func Serialize(in Input) (string, error) {
	type doc struct {
		Kind  string `json:"kind"`
		Trust string `json:"trust"`
		Text  string `json:"text"`
	}
	v := struct {
		Contract  string `json:"contract"`
		Task      string `json:"task"`
		Documents []doc  `json:"documents"`
	}{in.Contract, in.Task, make([]doc, 0, len(in.Documents))}
	for _, d := range in.Documents {
		v.Documents = append(v.Documents, doc{d.Kind, d.Trust, d.Text})
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(b.String(), "\n"), nil
}
func (a *Adapter) count(ctx context.Context, in Input) (int, error) {
	s, err := Serialize(in)
	if err != nil {
		return 0, err
	}
	ids, err := a.backend.Tokens(ctx, s)
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, fmt.Errorf("empty tokenization")
	}
	return len(ids), nil
}
func fullRange(i int, d Document) Range { return Range{i, d.Source, d.Kind, d.Trust, 0, len(d.Text)} }

// Analyze never returns an aggregate score on partial coverage or failure.
// Missing task is an explicit skipped result, not a clean verdict.
func (a *Adapter) Analyze(ctx context.Context, in Input) (result Result, err error) {
	result = Result{Status: "error", Reason: "invalid-input", Experimental: true, Model: a.backend.Info(), Coverage: "none"}
	defer func() {
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				result.Reason = "timeout-or-cancelled"
			}
			result.Coverage = "none"
			if len(result.Windows) > 0 {
				result.Coverage = "partial"
			}
			result.Score = nil
			result.Attack = nil
		}
	}()
	if in.Contract != Contract {
		return result, fmt.Errorf("unsupported input contract")
	}
	if strings.TrimSpace(in.Task) == "" {
		result.Status = "missing-context"
		result.Reason = "missing-user-task"
		return result, nil
	}
	size := len(in.Task)
	if !utf8.ValidString(in.Task) || len(in.Documents) == 0 || len(in.Documents) > a.options.MaxDocuments {
		return result, fmt.Errorf("invalid task or document count")
	}
	for _, d := range in.Documents {
		size += len(d.Text) + len(d.Source)
		if !utf8.ValidString(d.Text) || !utf8.ValidString(d.Source) || strings.TrimSpace(d.Text) == "" || (d.Kind != "file" && d.Kind != "web" && d.Kind != "mcp") || (d.Trust != "untrusted" && d.Trust != "user-provided") {
			return result, fmt.Errorf("invalid document or elevated trust")
		}
	}
	if size > a.options.MaxBytes {
		result.Reason = "input-limit"
		return result, fmt.Errorf("context exceeds byte limit")
	}
	ctx, cancel := context.WithTimeout(ctx, a.options.Timeout)
	defer cancel()
	plan, e := a.plan(ctx, in)
	if e != nil {
		result.Reason = "planning-failed"
		return result, e
	}
	result.Coverage = "joint"
	if len(plan) > 1 {
		result.Coverage = "segmented"
		result.Warnings = []string{"Cross-window interactions are not evaluated; max-window aggregation is not calibrated to the whole-input FPR."}
	}
	maximum := 0.0
	for _, p := range plan {
		text, e := Serialize(p.input)
		if e != nil {
			return result, e
		}
		score, e := a.backend.Score(ctx, text)
		if e != nil {
			result.Reason = "inference-failed"
			return result, e
		}
		if math.IsNaN(score) || math.IsInf(score, 0) || score < 0 || score > 1 {
			result.Reason = "invalid-score"
			return result, fmt.Errorf("invalid contextual score")
		}
		result.Windows = append(result.Windows, Window{p.ranges, p.tokens, score, score >= result.Model.Threshold})
		maximum = max(maximum, score)
	}
	if e := ctx.Err(); e != nil {
		result.Reason = "timeout-or-cancelled"
		return result, e
	}
	decision := maximum >= result.Model.Threshold
	result.Status = "complete"
	result.Reason = "frozen-threshold"
	result.Score = &maximum
	result.Attack = &decision
	return result, nil
}

func (a *Adapter) plan(ctx context.Context, in Input) ([]planned, error) {
	n, err := a.count(ctx, in)
	if err != nil {
		return nil, err
	}
	ranges := make([]Range, 0, len(in.Documents))
	for i, d := range in.Documents {
		ranges = append(ranges, fullRange(i, d))
	}
	if n <= 512 {
		return []planned{{in, ranges, n}}, nil
	}
	var out []planned
	current := planned{input: Input{Contract: in.Contract, Task: in.Task}}
	flush := func() error {
		if len(current.ranges) == 0 {
			return nil
		}
		if len(out) >= a.options.MaxWindows {
			return fmt.Errorf("context exceeds window limit; no aggregate decision")
		}
		out = append(out, current)
		current = planned{input: Input{Contract: in.Contract, Task: in.Task}}
		return nil
	}
	for i, d := range in.Documents {
		candidate := Input{Contract: in.Contract, Task: in.Task, Documents: append(append([]Document{}, current.input.Documents...), d)}
		n, err = a.count(ctx, candidate)
		if err != nil {
			return nil, err
		}
		if n <= 512 {
			current.input = candidate
			current.ranges = append(current.ranges, fullRange(i, d))
			current.tokens = n
			continue
		}
		if err = flush(); err != nil {
			return nil, err
		}
		single := Input{Contract: in.Contract, Task: in.Task, Documents: []Document{d}}
		n, err = a.count(ctx, single)
		if err != nil {
			return nil, err
		}
		if n <= 512 {
			current = planned{single, []Range{fullRange(i, d)}, n}
			continue
		}
		for start := 0; start < len(d.Text); {
			if e := ctx.Err(); e != nil {
				return nil, e
			}
			end := min(len(d.Text), start+2048)
			// Ensure end is a UTF-8 boundary (end itself is excluded).
			for end < len(d.Text) && end > start && !utf8.RuneStart(d.Text[end]) {
				end--
			}
			for {
				if end <= start {
					return nil, fmt.Errorf("task/metadata leaves no room for document text")
				}
				piece := d
				piece.Text = d.Text[start:end]
				single.Documents = []Document{piece}
				// Whitespace-only pieces carry no instruction; extend to the next rune
				// rather than silently discarding bytes. Hard byte limit still bounds work.
				if strings.TrimSpace(piece.Text) == "" {
					return nil, fmt.Errorf("uninspectable whitespace segment")
				}
				n, err = a.count(ctx, single)
				if err != nil {
					return nil, err
				}
				if n <= 512 {
					break
				}
				end = start + (end-start)/2
				for end > start && !utf8.RuneStart(d.Text[end]) {
					end--
				}
			}
			r := fullRange(i, d)
			r.Start = start
			r.End = end
			current = planned{Input{single.Contract, single.Task, append([]Document{}, single.Documents...)}, []Range{r}, n}
			if err = flush(); err != nil {
				return nil, err
			}
			if end == len(d.Text) {
				break
			}
			next := end
			for j := 0; j < 32 && next > start; j++ {
				_, w := utf8.DecodeLastRuneInString(d.Text[start:next])
				next -= w
			}
			if next <= start {
				next = end
			}
			start = next
		}
	}
	if err = flush(); err != nil {
		return nil, err
	}
	return out, nil
}
