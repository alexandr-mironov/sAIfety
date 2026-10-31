// Package redact finds and masks secrets, credentials and personal data in
// text. It serves two jobs: producing findings for the scanner, and masking
// the data before it reaches the agent (the "обезличивание" block from the
// project idea). Everything is offline: curated patterns plus Shannon
// entropy, no network verification.
package redact

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/saifety-org/sAIfety/internal/scan/normalize"
)

// Kind labels what a match is, and drives the placeholder it is masked with.
type Kind string

const (
	KindSecret Kind = "secret" // API keys, tokens, private keys
	KindPII    Kind = "pii"    // Russian names and RF mobile phones
	KindAuth   Kind = "auth"   // Authorization headers, credentials in URLs
	KindCustom Kind = "custom" // matched a user keyword denylist entry
)

// Match is one detected span.
type Match struct {
	Kind       Kind
	Label      string  // e.g. "aws_access_key", "phone", "jwt"
	Start, End int     // byte offsets
	Confidence float64 // 0..1
}

// Options tune detection and masking.
type Options struct {
	orderValue bool // explicit order field; never bypasses secret inspection
	ner        NER
	nerErr     error
	// Keywords are extra literal strings to redact (case-insensitive).
	Keywords []string
	// Allowlist are substrings that must never be redacted even if matched.
	Allowlist []string
	// MinEntropy is the Shannon-entropy threshold for generic high-entropy
	// token detection (bits per char). 0 disables entropy scanning.
	MinEntropy float64
}

// DefaultOptions masks credentials, Russian names and RF mobiles, without a model.
var DefaultOptions = Options{}

// Find returns all matches in text, sorted by position, de-overlapped so a
// secret isn't also reported as generic entropy.
func Find(text string, opts Options) []Match {
	matches, _ := find(text, opts)
	return matches
}

// FindChecked reports incomplete inspection explicitly. Runtime output paths
// must not turn an inspection failure into a successful no-match.
func FindChecked(text string, opts Options) (matches []Match, err error) {
	defer func() {
		if recover() != nil {
			matches, err = nil, fmt.Errorf("PII inspection failed")
		}
	}()
	return find(text, opts)
}

func find(text string, opts Options) ([]Match, error) {
	var out []Match
	for _, p := range patterns {
		for _, m := range p.re.FindAllStringSubmatchIndex(text, -1) {
			s, e := m[0], m[1]
			if len(m) >= 4 && m[2] >= 0 { // capture group 1 = the sensitive part
				s, e = m[2], m[3]
			}
			if p.validate != nil && !p.validate(text[s:e]) {
				continue
			}
			out = append(out, Match{Kind: p.kind, Label: p.label, Start: s, End: e, Confidence: p.conf})
		}
	}
	for _, kw := range opts.Keywords {
		if kw == "" {
			continue
		}
		re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(kw))
		for _, m := range re.FindAllStringIndex(text, -1) {
			out = append(out, Match{Kind: KindCustom, Label: "keyword", Start: m[0], End: m[1], Confidence: 1})
		}
	}
	if opts.MinEntropy > 0 {
		out = append(out, entropyMatches(text, opts.MinEntropy)...)
	}
	out = append(out, russianNames(text)...)
	out = append(out, mobilePhones(text, opts.orderValue)...)
	out = append(out, labelledMatches(text)...)
	if opts.nerErr != nil {
		return nil, fmt.Errorf("PII recognizer unavailable")
	}
	if opts.ner != nil {
		var modelMatches []Match
		if checked, ok := opts.ner.(CheckedNER); ok {
			var err error
			modelMatches, err = checked.RecognizeChecked(text)
			if err != nil {
				return nil, fmt.Errorf("PII recognizer failed")
			}
		} else {
			modelMatches = opts.ner.Recognize(text)
		}
		out = append(out, modelMatches...)
	}
	for _, m := range out {
		if m.Start < 0 || m.End > len(text) || m.End <= m.Start {
			return nil, fmt.Errorf("invalid PII span")
		}
	}
	out = filterAllowlisted(text, out, opts.Allowlist)
	return dedupe(out), nil
}

// Text fully hides detected values. Errors never produce an uninspected copy.
func Text(text string, opts Options) (string, error) {
	// Normalized offsets cannot be applied to the original bytes. Hide the
	// whole value rather than letting invisibles/confusables retain a copy.
	if normalized := normalize.Text(text); normalized != text {
		matches, err := FindChecked(normalized, opts)
		if err != nil {
			return "", err
		}
		if len(matches) > 0 {
			return Placeholder("normalized_pii"), nil
		}
	}
	matches, err := FindChecked(text, opts)
	if err != nil {
		return "", err
	}
	return Mask(text, matches), nil
}

// Mask replaces every match with a typed placeholder, outermost first, so the
// agent sees structure without the sensitive value.
func Mask(text string, matches []Match) string {
	if len(matches) == 0 {
		return text
	}
	ms := append([]Match(nil), matches...)
	sort.Slice(ms, func(i, j int) bool { return ms[i].Start < ms[j].Start })
	var b strings.Builder
	pos := 0
	for _, m := range ms {
		if m.Start < pos || m.Start < 0 || m.End > len(text) || m.End <= m.Start {
			continue
		}
		b.WriteString(text[pos:m.Start])
		b.WriteString(Placeholder(m.Label))
		pos = m.End
	}
	b.WriteString(text[pos:])
	return b.String()
}

func filterAllowlisted(text string, in []Match, allow []string) []Match {
	if len(allow) == 0 {
		return in
	}
	var out []Match
	for _, m := range in {
		val := text[m.Start:m.End]
		keep := true
		for _, a := range allow {
			if a != "" && strings.Contains(val, a) {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, m)
		}
	}
	return out
}

// dedupe merges overlapping matches. Skipping a crossing span would expose its
// tail; containment alone is insufficient for a privacy boundary.
func dedupe(in []Match) []Match {
	sort.Slice(in, func(i, j int) bool {
		if in[i].Start != in[j].Start {
			return in[i].Start < in[j].Start
		}
		if in[i].End != in[j].End {
			return in[i].End > in[j].End
		}
		return in[i].Confidence > in[j].Confidence
	})
	var out []Match
	for _, m := range in {
		if len(out) > 0 && m.Start < out[len(out)-1].End {
			last := &out[len(out)-1]
			if m.End > last.End {
				last.End = m.End
			}
			continue
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

// Placeholder never retains initials, domains, prefixes or suffixes.
func Placeholder(label string) string { return "[REDACTED:" + label + "]" }
