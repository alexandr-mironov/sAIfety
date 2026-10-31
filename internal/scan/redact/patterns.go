package redact

import (
	"math"
	"regexp"
	"strings"
	"unicode"
)

type pattern struct {
	kind     Kind
	label    string
	re       *regexp.Regexp
	conf     float64
	validate func(string) bool // optional extra check on the matched value
}

// patterns is the curated detection set. Where a capture group is present,
// group 1 is the sensitive span to mask (so surrounding context like a key
// name stays visible).
var patterns = []pattern{
	// --- secrets / tokens ---
	{KindSecret, "aws_access_key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), 0.95, nil},
	{KindSecret, "aws_secret_key", regexp.MustCompile(`(?i)aws_secret_access_key\s*[:=]\s*["']?([A-Za-z0-9/+]{40})`), 0.9, nil},
	{KindSecret, "github_token", regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,255}\b`), 0.95, nil},
	{KindSecret, "gitlab_token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`), 0.9, nil},
	{KindSecret, "slack_token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`), 0.9, nil},
	{KindSecret, "google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), 0.9, nil},
	{KindSecret, "stripe_key", regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b`), 0.95, nil},
	{KindSecret, "openai_key", regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`), 0.7, nil},
	{KindSecret, "private_key", regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`), 0.98, nil},
	{KindSecret, "jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`), 0.9, nil},
	{KindSecret, "generic_secret", regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret|token|passwd|password|access[_-]?key)\b\s*[:=]\s*["']([^"'\s]{8,})["']`), 0.6, nil},

	// --- auth ---
	{KindAuth, "auth_header", regexp.MustCompile(`(?i)authorization\s*:\s*(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{8,})`), 0.85, nil},
	{KindAuth, "url_credentials", regexp.MustCompile(`\b[a-z][a-z0-9+.-]*://[^/\s:@]+:([^/\s:@]+)@`), 0.8, nil},
}

// entropyMatches flags high-entropy tokens (likely secrets) not already
// covered by a specific pattern.
func entropyMatches(text string, min float64) []Match {
	var out []Match
	tokenRe := regexp.MustCompile(`[A-Za-z0-9+/_=-]{20,}`)
	for _, m := range tokenRe.FindAllStringIndex(text, -1) {
		tok := text[m[0]:m[1]]
		if shannon(tok) >= min && mixed(tok) {
			out = append(out, Match{Kind: KindSecret, Label: "high_entropy", Start: m[0], End: m[1], Confidence: 0.5})
		}
	}
	return out
}

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// mixed requires both letters and digits so words and hashes of one class
// don't trip entropy.
func mixed(s string) bool {
	var letter, digit bool
	for _, r := range s {
		if unicode.IsLetter(r) {
			letter = true
		}
		if unicode.IsDigit(r) {
			digit = true
		}
	}
	return letter && digit && !strings.Contains(s, " ")
}
