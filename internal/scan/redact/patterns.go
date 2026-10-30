package redact

import (
	"math"
	"net/netip"
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

	// --- Russian full names (ФИО) ---
	// The patronymic is the reliable offline signal: a capitalized Cyrillic
	// triple or pair whose last token ends in a patronymic suffix. Group 1 is
	// the name span (Find masks group 1) so surrounding punctuation stays.
	{KindPII, "full_name", regexp.MustCompile(`(?:^|[\s(,:;«"'])([А-ЯЁ][а-яё]+\s+[А-ЯЁ][а-яё]+\s+[А-ЯЁ][а-яё]*(?:ович|евич|ьич|ич|овна|евна|инична|ична))(?:$|[\s).,;:!?»"'])`), 0.88, nil},
	{KindPII, "full_name", regexp.MustCompile(`(?:^|[\s(,:;«"'])([А-ЯЁ][а-яё]+\s+[А-ЯЁ][а-яё]*(?:ович|евич|ьич|ич|овна|евна|инична|ична))(?:$|[\s).,;:!?»"'])`), 0.75, nil},
	{KindPII, "full_name", regexp.MustCompile(`(?:^|[\s(,:;«"'])([А-ЯЁ][а-яё]+\s+[А-ЯЁ]\.\s?[А-ЯЁ]\.)(?:$|[\s).,;:!?»"'])`), 0.7, nil},
	{KindPII, "full_name", regexp.MustCompile(`(?:^|[\s(,:;«"'])([А-ЯЁ]\.\s?[А-ЯЁ]\.\s?[А-ЯЁ][а-яё]+)(?:$|[\s).,;:!?»"'])`), 0.7, nil},

	// --- PII ---
	{KindPII, "email", regexp.MustCompile(`[\p{L}\p{N}._%+\-]+@[\p{L}\p{N}.\-]+\.[\p{L}]{2,}`), 0.9, nil},
	{KindPII, "email", regexp.MustCompile(`(?i)[\p{L}\p{N}._%+\-]+[ \t]*(?:\[at\]|\(at\)|[ \t]+at[ \t]+)[ \t]*[\p{L}\p{N}\-]+(?:[ \t]*(?:\[dot\]|\(dot\)|[ \t]+dot[ \t]+)[ \t]*[\p{L}\p{N}\-]+)+`), 0.8, nil},
	{KindPII, "phone", regexp.MustCompile(`\+\d[\d ()-]{7,}\d|\b\d{2,4}[ ()-][\d ()-]{5,}\d\b`), 0.5, validPhone},
	{KindPII, "phone", regexp.MustCompile(`\b(?:[78]\d{10}|[2-9]\d{9})\b`), 0.65, validPhone},
	{KindPII, "credit_card", regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`), 0.9, validLuhn},
	{KindPII, "ip", regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`), 0.6, nil},
	{KindPII, "ip", regexp.MustCompile(`[0-9A-Fa-f:]*:[0-9A-Fa-f:]+(?:%[A-Za-z0-9_.-]+)?`), 0.6, validIPv6},
	{KindPII, "iban", regexp.MustCompile(`\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b`), 0.9, validIBAN},
}

func validIPv6(s string) bool {
	addr, err := netip.ParseAddr(s)
	return err == nil && addr.Is6()
}

func validIBAN(s string) bool {
	s = strings.ReplaceAll(s, " ", "")
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	remainder := 0
	for _, r := range s[4:] + s[:4] {
		switch {
		case r >= '0' && r <= '9':
			remainder = (remainder*10 + int(r-'0')) % 97
		case r >= 'A' && r <= 'Z':
			remainder = (remainder*100 + int(r-'A') + 10) % 97
		default:
			return false
		}
	}
	return remainder == 1
}

// validLuhn checks the Luhn checksum so ordinary long digit runs aren't
// flagged as card numbers.
func validLuhn(s string) bool {
	var digits []int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	dbl := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if dbl {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		dbl = !dbl
	}
	return sum%10 == 0
}

var dateLike = regexp.MustCompile(`\d{4}-\d\d-\d\d|\d\d\.\d\d\.\d{4}`)

// validPhone rejects date/timestamp-shaped strings (a common false positive
// in logs) and requires a phone-length digit count.
func validPhone(s string) bool {
	if dateLike.MatchString(s) {
		return false
	}
	digits := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	// 10-15 digits covers national and international numbers; shorter runs
	// (e.g. 8-digit dates like 20260922) are not treated as phones.
	return digits >= 10 && digits <= 15
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
