package redact

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Match eleven digits with bounded presentation separators. Stripping arbitrary
// punctuation from a whole document could join unrelated identifiers.
var mobileCandidate = regexp.MustCompile(`\+?[78](?:[ \t\x{00a0}\x{202f}()\-‐‑‒–—−]{0,4}[0-9]){10}`)
var orderBefore = regexp.MustCompile(`(?i)(?:^|[^\p{L}\p{N}_])(?:номер[ \t]+заказа|заказ|order(?:[_ \t]*(?:number|id|no))?)[ \t]*[:=#№"']?[ \t\r\n"']*$`)

func mobilePhones(text string, orderValue bool) []Match {
	var out []Match
	for _, at := range mobileCandidate.FindAllStringIndex(text, -1) {
		start, end := at[0], at[1]
		if !mobileBoundary(text, start, end) {
			continue
		}
		value := text[start:end]
		digits := phoneDigits(value)
		if len(digits) != 11 || digits[1] != '9' || strings.HasPrefix(value, "+8") {
			continue
		}
		if value == digits && (orderValue || orderBefore.MatchString(text[max(0, start-96):start])) {
			continue
		}
		out = append(out, Match{Kind: KindPII, Label: "phone", Start: start, End: end, Confidence: 0.95})
	}
	return out
}

func phoneDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func mobileBoundary(text string, start, end int) bool {
	if start > 0 {
		r, _ := utf8.DecodeLastRuneInString(text[:start])
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '+' {
			return false
		}
		if r == '-' && start == 1 {
			return false
		}
		if (r == '-' || r == '.') && start > 1 {
			p, _ := utf8.DecodeLastRuneInString(text[:start-1])
			if unicode.IsLetter(p) || unicode.IsDigit(p) {
				return false
			}
		}
	}
	if end < len(text) {
		r, _ := utf8.DecodeRuneInString(text[end:])
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			return false
		}
		if r == '.' && end+1 < len(text) && text[end+1] >= '0' && text[end+1] <= '9' {
			return false
		}
		tail := text[end:]
		if len(tail) > 16 {
			tail = tail[:16]
		}
		if len(tail) > 1 && (tail[0] == '-' || tail[0] == '(') {
			for _, r := range tail[1:] {
				if r >= '0' && r <= '9' {
					return false
				}
				if r != ' ' && r != '-' && r != ')' {
					break
				}
			}
		}
	}
	return true
}
