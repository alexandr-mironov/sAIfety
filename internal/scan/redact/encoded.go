package redact

import (
	"encoding/base64"
	"regexp"
	"unicode/utf8"
)

var encodedValue = regexp.MustCompile(`^[A-Za-z0-9+/_-]{16,}={0,2}$`)

// EncodedSensitive covers short scalar copies (a mobile needs only 16 base64
// bytes), below the general instruction decoder's minimum candidate length.
func EncodedSensitive(value string, opts Options) (bool, error) {
	if len(value) > 1<<20 || !encodedValue.MatchString(value) {
		return false, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := enc.DecodeString(value)
		if err != nil || !utf8.Valid(decoded) {
			continue
		}
		matches, err := FindChecked(string(decoded), opts)
		return len(matches) > 0, err
	}
	return false, nil
}
