package mcp

import (
	"regexp"
	"strings"

	"github.com/saifety-org/sAIfety/internal/scan/redact"
	"golang.org/x/text/language"
)

// Metadata is an exception to the parent person-data contract only when both
// its key and value fit a supported descriptor. A key alone is not evidence:
// {"full_name":{"label":"John Smith"}} still contains personal data.
// This deliberately favors privacy over preserving arbitrary UI copy.
func personMetadataValue(key string, value any) bool {
	key = strings.TrimPrefix(key, "x-")
	switch key {
	case "enabled", "visible", "hidden", "disabled", "editable":
		_, ok := value.(bool)
		return ok
	}
	text, ok := value.(string)
	if !ok {
		return false
	}
	switch key {
	case "language", "lang", "locale":
		if text == "C" || text == "POSIX" {
			return true
		}
		if !personLocaleCode.MatchString(text) {
			return false
		}
		_, err := language.Parse(strings.ReplaceAll(text, "_", "-"))
		return err == nil
	case "widget":
		switch text {
		case "text", "input", "textbox", "textarea", "hidden", "select", "combobox", "autocomplete", "name", "person-name":
			return true
		}
	case "encoding":
		switch strings.ToLower(text) {
		case "utf-8", "utf8", "utf-16", "utf16", "utf-16le", "utf-16be", "ascii", "base64", "hex", "unicode", "plain":
			return true
		}
	case "label", "title", "description":
		if redact.PersonField(text) {
			return true
		}
		switch strings.ToLower(text) {
		case "", "name", "display name", "legal name", "preferred name", "user field", "field definition":
			return true
		}
	}
	return false
}

// A bounded technical spelling, not arbitrary prose or a full BCP-47 parser.
// Private-use/extensions are excluded so they cannot carry an uninspected name.
var personLocaleCode = regexp.MustCompile(`^[a-z]{2,3}(?:[-_][A-Z][a-z]{3})?(?:[-_](?:[A-Z]{2}|[0-9]{3}))?$`)
