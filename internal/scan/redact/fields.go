package redact

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/saifety-org/sAIfety/internal/scan/normalize"
)

// Fields provide context, not permission to mask arbitrary configuration.
var fieldLabels = map[string]string{
	"firstname": "full_name", "givenname": "full_name", "lastname": "full_name",
	"surname": "full_name", "familyname": "full_name", "patronymic": "full_name",
	"middlename": "full_name", "fullname": "full_name", "personname": "full_name",
	"customername": "full_name", "contactname": "full_name", "fio": "full_name",
	"имя": "full_name", "фамилия": "full_name", "отчество": "full_name", "фио": "full_name",
	"phone": "phone", "phonenumber": "phone", "telephone": "phone", "mobile": "phone",
	"mobilephone": "phone", "contactmobile": "phone", "телефон": "phone", "номертелефона": "phone",
}

func fieldKey(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func FieldLabel(field string) string { return fieldLabels[fieldKey(field)] }

// PersonField is an explicit person-data contract, not a general object name.
// Ambiguous legacy contact/customer names retain their heuristic behavior.
func PersonField(field string) bool {
	switch fieldKey(field) {
	case "firstname", "givenname", "lastname", "surname", "familyname",
		"patronymic", "middlename", "fullname", "personname", "fio",
		"имя", "фамилия", "отчество", "фио":
		return true
	}
	return false
}

func orderField(field string) bool {
	switch fieldKey(field) {
	case "orderid", "ordernumber", "orderno", "номерзаказа", "идентификаторзаказа":
		return true
	}
	return false
}

func Field(field, text string, opts Options) (string, error) {
	// A schema/config value is not a person just because the key is first_name.
	if FieldLabel(field) == "full_name" && personalFieldValue(field, text) {
		for _, a := range opts.Allowlist {
			if a != "" && strings.Contains(text, a) {
				return text, nil
			}
		}
		return Placeholder("full_name"), nil
	}
	opts.orderValue = orderField(field)
	return Text(text, opts)
}

func personalFieldValue(field, text string) bool {
	if PersonField(field) {
		value := strings.Join(strings.Fields(normalize.Text(text)), " ")
		if value == "" || value == Placeholder("full_name") || nonPersonLiteral(value) {
			return false
		}
		// A malformed spelling, encoded string or forged placeholder must not
		// exempt a declared person's value. Do not guess its language/ethnicity.
		return strings.ContainsFunc(value, unicode.IsLetter)
	}
	value := strings.TrimSpace(text)
	// A forged placeholder does not exempt a remaining component.
	value = strings.TrimSpace(strings.TrimPrefix(value, Placeholder("full_name")))
	return len(russianNames(value)) > 0
}

var nameTypeLiteral = regexp.MustCompile(`(?i)^(?:(?:string|str|text|integer|int|int32|int64|number|float|float64|double|bool|boolean|object|array|null|строка|число|целое|логическое)(?:[?!]|[ \t]*\|[ \t]*null)?|optional\[(?:str|string)\]|(?:n?varchar|char|character varying)\([0-9]{1,5}\))$`)

func nonPersonLiteral(value string) bool {
	if nameTypeLiteral.MatchString(value) {
		return true
	}
	switch strings.ToLower(value) {
	case "none", "undefined", "unknown", "unset", "n/a", "not provided", "not specified",
		"не указано", "не указан", "не указана", "не задано", "неизвестно", "отсутствует", "нет", "пусто":
		return true
	}
	return false
}

// Quoted values are captured without their quotes, preserving JSON/SQL-style
// punctuation in text copies. This is field syntax, not a title-case heuristic.
var nameLabel = regexp.MustCompile(`(?im)(?:^|[^\p{L}\p{N}_])["']?((?:first|last|given|family|full|person)[_ -]?name|patronymic|middle[_ -]?name|surname|fio|имя|фамилия|отчество|фио)["']?[ \t]*[:=：][ \t]*(?:"((?:\\.|[^"\\\r\n])*)"|'((?:\\.|[^'\\\r\n])*)'|([^\r\n;,]+))`)

var nameTypeContext = regexp.MustCompile(`(?is)(?:^|[;\r\n])[ \t]*(?:export[ \t]+)?(?:interface|type|class|struct)[ \t]+[\p{L}\p{N}_]+[^{}]*\{[^}]*$`)

func plainNameValue(value string) bool {
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsMark(r) || unicode.IsSpace(r) || strings.ContainsRune(".'’ʼ-‐‑–—", r) {
			continue
		}
		return false
	}
	return true
}

func labelledMatches(text string) []Match {
	var out []Match
	for _, m := range nameLabel.FindAllStringSubmatchIndex(text, -1) {
		field := text[m[2]:m[3]]
		start, end := -1, -1
		for group := 4; group < len(m); group += 2 {
			if m[group] >= 0 {
				start, end = m[group], m[group+1]
				break
			}
		}
		if start < 0 {
			continue
		}
		value := text[start:end]
		if m[8] >= 0 {
			value = strings.TrimRight(value, " .!?")
			if !plainNameValue(value) || nameTypeContext.MatchString(text[max(0, m[2]-1024):m[2]]) {
				continue
			}
			// An unquoted lower-case assignment is commonly a variable, not a
			// literal personal value. Quoted data and colon labels stay covered.
			if strings.Contains(text[m[3]:start], "=") && strings.TrimSpace(value) == strings.ToLower(strings.TrimSpace(value)) && !strings.ContainsAny(value, " \t") {
				ascii := true
				for _, r := range value {
					ascii = ascii && r < 128
				}
				if ascii {
					continue
				}
			}
		}
		if personalFieldValue(field, value) {
			out = append(out, Match{Kind: KindPII, Label: "full_name", Start: start, End: start + len(value), Confidence: 0.9})
		}
	}
	return out
}
