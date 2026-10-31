package redact

import (
	"regexp"
	"strings"
	"unicode"
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
	key := fieldKey(field)
	value := strings.TrimSpace(text)
	// A forged placeholder does not exempt a remaining component.
	value = strings.TrimSpace(strings.TrimPrefix(value, Placeholder("full_name")))
	parts := strings.Fields(value)
	if len(parts) == 1 && nameToken(value) {
		switch key {
		case "firstname", "givenname":
			return true
		case "имя":
			return isGiven(value)
		case "patronymic", "middlename", "отчество":
			return patronymicEnding.MatchString(value)
		case "lastname", "surname", "familyname", "фамилия":
			return true
		}
	}
	return len(russianNames(value)) > 0
}

var nameLabel = regexp.MustCompile(`(?im)(?:^|[^\p{L}\p{N}_])((?:first|last|given|family|full)[_ -]?name|patronymic|имя|фамилия|отчество|фио)[ \t]*[:=：][ \t]*([^\r\n;,]+)`)

func labelledMatches(text string) []Match {
	var out []Match
	for _, m := range nameLabel.FindAllStringSubmatchIndex(text, -1) {
		field, value := text[m[2]:m[3]], text[m[4]:m[5]]
		value = strings.TrimRight(value, " .!?")
		if personalFieldValue(field, value) {
			out = append(out, Match{Kind: KindPII, Label: "full_name", Start: m[4], End: m[4] + len(value), Confidence: 0.9})
		}
	}
	return out
}
