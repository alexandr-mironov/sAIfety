package redact

import (
	"regexp"
	"strings"
	"unicode"
)

// Explicit field context identifies sensitive values even when they are numbers,
// split names, invalid check digits or scripts the optional model does not know.
// Generic name/id/date/number keys are intentionally absent.
var fieldLabels = map[string]string{
	"firstname": "full_name", "givenname": "full_name", "lastname": "full_name",
	"surname": "full_name", "familyname": "full_name", "patronymic": "full_name",
	"middlename": "full_name", "fullname": "full_name", "personname": "full_name",
	"customername": "full_name", "contactname": "full_name", "fio": "full_name",
	"имя": "full_name", "фамилия": "full_name", "отчество": "full_name", "фио": "full_name",
	"姓名":    "full_name",
	"email": "email", "emailaddress": "email", "электроннаяпочта": "email", "почта": "email",
	"phone": "phone", "phonenumber": "phone", "telephone": "phone", "mobile": "phone",
	"mobilephone": "phone", "телефон": "phone", "номертелефона": "phone",
	"card": "credit_card", "creditcard": "credit_card", "cardnumber": "credit_card",
	"pan": "credit_card", "номеркарты": "credit_card",
	"passport": "passport", "passportnumber": "passport", "passportseries": "passport",
	"паспорт": "passport", "номерпаспорта": "passport", "серияпаспорта": "passport",
	"snils": "snils", "снилс": "snils", "inn": "inn", "инн": "inn",
	"taxid": "inn", "taxpayerid": "inn", "ssn": "national_id", "nationalid": "national_id",
	"dob": "date", "birthdate": "date", "dateofbirth": "date", "датарождения": "date",
	"address": "address", "postaladdress": "address", "street": "address",
	"city": "address", "house": "address", "apartment": "address", "postcode": "address",
	"zipcode": "address", "адрес": "address", "город": "address", "улица": "address",
	"account": "bank_account", "accountnumber": "bank_account", "bankaccount": "bank_account",
	"расчетныйсчет": "bank_account", "расчётныйсчёт": "bank_account", "iban": "iban",
	"ip": "ip", "ipaddress": "ip", "ipv4": "ip", "ipv6": "ip",
}

// FieldLabel is based on an exact normalized key, never a substring such as id.
func FieldLabel(field string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(field) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return fieldLabels[b.String()]
}

// Field fully hides a declared sensitive scalar. Explicit operator exceptions
// still apply. The caller decides how a number/object type change is represented.
func Field(field, text string, opts Options) (string, error) {
	label := FieldLabel(field)
	if label == "ip" && !opts.MaskIP {
		label = ""
	}
	if label != "" && strings.TrimSpace(text) != "" {
		for _, allowed := range opts.Allowlist {
			if allowed != "" && strings.Contains(text, allowed) {
				return text, nil
			}
		}
		return Placeholder(label), nil
	}
	return Text(text, opts)
}

var labelledPatterns = []struct {
	label string
	re    *regexp.Regexp
}{
	{"full_name", regexp.MustCompile(`(?im)(?:^|[^\p{L}\p{N}_])(?:first[_ -]?name|last[_ -]?name|full[_ -]?name|patronymic|имя|фамилия|отчество|фио|姓名)[ \t]*[:=：][ \t]*([^\r\n;]+)`)},
	{"passport", regexp.MustCompile(`(?i)(?:passport|паспорт|серия паспорта|номер паспорта)[ \t]*[:=]?[ \t]*(\d[\d -]{5,}\d)`)},
	{"snils", regexp.MustCompile(`(?i)(?:snils|снилс)[ \t]*[:=]?[ \t]*(\d[\d -]{8,}\d)`)},
	{"inn", regexp.MustCompile(`(?i)(?:\binn\b|инн|tax[_ -]?id)[ \t]*[:=]?[ \t]*(\d{10,12})\b`)},
	{"date", regexp.MustCompile(`(?i)(?:date of birth|birth[_ -]?date|dob|дата рождения)[ \t]*[:=]?[ \t]*(\d{1,4}[./-]\d{1,2}[./-]\d{1,4})`)},
	{"address", regexp.MustCompile(`(?im)(?:postal address|address|адрес)[ \t]*[:=][ \t]*([^\r\n;]+)`)},
	{"bank_account", regexp.MustCompile(`(?i)(?:bank account|account(?: number)?|расч[её]тный сч[её]т|сч[её]т)[ \t]*[:=]?[ \t]*(\d[\d ]{14,32}\d)`)},
	{"iban", regexp.MustCompile(`(?i)\biban[ \t]*[:=]?[ \t]*([a-z]{2}\d{2}[a-z0-9 ]{11,35})`)},
}

func labelledMatches(text string) []Match {
	var out []Match
	for _, p := range labelledPatterns {
		for _, m := range p.re.FindAllStringSubmatchIndex(text, -1) {
			start, end := m[2], m[3]
			trimmed := strings.TrimSpace(text[start:end])
			if trimmed == "" {
				continue
			}
			end = start + len(strings.TrimRightFunc(text[start:end], unicode.IsSpace))
			out = append(out, Match{Kind: KindPII, Label: p.label, Start: start, End: end, Confidence: 0.9})
		}
	}
	return out
}

// A whole standalone title-case value is conservatively treated as a name.
// This does not claim general name recognition inside prose; NER remains useful.
var bareName = regexp.MustCompile(`(?m)^[ \t]*([\p{Lu}][\p{Ll}]+(?:[-'][\p{Lu}\p{Ll}]+)?(?:[ \t]+[\p{Lu}][\p{Ll}]+(?:[-'][\p{Lu}\p{Ll}]+)?){1,2})[ \t]*$`)

func bareNames(text string) []Match {
	var out []Match
	for _, m := range bareName.FindAllStringSubmatchIndex(text, -1) {
		out = append(out, Match{Kind: KindPII, Label: "full_name", Start: m[2], End: m[3], Confidence: 0.55})
	}
	return out
}
