package redact

import (
	"strings"
	"testing"
)

func TestExplicitPersonFieldsAreScriptIndependent(t *testing.T) {
	values := []string{"Шахержон Тахержон", "Shaherzhon Taherzhon", "Ivan Petrov", "Li", "李", "ليلى حكيم", "Νίκη Δάφνη", "अनाया मेहरा", "Анна-Мария", "O'Connell", "D’Aubigné", "e\u0301lodie", "[REDACTED:full_name] Ivan", "[REDACTED:full_name] [REDACTED:full_name] Ivan", "SWFuIFBldHJvdg=="}
	for _, key := range []string{"first_name", "givenName", "last_name", "surname", "familyName", "patronymic", "middle_name", "full_name", "personName", "fio", "ФИО", "имя", "фамилия", "отчество"} {
		for _, value := range values {
			got, err := Field(key, value, DefaultOptions)
			if err != nil || got != Placeholder("full_name") {
				t.Errorf("person field %s=%q => %q (%v)", key, value, got, err)
			}
		}
	}
	for _, tc := range []struct{ input, want string }{
		{`Full name: Shaherzhon Taherzhon; ok`, `Full name: [REDACTED:full_name]; ok`},
		{`ФИО: Шахержон Тахержон.`, `ФИО: [REDACTED:full_name].`},
		{`{"first_name":"Ivan","last_name":"Petrov","count":7}`, `{"first_name":"[REDACTED:full_name]","last_name":"[REDACTED:full_name]","count":7}`},
		{`first_name = 'O\'Connell'`, `first_name = '[REDACTED:full_name]'`},
		{"First name: сайёра\nLast name: йулдошева", "First name: [REDACTED:full_name]\nLast name: [REDACTED:full_name]"},
	} {
		got, err := Text(tc.input, DefaultOptions)
		if err != nil || got != tc.want {
			t.Errorf("text field %q => %q, want %q (%v)", tc.input, got, tc.want, err)
		}
	}
}

func TestPersonFieldDescriptorsAndAbsenceStayVisible(t *testing.T) {
	for _, value := range []string{"", " ", "String", "string?", "string | null", "Optional[str]", "VARCHAR(128)", "Строка", "number", "object", "None", "не указано", "N/A", "[REDACTED:full_name]", "12345"} {
		got, err := Field("full_name", value, DefaultOptions)
		if err != nil || got != value {
			t.Errorf("descriptor/empty %q => %q (%v)", value, got, err)
		}
	}
	for _, input := range []string{
		`{"first_name":"String","last_name":"string | null"}`,
		"first_name: String\nlast_name: String",
		`interface Contact { first_name: PersonName; last_name: String }`,
		"type Contact = {\nfirst_name: PersonName;\nlast_name: string\n}",
		`first_name = record.first_name`, `first_name = getName()`, `first_name = payload`,
		`return user.first_name`, `Имя: строка; Фамилия: строка`,
	} {
		got, err := Text(input, DefaultOptions)
		if err != nil || got != input {
			t.Errorf("code/schema changed: %q => %q (%v)", input, got, err)
		}
	}
	for _, key := range []string{"name", "title", "company_name", "filename", "имя_файла", "customer_name", "contact_name"} {
		value := "Release Overview"
		got, err := Field(key, value, DefaultOptions)
		if err != nil || got != value {
			t.Errorf("generic alias %s changed: %q (%v)", key, got, err)
		}
	}
	opts := DefaultOptions
	opts.Allowlist = []string{"Shaherzhon Taherzhon"}
	if got, _ := Field("full_name", "Shaherzhon Taherzhon", opts); !strings.Contains(got, "Shaherzhon") {
		t.Fatal("operator exception lost", got)
	}
}
