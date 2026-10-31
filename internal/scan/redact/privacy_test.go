package redact

import (
	"strings"
	"testing"
)

func TestRussianNamesAndMobileFullMask(t *testing.T) {
	for _, value := range []string{
		"Иванов Иван Иванович", "Иван Иванович Иванов", "Дроздов Елисей Мефодьевич", "Раиса Викторовна Кострова",
		"Алина Белова", "Иван Петров", "Марии Петровой", "Сергею Иванову",
		"Анна-Мария Петрова-Сидорова", "Иванов И.И.", "И. И. Иванов",
		"79165550132", "89165550132", "+79165550132", "+7(916)555-01-32", "8 (916) 555 01 32",
		"+7\u00a0(916)\u00a0555–01–32", "+7\u202f916\u202f555\u202f01\u202f32",
		"demo.person@example.invalid", "user+tag@corp.example.com",
		"AKIAIOSFODNN7EXAMPLE", "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
	} {
		t.Run(value, func(t *testing.T) {
			got, err := Text(value, DefaultOptions)
			if err != nil || !strings.HasPrefix(got, "[REDACTED:") || !strings.HasSuffix(got, "]") || strings.Count(got, "[REDACTED:") != 1 {
				t.Fatalf("incomplete mask: %q, %v", got, err)
			}
		})
	}
	for _, tc := range []struct{ input, want string }{
		{"Протокол подписала Алина Белова после обсуждения.", "Протокол подписала [REDACTED:full_name] после обсуждения."},
		{"Контактное лицо: Раиса Викторовна Кострова.", "Контактное лицо: [REDACTED:full_name]."},
		{"ФИО: иван петрович ким", "ФИО: [REDACTED:full_name]"},
		{"Фамилия: Петров", "Фамилия: [REDACTED:full_name]"},
		{"Имя: Иван", "Имя: [REDACTED:full_name]"},
		{"Ответственный за согласование: елисей мефодьевич ким.", "Ответственный за согласование: [REDACTED:full_name]."},
		{"Согласовал Иван Иванович вчера.", "Согласовал [REDACTED:full_name] вчера."},
	} {
		got, err := Text(tc.input, DefaultOptions)
		if err != nil || got != tc.want {
			t.Errorf("%q => %q, want %q (%v)", tc.input, got, tc.want, err)
		}
	}
}

func TestRussianPIINegativeControls(t *testing.T) {
	for _, value := range []string{
		"Роман готов к печати.", "Любовь к книгам полезна.", "Release Overview", "План Поставки", "Статус Сборки", "Нижний Новгород", "Красный Октябрь",
	} {
		got, err := Text(value, DefaultOptions)
		if err != nil || got != value {
			t.Errorf("false name: %q => %q", value, got)
		}
	}
	for _, value := range []string{
		"first_name: String\nlast_name: String", "Имя: строка; Фамилия: строка", "return user.first_name",
		"+1 (415) 555-0132", "+44 7700 900123", "+7 (495) 555-01-32", "9165550132",
		"+89165550132", "1791655501320", "791655501321", "7916555013", "sku-79165550132-x",
		"79165550132-123", "7916-555-0132-9", "2026-10-31 12:34:56", "value=9007199254740993",
		"192.0.2.42", "2001:db8::42", "4111111111111111",
		"Паспорт: 45 08 123456", "СНИЛС: 112-233-445 95", "ИНН: 123456789012",
		"Дата рождения: 14.02.1990", "Адрес: город Тестоград, дом 42", "Jonathan Whitfield",
		"Номер заказа: 79165550132", "Order #89165550132", "order_id=79165550132",
	} {
		got, err := Text(value, DefaultOptions)
		if err != nil || got != value {
			t.Errorf("false redaction: %q => %q, %v", value, got, err)
		}
	}
	// Synthetic three-digit business prefixes followed by counters of different lengths.
	for _, prefix := range []string{"123", "234", "345", "456", "567", "678", "900"} {
		for _, counter := range []string{"9", "1234567", "12345678", "123456789", "79165550132"} {
			input := prefix + counter
			got, err := Text(input, DefaultOptions)
			if err != nil || got != input {
				t.Errorf("order changed: %s => %s", input, got)
			}
		}
	}
}

func TestRussianFieldContext(t *testing.T) {
	for _, tc := range []struct{ key, value, label string }{
		{"first_name", "Иван", "full_name"}, {"firstName", "Елисей", "full_name"}, {"lastName", "Ким", "full_name"}, {"patronymic", "Иванович", "full_name"},
		{"phone", "79165550132", "phone"}, {"fio", "Иванов Иван Иванович", "full_name"},
		{"first_name", "[REDACTED:full_name] Иван", "full_name"},
	} {
		got, err := Field(tc.key, tc.value, DefaultOptions)
		if err != nil || got != Placeholder(tc.label) {
			t.Errorf("%s=%s => %s, %v", tc.key, tc.value, got, err)
		}
	}
	for _, tc := range []struct{ key, value string }{
		{"first_name", "String"}, {"first_name", "строка"}, {"last_name", "не указано"}, {"phone", "feature disabled"},
		{"account", "active"}, {"city", "Тестоград"}, {"order_number", "79165550132"}, {"order_id", "89165550132"},
	} {
		got, err := Field(tc.key, tc.value, DefaultOptions)
		if err != nil || got != tc.value {
			t.Errorf("false field redaction: %+v => %s", tc, got)
		}
	}
	// Order context cannot bypass a secret or a decorated phone.
	for _, v := range []string{"AKIAIOSFODNN7EXAMPLE", "+79165550132"} {
		got, _ := Field("order_number", v, DefaultOptions)
		if got == v {
			t.Fatalf("order exemption bypassed protection: %s", v)
		}
	}
	opts := DefaultOptions
	opts.Allowlist = []string{"Иван Петров"}
	if got, _ := Text("Иван Петров", opts); got != "Иван Петров" {
		t.Fatal("operator allowlist ignored")
	}
}

func TestOrderMarkerHasWordBoundary(t *testing.T) {
	for _, input := range []string{"disorder: 79165550132", "preorder_id=79165550132"} {
		got, err := Text(input, DefaultOptions)
		if err != nil || strings.Contains(got, "79165550132") {
			t.Fatal("non-order substring bypassed mobile check", got, err)
		}
	}
}

func TestCrossingSpansDoNotExposeTail(t *testing.T) {
	matches := dedupe([]Match{{Kind: KindPII, Label: "phone", Start: 0, End: 7}, {Kind: KindSecret, Label: "secret", Start: 4, End: 10}})
	if got := Mask("0123456789", matches); strings.ContainsAny(got, "0123456789") {
		t.Fatal("crossing span leaked", got)
	}
}

func TestNormalizedPIIDoesNotKeepOriginalCopy(t *testing.T) {
	got, err := Text("+7916\u200b5550132", DefaultOptions)
	if err != nil || got != Placeholder("normalized_pii") {
		t.Fatal("normalized copy survived", got, err)
	}
}
