package redact

import (
	"errors"
	"strings"
	"testing"

	"github.com/sugarme/tokenizer"
)

func TestFullMasking(t *testing.T) {
	for _, text := range []string{
		"+7 916 555-01-32", "79165550132", "9165550132",
		"demo.person@example.invalid", "пример@пример.рф",
		"demo.person [at] example [dot] invalid",
		"4111 1111 1111 1111", "4111111111111111",
		"Иванов Иван Иванович", "Иван Петров", "Jonathan Whitfield",
		"192.0.2.42", "2001:db8::42", "::1",
		"DE89370400440532013000",
		"AKIAIOSFODNN7EXAMPLE", "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
		"sk_live_1234567890abcdefgh",
	} {
		t.Run(text, func(t *testing.T) {
			got, err := Text(text, DefaultOptions)
			if err != nil || !strings.HasPrefix(got, "[REDACTED:") || !strings.HasSuffix(got, "]") {
				t.Fatalf("not fully masked: %q, %v", got, err)
			}
			if strings.Count(got, "[REDACTED:") != 1 {
				t.Fatalf("value was split instead of fully masked: %q", got)
			}
		})
	}
}

func TestLabelledPersonalData(t *testing.T) {
	for _, tc := range []struct{ text, value string }{
		{"Паспорт: 45 08 123456", "45 08 123456"},
		{"СНИЛС: 112-233-445 95", "112-233-445 95"},
		{"ИНН: 123456789012", "123456789012"},
		{"Дата рождения: 14.02.1990", "14.02.1990"},
		{"Адрес: г. Тестоград, ул. Примерная, д. 42, кв. 7", "Тестоград"},
		{"Расчётный счёт: 40817810099910004312", "40817810099910004312"},
		{"姓名：张伟", "张伟"},
		{"First name: Alex", "Alex"},
	} {
		got, err := Text(tc.text, DefaultOptions)
		if err != nil || strings.Contains(got, tc.value) || !strings.Contains(got, "[REDACTED:") {
			t.Errorf("not masked: %q => %q, %v", tc.text, got, err)
		}
	}
}

func TestSensitiveFieldContext(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"first_name", "Иван"}, {"lastName", "Петров"}, {"patronymic", "Иванович"},
		{"phone", "79165550132"}, {"card", "4111111111111111"},
		{"passport_series", "4508"}, {"passport_number", "123456"},
		{"birth_date", "1990-02-14"}, {"inn", "123456789012"},
		{"city", "Тестоград"}, {"account", "40817810099910004312"},
		{"姓名", "张伟"},
	} {
		got, err := Field(tc.key, tc.value, DefaultOptions)
		if err != nil || got != Placeholder(FieldLabel(tc.key)) {
			t.Errorf("field %s => %q, %v", tc.key, got, err)
		}
	}
	for _, key := range []string{"id", "count", "date", "number", "cardinality", "username"} {
		if label := FieldLabel(key); label != "" {
			t.Errorf("generic key %s considered sensitive: %s", key, label)
		}
	}
}

func TestPrivacyNegativeControls(t *testing.T) {
	for _, text := range []string{
		"The build completed successfully.", "2026-10-30 12:34:56",
		"Order #1234567890", "value=9007199254740993", "1.2.3", "12:34:56",
		"Проект собрали в срок.", "return user.first_name", "date: 2026-10-30",
	} {
		got, err := Text(text, DefaultOptions)
		if err != nil || got != text {
			t.Errorf("false redaction: %q => %q, %v", text, got, err)
		}
	}
	opts := DefaultOptions
	opts.Allowlist = []string{"demo.person@example.invalid"}
	got, err := Field("email", "demo.person@example.invalid", opts)
	if err != nil || got != "demo.person@example.invalid" {
		t.Fatal("explicit allowlist ignored", got, err)
	}
	opts.MaskIP = false
	for _, text := range []string{"192.0.2.42", "2001:db8::42"} {
		if got, err := Field("ip", text, opts); err != nil || got != text {
			t.Fatal("explicit IP exception ignored", got, err)
		}
	}
}

func TestCrossingSpansDoNotExposeTail(t *testing.T) {
	matches := dedupe([]Match{
		{Kind: KindPII, Label: "phone", Start: 0, End: 7},
		{Kind: KindPII, Label: "credit_card", Start: 4, End: 10},
	})
	if got := Mask("0123456789", matches); strings.ContainsAny(got, "0123456789") {
		t.Fatal("overlapping tail leaked:", got)
	}
}

func TestNormalizedPIIDoesNotKeepOriginalCopy(t *testing.T) {
	text := "demo.per\u200bson@example.invalid"
	got, err := Text(text, DefaultOptions)
	if err != nil || got != Placeholder("normalized_pii") {
		t.Fatal("invisible-character copy retained", got, err)
	}
}

type failedNER struct{}

func (failedNER) Recognize(string) []Match { return nil }
func (failedNER) RecognizeChecked(string) ([]Match, error) {
	return nil, errors.New("fixture inference error")
}

func TestCheckedNERFailureIsNotNoMatch(t *testing.T) {
	if _, err := Text("unrecognized entity", DefaultOptions.WithNER(failedNER{})); err == nil {
		t.Fatal("failed enabled model treated as successful inspection")
	}
	if _, err := Text("plain", DefaultOptions.WithNERError(errors.New("init failed"))); err == nil {
		t.Fatal("initialization failure ignored")
	}
}

func TestNERWindowCoverageAndLimits(t *testing.T) {
	encoding := func(n int) *tokenizer.Encoding {
		en := &tokenizer.Encoding{Ids: make([]int, n), Offsets: make([][]int, n), SpecialTokenMask: make([]int, n)}
		for i := range n {
			en.Ids[i], en.Offsets[i] = i, []int{i * 2, i*2 + 2}
		}
		en.SpecialTokenMask[0], en.SpecialTokenMask[n-1] = 1, 1
		en.Offsets[0], en.Offsets[n-1] = []int{0, 0}, []int{0, 0}
		return en
	}
	for _, n := range []int{2, 511, 512, 513, 1024, 4000} {
		en := encoding(n)
		windows, err := nerWindows(en)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[int]bool{}
		for _, window := range windows {
			if len(window.Ids) > nerMaxSeq || window.Ids[0] != en.Ids[0] ||
				window.Ids[len(window.Ids)-1] != en.Ids[n-1] {
				t.Fatal("invalid window")
			}
			for i, id := range window.Ids {
				seen[id] = true
				if id > 0 && id < n-1 && window.Offsets[i][0] != en.Offsets[id][0] {
					t.Fatal("original offsets changed")
				}
			}
		}
		if len(seen) != n {
			t.Fatalf("missing token coverage: %d/%d", len(seen), n)
		}
	}
	if windows, err := nerWindows(encoding(nerMaxSeq * (nerMaxWindows + 1))); err == nil || windows != nil {
		t.Fatal("over-limit input returned a successful prefix")
	}
	en := encoding(600)
	en.SpecialTokenMask = nil
	if _, err := nerWindows(en); err == nil {
		t.Fatal("missing special-token contract accepted")
	}
	en = encoding(10)
	en.Overflowing = []tokenizer.Encoding{{}}
	if _, err := nerWindows(en); err == nil {
		t.Fatal("truncated tokenizer output accepted")
	}
}
