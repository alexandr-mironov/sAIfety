package redact

import (
	"strings"
	"testing"
)

func labels(ms []Match) map[string]bool {
	m := map[string]bool{}
	for _, x := range ms {
		m[x.Label] = true
	}
	return m
}

func TestSecretsDetected(t *testing.T) {
	text := `
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
github: ghp_1234567890abcdefghijklmnopqrstuvwxyz
token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123456"
Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz012345
`
	got := labels(Find(text, DefaultOptions))
	for _, want := range []string{"aws_access_key", "github_token", "jwt", "auth_header"} {
		if !got[want] {
			t.Errorf("missing %s in %v", want, got)
		}
	}
}

func TestPrivateKeyBlock(t *testing.T) {
	text := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----"
	ms := Find(text, DefaultOptions)
	if !labels(ms)["private_key"] {
		t.Fatalf("private key block not detected: %v", ms)
	}
	if out := Mask(text, ms); strings.Contains(out, "b3BlbnNz") {
		t.Fatalf("private key not masked: %q", out)
	}
}

func TestMaskAndAllowlist(t *testing.T) {
	text := "key AKIAIOSFODNN7EXAMPLE and email keep@example.com"
	opts := DefaultOptions
	opts.Allowlist = []string{"keep@example.com"}
	ms := Find(text, opts)
	out := Mask(text, ms)
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("secret not masked: %q", out)
	}
	if !strings.Contains(out, "keep@example.com") {
		t.Fatalf("allowlisted value should remain: %q", out)
	}
}

func TestKeywordDenylist(t *testing.T) {
	text := "the project codename is BLUEFALCON and it is secret"
	opts := DefaultOptions
	opts.Keywords = []string{"BLUEFALCON"}
	out := Mask(text, Find(text, opts))
	if strings.Contains(out, "BLUEFALCON") {
		t.Fatalf("keyword not redacted: %q", out)
	}
}

func TestCleanTextNoMatches(t *testing.T) {
	text := "The build compiles the widgets and runs the tests in CI."
	if ms := Find(text, DefaultOptions); len(ms) != 0 {
		t.Fatalf("unexpected matches: %v", ms)
	}
}

func TestRussianFullName(t *testing.T) {
	cases := map[string]bool{
		"Заявку подал Иванов Иван Иванович сегодня.": true,
		"Ответственный: Петрова Мария Сергеевна.":    true,
		"Согласовал Иван Иванович вчера.":            true,
		"Подпись: Иванов И.И. поставлена.":           true,
		"Проект собрали в срок, тесты прошли.":       false,
		"Нижний Новгород и Санкт Петербург города.":  false,
	}
	for text, want := range cases {
		got := labels(Find(text, DefaultOptions))["full_name"]
		if got != want {
			t.Errorf("full_name(%q) = %v, want %v (matches: %v)", text, got, want, Find(text, DefaultOptions))
		}
	}
}

func TestFullNameMasked(t *testing.T) {
	text := "Заявку подал Иванов Иван Иванович, тел. +7 916 555-01-32."
	out := Mask(text, Find(text, DefaultOptions))
	if strings.Contains(out, "Иванов Иван Иванович") {
		t.Fatalf("ФИО not masked: %q", out)
	}
	if strings.Contains(out, "555-01-32") {
		t.Fatalf("phone not masked: %q", out)
	}
	if out == text {
		t.Fatalf("nothing was masked: %q", out)
	}
}

func TestContextNameNearContact(t *testing.T) {
	yes := []string{
		"Заявку подал Иван Петров, телефон +7 916 555-01-32.",
		"Контакт: Иван Сидоров, +7 916 555-01-32.",
		"Свяжитесь: Мария Кузнецова, mariak@corp.example",
	}
	for _, text := range yes {
		if !labels(Find(text, DefaultOptions))["full_name"] {
			t.Errorf("name near contact not flagged: %q -> %v", text, Find(text, DefaultOptions))
		}
	}
	// A capitalized pair with NO contact nearby stays unflagged (precision).
	no := "Проект Ракета Восход запущен в срок."
	if labels(Find(no, DefaultOptions))["full_name"] {
		t.Errorf("pair without contact should not be flagged: %q", no)
	}
}

func TestContextNameMasked(t *testing.T) {
	text := "Контакт: Иван Сидоров, +7 916 555-01-32."
	out := Mask(text, Find(text, DefaultOptions))
	if strings.Contains(out, "Иван Сидоров") {
		t.Fatalf("context name not masked: %q", out)
	}
}

func TestPhoneNotDate(t *testing.T) {
	// Dates and timestamps must NOT be masked as phone numbers.
	for _, s := range []string{
		"index k8s-production-2026-09-22-22 created",
		"time 2026-09-30T00:59:14.277+03:00 level INFO",
		"date 30.09.2026 event",
	} {
		for _, m := range Find(s, DefaultOptions) {
			if m.Label == "phone" {
				t.Errorf("date masked as phone in %q: %q", s, s[m.Start:m.End])
			}
		}
	}
	// A real phone still matches.
	if !labels(Find("call +7 916 555 01 32 please", DefaultOptions))["phone"] {
		t.Error("real phone not detected")
	}
}
