package redact

import (
	"errors"
	"strings"
	"testing"
)

type fixtureNER struct {
	values []string
	err    error
}

func (n fixtureNER) Recognize(text string) []Match { out, _ := n.RecognizeChecked(text); return out }
func (n fixtureNER) RecognizeChecked(text string) ([]Match, error) {
	if n.err != nil {
		return nil, n.err
	}
	var out []Match
	for _, value := range n.values {
		if i := strings.Index(text, value); i >= 0 {
			out = append(out, Match{Kind: KindPII, Label: "full_name", Start: i, End: i + len(value), Confidence: 1})
		}
	}
	return out, nil
}

func TestOptionalNERAddsSpansWithoutChangingRules(t *testing.T) {
	names := []string{"Шахержон Тахержон", "Shaherzhon Taherzhon", "Shakherzhon Takherzhon", "Ivan Petrov", "Ivanov Ivan Ivanovich"}
	opts := DefaultOptions.WithNER(fixtureNER{values: names})
	for _, name := range names {
		input := "Контакт в записи: " + name + "; номер +79165550132."
		got, err := Text(input, opts)
		if err != nil || strings.Contains(got, name) || strings.Contains(got, "79165550132") {
			t.Fatalf("explicit model span or rule phone leaked: %q (%v)", got, err)
		}
	}
	for _, safe := range []string{"Release Overview", "План Поставки", "first_name: String", "Номер заказа: 79165550132"} {
		got, err := Text(safe, opts)
		if err != nil || got != safe {
			t.Fatalf("model integration changed a safe result: %q => %q (%v)", safe, got, err)
		}
	}
	// This controlled recognizer tests integration, not a real model's accuracy.
}

func TestEnabledNERFailureCannotBecomeSuccessfulNoMatch(t *testing.T) {
	for _, opts := range []Options{DefaultOptions.WithNER(fixtureNER{err: errors.New("fixture failure")}), DefaultOptions.WithNERError(errors.New("initialization failed"))} {
		if got, err := Text("Шахержон Тахержон", opts); err == nil || got != "" {
			t.Fatalf("failed enabled NER returned inspected output: %q (%v)", got, err)
		}
	}
}

func TestNERDefaultsToPersonsOnly(t *testing.T) {
	labels := []string{"O", "B-PER", "I-PER", "B-PERSON", "B-DATE", "B-ORG", "B-LOC"}
	keep := nerEntityLabels(labels, nil)
	if keep["PER"] != "full_name" || keep["PERSON"] != "full_name" || len(keep) != 2 {
		t.Fatal("default broadened beyond persons", keep)
	}
	keep = nerEntityLabels(labels, []string{"PER", "LOC"})
	if keep["LOC"] != "location" || keep["PER"] != "full_name" || len(keep) != 2 {
		t.Fatal("explicit labels ignored", keep)
	}
}

func TestNERSupplementSpanValidation(t *testing.T) {
	if _, err := Text("Иван Петров", DefaultOptions.WithNER(invalidNER{})); err == nil {
		t.Fatal("invalid enabled model span accepted")
	}
}

type invalidNER struct{}

func (invalidNER) Recognize(string) []Match {
	return []Match{{Kind: KindPII, Label: "full_name", Start: 0, End: 99999}}
}
