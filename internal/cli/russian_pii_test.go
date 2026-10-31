package cli

import (
	"github.com/saifety-org/sAIfety/internal/scan/redact"
	"testing"
)

func TestPIIProfileStaysModelFreeWithoutOptIn(t *testing.T) {
	for _, useModel := range []bool{false, true} {
		for _, noModel := range []bool{false, true} {
			cfg := Config{Redact: RedactConfig{NoModel: noModel, NERLabels: []string{"PER", "ORG", "LOC", "DATE"}, KeepIP: false}}
			opts := RedactOptions(cfg, useModel)
			for input, want := range map[string]bool{"Иван Петров": true, "+79165550132": true, "Release Overview": false, "John Smith": false, "192.0.2.42": false, "demo@fixture.invalid": true} {
				got, err := redact.FindChecked(input, opts)
				if err != nil || (len(got) > 0) != want {
					t.Errorf("model=%v/noModel=%v: %q => %v (%v)", useModel, noModel, input, got, err)
				}
			}
		}
	}
}
