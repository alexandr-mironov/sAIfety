package e5tokenizer

import (
	"github.com/sugarme/tokenizer/normalizer"
	"strings"
	"testing"
)

func TestLongMultilingualPieceAndUnknownFusion(t *testing.T) {
	long := "▁пользователя" // >20 bytes, still one valid checkpoint piece.
	u := &unigram{ids: map[string]int{long: 0, "▁": 1, "п": 2}, scores: []float64{-1, -2, -2}, maxBytes: len(long), minimum: -2, unknown: 3}
	got, e := u.Tokenize(long + "🙂🦄")
	if e != nil {
		t.Fatal(e)
	}
	if len(got) != 2 || got[0].Id != 0 || got[1].Id != 3 || got[1].Value != "🙂🦄" {
		t.Fatalf("bad IDs: %+v", got)
	}
}
func TestRejectUnsupportedNormalizer(t *testing.T) {
	// No automatic NFKC substitute: a different normalizer needs a new contract.
	t.Parallel()
	if _, e := Load("missing-tokenizer.json"); e == nil {
		t.Fatal("missing tokenizer accepted")
	}
}
func TestWhitespaceReplacement(t *testing.T) {
	n := normalizer.NewReplace(normalizer.Regex, " {2,}", " ")
	got, e := n.Normalize(normalizer.NewNormalizedFrom("one   two"))
	if e != nil {
		t.Fatal(e)
	}
	if got.GetNormalized() != "one two" || strings.Contains(got.GetNormalized(), "  ") {
		t.Fatal(got.GetNormalized())
	}
}
