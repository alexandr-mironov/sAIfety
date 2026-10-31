package redact

import (
	"github.com/sugarme/tokenizer"
	"testing"
)

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
