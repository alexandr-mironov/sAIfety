package e5tokenizer

import (
	"encoding/binary"
	"github.com/sugarme/tokenizer/normalizer"
	"github.com/sugarme/tokenizer/spm"
	"testing"
)

func TestPrecompiledExpansionRemovalAndCombiningMarks(t *testing.T) {
	// Synthetic double-array charmap: a -> AB, k -> empty. No upstream model download.
	data := make([]byte, 4+1024*4)
	binary.LittleEndian.PutUint32(data[:4], 1024*4)
	set := func(i int, v uint32) { binary.LittleEndian.PutUint32(data[4+i*4:4+(i+1)*4], v) }
	set(0, 1<<10)
	for _, r := range []byte{'a', 'k'} {
		node := int(r) ^ 1
		set(node, uint32(r)|256|(512<<10))
		offset := uint32(0)
		if r == 'k' {
			offset = 3
		}
		set(node^512, offset)
	}
	data = append(data, []byte("AB\x00\x00")...)
	table, e := spm.NewPrecompiledFrom(data)
	if e != nil {
		t.Fatal(e)
	}
	n := charsmap{table}
	got, e := n.Normalize(normalizer.NewNormalizedFrom("a k café 🙂"))
	if e != nil {
		t.Fatal(e)
	}
	if got.GetNormalized() != "AB  cABfé 🙂" {
		t.Fatalf("bad normalization %q", got.GetNormalized())
	}
}
