package redact

import (
	"fmt"

	"github.com/sugarme/tokenizer"
)

const (
	nerMaxSeq     = 512
	nerMaxWindows = 32
	nerOverlap    = 32
)

// nerWindows preserves the tokenizer's original byte offsets and wraps every
// content window in the original single-sequence special tokens. A limit is an
// explicit incomplete inspection, never a successful result for the prefix.
func nerWindows(en *tokenizer.Encoding) ([]*tokenizer.Encoding, error) {
	n := len(en.Ids)
	if n == 0 || len(en.Offsets) != n || len(en.Overflowing) != 0 {
		return nil, fmt.Errorf("incomplete NER encoding")
	}
	if n <= nerMaxSeq {
		return []*tokenizer.Encoding{en}, nil
	}
	if len(en.SpecialTokenMask) != n || en.SpecialTokenMask[0] != 1 || en.SpecialTokenMask[n-1] != 1 {
		return nil, fmt.Errorf("unsupported NER special tokens")
	}
	for i := 1; i < n-1; i++ {
		if en.SpecialTokenMask[i] != 0 {
			return nil, fmt.Errorf("unsupported NER sequence")
		}
	}
	var windows []*tokenizer.Encoding
	for start := 1; start < n-1; {
		if len(windows) == nerMaxWindows {
			return nil, fmt.Errorf("NER window limit exceeded")
		}
		end := min(start+nerMaxSeq-2, n-1)
		ids := append([]int{en.Ids[0]}, en.Ids[start:end]...)
		ids = append(ids, en.Ids[n-1])
		offsets := append([][]int{{0, 0}}, en.Offsets[start:end]...)
		offsets = append(offsets, []int{0, 0})
		windows = append(windows, &tokenizer.Encoding{Ids: ids, Offsets: offsets})
		if end == n-1 {
			break
		}
		start = end - nerOverlap
	}
	return windows, nil
}
