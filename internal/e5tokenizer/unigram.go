package e5tokenizer

import (
	"fmt"
	"math"
	"unicode/utf8"

	"github.com/sugarme/tokenizer"
)

// The upstream implementation caps pieces at 20 BYTES, splitting valid long
// multilingual pieces. This scorer uses every vocabulary piece and its unchanged
// checkpoint score. No length bonus, sampling, truncation, or byte fallback.
type unigram struct {
	tokenizer.Model
	ids      map[string]int
	scores   []float64
	maxBytes int
	unknown  int
	minimum  float64
}

func (u *unigram) Tokenize(s string) ([]tokenizer.Token, error) {
	if s == "" {
		return nil, nil
	}
	type state struct {
		score        float64
		previous, id int
	}
	best := make([]state, len(s)+1)
	for i := 1; i < len(best); i++ {
		best[i] = state{math.Inf(-1), -1, -1}
	}
	for start := 0; start < len(s); {
		_, width := utf8.DecodeRuneInString(s[start:])
		if width < 1 {
			return nil, fmt.Errorf("invalid UTF8")
		}
		if !math.IsInf(best[start].score, -1) {
			single := false
			endLimit := min(len(s), start+u.maxBytes)
			for end := start + 1; end <= endLimit; end++ {
				id, ok := u.ids[s[start:end]]
				if !ok {
					continue
				}
				if end == start+width {
					single = true
				}
				score := best[start].score + u.scores[id]
				if score > best[end].score {
					best[end] = state{score, start, id}
				}
			}
			if !single {
				end := start + width
				score := best[start].score + u.minimum - 10
				if score > best[end].score {
					best[end] = state{score, start, u.unknown}
				}
			}
		}
		start += width
	}
	var reverse []tokenizer.Token
	for end := len(s); end > 0; {
		node := best[end]
		if node.previous < 0 {
			return nil, fmt.Errorf("unreachable Unigram path")
		}
		reverse = append(reverse, tokenizer.Token{Id: node.id, Value: s[node.previous:end], Offsets: []int{node.previous, end}})
		end = node.previous
	}
	out := make([]tokenizer.Token, 0, len(reverse))
	for i := len(reverse) - 1; i >= 0; i-- {
		v := reverse[i]
		if len(out) > 0 && v.Id == u.unknown && out[len(out)-1].Id == u.unknown {
			last := &out[len(out)-1]
			last.Value += v.Value
			last.Offsets[1] = v.Offsets[1]
		} else {
			out = append(out, v)
		}
	}
	return out, nil
}
