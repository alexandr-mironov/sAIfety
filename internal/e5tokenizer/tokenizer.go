// Package e5tokenizer provides IDs for the pinned XLM-R tokenizer. It deliberately
// exposes no offsets: upstream Precompiled's alignment code is incorrect for
// Unicode expansion/removal. Keep the checkpoint's charmap, never replace it by NFKC.
package e5tokenizer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/rivo/uniseg"
	"github.com/sugarme/tokenizer"
	"github.com/sugarme/tokenizer/normalizer"
	"github.com/sugarme/tokenizer/pretrained"
	"github.com/sugarme/tokenizer/spm"
)

type charsmap struct{ table *spm.Precompiled }

// Normalize follows HF tokenizers v0.22.2 normalizers/precompiled.rs for text,
// rebuilding alignment against normalized text because this tool returns IDs only.
func (n charsmap) Normalize(value *normalizer.NormalizedString) (*normalizer.NormalizedString, error) {
	var out strings.Builder
	g := uniseg.NewGraphemes(value.GetNormalized())
	for g.Next() {
		s := g.Str()
		if len(s) < 6 {
			if v, ok := n.transform(s); ok {
				out.WriteString(v)
				continue
			}
		}
		for _, r := range s {
			p := string(r)
			if v, ok := n.transform(p); ok {
				out.WriteString(v)
			} else {
				out.WriteString(p)
			}
		}
	}
	return normalizer.NewNormalizedFrom(out.String()), nil
}
func (n charsmap) transform(s string) (string, bool) {
	offsets := n.table.Trie.CommonPrefixSearch([]byte(s))
	if len(offsets) == 0 {
		return "", false
	}
	start := offsets[0]
	rest := n.table.Normalized[start:]
	end := strings.IndexByte(rest, 0)
	if end < 0 {
		return rest, true
	}
	return rest[:end], true
}

// Load accepts the exact Sequence(Precompiled, Replace spaces) XLM-R layout.
func Load(path string) (*tokenizer.Tokenizer, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var cfg struct {
		Model struct {
			Type         string              `json:"type"`
			Vocab        [][]json.RawMessage `json:"vocab"`
			Unknown      int                 `json:"unk_id"`
			ByteFallback bool                `json:"byte_fallback"`
		} `json:"model"`
		Normalizer struct {
			Type        string            `json:"type"`
			Normalizers []json.RawMessage `json:"normalizers"`
		} `json:"normalizer"`
	}
	if e = json.Unmarshal(b, &cfg); e != nil {
		return nil, e
	}
	if cfg.Normalizer.Type != "Sequence" || len(cfg.Normalizer.Normalizers) != 2 {
		return nil, fmt.Errorf("unsupported E5 normalizer")
	}
	var first struct {
		Type  string `json:"type"`
		Chars string `json:"precompiled_charsmap"`
	}
	if e = json.Unmarshal(cfg.Normalizer.Normalizers[0], &first); e != nil {
		return nil, e
	}
	var second struct {
		Type    string            `json:"type"`
		Pattern map[string]string `json:"pattern"`
		Content string            `json:"content"`
	}
	if e = json.Unmarshal(cfg.Normalizer.Normalizers[1], &second); e != nil {
		return nil, e
	}
	if first.Type != "Precompiled" || second.Type != "Replace" || second.Pattern["Regex"] != " {2,}" || second.Content != " " {
		return nil, fmt.Errorf("unsupported E5 normalizer")
	}
	data, e := base64.StdEncoding.DecodeString(first.Chars)
	if e != nil {
		return nil, e
	}
	// Pinned tokenizer bytes are verified by the bundle before this parser is called.
	table, e := spm.NewPrecompiledFrom(data)
	if e != nil {
		return nil, e
	}
	t, e := pretrained.FromFile(path)
	if e != nil {
		return nil, e
	}
	t.WithNormalizer(normalizer.NewSequence([]normalizer.Normalizer{charsmap{table}, normalizer.NewReplace(normalizer.Regex, " {2,}", " ")}))
	if cfg.Model.Type != "Unigram" || cfg.Model.ByteFallback {
		return nil, fmt.Errorf("unsupported E5 model")
	}
	u := &unigram{Model: t.GetModel(), ids: map[string]int{}, unknown: cfg.Model.Unknown, minimum: math.Inf(1)}
	for id, pair := range cfg.Model.Vocab {
		if len(pair) != 2 {
			return nil, fmt.Errorf("invalid Unigram vocabulary")
		}
		var piece string
		var score float64
		if e = json.Unmarshal(pair[0], &piece); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(pair[1], &score); e != nil {
			return nil, e
		}
		u.ids[piece] = id
		u.scores = append(u.scores, score)
		u.maxBytes = max(u.maxBytes, len(piece))
		u.minimum = min(u.minimum, score)
	}
	if u.unknown < 0 || u.unknown >= len(u.scores) {
		return nil, fmt.Errorf("invalid unknown ID")
	}
	t.WithModel(u)
	t.WithTruncation(nil)
	t.WithPadding(nil)
	return t, nil
}
