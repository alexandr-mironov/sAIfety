//go:build onnx

package redact

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/saifety-org/sAIfety/internal/onnxenv"
	"github.com/sugarme/tokenizer"
	"github.com/sugarme/tokenizer/pretrained"
	ort "github.com/yalue/onnxruntime_go"
)

// onnxNER is a token-classification NER model for personal data. It works
// with 2-input (DistilBERT) and 3-input (BERT with token_type_ids) models,
// and maps BIO entity labels to redaction labels. Built only with -tags onnx.
type onnxNER struct {
	tk         *tokenizer.Tokenizer
	session    *ort.DynamicAdvancedSession
	labels     []string
	numLbl     int
	inputNames []string
	keep       map[string]string // entity (PER/DATE/...) -> redaction label
	mu         sync.Mutex
}

// NERConfig points the recognizer at its artifacts. Entities lists the NER
// entity types to mask; empty means the default set (persons and dates).
type NERConfig struct {
	LibraryPath   string
	ModelPath     string
	TokenizerPath string
	ConfigPath    string
	Entities      []string
}

// defaultEntityMap maps common NER entities to redaction labels. PER (a
// person's name) and DATE (e.g. a date of birth) are personal; LOC and ORG
// are opt-in via NERConfig.Entities.
var defaultEntityMap = map[string]string{
	"PER": "full_name", "PERSON": "full_name", "NAME": "full_name",
	"GIVENNAME": "full_name", "SURNAME": "full_name", "FIRSTNAME": "full_name", "LASTNAME": "full_name",
	"DATE": "date", "DOB": "date", "DATEOFBIRTH": "date",
	"LOC": "location", "GPE": "location", "CITY": "location", "STREET": "address", "ADDRESS": "address",
	"ORG": "org",
}

// NewONNXNER loads a token-classification NER model.
func NewONNXNER(cfg NERConfig) (NER, error) {
	for _, p := range []string{cfg.LibraryPath, cfg.ModelPath, cfg.TokenizerPath, cfg.ConfigPath} {
		if p == "" {
			return nil, fmt.Errorf("ner: empty artifact path")
		}
		if _, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("ner: %w", err)
		}
	}
	labels, err := loadLabels(cfg.ConfigPath)
	if err != nil {
		return nil, err
	}
	tk, err := pretrained.FromFile(cfg.TokenizerPath)
	if err != nil {
		return nil, fmt.Errorf("ner: tokenizer: %w", err)
	}
	// Coverage is controlled by nerWindows, not by tokenizer-side truncation.
	tk.WithTruncation(nil)
	tk.WithPadding(nil)
	if err := onnxenv.Init(cfg.LibraryPath); err != nil {
		return nil, fmt.Errorf("ner: runtime init: %w", err)
	}
	// Discover the model's input names so we pass token_type_ids only when
	// the model expects it.
	inInfo, _, err := ort.GetInputOutputInfo(cfg.ModelPath)
	if err != nil {
		return nil, fmt.Errorf("ner: model info: %w", err)
	}
	var names []string
	for _, in := range inInfo {
		names = append(names, in.Name)
	}
	sess, err := ort.NewDynamicAdvancedSession(cfg.ModelPath, names, []string{"logits"}, nil)
	if err != nil {
		return nil, fmt.Errorf("ner: session: %w", err)
	}

	keep := map[string]string{}
	if len(cfg.Entities) == 0 {
		keep["PER"] = "full_name"
		keep["DATE"] = "date"
		// also honor model-specific person/date labels present in defaultEntityMap
		for _, l := range labels {
			e := entityOf(l)
			if rl, ok := defaultEntityMap[e]; ok && (rl == "full_name" || rl == "date") {
				keep[e] = rl
			}
		}
	} else {
		for _, e := range cfg.Entities {
			e = strings.ToUpper(e)
			if rl, ok := defaultEntityMap[e]; ok {
				keep[e] = rl
			} else {
				keep[e] = strings.ToLower(e)
			}
		}
	}
	return &onnxNER{tk: tk, session: sess, labels: labels, numLbl: len(labels), inputNames: names, keep: keep}, nil
}

func entityOf(label string) string {
	return strings.ToUpper(strings.TrimPrefix(strings.TrimPrefix(label, "B-"), "I-"))
}

func loadLabels(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c struct {
		Id2Label map[string]string `json:"id2label"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if len(c.Id2Label) == 0 {
		return nil, fmt.Errorf("ner: config has no id2label")
	}
	labels := make([]string, len(c.Id2Label))
	for k, v := range c.Id2Label {
		i, err := strconv.Atoi(k)
		if err != nil || i < 0 || i >= len(labels) {
			return nil, fmt.Errorf("ner: bad label index %q", k)
		}
		labels[i] = v
	}
	return labels, nil
}

// Recognize runs the model and decodes BIO tags into masked spans. It never
// panics: a tokenizer panic degrades to no model matches (heuristics still
// apply).
func (n *onnxNER) Recognize(text string) []Match {
	out, _ := n.RecognizeChecked(text)
	return out
}

func (n *onnxNER) RecognizeChecked(text string) (out []Match, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("NER inspection failed")
		}
	}()
	n.mu.Lock()
	defer n.mu.Unlock()
	en, terr := safeEncodeNER(n.tk, text)
	if terr != nil || en == nil || len(en.Ids) == 0 {
		return nil, fmt.Errorf("NER tokenization failed")
	}
	windows, err := nerWindows(en)
	if err != nil {
		return nil, err
	}
	for _, window := range windows {
		matches, err := n.recognizeWindow(text, window)
		if err != nil {
			return nil, err // Never retain only the completed prefix.
		}
		out = append(out, matches...)
	}
	return dedupe(out), nil
}

func (n *onnxNER) recognizeWindow(text string, en *tokenizer.Encoding) ([]Match, error) {
	var out []Match
	seq := len(en.Ids)
	ids := make([]int64, seq)
	mask := make([]int64, seq)
	zeros := make([]int64, seq)
	for i := 0; i < seq; i++ {
		ids[i] = int64(en.Ids[i])
		mask[i] = 1
	}
	shape := ort.NewShape(1, int64(seq))
	var inputs []ort.Value
	var cleanup []interface{ Destroy() error }
	for _, name := range n.inputNames {
		var data []int64
		switch name {
		case "attention_mask":
			data = mask
		case "token_type_ids":
			data = zeros
		default: // input_ids
			data = ids
		}
		tv, err := ort.NewTensor(shape, data)
		if err != nil {
			for _, c := range cleanup {
				_ = c.Destroy() // Best-effort tensor cleanup.
			}
			return nil, fmt.Errorf("NER tensor unavailable")
		}
		cleanup = append(cleanup, tv)
		inputs = append(inputs, tv)
	}
	outT, err := ort.NewEmptyTensor[float32](ort.NewShape(1, int64(seq), int64(n.numLbl)))
	if err != nil {
		for _, c := range cleanup {
			_ = c.Destroy() // Best-effort tensor cleanup.
		}
		return nil, fmt.Errorf("NER output unavailable")
	}
	defer func() { _ = outT.Destroy() }() // Best-effort tensor cleanup.

	err = n.session.Run(inputs, []ort.Value{outT})
	for _, c := range cleanup {
		_ = c.Destroy() // Best-effort tensor cleanup.
	}
	if err != nil {
		return nil, fmt.Errorf("NER inference failed")
	}
	logits := outT.GetData()
	if len(logits) != seq*n.numLbl {
		return nil, fmt.Errorf("invalid NER output shape")
	}
	for _, logit := range logits {
		if math.IsNaN(float64(logit)) || math.IsInf(float64(logit), 0) {
			return nil, fmt.Errorf("nonfinite NER output")
		}
	}

	var cur *Match
	var curConf []float64
	flush := func() {
		if cur != nil {
			sum := 0.0
			for _, c := range curConf {
				sum += c
			}
			cur.Confidence = sum / float64(len(curConf))
			out = append(out, *cur)
			cur, curConf = nil, nil
		}
	}
	for i := 0; i < seq; i++ {
		off := en.Offsets[i]
		if len(off) < 2 || off[0] < 0 || off[1] < off[0] || off[1] > len(text) {
			return nil, fmt.Errorf("invalid NER token offsets")
		}
		if off[0] == 0 && off[1] == 0 {
			flush()
			continue
		}
		best, conf := argmaxSoftmax(logits[i*n.numLbl : (i+1)*n.numLbl])
		entity := entityOf(n.labels[best])
		rl, ok := n.keep[entity]
		if !ok {
			flush()
			continue
		}
		if cur != nil && cur.Label == rl && off[0] <= cur.End+1 {
			cur.End = off[1]
			curConf = append(curConf, conf)
			continue
		}
		flush()
		cur = &Match{Kind: KindPII, Label: rl, Start: off[0], End: off[1]}
		curConf = []float64{conf}
	}
	flush()
	return out, nil
}

func argmaxSoftmax(row []float32) (int, float64) {
	best := 0
	max := row[0]
	for j, v := range row {
		if v > max {
			max, best = v, j
		}
	}
	var sum float64
	for _, v := range row {
		sum += math.Exp(float64(v - max))
	}
	return best, 1.0 / sum
}
