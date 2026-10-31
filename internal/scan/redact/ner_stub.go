//go:build !onnx

package redact

import "fmt"

// NERConfig mirrors the onnx-build type so callers compile without the tag.
type NERConfig struct {
	LibraryPath   string
	ModelPath     string
	TokenizerPath string
	ConfigPath    string
	Entities      []string
}

// NewONNXNER is unavailable unless built with -tags onnx.
func NewONNXNER(NERConfig) (NER, error) {
	return nil, fmt.Errorf("ner model not built in; rebuild with: go build -tags onnx")
}
