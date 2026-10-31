//go:build onnx

package redact

import "github.com/sugarme/tokenizer"

// safeEncodeNER wraps EncodeSingle so a tokenizer panic becomes an error.
func safeEncodeNER(tk *tokenizer.Tokenizer, text string) (en *tokenizer.Encoding, err error) {
	defer func() {
		if r := recover(); r != nil {
			en, err = nil, errTok
		}
	}()
	e, err := tk.EncodeSingle(text, true)
	if err != nil {
		return nil, err
	}
	return e, nil
}

type tokErr string

func (e tokErr) Error() string { return string(e) }

var errTok = tokErr("tokenizer panicked")
