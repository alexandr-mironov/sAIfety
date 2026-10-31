package redact

// NER is an explicitly attached named-entity recognizer. DefaultOptions never
// contains one; runtime enablement and provisioning are separate operator actions.
type NER interface {
	// Recognize returns PII spans found by the model.
	Recognize(text string) []Match
}

// CheckedNER reports an incomplete/failed enabled model explicitly.
type CheckedNER interface {
	RecognizeChecked(text string) ([]Match, error)
}

// WithNER returns a copy of opts using the given recognizer.
func (o Options) WithNER(n NER) Options {
	o.ner = n
	o.nerErr = nil
	return o
}

// WithNERError records failure to initialize a provisioned enabled model.
func (o Options) WithNERError(err error) Options {
	o.nerErr = err
	o.ner = nil
	return o
}

// NERError reports an initialization failure without running inference.
func (o Options) NERError() error { return o.nerErr }

// CloseNER releases an explicitly attached recognizer when it owns resources.
func (o Options) CloseNER() error {
	if n, ok := o.ner.(interface{ Close() error }); ok {
		return n.Close()
	}
	return nil
}
