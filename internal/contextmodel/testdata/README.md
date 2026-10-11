This ~9 KB bundle is a synthetic runtime regression fixture, not trained E5
weights. The ONNX graph declares the two required int64 inputs and returns
constant float32 logits `[0, 1]`. The tokenizer uses a tiny identity charmap,
Unigram and the production preprocessing layout. All files are synthetic.

The closed v4 contract/identity fields let the real loader exercise the same
code path. The fixture has a **distinct manifest pin** and is rejected by the
canonical E5 pin. It provides no model quality or numerical parity evidence.

One-time generation used ONNX helper/protobuf and HF tokenizers in lab-py's
ML environment. No Python tooling is required by this application or its CI.
Tests exercise manifest identity, real ORT tensors/session, Unicode tokenization,
finite binary score and the no-truncation limit. Production artifacts belong
in prompt-injection-model; research datasets/tools remain in lab/lab-py.
