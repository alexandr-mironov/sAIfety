# Synthetic NER fixture

These files exercise native tokenization, ONNX inference, Unicode byte offsets
and coverage beyond 512 tokens. They contain no trained weights or real PII.
They are plumbing tests, not evidence of recognition quality.

The 409-byte ONNX graph uses opset 17 / IR 8. For each input token ID it emits
two logits: [1, 0] for IDs below 4 and [0, 1] otherwise. Its nodes are
GreaterOrEqual, Cast, Sub, two Unsqueeze operations and Concat. The tokenizer is
a tiny WordLevel vocabulary with CLS/SEP template processing.

The fixture is checked with onnx.checker before being committed. Tests use
the same pinned native runtime as the contextual integration fixture in CI.
No Python, model download or training is needed to run the tests.

The vocabulary also contains synthetic Cyrillic/Latin personal-name examples.
This makes span/offset integration deterministic; it is not a model-quality test.
