# Experimental contextual inference

The Go runtime can evaluate the local contextual E5 v4 ONNX bundle. This is
**advisory shadow inference**, separate from the existing scanner, sanitization
and blocking policy. It is off by default. The candidate's previously observed
synthetic test FPR was 1.43%, above the 1% target; segmentation has not been
calibrated. A contextual score is not a guarantee of safety or release readiness.

## Local configuration and CLI

Build with `make build`. Use a local bundle exported by lab-py and verified against
`prompt-injection-model/models/contextual-e5-v4/manifest.json`. No Python process,
model download, training data or trained weights are included in this runtime.
Model artifacts remain in prompt-injection-model; research tooling stays in lab
and lab-py. The input contract and artifacts are pinned to v4-onnx-fp32-1.

Add to the operator-owned config selected by `-config` / `SAIFETY_CONFIG`:

```json
{
  "experimentalContext": {
    "mode": "shadow",
    "bundle": "/absolute/path/to/bundle",
    "library": "/absolute/path/to/libonnxruntime.dylib",
    "manifestSHA256": "a749100810cd6cd689bafdd97623d714fbb10aa969f000be514c8da5eddcd73d",
    "timeoutMS": 5000,
    "maxWindows": 32
  }
}
```

Use the corresponding `.so` / `.dll` library on Linux / Windows. The default
manifest pin is the value above, from the accepted model repository. An explicit
alternative pin is an operator decision; artifact hashes are not signatures or
proof of model quality. Keep the local artifact directory immutable while serving.
`mode` accepts `off` (also the default) or `shadow`. `classifier` retains its
existing meaning; contextual inference never replaces it.

`saifety context -config /path/config.json` reads one JSON input from stdin:

```json
{
  "contract": "context-json-v2",
  "task": "Summarize the fetched release notes",
  "documents": [
    {
      "kind": "web",
      "trust": "untrusted",
      "text": "Release notes supplied by the source",
      "source": "release-notes"
    }
  ]
}
```

`task` is the authorized user goal, supplied separately by the caller. Documents
accept `kind: file | web | mcp` and `trust: untrusted | user-provided`. Neither
trust value grants instruction authority. Assertions such as "system message"
inside a document cannot elevate its trust. `source` is optional application
metadata; it is excluded from model input. The app renders compact ordered JSON
with Go's HTML escaping disabled, matching the corpus renderer, then the worker
adds the trained `query: ` prefix. The checkpoint tokenizer is the only text
normalization; no translation, NFKC substitution or language filtering is added.

Output includes status/reason, experimental flag, model version, manifest and
runtime hashes/version, frozen threshold, coverage and per-window scores. Source
ranges are half-open UTF-8 **byte ranges in the original input**, not model
attributions. The token compatibility layer exposes IDs only, not original-text
token offsets. The CLI uses exit 0 for a completed advisory result, even an attack;
invalid/missing/incomplete context returns nonzero. Existing `scan` exit codes and
reports are unchanged.

## MCP and Claude Code hooks

Enable the same shadow config and supply an actual task explicitly:

```sh
saifety proxy -config /path/config.json -task 'Summarize release notes'
saifety hook -config /path/config.json -task 'Summarize release notes' post-tool-use
```

The task applies to that invocation; a long-running proxy must be restarted with
the updated task when the user goal changes. The host protocols do not provide
an authorized task in these existing payloads. Tool arguments, `_meta`, tool
names, commands, output and repository instructions are **never used as task**.
Without `-task`, the observer logs `missing-context` and does not load the model.
There is no attempt to read transcripts or infer a task from external content.

MCP observes the bounded, ordered textual representation already inspected by
the result walker: text, structuredContent, embedded resources, keys and textual
extensions. Protocol image/audio/blob payloads remain opaque, as in the existing
scanner. All this content remains `mcp/untrusted`, including allowlisted upstreams.
Hook SessionStart supplies available instruction files as `file/untrusted`.
PostToolUse supplies the raw response JSON, with kind taken from available
file/path/url provenance (otherwise `mcp`); it does not invent missing data.
Descriptions and PreToolUse have no contextual-model inference in this version.
The wrapper does not claim the unavailable conversation history is covered.

Shadow scores/errors do not rewrite, block, allow or persist sources. Existing
rule/classifier and blocklist behavior still applies. Diagnostics go to stderr,
not protocol stdout, and include no task, payload or source strings. The JSON
context CLI intentionally returns source metadata supplied by its caller.

## Limits, segmentation and errors

- Default 1 MiB total task/document/source bytes, at most 128 documents, 32 windows
  and a 5-second **whole analysis** timeout including tokenization, queueing and
  inference. API options may reduce these limits; timeout can be at most 60 seconds.
  Native worker startup/artifact verification has a separate 60-second CLI limit.
- Token counts include special tokens. Up to 512 tokens are evaluated jointly,
  preserving document order, kind and trust. No silent truncation is permitted.
- On overflow, whole documents are greedily packed in order. Oversized documents
  are split at UTF-8 boundaries, initially at most 2048 bytes, halved until the
  serialized task/document window fits. Adjacent pieces overlap by up to 32 Unicode
  code points. Each window repeats the complete task. Exact byte ranges retain
  source and trust. This bounds computation; it is not semantic segmentation.
- A task leaving no space for document content, whitespace-only pieces, an
  exceeded window/byte/document limit or incomplete inference produces an error,
  **no aggregate score/decision**. Previously scored windows may be reported as
  partial evidence. No partial result is called clean.
- Complete results aggregate by maximum window attack score and compare with the
  manifest's frozen threshold. Cross-window attacks may be missed; this aggregation
  is not calibrated to the whole-input FPR. Segmented results carry that warning.
- Missing task returns `missing-context`; unknown contract/trust, artifact/schema
  mismatch, tokenization failure, runtime error and nonfinite scores are explicit
  errors. There is no fallback score or substitute classifier. Shadow startup/inference
  errors are logged but do not skip the existing scanner. Hook PreToolUse does
  not initialize this optional model; even an invalid shadow config cannot bypass
  its blocklist enforcement. The context CLI itself returns an error on startup
  failure.
- Native inference runs in one resident child of the same Go executable. A
  context deadline/cancellation kills and reaps it, rather than leaving inference
  running in a goroutine. Requests are serialized with cancellable queueing; the
  next request can restart the worker. Owners must close it on shutdown. Native
  crashes/protocol failures also discard the worker. A lite build reports that
  ONNX support is required when a task needs inference.

## Go embedding and verification

`pkg/contextscan` exposes `Input`, `Document`, `Worker`, `Adapter` and `Observer`.
Open a Worker with a context deadline, an ONNX-enabled sAIfety executable and local
artifact paths/pin; defer `Close()`. Construct `New(worker, Options{})`, then call
`Analyze(ctx, input)`. The Backend interface allows hosts to supply a checked,
cancellable backend, but never adapts the legacy text-only `Scorer` implicitly.
The existing `pkg/scanner` API remains compatible. Observer reports must be
concurrency-safe and avoid logging private payload/source data.

Tests cover trust/task boundaries, Unicode coverage, late-window detection,
limits, partial failures, real subprocess cancellation/restart and unchanged
transport policies. `make ci-test` runs race tests and separate ONNX tests. CI
checks real native inference using the ~9 KB constant-logit fixture; it is not a
trained classifier. Set `SAIFETY_CONTEXT_TEST_LIBRARY` to a local ORT library to
run that test locally. Full E5 integration parity is checked separately on the
previously observed 575 parity inputs: exact token IDs and decisions, maximum
score delta 0 against the accepted Go bridge on the same runtime. This checks
integration, not a new quality evaluation. The runtime
compatibility implementation derives from accepted lab#11; historical pinned
research bridges retain their reproducible implementation. Core now owns the
application's tokenizer/inference path; future research tools can consume this API.
