package contextscan

import (
	"context"
	"strings"
)

// Observer is an advisory transport adapter. Task is supplied separately by the
// caller/operator. It must never be populated from tool arguments or output.
// Report must be concurrency-safe and must not log payloads or source strings.
type Observer struct {
	Adapter *Adapter
	Task    string
	Report  func(Result, error)
}

func (o *Observer) Observe(ctx context.Context, documents []Document) {
	if o == nil {
		return
	}
	var result Result
	var err error
	if strings.TrimSpace(o.Task) == "" {
		result = Result{Status: "missing-context", Reason: "missing-user-task", Experimental: true, Coverage: "none"}
	} else if o.Adapter == nil {
		result = Result{Status: "error", Reason: "backend-unavailable", Experimental: true, Coverage: "none"}
	} else {
		result, err = o.Adapter.Analyze(ctx, Input{Contract: Contract, Task: o.Task, Documents: documents})
	}
	if o.Report != nil {
		o.Report(result, err)
	}
}
