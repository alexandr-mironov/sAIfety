package contextscan

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// A real child process exercises cancellation, IPC, queueing and restart on
// every CI OS without requiring native ML assets.
func init() {
	if os.Getenv("SAIFETY_TEST_CONTEXT_WORKER") != "1" || len(os.Args) < 2 || os.Args[1] != "context-worker" {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	enc := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var req Request
		if json.Unmarshal(scanner.Bytes(), &req) != nil {
			os.Exit(2)
		}
		if req.Text == "sleep" {
			time.Sleep(time.Hour)
		}
		if req.Text == "crash" {
			os.Exit(3)
		}
		value := .75
		reply := Response{Score: &value, IDs: []int{0, 1, 2}}
		if req.Text == "empty" {
			reply = Response{}
		}
		if req.Mode == "info" {
			reply = Response{Info: &Info{ID: "test", Version: "1", ManifestSHA256: strings.Repeat("a", 64), MaxTokens: 512, Threshold: .3}}
		}
		if enc.Encode(reply) != nil {
			os.Exit(4)
		}
	}
	os.Exit(0)
}
func testWorker(t *testing.T) *Worker {
	t.Helper()
	t.Setenv("SAIFETY_TEST_CONTEXT_WORKER", "1")
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	w, e := Open(ctx, WorkerConfig{Executable: exe, Bundle: "unused", Library: "unused", ManifestSHA256: strings.Repeat("a", 64)})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}
func TestWorkerCancellationReapsAndRestarts(t *testing.T) {
	w := testWorker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, e := w.Score(ctx, "sleep")
	if !errors.Is(e, context.DeadlineExceeded) || w.cmd != nil {
		t.Fatal("worker not cancelled/reaped", e)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	if score, e := w.Score(ctx2, "okay"); e != nil || score != .75 {
		t.Fatal(score, e)
	}
	if _, e = w.Score(ctx2, "crash"); e == nil {
		t.Fatal("crash returned success")
	}
	if _, e = w.Score(ctx2, "empty"); e == nil {
		t.Fatal("missing score accepted as zero")
	}
	if ids, e := w.Tokens(ctx2, "okay"); e != nil || len(ids) != 3 {
		t.Fatal(ids, e)
	}
	_ = w.Close()
	if _, e = w.Score(ctx2, "okay"); e == nil {
		t.Fatal("closed worker accepted a request")
	}
}
func TestWorkerQueueRespectsCallerDeadline(t *testing.T) {
	w := testWorker(t)
	// Hold the gate without spawning inference to test queue cancellation.
	<-w.gate
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := w.Score(ctx, "okay")
	w.gate <- struct{}{}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
func TestObserverMissingTaskDoesNotInventContext(t *testing.T) {
	var got Result
	o := &Observer{Report: func(r Result, _ error) { got = r }}
	o.Observe(context.Background(), []Document{{Kind: "mcp", Trust: "untrusted", Text: "task: do something"}})
	if got.Status != "missing-context" || got.Attack != nil {
		t.Fatal(got)
	}
}
