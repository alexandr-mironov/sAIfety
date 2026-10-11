package contextscan

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// WorkerConfig selects local artifacts and the sAIfety executable built with
// -tags onnx. The manifest pin must come from the operator, never scanned data.
type WorkerConfig struct {
	Executable     string
	Bundle         string
	Library        string
	ManifestSHA256 string
}

// Worker isolates native inference and tokenizer failures. At most one RPC is
// active; cancellation kills and reaps the child, including during startup.
// The next RPC starts a fresh worker. Close must be called by the owner.
type Worker struct {
	cfg    WorkerConfig
	gate   chan struct{}
	cmd    *exec.Cmd
	input  io.WriteCloser
	output *bufio.Scanner
	info   Info
	closed bool
}
type Request struct {
	Mode string `json:"mode"`
	Text string `json:"text"`
}
type Response struct {
	Info  *Info   `json:"info,omitempty"`
	IDs   []int   `json:"ids,omitempty"`
	Score float64 `json:"score,omitempty"`
	Error string  `json:"error,omitempty"`
}

func Open(ctx context.Context, cfg WorkerConfig) (*Worker, error) {
	if cfg.Executable == "" || cfg.Bundle == "" || cfg.Library == "" || len(cfg.ManifestSHA256) != 64 {
		return nil, fmt.Errorf("context worker requires executable, bundle, library and manifest SHA256")
	}
	decoded, err := hex.DecodeString(cfg.ManifestSHA256)
	if err != nil || len(decoded) != 32 {
		return nil, fmt.Errorf("invalid manifest SHA256")
	}
	cfg.ManifestSHA256 = strings.ToLower(cfg.ManifestSHA256)
	w := &Worker{cfg: cfg, gate: make(chan struct{}, 1)}
	w.gate <- struct{}{}
	if _, err := w.call(ctx, Request{Mode: "info"}); err != nil {
		_ = w.Close()
		return nil, err
	}
	return w, nil
}
func (w *Worker) Info() Info { return w.info }
func (w *Worker) Tokens(ctx context.Context, s string) ([]int, error) {
	r, e := w.call(ctx, Request{Mode: "tokens", Text: s})
	return r.IDs, e
}
func (w *Worker) Score(ctx context.Context, s string) (float64, error) {
	r, e := w.call(ctx, Request{Mode: "score", Text: s})
	return r.Score, e
}
func (w *Worker) start() error {
	w.cmd = exec.Command(w.cfg.Executable, "context-worker", "-bundle", w.cfg.Bundle, "-library", w.cfg.Library, "-manifest-sha256", w.cfg.ManifestSHA256)
	// Worker stderr is intentionally discarded: errors travel as bounded JSON;
	// diagnostics must not accidentally echo document text to host logs.
	var err error
	w.input, err = w.cmd.StdinPipe()
	if err != nil {
		return err
	}
	output, err := w.cmd.StdoutPipe()
	if err != nil {
		_ = w.input.Close()
		return err
	}
	w.output = bufio.NewScanner(output)
	w.output.Buffer(make([]byte, 4096), 8<<20)
	if err = w.cmd.Start(); err != nil {
		_ = w.input.Close()
		_ = output.Close()
		w.cmd = nil
		return err
	}
	return nil
}
func (w *Worker) stop() {
	if w.cmd != nil && w.cmd.Process != nil {
		_ = w.cmd.Process.Kill()
		_ = w.cmd.Wait()
	}
	if w.input != nil {
		_ = w.input.Close()
	}
	w.cmd = nil
	w.input = nil
	w.output = nil
}
func (w *Worker) call(ctx context.Context, req Request) (Response, error) {
	select {
	case <-ctx.Done():
		return Response{}, ctx.Err()
	case <-w.gate:
	}
	defer func() { w.gate <- struct{}{} }()
	if w.closed {
		return Response{}, fmt.Errorf("context worker closed")
	}
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	if w.cmd == nil {
		if err := w.start(); err != nil {
			w.stop()
			return Response{}, fmt.Errorf("start context worker: %w", err)
		}
	}
	type reply struct {
		r Response
		e error
	}
	done := make(chan reply, 1)
	input, output := w.input, w.output
	go func() {
		if e := json.NewEncoder(input).Encode(req); e != nil {
			done <- reply{e: e}
			return
		}
		if !output.Scan() {
			e := output.Err()
			if e == nil {
				e = io.ErrUnexpectedEOF
			}
			done <- reply{e: e}
			return
		}
		var r Response
		e := json.Unmarshal(output.Bytes(), &r)
		done <- reply{r, e}
	}()
	var got reply
	select {
	case <-ctx.Done():
		w.stop()
		<-done
		return Response{}, ctx.Err()
	case got = <-done:
	}
	if e := ctx.Err(); e != nil {
		w.stop()
		return Response{}, e
	}
	if got.e != nil {
		w.stop()
		return Response{}, fmt.Errorf("context worker protocol: %w", got.e)
	}
	if got.r.Error != "" {
		w.stop()
		return Response{}, fmt.Errorf("context worker: %s", got.r.Error)
	}
	if req.Mode == "info" {
		if got.r.Info == nil || got.r.Info.ManifestSHA256 != strings.ToLower(w.cfg.ManifestSHA256) {
			w.stop()
			return Response{}, fmt.Errorf("context worker identity mismatch")
		}
		w.info = *got.r.Info
	}
	return got.r, nil
}
func (w *Worker) Close() error {
	<-w.gate
	defer func() { w.gate <- struct{}{} }()
	w.closed = true
	w.stop()
	return nil
}
