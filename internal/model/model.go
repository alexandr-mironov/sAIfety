// Package model provisions the optional transformer classifier: it downloads
// the ONNX prompt-injection model, its tokenizer and the matching ONNX
// Runtime shared library into a local cache, and reports where they are.
//
// The weights are NOT committed to the repository. A DeBERTa model is
// hundreds of megabytes, which exceeds GitHub's 100 MB file limit and would
// live in git history forever. Instead the tool fetches them on demand, the
// way whisper.cpp and spaCy do, so the repo stays small and the binary still
// works out of the box (falling back to the built-in lexical classifier
// until the model is pulled).
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Artifact is one downloadable file with an optional integrity checksum.
type Artifact struct {
	Name   string // local filename inside the cache dir
	URL    string
	SHA256 string // lowercase hex; empty skips verification
	Size   int64  // expected size in bytes, 0 if unknown (progress only)
	// Unpack, when set, treats the download as a .tgz and extracts the
	// single member whose base name matches Extract into Name.
	Unpack  bool
	Extract string
}

// Bundle is everything the ONNX classifier needs on disk.
type Bundle struct {
	Model     Artifact
	Tokenizer Artifact
	Config    Artifact // optional model config.json
	Runtime   Artifact // ONNX Runtime shared library for this OS/arch
	// Labels maps the logit index of the positive ("injection") class.
	InjectionIndex int
	Threshold      float64
}

// CacheDir returns the directory holding provisioned models. Override with
// SAIFETY_CACHE; otherwise $XDG_CACHE_HOME/saifety or ~/.cache/saifety.
func CacheDir() string {
	if p := os.Getenv("SAIFETY_CACHE"); p != "" {
		return p
	}
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, "saifety")
}

// Path is the absolute location an artifact resolves to on disk.
func Path(a Artifact) string { return filepath.Join(CacheDir(), a.Name) }

// Present reports whether every artifact of the bundle is already on disk.
func (b Bundle) Present() bool {
	for _, a := range []Artifact{b.Model, b.Tokenizer, b.Config, b.Runtime} {
		if a.URL == "" {
			continue
		}
		if fi, err := os.Stat(Path(a)); err != nil || fi.Size() == 0 {
			return false
		}
	}
	return true
}

// Pull downloads any missing artifacts, printing progress to w. Existing
// files with a matching checksum are left untouched.
func (b Bundle) Pull(w io.Writer, force bool) error {
	if err := os.MkdirAll(CacheDir(), 0o755); err != nil {
		return err
	}
	for _, a := range []Artifact{b.Runtime, b.Config, b.Tokenizer, b.Model} {
		if a.URL == "" {
			continue
		}
		if err := fetch(w, a, force); err != nil {
			return fmt.Errorf("%s: %w", a.Name, err)
		}
	}
	return nil
}

func fetch(w io.Writer, a Artifact, force bool) error {
	dst := Path(a)
	if !force {
		if ok, _ := verify(dst, a); ok {
			fmt.Fprintf(w, "  ok    %s (cached)\n", a.Name)
			return nil
		}
	}
	fmt.Fprintf(w, "  fetch %s\n", a.Name)
	tmp := dst + ".part"
	if a.Unpack {
		return fetchTgz(w, a, dst, tmp)
	}
	if err := download(w, a.URL, tmp, a.Name, a.Size); err != nil {
		return err
	}
	if ok, err := verify(tmp, a); !ok {
		_ = os.Remove(tmp) // Cleanup after read or failure.
		if err != nil {
			return err
		}
		return fmt.Errorf("checksum mismatch")
	}
	return os.Rename(tmp, dst)
}

func download(w io.Writer, url, dst, name string, size int64) error {
	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }() // Best-effort cleanup.
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // Best-effort cleanup.
	total := resp.ContentLength
	if total <= 0 {
		total = size // fall back to the manifest size
	}
	pw := newProgress(w, name, total)
	_, err = io.Copy(io.MultiWriter(f, pw), resp.Body)
	pw.done()
	if err != nil {
		return err
	}
	return f.Close()
}

func verify(path string, a Artifact) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() == 0 {
		return false, nil
	}
	if a.SHA256 == "" {
		return true, nil // presence is enough when no checksum is pinned
	}
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }() // Best-effort cleanup.
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, a.SHA256) {
		return false, fmt.Errorf("sha256 %s != %s", got, a.SHA256)
	}
	return true, nil
}
