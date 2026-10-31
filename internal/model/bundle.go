package model

import (
	"fmt"
	"runtime"
)

// DefaultBundle is the prompt-injection classifier sAIfety provisions:
// protectai/deberta-v3-base-prompt-injection-v2 (English DeBERTa-v3,
// labels SAFE=0 / INJECTION=1) plus the matching ONNX Runtime library.
//
// No checksums are pinned for the model and tokenizer yet: they are large
// and the upstream may repackage. Pin SHA256 here once a release is frozen.
func DefaultBundle() (Bundle, error) {
	const hf = "https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/resolve/main"
	rt, err := runtimeArtifact()
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{
		Model:          Artifact{Name: "model.onnx", URL: hf + "/onnx/model.onnx", Size: 738563188},
		Tokenizer:      Artifact{Name: "tokenizer.json", URL: hf + "/tokenizer.json"},
		Runtime:        rt,
		InjectionIndex: 1,
		Threshold:      0.5,
	}, nil
}

// PIIBundle is an optional multilingual ONNX token-classification bundle.
// It must be provisioned explicitly; only person labels are used by default.
// Availability does not establish recognition quality for a language/script.
func PIIBundle() (Bundle, error) {
	const hf = "https://huggingface.co/Xenova/bert-base-multilingual-cased-ner-hrl/resolve/main"
	rt, err := runtimeArtifact()
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{
		Model:     Artifact{Name: "pii-model.onnx", URL: hf + "/onnx/model_quantized.onnx", Size: 178495423},
		Tokenizer: Artifact{Name: "pii-tokenizer.json", URL: hf + "/tokenizer.json"},
		Config:    Artifact{Name: "pii-config.json", URL: hf + "/config.json"},
		Runtime:   rt,
	}, nil
}

// ortVersion is the ONNX Runtime release whose C API (21) matches the
// onnxruntime_go binding used by the onnx build.
const ortVersion = "1.22.0"

func runtimeArtifact() (Artifact, error) {
	const rel = "https://github.com/microsoft/onnxruntime/releases/download/v" + ortVersion
	var platform, lib string
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "darwin/arm64":
		platform, lib = "osx-arm64", "libonnxruntime."+ortVersion+".dylib"
	case "darwin/amd64":
		platform, lib = "osx-x86_64", "libonnxruntime."+ortVersion+".dylib"
	case "linux/amd64":
		platform, lib = "linux-x64", "libonnxruntime.so."+ortVersion
	case "linux/arm64":
		platform, lib = "linux-aarch64", "libonnxruntime.so."+ortVersion
	default:
		return Artifact{}, fmt.Errorf("no prebuilt ONNX Runtime for %s/%s; install it and set SAIFETY_ORT_LIB", runtime.GOOS, runtime.GOARCH)
	}
	name := fmt.Sprintf("onnxruntime-%s-%s", platform, ortVersion)
	localLib := "libonnxruntime" + libExt()
	return Artifact{
		Name:    localLib,
		URL:     fmt.Sprintf("%s/%s.tgz", rel, name),
		Unpack:  true,
		Extract: lib,
	}, nil
}

func libExt() string {
	switch runtime.GOOS {
	case "darwin":
		return ".dylib"
	case "windows":
		return ".dll"
	default:
		return ".so"
	}
}

// RuntimeLibPath is the shared library the onnx classifier should load.
// SAIFETY_ORT_LIB overrides it (e.g. a system-installed runtime).
func RuntimeLibPath() string {
	rt, err := DefaultBundle()
	if err != nil {
		return ""
	}
	return Path(rt.Runtime)
}
