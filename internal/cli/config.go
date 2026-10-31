package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/saifety-org/sAIfety/internal/mcp"
)

// Config is saifety.json. The mcpServers block is byte-compatible with
// Claude Code's .mcp.json so an existing file can be reused as-is.
type Config struct {
	ExperimentalContext ContextConfig             `json:"experimentalContext"`
	MCPServers          map[string]mcp.ServerSpec `json:"mcpServers"`
	TrustedSources      []string                  `json:"trustedSources"`
	MaxDecodeDepth      int                       `json:"maxDecodeDepth"`
	MaxFileSize         int64                     `json:"maxFileSize"`
	// ClaudeBinary overrides the `claude` executable used by launch.
	ClaudeBinary string `json:"claudeBinary"`
	// Classifier selects "trained" (default, embedded model), "lexical"
	// (heuristics), "onnx" (transformer, downloaded on first use; requires
	// an onnx build), or "auto" (cached onnx, otherwise lexical).
	Classifier string `json:"classifier"`
	// Policy is the strictness profile: "strict" (default) or "balanced".
	Policy string `json:"policy"`
	// Redact controls masking of secrets and personal data in outputs.
	Redact RedactConfig `json:"redact"`
}

// RedactConfig configures the anonymization pass.
type RedactConfig struct {
	// Disabled turns off masking of tool outputs (default: enabled).
	Disabled bool `json:"disabled"`
	// AllowOpaque permits uninspected binary image/audio/blob responses.
	AllowOpaque bool `json:"allowOpaque"`
	// Keywords are extra literal strings to redact.
	Keywords []string `json:"keywords"`
	// Allowlist are substrings that must never be redacted.
	Allowlist []string `json:"allowlist"`
	// Deprecated: IP addresses are outside the PII profile.
	KeepIP bool `json:"keepIP"`
	// MinEntropy enables generic high-entropy token masking when > 0.
	MinEntropy float64 `json:"minEntropy"`
	// Deprecated: NER is never loaded; retained for existing config files.
	NoModel bool `json:"noModel"`
	// Deprecated: NER labels have no effect.
	NERLabels []string `json:"nerLabels"`
}

// DefaultConfigPath is $SAIFETY_CONFIG, else saifety/saifety.json under
// os.UserConfigDir().
// The config is deliberately NOT read from the project directory: a
// poisoned repository must not be able to declare itself trusted.
func DefaultConfigPath() string {
	if p := os.Getenv("SAIFETY_CONFIG"); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "saifety.json"
	}
	return filepath.Join(dir, "saifety", "saifety.json")
}

// LoadConfig reads path; a missing file yields the zero config, not an error.
func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	return c, json.Unmarshal(b, &c)
}
