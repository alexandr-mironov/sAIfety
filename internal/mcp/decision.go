package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/saifety-org/sAIfety/internal/scan"
)

// Decision is operator telemetry, never part of the agent's tool response.
// Findings deliberately omit source, spans, excerpts, messages and decoded text.
type Decision struct {
	Schema         string            `json:"schema"`
	RequestSHA256  string            `json:"request_sha256"`
	UpstreamCalled bool              `json:"upstream_called"`
	Action         string            `json:"action"`
	Delivery       string            `json:"delivery"`
	Reason         string            `json:"reason"`
	Scope          string            `json:"scope"`
	Level          string            `json:"level,omitempty"`
	Findings       []DecisionFinding `json:"findings,omitempty"`
	FindingCount   int               `json:"finding_count"`
	Suppressed     int               `json:"suppressed"`
}

type DecisionFinding struct {
	Detector   string        `json:"detector"`
	Category   scan.Category `json:"category"`
	Level      string        `json:"level"`
	Confidence float64       `json:"confidence"`
}

func verdictDecision(v scan.Verdict) Decision {
	d := Decision{Action: v.Action.String(), Delivery: "original", Reason: "scanned", Scope: "result", Level: v.Level.String(), FindingCount: len(v.Findings), Suppressed: len(v.Suppressed)}
	findings := v.Findings
	if len(findings) > 128 {
		findings = findings[:128] // Bound per-call telemetry; total count remains explicit.
	}
	for _, f := range findings {
		d.Findings = append(d.Findings, DecisionFinding{f.Detector, f.Category, f.Level.String(), f.Confidence})
	}
	return d
}

func (p *Proxy) recordDecision(id json.RawMessage, d Decision) {
	if p.DecisionLog == nil {
		return
	}
	hash := sha256.Sum256(id)
	d.Schema = "saifety-proxy-decision-v1"
	d.RequestSHA256 = hex.EncodeToString(hash[:])
	p.decisionMu.Lock()
	err := json.NewEncoder(p.DecisionLog).Encode(d)
	p.decisionMu.Unlock()
	if err != nil {
		// Never echo writer errors, which can contain operator paths or data.
		p.logf("decision log write failed")
	}
}
