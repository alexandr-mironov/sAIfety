package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/saifety-org/sAIfety/internal/sanitize"
	"github.com/saifety-org/sAIfety/internal/scan"
	"github.com/saifety-org/sAIfety/internal/scan/redact"
	"github.com/saifety-org/sAIfety/pkg/contextscan"
)

const (
	maxResultBytes = 32 << 20 // Includes opaque image/audio/blob data.
	maxResultText  = 1 << 20  // Aggregate decoded keys and textual values.
	maxResultDepth = 64
	maxResultNodes = 65536
)

// scanToolResult treats every textual representation as one document. Replacing
// a flagged result wholesale prevents an uncleaned copy surviving in another
// field and avoids claiming that rewritten JSON still satisfies outputSchema.
func (p *Proxy) scanToolResult(ctx context.Context, source string, trusted bool, raw json.RawMessage) any {
	result, _ := p.inspectToolResult(ctx, source, trusted, raw)
	return result
}

func (p *Proxy) inspectToolResult(ctx context.Context, source string, trusted bool, raw json.RawMessage) (output any, decision Decision) {
	decision = Decision{Action: "withhold", Delivery: "withheld", Reason: "inspection_unavailable", Scope: "result"}
	result, err := parseToolResult(raw)
	if err != nil {
		p.logf("tool result withheld for %s: %v", source, err)
		decision.Reason = "invalid_or_limited_result"
		return withheldResult("invalid tool result or inspection limit exceeded"), decision
	}
	var text strings.Builder
	err = walkResult(result, resultRoot, func(s string, _ bool) (string, error) {
		if text.Len()+len(s)+1 > maxResultText {
			return "", fmt.Errorf("text exceeds %d bytes", maxResultText)
		}
		text.WriteString(s)
		text.WriteByte('\n')
		return s, nil
	})
	if err != nil {
		decision.Reason = "text_limit"
		return withheldResult("tool result text exceeds inspection limit"), decision
	}
	if ctx.Err() != nil || p.Scanner == nil {
		return withheldResult("tool result inspection unavailable"), decision
	}
	doc := &scan.Document{Source: source, Kind: scan.KindToolResult, Raw: text.String(), Trusted: trusted}
	v := p.Scanner.Scan(ctx, doc)
	if ctx.Err() != nil {
		decision.Reason = "inspection_interrupted"
		return withheldResult("tool result inspection interrupted"), decision
	}
	// An allowlisted upstream does not grant instruction authority. Observe all
	// textual fields already inspected by the bounded MCP walker, before rewriting.
	if p.Context != nil && strings.TrimSpace(text.String()) != "" {
		p.Context.Observe(ctx, []contextscan.Document{{Kind: "mcp", Trust: "untrusted", Text: text.String(), Source: source}})
	}
	if ctx.Err() != nil {
		decision.Reason = "inspection_interrupted"
		return withheldResult("tool result inspection interrupted"), decision
	}
	decision = verdictDecision(v)
	p.Stats.Record(v)
	if v.Action == scan.ActionBlock {
		p.block(source, fmt.Sprintf("%s in tool result", v.Level))
		decision.Delivery, decision.Scope = "withheld", "tool"
		return blockedResult(), decision
	}
	if v.Action != scan.ActionPass {
		// Findings refer to the normalized document, not raw JSON offsets.
		decision.Delivery = "transformed"
		return withheldResultText(p.redactResultText(sanitize.Apply(doc.Text, v))), decision
	}
	if !p.RedactOn {
		return raw, decision // Preserve numbers, extensions, annotations and formatting.
	}
	changed, protectedChanged := false, false
	err = walkResult(result, resultRoot, func(s string, protected bool) (string, error) {
		masked := p.redactResultText(s)
		if masked != s {
			changed = true
			if protected {
				protectedChanged = true
				return s, nil // Avoid key collisions and invalid protocol identifiers.
			}
		}
		return masked, nil
	})
	if err != nil {
		decision.Action, decision.Delivery, decision.Reason = "withhold", "withheld", "redaction_error"
		return withheldResult("tool result redaction failed"), decision
	}
	if protectedChanged {
		decision.Delivery, decision.Reason = "transformed", "protected_field_redacted"
		return withheldResultText("[sAIfety] Sensitive JSON key or protocol field; result withheld.\n" + p.redactResultText(doc.Raw)), decision
	}
	if changed {
		decision.Delivery, decision.Reason = "transformed", "redacted"
		return result, decision
	}
	return raw, decision
}

func (p *Proxy) redactResultText(s string) string {
	if p.RedactOn {
		return redact.Mask(s, redact.Find(s, p.Redact))
	}
	return s
}

func withheldResult(reason string) map[string]any {
	return withheldResultText("[sAIfety] Tool result withheld: " + reason + ".")
}

func withheldResultText(text string) map[string]any {
	return map[string]any{"isError": true, "content": []map[string]string{{"type": "text", "text": text}}}
}

// Parse with explicit work limits and reject duplicate keys before decoding
// into maps, so different clients cannot interpret a different hidden value.
func parseToolResult(raw json.RawMessage) (map[string]any, error) {
	if len(raw) > maxResultBytes {
		return nil, fmt.Errorf("result exceeds %d bytes", maxResultBytes)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	value, err := readResultValue(d, 0, &nodes)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("unexpected trailing JSON")
	}
	result, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("result must be an object")
	}
	if content, exists := result["content"]; exists {
		blocks, ok := content.([]any)
		if !ok {
			return nil, fmt.Errorf("content must be an array")
		}
		for _, block := range blocks {
			if _, ok := block.(map[string]any); !ok {
				return nil, fmt.Errorf("content item must be an object")
			}
		}
	}
	if structured, exists := result["structuredContent"]; exists {
		if _, ok := structured.(map[string]any); !ok {
			return nil, fmt.Errorf("structuredContent must be an object")
		}
	}
	return result, nil
}

func readResultValue(d *json.Decoder, depth int, nodes *int) (any, error) {
	(*nodes)++
	if depth > maxResultDepth || *nodes > maxResultNodes {
		return nil, fmt.Errorf("JSON depth or node limit exceeded")
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	delim, container := token.(json.Delim)
	if !container {
		return token, nil
	}
	switch delim {
	case '{':
		object := map[string]any{}
		for d.More() {
			keyToken, err := d.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("object key must be a string")
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("duplicate JSON key")
			}
			value, err := readResultValue(d, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if _, err := d.Token(); err != nil {
			return nil, err
		}
		return object, nil
	case '[':
		array := []any{}
		for d.More() {
			value, err := readResultValue(d, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if _, err := d.Token(); err != nil {
			return nil, err
		}
		return array, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter")
	}
}

type resultLocation int

const (
	resultOther resultLocation = iota
	resultRoot
	resultContent
	resultBlock
	resultResource
	resultProtocol
)

// Only protocol-defined binary fields are opaque. A structuredContent object
// with {"type":"image","data":"..."} is ordinary JSON and is still scanned.
func opaqueResultField(object map[string]any, location resultLocation, key string) bool {
	return location == resultResource && key == "blob" ||
		location == resultBlock && key == "data" && (object["type"] == "image" || object["type"] == "audio")
}

// walkResult visits decoded keys and strings, including resource metadata,
// annotations and extension fields. Sorted keys give a deterministic text view.
func walkResult(value any, location resultLocation, visit func(string, bool) (string, error)) error {
	switch value := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if _, err := visit(key, true); err != nil {
				return err
			}
			if opaqueResultField(value, location, key) {
				encoded, ok := value[key].(string)
				if !ok {
					return fmt.Errorf("binary field must be a base64 string")
				}
				if _, err := io.Copy(io.Discard, base64.NewDecoder(base64.StdEncoding, strings.NewReader(encoded))); err != nil {
					return fmt.Errorf("invalid base64 binary field")
				}
				continue
			}
			child := resultOther
			if location == resultRoot && key == "content" {
				child = resultContent
			} else if location == resultBlock && value["type"] == "resource" && key == "resource" {
				child = resultResource
			} else if location == resultProtocol || (location == resultBlock || location == resultResource) && key == "annotations" {
				child = resultProtocol
			}
			if s, ok := value[key].(string); ok {
				protected := location == resultProtocol || (location == resultBlock || location == resultResource) && (key == "type" || key == "uri" || key == "mimeType")
				updated, err := visit(s, protected)
				if err != nil {
					return err
				}
				value[key] = updated
			} else if err := walkResult(value[key], child, visit); err != nil {
				return err
			}
		}
	case []any:
		child := resultOther
		switch location {
		case resultContent:
			child = resultBlock
		case resultProtocol:
			child = resultProtocol
		}
		for i, item := range value {
			if s, ok := item.(string); ok {
				updated, err := visit(s, location == resultProtocol)
				if err != nil {
					return err
				}
				value[i] = updated
			} else if err := walkResult(item, child, visit); err != nil {
				return err
			}
		}
	}
	return nil
}
