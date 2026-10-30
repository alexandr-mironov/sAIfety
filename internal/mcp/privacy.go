package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/saifety-org/sAIfety/internal/scan"
	"github.com/saifety-org/sAIfety/internal/scan/redact"
)

var errOpaquePII = errors.New("opaque content cannot be inspected for PII")

type privacyChange struct {
	changed, protected, numeric bool
}

// redactValue operates on decoded values with their field context. Numeric
// values are inspected without float64 conversion; a masked number is later
// rendered as text instead of silently violating a tool's structured schema.
func (p *Proxy) redactValue(ctx context.Context, value any, location resultLocation, field string, change *privacyChange) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch value := value.(type) {
	case map[string]any:
		for key, item := range value {
			keyField := ""
			if redact.FieldLabel(field) != "" && redact.FieldLabel(key) == "" {
				keyField = field
			}
			maskedKey, err := redact.Field(keyField, key, p.Redact)
			if err != nil {
				return nil, err
			}
			if maskedKey != key {
				change.protected = true // Never rename keys or create collisions.
			}
			if opaqueResultField(value, location, key) {
				if !p.AllowOpaque {
					return nil, errOpaquePII
				}
				continue
			}
			child := resultChild(value, location, key)
			childField := key
			if redact.FieldLabel(key) == "" && redact.FieldLabel(field) != "" {
				childField = field
			}
			updated, err := p.redactValue(ctx, item, child, childField, change)
			if err != nil {
				return nil, err
			}
			if (location == resultProtocol || (location == resultBlock || location == resultResource) &&
				(key == "type" || key == "uri" || key == "mimeType")) && !sameScalar(item, updated) {
				change.protected = true
			}
			value[key] = updated
		}
		return value, nil
	case []any:
		child := resultOther
		switch location {
		case resultContent:
			child = resultBlock
		case resultProtocol:
			child = resultProtocol
		}
		for i, item := range value {
			updated, err := p.redactValue(ctx, item, child, field, change)
			if err != nil {
				return nil, err
			}
			if location == resultProtocol && !sameScalar(item, updated) {
				change.protected = true
			}
			value[i] = updated
		}
		return value, nil
	case string:
		masked, err := redact.Field(field, value, p.Redact)
		if err != nil {
			return nil, err
		}
		change.changed = change.changed || masked != value
		return masked, nil
	case json.Number:
		text := piiNumberText(value.String())
		masked, err := redact.Field(field, text, p.Redact)
		if err != nil {
			return nil, err
		}
		if masked != text {
			change.changed, change.numeric = true, true
			return masked, nil
		}
	}
	return value, nil
}

// Inspect equivalent integer spellings (decimal/exponent) without float64 or
// unbounded big-number allocation. Unchanged numbers retain their original JSON.
func piiNumberText(raw string) string {
	if len(raw) > 128 || strings.HasPrefix(raw, "-") {
		return raw
	}
	mantissa, exponent := raw, 0
	if at := strings.IndexAny(raw, "eE"); at >= 0 {
		mantissa = raw[:at]
		var err error
		exponent, err = strconv.Atoi(raw[at+1:])
		if err != nil || exponent < -64 || exponent > 64 {
			return raw
		}
	}
	fraction := 0
	if at := strings.IndexByte(mantissa, '.'); at >= 0 {
		fraction = len(mantissa) - at - 1
		mantissa = mantissa[:at] + mantissa[at+1:]
	}
	shift := exponent - fraction
	if shift < 0 {
		cut := len(mantissa) + shift
		if cut <= 0 || strings.Trim(mantissa[cut:], "0") != "" {
			return raw
		}
		mantissa = mantissa[:cut]
	} else {
		if len(mantissa)+shift > 34 {
			return raw
		}
		mantissa += strings.Repeat("0", shift)
	}
	integer := strings.TrimLeft(mantissa, "0")
	if integer == "" {
		return "0"
	}
	return integer
}

func resultChild(object map[string]any, location resultLocation, key string) resultLocation {
	switch {
	case location == resultRoot && key == "content":
		return resultContent
	case location == resultBlock && object["type"] == "resource" && key == "resource":
		return resultResource
	case location == resultProtocol || (location == resultBlock || location == resultResource) && key == "annotations":
		return resultProtocol
	default:
		return resultOther
	}
}

func sameScalar(a, b any) bool {
	switch a := a.(type) {
	case string:
		s, ok := b.(string)
		return ok && a == s
	case json.Number:
		n, ok := b.(json.Number)
		return ok && a == n
	}
	return true // Containers are covered by the recursive flags.
}

func privacyOnly(v scan.Verdict) bool {
	if len(v.Findings) == 0 {
		return false
	}
	for _, f := range v.Findings {
		if f.Category != scan.CatPII && f.Category != scan.CatSecret {
			return false
		}
	}
	return true
}

func hiddenPrivacy(v scan.Verdict) bool {
	for _, f := range v.Findings {
		if (f.Category == scan.CatPII || f.Category == scan.CatSecret) && len(f.Chain) > 0 {
			return true
		}
	}
	return false
}

func maskedResultText(result any) (string, error) {
	raw, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("cannot render masked result")
	}
	return "[sAIfety] Sensitive values removed; structured result provided as text.\n" + string(raw), nil
}
