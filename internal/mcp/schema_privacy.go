package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/saifety-org/sAIfety/internal/scan/redact"
)

// Tool schema constraints are executable protocol, unlike data values. Remove
// sensitive default/examples annotations; never change enum/const/pattern or
// property names into a different set of permitted arguments.
func (p *Proxy) redactTool(ctx context.Context, tool Tool) (Tool, bool) {
	name, err := redact.Text(tool.Name, p.Redact)
	if err != nil || name != tool.Name {
		return Tool{}, false
	}
	description, err := redact.Text(tool.Description, p.Redact)
	if err != nil {
		return Tool{}, false
	}
	tool.Description = description
	schema, err := parseJSONObject(tool.InputSchema)
	if err != nil {
		return Tool{}, false
	}
	schemaChange := privacyChange{}
	if err := p.redactSchema(ctx, schema, "", &schemaChange); err != nil {
		return Tool{}, false
	}
	tool.InputSchema, err = json.Marshal(schema)
	if err != nil {
		return Tool{}, false
	}
	if len(tool.Annotations) > 0 {
		annotations, err := parseJSONObject(tool.Annotations)
		if err != nil {
			return Tool{}, false
		}
		change := privacyChange{}
		if _, err := p.redactValue(ctx, annotations, resultOther, "", &change); err != nil || change.protected {
			return Tool{}, false
		}
		tool.Annotations, err = json.Marshal(annotations)
		if err != nil {
			return Tool{}, false
		}
	}
	return tool, true
}

func (p *Proxy) redactSchema(ctx context.Context, value any, field string, change *privacyChange) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	switch value := value.(type) {
	case map[string]any:
		for key, item := range value {
			masked, err := redact.Text(key, p.Redact)
			if err != nil || masked != key {
				return fmt.Errorf("sensitive schema identifier")
			}
			switch key {
			case "default", "examples", "example":
				itemChange := privacyChange{}
				if _, err := p.redactValue(ctx, item, resultOther, field, &itemChange); err != nil {
					return err
				}
				if itemChange.changed || itemChange.protected {
					delete(value, key)
					change.changed = true
				}
			case "description", "title":
				if redact.PersonField(field) && !personMetadataValue(key, item) {
					itemChange := privacyChange{}
					updated, err := p.redactValue(ctx, item, resultOther, field, &itemChange)
					if err != nil {
						return err
					}
					if itemChange.protected || itemChange.numeric {
						delete(value, key) // An annotation may be dropped, never rename its keys.
					} else {
						value[key] = updated
					}
					change.changed = change.changed || itemChange.changed || itemChange.protected || itemChange.numeric
					continue
				}
				if text, ok := item.(string); ok {
					masked, err := redact.Text(text, p.Redact)
					if err != nil {
						return err
					}
					value[key] = masked
					change.changed = change.changed || masked != text
				} else if err := p.redactSchema(ctx, item, field, change); err != nil {
					return err
				}
			case "enum", "const":
				itemChange := privacyChange{}
				if _, err := p.redactValue(ctx, item, resultOther, field, &itemChange); err != nil {
					return err
				}
				if itemChange.changed || itemChange.protected {
					return fmt.Errorf("sensitive schema constraint")
				}
			case "properties", "$defs", "definitions", "patternProperties", "dependentSchemas":
				if properties, ok := item.(map[string]any); ok {
					for name, schema := range properties {
						masked, err := redact.Text(name, p.Redact)
						if err != nil || masked != name {
							return fmt.Errorf("sensitive schema identifier")
						}
						if err := p.redactSchema(ctx, schema, name, change); err != nil {
							return err
						}
					}
				} else if err := p.redactSchema(ctx, item, field, change); err != nil {
					return err
				}
			default:
				// Check all extensions and nested constraints, preserving their
				// meaning exactly or omitting the whole tool on sensitive data.
				if !schemaKeywords[key] {
					itemField := key
					if redact.PersonField(field) && !personMetadataValue(key, item) {
						itemField = field
					}
					itemChange := privacyChange{}
					if _, err := p.redactValue(ctx, item, resultOther, itemField, &itemChange); err != nil {
						return err
					}
					if itemChange.changed || itemChange.protected {
						return fmt.Errorf("sensitive schema extension")
					}
				}
				if err := p.redactSchema(ctx, item, field, change); err != nil {
					return err
				}
			}
		}
	case []any:
		for _, item := range value {
			if err := p.redactSchema(ctx, item, field, change); err != nil {
				return err
			}
		}
	case string:
		masked, err := redact.Text(value, p.Redact)
		if err != nil || masked != value {
			return fmt.Errorf("sensitive schema constraint")
		}
	case json.Number:
		masked, err := redact.Text(value.String(), p.Redact)
		if err != nil || masked != value.String() {
			return fmt.Errorf("sensitive schema constraint")
		}
	}
	return nil
}

var schemaKeywords = map[string]bool{
	"$schema": true, "$id": true, "id": true, "$ref": true, "$anchor": true,
	"$dynamicAnchor": true, "$dynamicRef": true, "$vocabulary": true, "$comment": true,
	"type": true, "allOf": true, "anyOf": true, "oneOf": true, "not": true,
	"if": true, "then": true, "else": true, "items": true, "prefixItems": true,
	"additionalItems": true, "contains": true, "minContains": true, "maxContains": true,
	"additionalProperties": true, "unevaluatedProperties": true, "unevaluatedItems": true,
	"propertyNames": true, "required": true, "dependentRequired": true, "dependencies": true,
	"minProperties": true, "maxProperties": true, "minItems": true, "maxItems": true,
	"uniqueItems": true, "minimum": true, "maximum": true, "exclusiveMinimum": true,
	"exclusiveMaximum": true, "multipleOf": true, "minLength": true, "maxLength": true,
	"pattern": true, "format": true, "contentEncoding": true, "contentMediaType": true,
	"contentSchema": true, "readOnly": true, "writeOnly": true, "deprecated": true,
}

var schemaAnnotationKeys = map[string]bool{"description": true, "title": true, "default": true, "examples": true, "example": true}

// A typed, keyword-only descriptor under a person field is schema, not a name.
// Unknown shapes keep the conservative data walk, including protected-key checks.
func personalFieldSchema(value map[string]any, field string) bool {
	if !redact.PersonField(field) {
		return false
	}
	typeOK := func(v any) bool {
		s, ok := v.(string)
		if !ok {
			return false
		}
		switch s {
		case "string", "number", "integer", "boolean", "object", "array", "null":
			return true
		}
		return false
	}
	valid := typeOK(value["type"])
	if types, ok := value["type"].([]any); ok && len(types) > 0 {
		valid = true
		for _, t := range types {
			valid = valid && typeOK(t)
		}
	}
	if !valid {
		return false
	}
	for key := range value {
		if schemaKeywords[key] || schemaAnnotationKeys[key] {
			continue
		}
		switch key {
		case "properties", "$defs", "definitions", "patternProperties", "dependentSchemas", "enum", "const":
			continue
		}
		if (personContainerKey(key) && !personValueCarrier(key)) || strings.HasPrefix(key, "x-") {
			continue
		}
		return false
	}
	return true
}
