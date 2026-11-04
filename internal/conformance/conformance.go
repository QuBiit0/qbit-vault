// Package conformance checks traffic against the contract's JSON schema
// (contracts/secrets-broker/v1/secrets-broker.v1.schema.json, TESTING.md §
// Contract conformance). A host adapter, and the broker itself, is
// conformant when every request it emits and every response it accepts
// validates as the $def of its op, and every refusal as `refusal`.
package conformance

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/google/jsonschema-go/jsonschema"
)

// Schema is the contract schema, resolvable per $def.
type Schema struct {
	doc      map[string]any
	resolved map[string]*jsonschema.Resolved
}

// Load reads the schema file.
func Load(path string) (*Schema, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	return &Schema{doc: doc, resolved: map[string]*jsonschema.Resolved{}}, nil
}

// Defs lists the schema's $defs.
func (s *Schema) Defs() []string {
	defs, _ := s.doc["$defs"].(map[string]any)
	out := make([]string, 0, len(defs))
	for k := range defs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// RefusalTypes is the refusal `type` enum of the schema.
func (s *Schema) RefusalTypes() []string {
	defs, _ := s.doc["$defs"].(map[string]any)
	r, _ := defs["refusal"].(map[string]any)
	p, _ := r["properties"].(map[string]any)
	in, _ := p["refusal"].(map[string]any)
	ip, _ := in["properties"].(map[string]any)
	ty, _ := ip["type"].(map[string]any)
	var out []string
	for _, v := range ty["enum"].([]any) {
		out = append(out, v.(string))
	}
	return out
}

// as resolves the schema with its root replaced by a $ref to def.
func (s *Schema) as(def string) (*jsonschema.Resolved, error) {
	if rs, ok := s.resolved[def]; ok {
		return rs, nil
	}
	root := map[string]any{}
	for k, v := range s.doc {
		if k != "oneOf" {
			root[k] = v
		}
	}
	root["$ref"] = "#/$defs/" + def
	b, err := json.Marshal(root)
	if err != nil {
		return nil, err
	}
	var sch jsonschema.Schema
	if err := json.Unmarshal(b, &sch); err != nil {
		return nil, err
	}
	rs, err := sch.Resolve(nil)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", def, err)
	}
	s.resolved[def] = rs
	return rs, nil
}

// Validate checks raw JSON against def.
func (s *Schema) Validate(def string, raw []byte) error {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("not JSON: %w", err)
	}
	rs, err := s.as(def)
	if err != nil {
		return err
	}
	return rs.Validate(v)
}

// ErrNotConformant wraps a message that matches neither allowed shape.
var ErrNotConformant = errors.New("conformance: message does not match the contract")

// Response validates a response to op: `<op>Res` when ok is true, else
// `refusal`. It returns which one matched.
func (s *Schema) Response(op string, raw []byte) (string, error) {
	var head struct {
		OK *bool `json:"ok"`
	}
	if err := json.Unmarshal(raw, &head); err != nil || head.OK == nil {
		return "", fmt.Errorf("%w: no ok field", ErrNotConformant)
	}
	def := "refusal"
	if *head.OK {
		def = op + "Res"
	}
	if err := s.Validate(def, raw); err != nil {
		return def, fmt.Errorf("%w: %s: %v", ErrNotConformant, def, err)
	}
	return def, nil
}

// Request validates a request of op as `<op>Req`.
func (s *Schema) Request(op string, raw []byte) error {
	if err := s.Validate(op+"Req", raw); err != nil {
		return fmt.Errorf("%w: %sReq: %v", ErrNotConformant, op, err)
	}
	return nil
}
