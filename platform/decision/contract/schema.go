package contract

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// schemaFS carries the versioned JSON Schemas. They are embedded rather than
// read from disk so that a deployed binary validates against the schema it was
// built with, and so the schema cannot drift from the Go types without the
// contract tests noticing.
//
//go:embed schema/*.json
var schemaFS embed.FS

// SchemaFile is the name of the committed schema document for the current
// contract version.
const SchemaFile = "schema/contract-" + SchemaVersion + ".schema.json"

// SchemaID is the identifier the document declares.
const SchemaID = "https://schemas.getaxonflow.com/decision/contract-" + SchemaVersion + ".schema.json"

// Schema names one validatable shape inside the contract document.
type Schema string

const (
	SchemaRequest    Schema = "request"
	SchemaDecision   Schema = "decision"
	SchemaObligation Schema = "obligation"
	SchemaTrace      Schema = "trace"
	SchemaAttribute  Schema = "attribute"
	SchemaApproval   Schema = "approval_requirement"
	// SchemaApprovalClause is named separately because it is generated as a
	// type in every SDK; an anonymous inline shape would be regenerated under a
	// different name in each of the five.
	SchemaApprovalClause Schema = "approval_clause"
	SchemaIdentifier     Schema = "identifier"

	// The AuthZEN WIRE shapes. They are versioned by AuthZENProfileV1 rather
	// than by SchemaVersion: SchemaVersion versions the internal contract a
	// decision is computed against and is what rides in snapshot.schema_version,
	// whereas the profile constant is what a Policy Enforcement Point negotiates
	// to receive anything beyond the boolean. Adding these definitions changed no
	// existing shape, so the contract version is deliberately unchanged.
	SchemaAuthZENEnvelope        Schema = "authzen_envelope"
	SchemaAuthZENRequest         Schema = "authzen_request"
	SchemaAuthZENBulk            Schema = "authzen_bulk"
	SchemaAuthZENSubject         Schema = "authzen_subject"
	SchemaAuthZENAction          Schema = "authzen_action"
	SchemaAuthZENResource        Schema = "authzen_resource"
	SchemaAuthZENResponse        Schema = "authzen_response"
	SchemaAuthZENError           Schema = "authzen_error"
	SchemaAuthZENResponseContext Schema = "authzen_response_context"
)

// AllSchemas returns every validatable shape, so a test can prove each one
// compiles rather than only the ones a caller happens to use.
func AllSchemas() []Schema {
	return []Schema{
		SchemaRequest, SchemaDecision, SchemaObligation, SchemaTrace, SchemaAttribute, SchemaApproval,
		SchemaApprovalClause, SchemaIdentifier,
		SchemaAuthZENEnvelope, SchemaAuthZENRequest, SchemaAuthZENBulk,
		SchemaAuthZENSubject, SchemaAuthZENAction, SchemaAuthZENResource,
		SchemaAuthZENResponse, SchemaAuthZENResponseContext, SchemaAuthZENError,
	}
}

// SchemaDocument returns the raw schema document.
func SchemaDocument() ([]byte, error) { return schemaFS.ReadFile(SchemaFile) }

var (
	compileOnce sync.Once
	compiled    map[Schema]*jsonschema.Schema
	compileErr  error
)

func compileSchemas() (map[Schema]*jsonschema.Schema, error) {
	compileOnce.Do(func() {
		raw, err := SchemaDocument()
		if err != nil {
			compileErr = fmt.Errorf("contract: reading %s: %w", SchemaFile, err)
			return
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			compileErr = fmt.Errorf("contract: parsing %s: %w", SchemaFile, err)
			return
		}
		c := jsonschema.NewCompiler()
		if err := c.AddResource(SchemaID, doc); err != nil {
			compileErr = fmt.Errorf("contract: adding %s: %w", SchemaID, err)
			return
		}
		out := map[Schema]*jsonschema.Schema{}
		for _, s := range AllSchemas() {
			sch, err := c.Compile(SchemaID + "#/$defs/" + string(s))
			if err != nil {
				compileErr = fmt.Errorf("contract: compiling schema %q: %w", s, err)
				return
			}
			out[s] = sch
		}
		compiled = out
	})
	return compiled, compileErr
}

// ValidateAgainstSchema checks a value against one of the versioned schemas.
//
// It marshals through CanonicalJSON so that what is validated is exactly what
// would be transmitted and hashed, rather than a second encoding of the same
// value. A structure that passes the Go validators but not the schema is a real
// contract defect: the schema is what a non-Go plane reads.
func ValidateAgainstSchema(s Schema, v any) error {
	schemas, err := compileSchemas()
	if err != nil {
		return err
	}
	sch, ok := schemas[s]
	if !ok {
		return fmt.Errorf("contract: %q is not a declared schema", s)
	}
	raw, err := CanonicalJSON(v)
	if err != nil {
		return fmt.Errorf("contract: encoding for schema %q: %w", s, err)
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return fmt.Errorf("contract: decoding for schema %q: %w", s, err)
	}
	if err := sch.Validate(decoded); err != nil {
		return fmt.Errorf("contract: value does not satisfy schema %q: %w", s, err)
	}
	return nil
}
