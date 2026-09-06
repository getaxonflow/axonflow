package authoring

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"axonflow/platform/decision/contract"
)

// schemaFS carries the versioned authoring schema. It is embedded rather than
// read from disk so a deployed binary validates against the schema it was built
// with, and so the schema cannot drift from the Go types without the tests in
// this package noticing.
//
//go:embed schema/*.json
var schemaFS embed.FS

// SchemaFile is the committed schema document for the current envelope version.
const SchemaFile = "schema/authoring-v1.schema.json"

// SchemaID is the identifier the document declares.
const SchemaID = "https://schemas.getaxonflow.com/decision/authoring-v1.schema.json"

// SchemaDocument returns the raw schema document.
//
// It is exported because the schema is the contract a NON-Go plane reads. The
// portal editor, an import tool and any future HTTP surface all need the same
// vocabulary, and serving it from the binary that enforces it is what stops
// three copies existing.
func SchemaDocument() ([]byte, error) { return schemaFS.ReadFile(SchemaFile) }

var (
	compileOnce sync.Once
	compiled    *jsonschema.Schema
	compileErr  error
)

func documentSchema() (*jsonschema.Schema, error) {
	compileOnce.Do(func() {
		raw, err := SchemaDocument()
		if err != nil {
			compileErr = fmt.Errorf("authoring: reading %s: %w", SchemaFile, err)
			return
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			compileErr = fmt.Errorf("authoring: parsing %s: %w", SchemaFile, err)
			return
		}
		c := jsonschema.NewCompiler()
		if err := c.AddResource(SchemaID, doc); err != nil {
			compileErr = fmt.Errorf("authoring: adding %s: %w", SchemaID, err)
			return
		}
		compiled, compileErr = c.Compile(SchemaID)
	})
	return compiled, compileErr
}

// ValidateAgainstSchema checks a document against the published JSON Schema.
//
// It validates the EXACT rendering, not a second encoding of the same value, so
// what is checked is the byte sequence that would be stored, signed and read
// back. A document that satisfies the Go validators and not the schema is a
// real contract defect: the schema is what every plane that is not this binary
// reads.
//
// It is a shape check and never a substitute for Validate. A schema can say
// that a condition names an operator; it cannot say that the operator compares
// caller-supplied input against a trusted term, which is the rule that matters.
func ValidateAgainstSchema(d *Document) error {
	raw, err := Render(d)
	if err != nil {
		return err
	}
	return validateBytesAgainstSchema(raw)
}

// ValidateRawAgainstSchema checks the document AS IT ARRIVED, before decoding.
//
// The difference from ValidateAgainstSchema is the whole point, and it is a
// difference the schema's `required` lists depend on. That function validates a
// RE-RENDERED document: the bytes go through Parse into a Go value and back
// out, so a member the author OMITTED is re-materialised at its Go zero value
// and satisfies `required` on the way past. Every `required` declaration in the
// published schema is therefore unenforced at the wire for any member whose
// zero value serialises - which is every scalar without omitempty.
//
// That is the authoring-plane form of the same defect #3630 closes in the
// decision contract: an absent member and a member carrying its zero value are
// different facts, and only one of them is what the author wrote.
func ValidateRawAgainstSchema(raw []byte) error {
	return validateBytesAgainstSchema(raw)
}

func validateBytesAgainstSchema(raw []byte) error {
	sch, err := documentSchema()
	if err != nil {
		return err
	}
	var decoded any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		return fmt.Errorf("authoring: decoding for schema validation: %w", err)
	}
	if err := sch.Validate(decoded); err != nil {
		return fmt.Errorf("authoring: document does not satisfy %s: %w", SchemaID, err)
	}
	return nil
}

// schemaEnum reads one enum out of the compiled schema document, so a test can
// compare it against the Go declarations rather than against a second copy of
// the list.
func schemaEnum(def string) ([]string, error) {
	raw, err := SchemaDocument()
	if err != nil {
		return nil, err
	}
	var doc struct {
		Defs map[string]struct {
			Enum []string `json:"enum"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	entry, ok := doc.Defs[def]
	if !ok {
		return nil, fmt.Errorf("authoring: the schema declares no $defs/%s", def)
	}
	if len(entry.Enum) == 0 {
		return nil, fmt.Errorf("authoring: $defs/%s declares no enum", def)
	}
	return entry.Enum, nil
}

// SchemaVersions reports the three versions a document is subject to, which are
// deliberately independent: the authoring envelope, the decision contract, and
// the compiler. Folding any pair together would make one of those events force
// a false claim about the other.
func SchemaVersions() map[string]string {
	return map[string]string{
		"envelope":  APIVersion,
		"contract":  contract.SchemaVersion,
		"schema_id": SchemaID,
	}
}
