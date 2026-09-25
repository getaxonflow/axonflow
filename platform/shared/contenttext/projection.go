// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package contenttext presents structured content to a detector as the text it
// carries, unescaped.
//
// A detector matches text. Presenting structured content as JSON would hand it
// an ENCODING of that text - a newline written as a backslash and an n, a quote
// behind a backslash - so a pattern the receiver sees would not be the pattern
// the detector sees: tenant_id, a real newline, then "!= 42" reaches the
// receiver, while the JSON holds tenant_id\n!= 42 and a `\s*` never crosses the
// escape (#4249 row 5666236540, the step planes' finding).
//
// So the content is a PROJECTION: every key and every string leaf, raw, in
// sorted-path order, one per line; a number or a boolean as its JSON text; a
// null or an empty string as nothing. Adjacent leaves are joined by a newline,
// so a pattern can match across a key and its value. That is a match on what
// the content means, and it can only withhold. The JSON form remains what the
// content is RECORDED as; it is never what a detector reads.
//
// It is the one statement of the rule for both binaries: the orchestrator's
// step planes (step_content_projection.go, #4360) and the agent's cowork ingest
// storage pass (#4259) read it.
package contenttext

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"axonflow/platform/decision/contract"
)

// ErrNotUTF8 refuses content that is not valid UTF-8: it cannot be presented
// as the text a receiver gets, so it is refused rather than replaced.
var ErrNotUTF8 = errors.New("a key or value is not valid UTF-8 and cannot be presented as content")

// Projection is the projection of parts, in order.
func Projection(parts ...any) (string, error) {
	var lines []string
	for _, part := range parts {
		if err := projectLeaves(part, &lines); err != nil {
			return "", err
		}
	}
	return strings.Join(lines, "\n"), nil
}

func projectLeaves(v any, lines *[]string) error {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		if !utf8.ValidString(x) {
			return ErrNotUTF8
		}
		if x != "" {
			*lines = append(*lines, x)
		}
		return nil
	case bool, float64, float32, int, int32, int64, uint, uint32, uint64, json.Number:
		b, err := json.Marshal(x)
		if err != nil {
			return fmt.Errorf("a value cannot be presented as content: %w", err)
		}
		*lines = append(*lines, string(b))
		return nil
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if err := projectLeaves(k, lines); err != nil {
				return err
			}
			if err := projectLeaves(x[k], lines); err != nil {
				return err
			}
		}
		return nil
	case []interface{}:
		for _, e := range x {
			if err := projectLeaves(e, lines); err != nil {
				return err
			}
		}
		return nil
	default:
		// Any other shape (a typed map or slice a caller built in process) is
		// read as the JSON value it encodes to. ExactJSON refuses invalid UTF-8
		// where encoding/json would replace it; its output is only decoded
		// here, never presented.
		b, err := contract.ExactJSON(x)
		if err != nil {
			if strings.Contains(err.Error(), "UTF-8") {
				return ErrNotUTF8
			}
			return fmt.Errorf("a value cannot be presented as content: %w", err)
		}
		var generic any
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.UseNumber()
		if err := dec.Decode(&generic); err != nil {
			return fmt.Errorf("a value cannot be presented as content: %w", err)
		}
		return projectLeaves(generic, lines)
	}
}
