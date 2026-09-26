// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// DecodeStrict is how a transport decodes a typed-authoring request body: the
// ONE parser the orchestrator's typed route and the customer portal share
// (#4371). It decodes exactly one JSON value into into and refuses:
//
//   - a member the target does not declare, at any depth: a field this build
//     ignores is a field its author believes is in force (see Parse);
//   - a second value after the first;
//   - `binds_on: null` anywhere in the body.
//
// The last is checked on the raw bytes because the decoder cannot see it:
// encoding/json sets a pointer to nil on JSON null without consulting the
// type, so `"binds_on": null` would decode as ABSENT - every scope - for a
// policy whose author wrote something else. Absent is the only way to say
// "every scope", and `[]` is refused by the validator (CodeBindsOnEmpty).
//
// Numbers decode as they always did on both transports (no UseNumber), so no
// document's digest moves by being read through here.
func DecodeStrict(raw []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("the request body carries more than one JSON value")
	}
	var tree any
	if err := json.Unmarshal(raw, &tree); err != nil {
		return err
	}
	if path, found := nullBindsOn(tree, "$"); found {
		return fmt.Errorf("%s is null; leave binds_on out to bind the policy on every plane, or name the planes it binds on", path)
	}
	return nil
}

// nullBindsOn finds a binds_on member whose value is JSON null, returning its
// path.
func nullBindsOn(v any, path string) (string, bool) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if k == "binds_on" && child == nil {
				return path + ".binds_on", true
			}
			if p, ok := nullBindsOn(child, path+"."+k); ok {
				return p, true
			}
		}
	case []any:
		for i, child := range t {
			if p, ok := nullBindsOn(child, fmt.Sprintf("%s[%d]", path, i)); ok {
				return p, true
			}
		}
	}
	return "", false
}
