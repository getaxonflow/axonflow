// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"reflect"
	"strings"
	"testing"

	"axonflow/platform/shared/anchoredenforcer"
)

// TestTheAgentCallShapesMirrorTheSharedEnforcer holds each of this package's
// request shapes to the shared enforcer's, field for field.
//
// The seams hand the enforcer an anchoredCall and read back an anchoredVerdict,
// and evaluate converts both to and from anchoredenforcer's Call and Verdict. A
// field added to the shared shape and not carried by the conversion would
// silently read as its zero value on every agent plane - an absent observation,
// no PEP profile, a request that is not empty - so the two sides must name the
// same fields. Names are compared case-insensitively, because the agent's are
// unexported spellings of the shared ones; the one deliberate rename, a
// subject's legacy principal, is stated.
func TestTheAgentCallShapesMirrorTheSharedEnforcer(t *testing.T) {
	for _, c := range []struct {
		agent, shared reflect.Type
		renamed       map[string]string
	}{
		{reflect.TypeOf(anchoredCall{}), reflect.TypeOf(anchoredenforcer.Call{}), nil},
		{reflect.TypeOf(anchoredVerdict{}), reflect.TypeOf(anchoredenforcer.Verdict{}), nil},
		{reflect.TypeOf(decisionSubject{}), reflect.TypeOf(anchoredenforcer.Subject{}), map[string]string{"legacy": "principal"}},
	} {
		agentFields, sharedFields := fieldNames(c.agent, c.renamed), fieldNames(c.shared, nil)
		if !reflect.DeepEqual(agentFields, sharedFields) {
			t.Errorf("%s carries %v and %s carries %v; evaluate converts between them, so a field on one side only is dropped on every agent plane",
				c.agent, agentFields, c.shared, sharedFields)
		}
		// ANTI-VACUITY: two empty shapes would agree.
		if len(sharedFields) == 0 {
			t.Errorf("%s has no fields, so this comparison proves nothing", c.shared)
		}
	}
}

func fieldNames(ty reflect.Type, renamed map[string]string) []string {
	out := make([]string, 0, ty.NumField())
	for i := 0; i < ty.NumField(); i++ {
		name := ty.Field(i).Name
		if to, ok := renamed[name]; ok {
			name = to
		}
		out = append(out, strings.ToLower(name))
	}
	return out
}
