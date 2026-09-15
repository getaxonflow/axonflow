// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"net/http"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// TestTheOverrideRoutesAreRegisteredAsTheyWere pins, from a walk of a real
// router, the (method, path, handler) set registerOverrideRoutes registers.
// Those statements moved out of Run unchanged; this states what they register
// independently of the source that registers it, so a later edit to the
// function cannot quietly change the family.
func TestTheOverrideRoutesAreRegisteredAsTheyWere(t *testing.T) {
	r := mux.NewRouter()
	registerOverrideRoutes(r)
	var got []string
	err := r.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		h := route.GetHandler()
		if h == nil {
			return nil
		}
		tpl, err := route.GetPathTemplate()
		if err != nil {
			return err
		}
		methods, err := route.GetMethods()
		if err != nil {
			return err
		}
		fn, ok := h.(http.HandlerFunc)
		if !ok {
			t.Errorf("%s is not registered through HandleFunc", tpl)
			return nil
		}
		name := runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name()
		name = name[strings.LastIndex(name, ".")+1:]
		for _, m := range methods {
			got = append(got, m+" "+tpl+" "+name)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	sort.Strings(got)
	want := []string{
		"DELETE /api/v1/overrides/{id} revokeOverrideHandler",
		"GET /api/v1/overrides listOverridesHandler",
		"GET /api/v1/overrides/{id} getOverrideHandler",
		"POST /api/v1/overrides createOverrideHandler",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("registered:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}
