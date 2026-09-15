// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// #3941: an operation must reference the error family ITS HANDLER EMITS.
//
// TestNoOperationMixesTheTwoErrorFamilies (openapi_error_family_test.go) is the
// guard this one completes. That guard asks whether an operation is internally
// consistent - does it name two families at once - and it CANNOT ask whether
// the one family it names is the right one. So the document could be, and was,
// perfectly self-consistent and wrong about thirty-two operations at once:
//
//   * the sixteen /api/v1/euaiact/* operations declared the flat
//     `{success, error}` envelope while writeError emitted `{"error": "msg"}` -
//     one key, no `success` - and `success` is `required` on ErrorResponse, so
//     a strict generated client failed to DESERIALISE every error from that
//     surface rather than silently reading a missing false;
//   * the four /api/v1/webhooks/* operations did the same through sendError;
//   * twelve workflow-control operations declared flat while
//     Handler.writeError emitted the triplet `{error, code, message}`.
//
// #3941's own DoD names the missing piece exactly: "it needs a handler-to-
// family map the guard does not have today". This is that map, and the two
// halves below are what stop it from being a list of assertions someone typed.
//
// # 1. THE FAMILY OF A WRITER IS MEASURED, NOT DECLARED
//
// Every rule DRIVES its writer: it builds the production handler, issues a real
// request through the production route registration, and decodes the bytes that
// come back. The `family` field is then asserted against what was decoded. A
// rule whose stated family is wrong fails on its own drive before it is ever
// compared against the document, so this file cannot certify a claim about a
// handler that the handler does not support.
//
// That is the DoD's "verified by calling it, not by reading the handler", and
// it is not a formality: the first version of this work assigned families by
// PATH PREFIX, and driving the operations against a live stack showed that
// three /api/v1/workflows/* operations are served by run.go rather than by
// workflow_control and emit the flat envelope correctly. A prefix map would
// have "fixed" those three by making the document wrong about them.
//
// # 2. THE POPULATION OF A RULE IS DERIVED FROM THE ROUTER, NOT LISTED
//
// A rule does not carry a list of the operations it covers. It mounts its
// package's real RegisterRoutes on a router and ASKS that router which
// documented paths it matches. So the /api/v1/workflows prefix splitting
// between two writers needs no special case, the spec's `{workflowId}` versus
// the mux's `{workflow_id}` needs no normalisation table, and a route that
// moves between packages re-attributes itself. A hand-written list is a second
// copy of the routing table, free to drift from the one that serves traffic -
// which is the defect class this whole issue is made of.

package orchestrator

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/orchestrator/webhooks"
	"axonflow/platform/orchestrator/workflow_control"

	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"
)

// handlerFamilyRule binds one error WRITER to the documented operations it
// serves. Both halves are derived rather than asserted - see the file comment.
type handlerFamilyRule struct {
	// writer names the production function under test, for the failure message.
	writer string

	// family is what `drive` is EXPECTED to emit. It is checked against the
	// decoded bytes before it is used for anything, so it is a claim this file
	// proves rather than one it assumes.
	family string

	// drive issues a real request through the real route registration and
	// returns the response. It must provoke an error the writer produces, and
	// it must not need a database: everything here refuses before it reaches
	// one (a method check, or a tenancy bind).
	drive func(t *testing.T) *httptest.ResponseRecorder

	// routes mounts the package's production route registration so the
	// population can be asked of the router rather than listed.
	routes func(t *testing.T) routeMatcher

	// minOps is this rule's own anti-vacuity floor. A rule that matches no
	// documented operation has stopped measuring its surface - because the
	// routes moved, because the paths were renamed, or because the matcher
	// broke - and would otherwise pass in silence, which is the exact failure
	// the DoD's "a census enumerating nothing must fail" names.
	minOps int
}

// routeMatcher answers whether a concrete request path is served by a rule's
// package. It is deliberately not "does this string have this prefix".
type routeMatcher func(method, concretePath string) bool

// muxMatcher adapts a gorilla/mux router, which is what the orchestrator and
// the workflow-control and webhooks packages register onto.
func muxMatcher(r *mux.Router) routeMatcher {
	return func(method, path string) bool {
		req := httptest.NewRequest(method, path, nil)
		var match mux.RouteMatch
		return r.Match(req, &match) && match.MatchErr == nil
	}
}

// handlerFamilyRules is the map. The base set is edition-neutral; euaiact is an
// enterprise-tagged package and contributes its rule from
// openapi_handler_family_enterprise_test.go, so this file reaches the community
// mirror and passes there rather than fatalling on a package the mirror does
// not contain.
//
// #3949 shipped a census that carried no build tag and was not named
// `*_enterprise_test.go`, so BOTH community-strip mechanisms missed it and it
// fatalled on a missing ee/ root - reddening the community board on every run
// against a tree where nothing was wrong. This file is arranged so that cannot
// happen: nothing here names an enterprise-only package.
var handlerFamilyRules = []handlerFamilyRule{
	{
		// FIRST, AND THE ORDER IS THE POINT. run.go registers these FIVE
		// /api/v1/workflows routes at :740-745, BEFORE
		// workflowControlHandler.RegisterRoutes at :982 - and gorilla matches
		// in registration order, so in production run.go wins them. They are
		// served by sendErrorResponse and emit the FLAT envelope, correctly.
		//
		// All five are listed below, including
		// `/api/v1/workflows/executions/tenant/{tenant_id}`, which the first
		// version of this rule omitted along with `/executions`. Neither is
		// documented with an error response today, so nothing was
		// mis-attributed - but an omitted route is a route no rule claims, and
		// the day one is documented it would be silently unchecked rather than
		// caught. R3 counted them; "three" was this comment's own miscount of
		// the block it cites.
		//
		// R3 found this: without this rule, the WCP rule's router claimed
		// `GET /api/v1/workflows/executions` (its `/api/v1/workflows/{id}`
		// pattern matches it) and would have demanded the document say
		// `triplet` for an operation that emits `flat`. It escaped only
		// because that operation declares no error response today, so the
		// first person to document one would have hit it - which is verbatim
		// the prefix-map failure this file's header claims to have designed
		// away, reintroduced one route over by asking the PACKAGE's router
		// instead of the PRODUCTION one.
		writer: "sendErrorResponse (run.go's workflow-execution routes)",
		family: familyFlat,
		drive: func(t *testing.T) *httptest.ResponseRecorder {
			t.Helper()
			rec := httptest.NewRecorder()
			sendErrorResponse(rec, "driven refusal", http.StatusBadRequest)
			return rec
		},
		routes: func(t *testing.T) routeMatcher {
			t.Helper()
			r := mux.NewRouter()
			r.HandleFunc("/api/v1/workflows/executions/tenant/{tenant_id}", tenantWorkflowExecutionsHandler).Methods("GET")
			r.HandleFunc("/api/v1/workflows/execute", executeWorkflowHandler).Methods("POST")
			r.HandleFunc("/api/v1/workflows/executions/{id}", getWorkflowExecutionHandler).Methods("GET")
			r.HandleFunc("/api/v1/workflows/executions", listWorkflowExecutionsHandler).Methods("GET")
			r.HandleFunc("/api/v1/workflows/executions/{id}/hitl-status", getHITLExecutionStatusHandler).Methods("GET")
			return muxMatcher(r)
		},
		minOps: 3,
	},
	{
		writer: "workflow_control.Handler.writeError (the WCP plane)",
		family: familyTriplet,
		drive: func(t *testing.T) *httptest.ResponseRecorder {
			t.Helper()
			// No headers at all -> requireScope refuses before the nil service
			// is ever touched, through the same writeError every other refusal
			// on this plane uses.
			r := mux.NewRouter()
			workflow_control.NewHandler(nil).RegisterEnterpriseRoutes(r)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/workflows/approvals/pending", nil))
			return rec
		},
		routes: func(t *testing.T) routeMatcher {
			t.Helper()
			r := mux.NewRouter()
			h := workflow_control.NewHandler(nil)
			// Every registration this package has, so the population is the
			// package's whole surface and not the subset one edition mounts.
			h.RegisterRoutes(r)
			h.RegisterEnterpriseRoutes(r)
			h.RegisterEvaluationRoutes(r)
			return muxMatcher(r)
		},
		minOps: 12,
	},
	{
		writer: "webhooks.sendError",
		family: familyFlat,
		drive: func(t *testing.T) *httptest.ResponseRecorder {
			t.Helper()
			r := mux.NewRouter()
			webhooks.NewHandler(nil).RegisterRoutes(r)
			rec := httptest.NewRecorder()
			// No tenancy headers -> requireScope -> sendError, before the nil
			// service is reached.
			r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/anything", nil))
			return rec
		},
		routes: func(t *testing.T) routeMatcher {
			t.Helper()
			r := mux.NewRouter()
			webhooks.NewHandler(nil).RegisterRoutes(r)
			return muxMatcher(r)
		},
		minOps: 4,
	},
}

// TestEveryOperationReferencesTheFamilyItsHandlerEmits is the guard.
func TestEveryOperationReferencesTheFamilyItsHandlerEmits(t *testing.T) {
	doc := loadOrchestratorSpecForFamilies(t)

	rules := handlerFamilyRules
	if len(rules) < 2 {
		t.Fatalf("only %d handler-family rule(s) registered; this guard measures nothing", len(rules))
	}

	// THE ALLOWANCE LIST, AND ITS RATCHET. Every other suppression list over
	// this surface fails when a row matches nothing (#3949 added that to both
	// of its allowance lists after one survived its own stated cause being
	// replaced). This one was written without it and is the same hazard: a row
	// whose operation is renamed, whose status is corrected, or whose second
	// writer is removed becomes a false statement about the code that nothing
	// reports.
	allowed := map[string]bool{}
	reasonOf := map[string]string{}
	for _, a := range familyMismatchAllowances() {
		allowed[a.key()] = true
		reasonOf[a.key()] = a.reason
	}
	matchedAllowance := map[string]bool{}

	var findings []string
	var bodyless []string
	totalCovered := 0
	// FIRST RULE WINS.
	//
	// gorilla resolves a request to the FIRST route that matches, so two rules
	// whose routers both match a path are not both right - the earlier one is.
	// Attributing an operation to every matching rule would demand the document
	// name two families for one operation, which is the defect this guard
	// reports. R3 measured ZERO overlap on today's document across every
	// path x verb and all four rules, so this changes nothing now and is what
	// stops the next documented operation from being claimed twice.
	//
	// THE SLICE ORDER IS NOT PRODUCTION REGISTRATION ORDER, and an earlier
	// version of this comment claimed it was. euaiact registers at run.go:862,
	// BEFORE workflow_control (:982) and webhooks (:1016), but its rule is
	// appended by an init() in the enterprise-tagged file and therefore lands
	// LAST. That is inert precisely because the overlap is zero - the three
	// prefixes are disjoint and none of the registrations uses PathPrefix - and
	// it is stated rather than fixed because making the order faithful would
	// mean the community and enterprise builds carrying different slice
	// orders, which is a worse thing to reason about than a measured zero.
	// If a future rule DOES overlap, order it explicitly rather than trusting
	// this.
	claimedBy := map[string]string{}
	// A drive that fails leaves its rule UNMEASURED, which is not the same as
	// its allowances being stale - see the ratchet below.
	allRulesMeasured := true

	for _, rule := range rules {
		// ---- half one: what does the writer ACTUALLY emit? --------------
		rec := rule.drive(t)
		body := rec.Body.Bytes()
		if len(body) == 0 {
			t.Errorf("%s: the drive produced an EMPTY body (status %d), so this rule proved nothing about "+
				"the writer and every operation it covers below is unverified. A drive that stops "+
				"provoking its error is indistinguishable from a writer that emits nothing.",
				rule.writer, rec.Code)
			allRulesMeasured = false
			continue
		}
		if rec.Code < 400 {
			t.Errorf("%s: the drive returned %d, which is not a refusal, so it did not reach the error "+
				"writer at all. Body: %.200q", rule.writer, rec.Code, string(body))
			allRulesMeasured = false
			continue
		}
		got, err := familyOfWireBody(body)
		if err != nil {
			t.Errorf("%s: %v", rule.writer, err)
			allRulesMeasured = false
			continue
		}
		if got != rule.family {
			t.Errorf("%s: this rule claims it emits the %s family and the bytes it wrote are %s.\n"+
				"    status %d, body %.200q\n"+
				"    The rule is what is wrong here, not the document - fix the rule, then look at what "+
				"the document says about the operations it covers.",
				rule.writer, rule.family, got, rec.Code, string(body))
			allRulesMeasured = false
			continue
		}

		// ---- half two: does the document agree, per operation? ----------
		matches := rule.routes(t)
		covered := 0
		for _, op := range doc.operations() {
			if !matches(op.method, concreteProbePath(op.path)) {
				continue
			}
			opKey := op.method + " " + op.path
			if owner, taken := claimedBy[opKey]; taken {
				// An earlier rule already owns it, so in production that
				// writer serves it and this one does not.
				_ = owner
				continue
			}
			claimedBy[opKey] = rule.writer
			covered++
			for _, status := range sortedStatuses(op.errorResponses) {
				fam, _, ok := classifyErrorFamily(op.errorResponses[status],
					doc.responses, doc.schemas, 0)
				if !ok {
					// A RESPONSE WITH NO BODY IS THIS GUARD'S BUSINESS, and
					// saying it was not was a hole R3 walked through.
					//
					// The other guard only reports an operation naming TWO
					// families, so one family plus a bodyless response passed
					// both. Five documented error responses on this very
					// population were in that state, every one of them served
					// by a handler that writes a JSON envelope: a client
					// generated from the document got `void` where the server
					// sends an error body. That is the same "cannot
					// deserialise the error" defect #3941 is about, inside the
					// guard's own coverage, passing.
					//
					// It is reported separately from a family MISMATCH because
					// the remedy differs - declare the body, rather than
					// repoint it - and because conflating them would make one
					// message answer two questions.
					if !errorResponseDeclaresABody(op.errorResponses[status]) {
						bodyless = append(bodyless, fmt.Sprintf(
							"%s %s  %s: no response body declared, but %s writes one",
							op.method, op.path, status, rule.writer))
					}
					continue
				}
				if fam == rule.family {
					continue
				}
				if key := op.method + " " + op.path + " " + status; allowed[key] {
					matchedAllowance[key] = true
					continue
				}
				findings = append(findings, fmt.Sprintf(
					"%s %s  %s: document says %s, %s emits %s",
					op.method, op.path, status, fam, rule.writer, rule.family))
			}
		}
		if covered < rule.minOps {
			t.Errorf("%s: matched only %d documented operation(s), below its floor of %d. This rule has "+
				"stopped seeing its own surface - the routes moved, the documented paths were renamed, "+
				"or the matcher broke - and the mismatches it exists to report would be an empty list "+
				"for the wrong reason.", rule.writer, covered, rule.minOps)
		}
		totalCovered += covered
	}

	// THE CENSUS-WIDE FLOOR, DERIVED rather than picked.
	//
	// It was `totalCovered < 16` against per-rule floors summing to exactly 16,
	// which R3 showed can never fire on its own: reaching it implies some rule
	// is already below its own floor and has already reported. A floor that
	// adds no detection is a floor that reads as coverage and is not.
	//
	// Summing the rules' floors and demanding the total EXCEED it does add
	// one: it catches every rule sitting exactly on its own floor at once,
	// which is what a document that lost operations across the board looks
	// like, and no individual floor reports that.
	floorSum := 0
	for _, rule := range rules {
		floorSum += rule.minOps
	}
	if totalCovered <= floorSum {
		t.Errorf("the census matched %d documented operations against a summed floor of %d across %d "+
			"rules. Every rule is at or below its own floor simultaneously, which is what a document "+
			"that lost operations across the board looks like.", totalCovered, floorSum, len(rules))
	}

	// THE RATCHET, AND THE CONDITION ON IT.
	//
	// `matchedAllowance` is only populated inside the rule loop, so any rule
	// that failed its drive and `continue`d leaves its allowances unmatched -
	// and reporting them as stale would prescribe DELETING a correct
	// suppression for a case the guard could not classify. R3 drove exactly
	// that: breaking one rule's drive produced two "the row's stated cause is
	// gone" errors against two rows whose cause was intact.
	for key := range allowed {
		if !allRulesMeasured {
			break
		}
		if !matchedAllowance[key] {
			t.Errorf("familyMismatchAllowances has a row for %q and no documented response mismatches "+
				"there any more. The row's stated cause is gone — delete it, or write a new row for "+
				"whatever that operation does now. A suppression that outlives its reason is a false "+
				"statement about the code.\n    Its stated reason was: %s", key, reasonOf[key])
		}
	}

	if len(bodyless) > 0 {
		sort.Strings(bodyless)
		t.Errorf("%d documented error response(s) declare NO body on an operation whose handler writes "+
			"one, so a client generated from this document has no type for them (#3941):\n    %s\n\n"+
			"Declare the envelope the handler emits. The reusable responses are BadRequest/NotFound/... "+
			"(flat), Coded* (nested) and Triplet* (`{error, code, message}`).",
			len(bodyless), strings.Join(bodyless, "\n    "))
	}

	if len(findings) > 0 {
		sort.Strings(findings)
		t.Errorf("%d documented response(s) reference an error family their handler does not emit, so a "+
			"client generated from this document cannot deserialise them (#3941):\n    %s\n\n"+
			"Fix the DOCUMENT where the handler's shape is the contract, or fix the HANDLER where the "+
			"document's shape is - and prefer the handler only when the move is ADDITIVE. Adding "+
			"`success` to `{error}` breaks no reader; retyping `error` from a string to an object "+
			"breaks every shipped SDK.",
			len(findings), strings.Join(findings, "\n    "))
	}
}

// familyMismatchAllowances carries the operations whose document deliberately
// names a family the rule's writer does not emit, because a DIFFERENT writer
// produces that status on that operation.
//
// It is a function returning rows rather than a bare predicate so each row can
// state its reason at its site AND so the set can be RATCHETED - a row matching
// nothing fails, which is what every other suppression list over this surface
// already does.
//
// There are two, and both name the idempotency-mismatch writer that
// TestNoOperationMixesTheTwoErrorFamilies already holds an allowance for.
func familyMismatchAllowances() []familyMismatchAllowance {
	const idempotency = "the 409 comes from writeIdempotencyKeyMismatch, a SEPARATE writer emitting the " +
		"nested `{error:{code,message,details}}` envelope with a details object no other body on this " +
		"surface carries — not from Handler.writeError, which emits the triplet. So this operation " +
		"genuinely answers in two shapes and the document describes that accurately. " +
		"TestNoOperationMixesTheTwoErrorFamilies holds the matching allowance for the same pair."
	return []familyMismatchAllowance{
		{"POST", "/api/v1/workflows/{workflow_id}/steps/{step_id}/gate", "409", idempotency},
		{"POST", "/api/v1/workflows/{workflow_id}/steps/{step_id}/complete", "409", idempotency},
	}
}

// familyMismatchAllowance is one documented response that legitimately names a
// family the rule's writer does not emit, because a DIFFERENT writer produces
// that status on that operation.
type familyMismatchAllowance struct {
	method, path, status, reason string
}

func (a familyMismatchAllowance) key() string {
	return a.method + " " + a.path + " " + a.status
}

// errorResponseDeclaresABody reports whether a response node describes a body
// at all, following one `$ref` into components/responses.
//
// It is deliberately coarser than classifyErrorFamily: a response with a
// `content` block of ANY media type has a declared body, even one this
// classifier has no family for. The question here is "does the document tell a
// client to expect bytes", not "which family are they".
func errorResponseDeclaresABody(node any) bool {
	m, ok := node.(map[string]any)
	if !ok {
		return false
	}
	if ref, isStr := m["$ref"].(string); isStr {
		// A $ref to a reusable response is a declared body by construction -
		// every entry in components.responses in this document carries one.
		return strings.HasPrefix(ref, "#/components/responses/")
	}
	content, hasContent := m["content"].(map[string]any)
	return hasContent && len(content) > 0
}

// --- spec reading -------------------------------------------------------

type familySpecOperation struct {
	method         string
	path           string
	errorResponses map[string]any
}

type familySpecDoc struct {
	paths     map[string]map[string]any
	responses map[string]any
	schemas   map[string]any
}

func (d familySpecDoc) operations() []familySpecOperation {
	var out []familySpecOperation
	for path, item := range d.paths {
		for verb, opAny := range item {
			op, isMap := opAny.(map[string]any)
			if !isMap {
				continue
			}
			responses, isMap := op["responses"].(map[string]any)
			if !isMap {
				continue
			}
			errs := map[string]any{}
			for status, r := range responses {
				if isErrorStatus(status) {
					errs[status] = r
				}
			}
			if len(errs) == 0 {
				continue
			}
			out = append(out, familySpecOperation{
				method:         strings.ToUpper(verb),
				path:           path,
				errorResponses: errs,
			})
		}
	}
	return out
}

func loadOrchestratorSpecForFamilies(t *testing.T) familySpecDoc {
	t.Helper()
	rel := filepath.Join("..", "..", "docs", "api", "orchestrator-api.yaml")
	blob, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	var doc struct {
		Paths      map[string]map[string]any `yaml:"paths"`
		Components struct {
			Responses map[string]any `yaml:"responses"`
			Schemas   map[string]any `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	if len(doc.Paths) < 120 {
		t.Fatalf("only %d paths parsed from orchestrator-api.yaml; the parse is reading nothing",
			len(doc.Paths))
	}
	return familySpecDoc{paths: doc.Paths, responses: doc.Components.Responses, schemas: doc.Components.Schemas}
}

var specPathTemplateVar = regexp.MustCompile(`\{[^}]*\}`)

// concreteProbePath turns an OpenAPI path template into a request path a
// router can match. The substituted segment must satisfy the tightest pattern
// any route puts on a variable - `{version:[0-9]+}` on the plan rollback route -
// so a digit is used rather than a word.
func concreteProbePath(template string) string {
	return specPathTemplateVar.ReplaceAllString(template, "1")
}

func sortedStatuses(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestTheWireClassifierReadsEveryEnvelopeTheHandlersEmit is familyOfWireBody's
// own control, and it exists for the reason the schema classifier's does: the
// live handlers are not a control. If every rule above happened to emit the
// flat envelope, a wire classifier that only understood flat would pass every
// assertion in this file while being blind to the two shapes the issue is about.
//
// The FLAT case deliberately uses the orchestrator's real five-extra-member
// envelope rather than a bare `{success, error}`, because that is the body
// sendErrorResponse actually writes and a rule keyed on "exactly two members"
// would reject it.
func TestTheWireClassifierReadsEveryEnvelopeTheHandlersEmit(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"flat, as sendErrorResponse writes it",
			`{"request_id":"","success":false,"error":"nope","redacted":false,"policy_info":null,` +
				`"provider_info":null,"processing_time":""}`, familyFlat},
		{"flat, minimal", `{"success":false,"error":"nope"}`, familyFlat},
		{"coded", `{"error":{"code":"X","message":"m"}}`, familyCoded},
		{"triplet", `{"error":"not_found","code":"NOT_FOUND","message":"m"}`, familyTriplet},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := familyOfWireBody([]byte(tc.body))
			if err != nil {
				t.Fatalf("not classified: %v", err)
			}
			if got != tc.want {
				t.Errorf("family = %q, want %q", got, tc.want)
			}
		})
	}

	// WHERE THE TWO ADAPTERS DIVERGE, PINNED RATHER THAN LEFT TO BE FOUND.
	//
	// `familyOfShape` is one rule, but the step that reads the `error` member's
	// own property set is supplied by the caller - and a SCHEMA and a VALUE are
	// not the same object, so the two adapters cannot be made identical. The
	// schema adapter asks the DECLARED type ("does this node have
	// `properties`?"); the wire adapter asks the RUNTIME type ("is this value a
	// JSON object?"). R3 found three inputs where they answer differently.
	//
	// They are asserted here so the boundary is a known property with a
	// direction, rather than an accident nobody has measured. In every case the
	// SCHEMA side is the more conservative one - it declines to classify where
	// the wire side commits - which is the safe direction: an unclassified
	// documented response is skipped, while a wrongly-classified one would be
	// reported as a mismatch that is not there.
	for _, tc := range []struct {
		name string
		body string
		want string
		why  string
	}{
		{
			name: "`error` is an object of anything, with code+message at the top level",
			body: `{"error":{"anything":1},"code":"C","message":"m"}`,
			want: familyTriplet,
			why:  "the child carries neither code nor message, so the top-level triple decides it",
		},
		{
			name: "`error` is null beside a top-level code+message",
			body: `{"error":null,"code":"C","message":"m"}`,
			want: familyTriplet,
			why: "a null `error` is not an object, so the coded arm cannot fire and the triple " +
				"decides it. The SCHEMA for the same operation may say coded; that divergence is " +
				"safe because a schema is a description of every response and a null is one value",
		},
		{
			name: "`error` is an object carrying code+message, nothing at the top level",
			body: `{"error":{"code":"C","message":"m"}}`,
			want: familyCoded,
			why: "the wire commits here where a schema written as `additionalProperties: true` with " +
				"no `properties` would NOT - the schema side declines, which is the conservative " +
				"direction",
		},
	} {
		t.Run("boundary: "+tc.name, func(t *testing.T) {
			got, err := familyOfWireBody([]byte(tc.body))
			if err != nil {
				t.Fatalf("not classified (%s): %v", tc.why, err)
			}
			if got != tc.want {
				t.Errorf("family = %q, want %q — %s", got, tc.want, tc.why)
			}
		})
	}

	// THE OTHER HALF. A classifier that named a family for everything would
	// satisfy all four cases above and protect nothing. The BARE case is the
	// one that matters most: `{"error": "msg"}` is precisely what euaiact and
	// webhooks emitted before this change, and it must be REFUSED rather than
	// guessed at, or the guard would have silently accepted the defect it
	// exists to catch.
	for _, tc := range []struct{ name, body string }{
		{"the BARE envelope this change removed", `{"error":"msg"}`},
		{"an object with neither member", `{"detail":"msg"}`},
		{"error present but nothing else identifying", `{"error":"msg","hint":"x"}`},
		{"a text/plain body", `404 page not found`},
		{"an empty body", ``},
	} {
		t.Run("refused: "+tc.name, func(t *testing.T) {
			if fam, err := familyOfWireBody([]byte(tc.body)); err == nil {
				t.Errorf("classified as %q; this classifier has no model for that shape and guessing "+
					"is a claim it cannot support", fam)
			}
		})
	}
}

// TestTheHandlerFamilyDriveRefusesAnUndrivenRule proves the first half of the
// guard can fail, using the guard's own machinery rather than a paraphrase of
// it: a rule whose stated family is wrong, and a rule whose drive provokes no
// error, must both be rejected.
//
// Without this, `drive` could silently stop reaching its writer - a route
// rename, a registration moving edition - and every rule would go on reporting
// that the document agrees with a handler nothing measured.
func TestTheHandlerFamilyDriveRefusesAnUndrivenRule(t *testing.T) {
	// A real rule, driven, with a DELIBERATELY WRONG stated family.
	honest := handlerFamilyRules[0]
	rec := honest.drive(t)
	got, err := familyOfWireBody(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("the real rule's drive did not produce a classifiable body, so this control cannot "+
			"distinguish a wrong claim from a broken drive: %v", err)
	}
	if got == familyCoded {
		t.Fatalf("this control assumes rule[0] does not emit the coded family; it now does, so the " +
			"mismatch below would not be a mismatch")
	}
	if got == honest.family {
		t.Logf("rule[0] drive confirmed: %s emits %s (status %d)", honest.writer, got, rec.Code)
	} else {
		t.Fatalf("rule[0] claims %s and emits %s", honest.family, got)
	}

	// And a body that reaches no writer at all must not classify.
	if _, err := familyOfWireBody(nil); err == nil {
		t.Error("an empty body classified as some family; a drive that stopped provoking its error " +
			"would then read as a passing rule")
	}
}
