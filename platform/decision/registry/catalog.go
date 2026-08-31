package registry

import (
	"fmt"
	"sort"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// CompatibilityException is one temporary, explicit, action-scoped licence for
// a permissive Unmatched posture.
//
// ADR-065 keeps the legacy compatibility posture available during migration
// only, and requires each exception to carry an owner, an action scope, an
// expiry date, a metric and a removal issue. Every one of those is a field
// here, and a missing one refuses the exception: an exception whose removal
// nobody tracks is a permanent product option that was described as temporary.
type CompatibilityException struct {
	// Action is the single action the exception scopes to.
	Action contract.ID `json:"action"`
	// Owner is the team accountable for removing it.
	Owner string `json:"owner"`
	// Metric names the observable that shows whether it is still firing.
	Metric string `json:"metric"`
	// RemovalIssue is the tracking issue for its removal.
	RemovalIssue string `json:"removal_issue"`
	// ExpiresAt is when it stops applying. It is compared against the
	// catalog's evaluation instant rather than a wall clock, so a registry
	// validated in a test and a registry validated in production answer the
	// same question the same way.
	ExpiresAt time.Time `json:"expires_at"`
}

// Validate checks one exception against an instant.
func (e CompatibilityException) Validate(now time.Time) Findings {
	subject := e.Action.String()
	var out Findings
	if e.Action.Kind != contract.KindAction {
		out = out.errorf(CodeIdentifierInvalid, subject,
			"a compatibility exception scopes to an action identifier, got kind %q", e.Action.Kind)
	}
	var missing []string
	if e.Owner == "" {
		missing = append(missing, "owner")
	}
	if e.Metric == "" {
		missing = append(missing, "metric")
	}
	if e.RemovalIssue == "" {
		missing = append(missing, "removal_issue")
	}
	if e.ExpiresAt.IsZero() {
		missing = append(missing, "expires_at")
	}
	if len(missing) > 0 {
		out = out.errorf(CodeCompatibilityIncomplete, subject,
			"the compatibility exception declares no %v; ADR-065 keeps this posture available during migration only, and an exception with no owner, metric, expiry or removal issue is a steady-state product option that was described as temporary",
			sortedStrings(missing))
	}
	if !e.ExpiresAt.IsZero() && !now.Before(e.ExpiresAt) {
		out = out.errorf(CodeCompatibilityExpired, subject,
			"the compatibility exception expired at %s and the catalog is being validated at %s",
			e.ExpiresAt.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	return out
}

// Catalog is the authoritative registry.
//
// Registration is CREATE-ONLY. Re-registering an identifier is refused rather
// than overwriting, because an overwrite is the bypass that would make the
// governed-tag change path advisory: a caller wanting to remove a governed tag
// could re-register the action without it, and the alarm nobody raised is the
// one that mattered. Changing an action's tags goes through ApplyTagChange;
// anything else needs a new registry version, which is the persistence PR.
//
// A Catalog is not safe for concurrent mutation. It is built once during
// startup or a test fixture and then read.
type Catalog struct {
	// Now is the instant compatibility expiry is judged against. A zero value
	// is refused by Validate rather than defaulted to time.Now: a registry
	// whose expiry check silently reads the wall clock cannot be replayed, and
	// ADR-065 requires a decision to be reproducible from pinned inputs.
	Now time.Time

	tags      map[string]TagRecord
	resources map[string]ResourceTypeRecord
	actions   map[string]ActionRecord
	tools     map[string]ToolRecord
	peps      map[string]PEPRecord
	realms    map[string]bool
	compat    map[string]CompatibilityException

	// aliases maps an alias to the canonical action it resolves to.
	aliases map[string]contract.ID
	// toolAliases maps an alias to the canonical tool it resolves to.
	toolAliases map[string]contract.ID

	events Events
}

// NewCatalog returns an empty catalog evaluated at an instant.
func NewCatalog(now time.Time) *Catalog {
	return &Catalog{
		Now:         now,
		tags:        map[string]TagRecord{},
		resources:   map[string]ResourceTypeRecord{},
		actions:     map[string]ActionRecord{},
		tools:       map[string]ToolRecord{},
		peps:        map[string]PEPRecord{},
		realms:      map[string]bool{},
		compat:      map[string]CompatibilityException{},
		aliases:     map[string]contract.ID{},
		toolAliases: map[string]contract.ID{},
		events:      nil,
	}
}

func (c *Catalog) record(code EventCode, sev Severity, subject, format string, args ...any) {
	c.events = append(c.events, Event{
		Code: code, Severity: sev, Subject: subject,
		Detail: fmt.Sprintf(format, args...), At: c.Now,
	})
}

// Events returns a copy of the event log.
func (c *Catalog) Events() Events { return append(Events(nil), c.events...) }

// RegisterRealm declares a trust realm identifier.
//
// The realm set is the catalog's half of the symmetric admission check: an
// unregistered action and an undeclared realm are both unknown surfaces, and
// admitting either lets a request reach evaluation with a fact no policy can be
// written about.
func (c *Catalog) RegisterRealm(qualifier string) error {
	if qualifier == "" {
		return Findings{}.errorf(CodeUnknownRealm, "(empty realm)", "a realm qualifier is not empty").Err()
	}
	if c.realms[qualifier] {
		return Findings{}.errorf(CodeAlreadyRegistered, qualifier, "realm %q is already declared", qualifier).Err()
	}
	c.realms[qualifier] = true
	return nil
}

// RegisterTag declares one entry in the tag vocabulary.
func (c *Catalog) RegisterTag(t TagRecord) error {
	f := t.Validate()
	if _, exists := c.tags[t.Tag]; exists {
		f = f.errorf(CodeAlreadyRegistered, t.Tag, "tag %q is already declared", t.Tag)
	}
	if err := f.Err(); err != nil {
		return err
	}
	c.tags[t.Tag] = t
	return nil
}

// RegisterResourceType declares one resource type.
func (c *Catalog) RegisterResourceType(r ResourceTypeRecord) error {
	f := r.Validate()
	if _, exists := c.resources[r.Type]; exists {
		f = f.errorf(CodeAlreadyRegistered, r.Type, "resource type %q is already declared", r.Type)
	}
	if err := f.Err(); err != nil {
		return err
	}
	c.resources[r.Type] = r.clone()
	return nil
}

// RegisterCompatibilityException declares one temporary exception.
//
// It is registered BEFORE the action that relies on it in the ordinary case,
// and the ordering does not matter: Validate re-checks every permissive posture
// against the exception set, so an exception that is removed later makes the
// catalog unprojectable rather than leaving a permissive posture unexplained.
func (c *Catalog) RegisterCompatibilityException(e CompatibilityException) error {
	f := e.Validate(c.Now)
	key := e.Action.String()
	if _, exists := c.compat[key]; exists {
		f = f.errorf(CodeAlreadyRegistered, key, "a compatibility exception for %q is already declared", key)
	}
	if err := f.Err(); err != nil {
		return err
	}
	c.compat[key] = e
	c.record(EventCompatibilityRegistered, SeverityAlarm, key,
		"temporary compatibility exception owned by %s, expiring %s, removal tracked in %s, observed by %s",
		e.Owner, e.ExpiresAt.Format(time.RFC3339), e.RemovalIssue, e.Metric)
	return nil
}

// RegisterAction declares one canonical action.
func (c *Catalog) RegisterAction(a ActionRecord) error {
	key := a.ID.String()
	f := a.Validate()
	if _, exists := c.actions[key]; exists {
		f = f.errorf(CodeAlreadyRegistered, key,
			"action %q is already registered; registration is create-only, and an action's governed tags change through ApplyTagChange so the change carries its approval evidence",
			key)
	}
	f = append(f, c.crossCheckAction(a)...)
	for _, alias := range sortedStrings(a.Aliases) {
		if existing, taken := c.aliases[alias]; taken && existing.String() != key {
			f = f.errorf(CodeAliasCollision, key,
				"alias %q already resolves to action %q; an alias that resolves to two actions makes the operation it names ungoverned",
				alias, existing)
		}
	}
	if err := f.Err(); err != nil {
		return err
	}
	stored := a.clone()
	c.actions[key] = stored
	for _, alias := range stored.Aliases {
		c.aliases[alias] = a.ID
	}
	c.record(EventActionRegistered, SeverityInfo, key,
		"registered with posture unmatched=%s on_error=%s and tags %v",
		a.Posture.Unmatched, a.Posture.OnError, stored.Tags)
	return nil
}

// RegisterTool declares one callable surface.
func (c *Catalog) RegisterTool(t ToolRecord) error {
	key := t.ID.String()
	f := t.Validate()
	if _, exists := c.tools[key]; exists {
		f = f.errorf(CodeAlreadyRegistered, key, "tool %q is already registered", key)
	}
	if _, ok := c.actions[t.Action.String()]; !ok {
		// This is where "a registered tool without a declared posture is
		// unregisterable" is enforced. Posture lives on the action, so a tool
		// binding to an action that is absent, or that was refused for an
		// undeclared posture, cannot be registered either.
		f = f.errorf(CodeUnknownAction, key,
			"tool %q resolves to action %q, which is not registered; a tool inherits its posture from its action, so a tool bound to an unregistered action has no declared failure semantics at all",
			key, t.Action)
	}
	for _, alias := range sortedStrings(t.Aliases) {
		if existing, taken := c.toolAliases[alias]; taken && existing.String() != key {
			f = f.errorf(CodeAliasCollision, key,
				"alias %q already resolves to tool %q", alias, existing)
		}
	}
	if err := f.Err(); err != nil {
		return err
	}
	c.tools[key] = t.clone()
	for _, alias := range sortedStrings(t.Aliases) {
		c.toolAliases[alias] = t.ID
	}
	c.record(EventToolRegistered, SeverityInfo, key,
		"registered against action %q at schema version %d through mapping %s",
		t.Action, t.SchemaVersion, t.Mapping)
	return nil
}

// RegisterPEP declares one enforcement point.
func (c *Catalog) RegisterPEP(p PEPRecord) error {
	f := p.Validate()
	if _, exists := c.peps[p.ID]; exists {
		f = f.errorf(CodeAlreadyRegistered, p.ID, "enforcement point %q is already registered", p.ID)
	}
	if p.Realm != "" && !c.realms[p.Realm] {
		f = f.errorf(CodeUnknownRealm, p.ID,
			"enforcement point %q authenticates as realm %q, which is not declared", p.ID, p.Realm)
	}
	if p.Realm == "" {
		f = f.errorf(CodeUnknownRealm, p.ID,
			"enforcement point %q declares no identity realm; a plane that authenticates as nothing cannot be scoped to by any policy",
			p.ID)
	}
	if err := f.Err(); err != nil {
		return err
	}
	stored := p.clone()
	stored.Capabilities = sortedCapabilities(p.Capabilities)
	c.peps[p.ID] = stored
	c.record(EventPEPRegistered, SeverityInfo, p.ID,
		"registered as a %s enforcement point in realm %q advertising %d capability(ies)",
		p.Edition, p.Realm, len(stored.Capabilities))
	return nil
}

// crossCheckAction applies the rules that need the rest of the catalog.
func (c *Catalog) crossCheckAction(a ActionRecord) Findings {
	key := a.ID.String()
	var out Findings
	for _, tag := range sortedStrings(a.Tags) {
		if _, ok := c.tags[tag]; !ok {
			out = out.errorf(CodeTagNotDeclared, key,
				"tag %q is not in the tag vocabulary; a policy selects actions by tag, so an undeclared tag is a policy channel with no owner and no review path",
				tag)
		}
	}
	if a.ResourceType != "" {
		if _, ok := c.resources[a.ResourceType]; !ok {
			out = out.errorf(CodeUnknownResourceType, key,
				"the action operates on resource type %q, which is not registered", a.ResourceType)
		}
	}
	out = append(out, c.validateActionPosture(a)...)
	return out
}

// validateActionPosture decides whether a permissive Unmatched axis is allowed
// on this action.
//
// It is the ONLY place that decision is made. Posture.Validate deliberately
// stops short of it because a posture does not know the action's risk classes
// or the exception set, and a rule split across two functions is a rule with
// two ways to be satisfied.
func (c *Catalog) validateActionPosture(a ActionRecord) Findings {
	key := a.ID.String()
	var out Findings
	if a.Posture.Unmatched != contract.AuthzPermit {
		return out
	}
	if why := a.Effects.CompatibilityIneligible(); len(why) > 0 {
		out = out.errorf(CodePostureCompatibilityIneligible, key,
			"a permissive unmatched posture is unavailable for this action because it is declared %v; the temporary compatibility posture is unavailable for privileged, irreversible and data-egress actions however it is configured",
			why)
		return out
	}
	e, ok := c.compat[key]
	if !ok {
		out = out.errorf(CodePostureCompatibilityRequired, key,
			"unmatched=%q is the source proposal's fail-open, which ADR-065 reverses; it is accepted only behind a registered compatibility exception naming an owner, a metric, an expiry and a removal issue",
			contract.AuthzPermit)
		return out
	}
	out = append(out, e.Validate(c.Now)...)
	return out
}

// ApplyTagChange applies one governed-vocabulary change and records its events.
//
// The change is refused, in full, if any part of it is refused. A partial tag
// change would leave the action carrying a vocabulary nobody approved.
func (c *Catalog) ApplyTagChange(ch TagChange) (Events, error) {
	key := ch.Action.String()
	var f Findings
	action, ok := c.actions[key]
	if !ok {
		f = f.errorf(CodeUnknownAction, key, "action %q is not registered", key)
		return nil, f.Err()
	}
	if ch.Actor == "" || ch.Reason == "" {
		f = f.errorf(CodeTagChangeUnapproved, key,
			"a tag change names its actor and its reason; a vocabulary edit with neither is indistinguishable from a mistake")
	}
	overlap := map[string]bool{}
	for _, t := range ch.Add {
		overlap[t] = true
	}
	for _, t := range ch.Remove {
		if overlap[t] {
			f = f.errorf(CodeTagChangeUnapproved, key,
				"tag %q is both added and removed by one change; that is a contradiction rather than a no-op, and resolving it either way would be this package guessing", t)
		}
	}
	for _, t := range append(sortedStrings(ch.Add), sortedStrings(ch.Remove)...) {
		if _, declared := c.tags[t]; !declared {
			f = f.errorf(CodeTagNotDeclared, key,
				"tag %q is not in the tag vocabulary; a change cannot invent a tag, because the vocabulary is what carries the tag's owner and governance class", t)
		}
	}
	if err := f.Err(); err != nil {
		return nil, err
	}

	delta := computeTagDelta(action.Tags, ch.Add, ch.Remove)
	// Governance is read from the vocabulary and applies to the tags that
	// ACTUALLY move. A change asking to remove a tag the action never carried
	// needs no approval, because it changes nothing that any policy reaches.
	governedMoving := false
	for _, t := range append(append([]string(nil), delta.added...), delta.removed...) {
		if c.tags[t].Governance.Governed() {
			governedMoving = true
		}
	}
	if governedMoving && ch.ApprovalRef == "" {
		return nil, Findings{}.errorf(CodeTagChangeUnapproved, key,
			"this change moves a governed tag and carries no approval reference; a governed tag is a policy channel, so changing one goes through the policy-change path rather than through a registry write").Err()
	}

	at := ch.At
	if at.IsZero() {
		at = c.Now
	}
	before := len(c.events)
	for _, t := range delta.added {
		if c.tags[t].Governance.Governed() {
			c.events = append(c.events, Event{
				Code: EventGovernedTagAdded, Severity: SeverityAlarm, Subject: key, At: at,
				Detail: fmt.Sprintf(
					"governed tag %q added by %s (approval %s): every permission selecting on %q now reaches this action, with no policy document edited. Owner: %s. Reason: %s",
					t, ch.Actor, ch.ApprovalRef, t, c.tags[t].Owner, ch.Reason),
			})
			continue
		}
		c.events = append(c.events, Event{
			Code: EventTagChanged, Severity: SeverityInfo, Subject: key, At: at,
			Detail: fmt.Sprintf("ungoverned tag %q added by %s: %s", t, ch.Actor, ch.Reason),
		})
	}
	for _, t := range delta.removed {
		if c.tags[t].Governance.Governed() {
			c.events = append(c.events, Event{
				Code: EventGovernedTagRemoved, Severity: SeverityAlarm, Subject: key, At: at,
				Detail: fmt.Sprintf(
					"governed tag %q removed by %s (approval %s): every constraint selecting on %q stops matching this action, silently and with nothing to see in any policy. Owner: %s. Reason: %s",
					t, ch.Actor, ch.ApprovalRef, t, c.tags[t].Owner, ch.Reason),
			})
			continue
		}
		c.events = append(c.events, Event{
			Code: EventTagChanged, Severity: SeverityInfo, Subject: key, At: at,
			Detail: fmt.Sprintf("ungoverned tag %q removed by %s: %s", t, ch.Actor, ch.Reason),
		})
	}
	action.Tags = applyTagDelta(action.Tags, delta)
	c.actions[key] = action
	return append(Events(nil), c.events[before:]...), nil
}

// Validate re-checks the whole catalog and returns every finding.
//
// Registration already refuses a bad record, so this exists for the rules that
// can be broken AFTER a successful registration: an exception whose expiry has
// since passed, a tool whose action was never registered, an action whose
// resource type is missing. Time alone can invalidate a catalog, which is why
// this is re-run rather than trusted from registration.
func (c *Catalog) Validate() Findings {
	var out Findings
	if c == nil {
		return Findings{}.errorf(CodeUnknownAction, "(nil catalog)", "the catalog is nil")
	}
	if c.Now.IsZero() {
		out = out.errorf(CodeCompatibilityIncomplete, "(catalog)",
			"the catalog declares no evaluation instant, so a compatibility expiry cannot be judged; a registry that silently read the wall clock could not be replayed")
	}
	if len(c.actions) == 0 {
		out = out.errorf(CodeUnknownAction, "(catalog)",
			"the catalog registers no actions; every request would be refused for naming an unregistered action, which is a deployment defect rather than a policy outcome")
	}
	for _, key := range sortedKeys(c.actions) {
		a := c.actions[key]
		out = append(out, a.Validate()...)
		out = append(out, c.crossCheckAction(a)...)
	}
	for _, key := range sortedKeys(c.tools) {
		t := c.tools[key]
		out = append(out, t.Validate()...)
		if _, ok := c.actions[t.Action.String()]; !ok {
			out = out.errorf(CodeUnknownAction, key,
				"tool %q resolves to action %q, which is not registered", key, t.Action)
		}
	}
	// Alias uniqueness is re-checked here rather than left to the registration
	// path. A rule enforced only at its call site is a rule the next writer
	// into these maps does not have, and an alias resolving to two things makes
	// the operation it names ungoverned rather than merely ambiguous.
	out = append(out, aliasCollisions("action", c.aliases, c.actions)...)
	out = append(out, aliasCollisions("tool", c.toolAliases, c.tools)...)
	for _, key := range sortedKeys(c.peps) {
		p := c.peps[key]
		out = append(out, p.Validate()...)
		if !c.realms[p.Realm] {
			out = out.errorf(CodeUnknownRealm, key,
				"enforcement point %q authenticates as realm %q, which is not declared", key, p.Realm)
		}
	}
	for _, key := range sortedKeys(c.resources) {
		out = append(out, c.resources[key].Validate()...)
	}
	for _, key := range sortedKeys(c.tags) {
		out = append(out, c.tags[key].Validate()...)
	}
	for _, key := range sortedKeys(c.compat) {
		out = append(out, c.compat[key].Validate(c.Now)...)
		if _, ok := c.actions[key]; !ok {
			out = out.errorf(CodeUnknownAction, key,
				"a compatibility exception scopes to action %q, which is not registered", key)
		}
	}
	return out.Sorted()
}

// PDPRegistry projects the catalog into the admission-time registry.
//
// It refuses to project a catalog with any blocking finding, and that refusal
// is the mechanism behind "missing either posture field means the action is
// unregisterable". An action can only be refused at registration if somebody
// called RegisterAction; a catalog assembled some other way, or one that became
// invalid because an exception expired, is stopped here instead. There is no
// path from an undeclared posture to a running evaluator.
func (c *Catalog) PDPRegistry() (*pdp.Registry, error) {
	if err := c.Validate().Err(); err != nil {
		return nil, fmt.Errorf("the catalog cannot be projected into an admission registry: %w", err)
	}
	actions := make(map[string]pdp.ActionEntry, len(c.actions))
	for key, a := range c.actions {
		actions[key] = a.entry()
	}
	realms := make(map[string]bool, len(c.realms))
	for q, ok := range c.realms {
		realms[q] = ok
	}
	return &pdp.Registry{Actions: actions, Realms: realms}, nil
}

// CompatibilityProfile projects the registered exceptions into the profile the
// merged engine applies, so the exceptions the registry governs and the ones an
// evaluation honours are one set rendered twice.
//
// Only actions whose posture actually declares unmatched=permit contribute. An
// exception registered against an action that fail-closes is inert by
// construction, and projecting it anyway would arm a fail-open that the action
// itself does not ask for.
func (c *Catalog) CompatibilityProfile() *pdp.CompatibilityProfile {
	var entries []pdp.CompatibilityEntry
	for _, key := range sortedKeys(c.compat) {
		e := c.compat[key]
		a, ok := c.actions[key]
		if !ok || a.Posture.Unmatched != contract.AuthzPermit {
			continue
		}
		entries = append(entries, pdp.CompatibilityEntry{
			Action: e.Action, Owner: e.Owner, ExpiresAt: e.ExpiresAt, RemovalIssue: e.RemovalIssue,
		})
	}
	if len(entries) == 0 {
		return nil
	}
	return &pdp.CompatibilityProfile{Entries: entries}
}

// aliasCollisions reports aliases resolving to something the catalog does not
// hold, which is the state a direct write into the maps can produce.
func aliasCollisions[V any](kind string, aliases map[string]contract.ID, records map[string]V) Findings {
	var out Findings
	for _, alias := range sortedKeys(aliases) {
		target := aliases[alias]
		if _, ok := records[target.String()]; !ok {
			out = out.errorf(CodeAliasCollision, target.String(),
				"%s alias %q resolves to %q, which the catalog does not hold", kind, alias, target)
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
