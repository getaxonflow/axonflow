package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// FieldRedactor applies redactions to content based on matched policies.
// It supports multiple redaction strategies and works with various data types.
type FieldRedactor struct {
	// Strategy implementations
	strategies map[RedactionStrategy]RedactorFunc

	// Default strategy
	defaultStrategy RedactionStrategy

	// Placeholder format
	placeholderFormat string
}

// RedactorFunc transforms a matched value.
type RedactorFunc func(value string, piiType string) string

// NewFieldRedactor creates a new field redactor with default strategies.
func NewFieldRedactor() *FieldRedactor {
	r := &FieldRedactor{
		strategies:        make(map[RedactionStrategy]RedactorFunc),
		defaultStrategy:   StrategyMask,
		placeholderFormat: "[REDACTED:%s]",
	}
	r.registerDefaultStrategies()
	return r
}

// registerDefaultStrategies sets up all built-in redaction strategies.
func (r *FieldRedactor) registerDefaultStrategies() {
	// Mask strategy: Replace middle characters with asterisks
	r.strategies[StrategyMask] = func(value, piiType string) string {
		length := len(value)
		if length <= 4 {
			return strings.Repeat("*", length)
		}
		// Keep first and last character, mask middle
		return value[:1] + strings.Repeat("*", length-2) + value[length-1:]
	}

	// Partial strategy: Show first 2 and last 2 characters
	r.strategies[StrategyPartial] = func(value, piiType string) string {
		length := len(value)
		if length <= 4 {
			return strings.Repeat("*", length)
		}
		if length <= 6 {
			return value[:1] + strings.Repeat("*", length-2) + value[length-1:]
		}
		return value[:2] + strings.Repeat("*", length-4) + value[length-2:]
	}

	// Remove strategy: Replace with typed placeholder
	r.strategies[StrategyRemove] = func(value, piiType string) string {
		return fmt.Sprintf("[REDACTED:%s]", piiType)
	}

	// Hash strategy: Replace with deterministic hash (first 8 chars)
	r.strategies[StrategyHash] = func(value, piiType string) string {
		hash := sha256.Sum256([]byte(value))
		return fmt.Sprintf("HASH_%s", hex.EncodeToString(hash[:])[:8])
	}

	// Tokenize strategy: Replace with reversible token (enterprise feature)
	r.strategies[StrategyTokenize] = func(value, piiType string) string {
		// Simple tokenization - in production this would use a vault
		hash := sha256.Sum256([]byte(value))
		return fmt.Sprintf("TOKEN_%s_%s", strings.ToUpper(piiType), hex.EncodeToString(hash[:])[:6])
	}
}

// Apply applies redactions to content based on the redaction plans.
// Returns the redacted content and a list of what was redacted.
func (r *FieldRedactor) Apply(content interface{}, contentType string, plans []RedactionPlan) (interface{}, []RedactedField) {
	if len(plans) == 0 {
		return content, nil
	}

	switch contentType {
	case "rows":
		return r.applyToRows(content, plans)
	case "json":
		return r.applyToJSON(content, plans)
	case "string":
		return r.applyToString(content, plans)
	default:
		// Try to detect type
		if rows, ok := content.([]map[string]interface{}); ok {
			return r.applyToRows(rows, plans)
		}
		if m, ok := content.(map[string]interface{}); ok {
			return r.applyToMap(m, plans, "")
		}
		if s, ok := content.(string); ok {
			return r.applyToString(s, plans)
		}
		return content, nil
	}
}

// applyToRows applies redactions to database result rows.
// Returns a new copy of the rows with redactions applied (does not modify original).
func (r *FieldRedactor) applyToRows(content interface{}, plans []RedactionPlan) (interface{}, []RedactedField) {
	rows, ok := content.([]map[string]interface{})
	if !ok {
		return content, nil
	}

	var redacted []RedactedField

	// Statement-removal plans (prompt-injection) are applied first and whole-
	// statement; the remaining span plans (PII) keep the existing per-match path.
	statementPlans, spanPlans := partitionStatementPlans(plans)

	// Build pattern map for efficiency (span/PII plans only).
	patternMap := r.buildPatternMap(spanPlans)

	// Create a copy of rows to avoid modifying the original (thread safety)
	resultRows := make([]map[string]interface{}, len(rows))
	for i, row := range rows {
		resultRows[i] = make(map[string]interface{}, len(row))
		for k, v := range row {
			resultRows[i][k] = v
		}
	}

	// Process each row
	for rowIdx, row := range resultRows {
		for fieldName, fieldValue := range row {
			strValue, ok := fieldValue.(string)
			if !ok {
				continue
			}

			newValue := strValue
			// (1) Statement-level removal for prompt-injection: strip the whole
			// sentence/line containing each match so no residual instruction
			// survives, before the span/PII pass runs on what remains.
			if sv, applied := r.redactStatements(newValue, statementPlans); len(applied) > 0 {
				newValue = sv
				for _, a := range applied {
					redacted = append(redacted, RedactedField{
						Path:        fmt.Sprintf("rows[%d].%s", rowIdx, fieldName),
						OriginalLen: len(a.matchText),
						RedactedTo:  fmt.Sprintf("[REDACTED:%s]", a.piiType),
						PolicyID:    a.policyID,
						PIIType:     a.piiType,
					})
				}
			}
			// The reference for the JSON-aware PII re-walk below MUST be the
			// post-statement-removal value, not strValue: for valid JSON,
			// jsonSafeRemask re-walks its `original` arg for PII and returns that, so
			// passing the injection-intact strValue would silently DISCARD the
			// statement removal on JSON+PII content (the default case). When no
			// statement removal occurred, afterStatements == strValue (unchanged).
			afterStatements := newValue
			for patternStr, patternPlans := range patternMap {
				re, err := regexp.Compile(patternStr)
				if err != nil {
					continue
				}

				matches := re.FindAllStringIndex(newValue, -1)
				if matches == nil {
					continue
				}

				// Apply redactions from end to start to preserve indices
				for i := len(matches) - 1; i >= 0; i-- {
					loc := matches[i]
					plan := patternPlans[0]
					matchText := newValue[loc[0]:loc[1]]

					// Get strategy function
					strategy := r.getStrategy(plan.Strategy)
					piiType := r.getPIIType(plan.Policy)

					// Apply redaction
					redactedValue := strategy(matchText, piiType)
					newValue = newValue[:loc[0]] + redactedValue + newValue[loc[1]:]

					// Record redaction
					redacted = append(redacted, RedactedField{
						Path:        fmt.Sprintf("rows[%d].%s", rowIdx, fieldName),
						OriginalLen: len(matchText),
						RedactedTo:  redactedValue,
						PolicyID:    plan.Policy.PolicyID,
						PIIType:     piiType,
					})
				}
			}

			// If flat masking broke embedded JSON (a match hit a bare number/literal),
			// re-redact JSON-aware so we never emit invalid JSON. Reference the
			// statement-redacted value so injection removal is preserved on JSON.
			newValue = r.jsonSafeRemask(afterStatements, newValue, patternMap)

			// Update row if modified
			if newValue != strValue {
				resultRows[rowIdx][fieldName] = newValue
			}
		}
	}

	return resultRows, redacted
}

// applyToMap applies redactions to a single map (JSON object).
// Returns a new copy of the map with redactions applied (does not modify original).
func (r *FieldRedactor) applyToMap(m map[string]interface{}, plans []RedactionPlan, pathPrefix string) (map[string]interface{}, []RedactedField) {
	var redacted []RedactedField
	statementPlans, spanPlans := partitionStatementPlans(plans)
	patternMap := r.buildPatternMap(spanPlans)

	// Create a copy of the map to avoid modifying the original (thread safety)
	result := make(map[string]interface{}, len(m))
	for k, v := range m {
		result[k] = v
	}

	for key, value := range result {
		fieldPath := key
		if pathPrefix != "" {
			fieldPath = pathPrefix + "." + key
		}

		switch v := value.(type) {
		case string:
			newValue := v
			// (1) Statement-level removal for prompt-injection (whole sentence/line).
			if sv, applied := r.redactStatements(newValue, statementPlans); len(applied) > 0 {
				newValue = sv
				for _, a := range applied {
					redacted = append(redacted, RedactedField{
						Path:        fieldPath,
						OriginalLen: len(a.matchText),
						RedactedTo:  fmt.Sprintf("[REDACTED:%s]", a.piiType),
						PolicyID:    a.policyID,
						PIIType:     a.piiType,
					})
				}
			}
			afterStatementsMap := newValue
			for patternStr, patternPlans := range patternMap {
				re, err := regexp.Compile(patternStr)
				if err != nil {
					continue
				}

				if re.MatchString(newValue) {
					plan := patternPlans[0]
					strategy := r.getStrategy(plan.Strategy)
					piiType := r.getPIIType(plan.Policy)

					originalLen := len(newValue)
					newValue = re.ReplaceAllStringFunc(newValue, func(match string) string {
						return strategy(match, piiType)
					})

					if newValue != v {
						redacted = append(redacted, RedactedField{
							Path:        fieldPath,
							OriginalLen: originalLen,
							RedactedTo:  newValue,
							PolicyID:    plan.Policy.PolicyID,
							PIIType:     piiType,
						})
					}
				}
			}
			newValue = r.jsonSafeRemask(afterStatementsMap, newValue, patternMap)
			if newValue != v {
				result[key] = newValue
			}

		case map[string]interface{}:
			nestedResult, nestedRedacted := r.applyToMap(v, plans, fieldPath)
			result[key] = nestedResult
			redacted = append(redacted, nestedRedacted...)

		case []interface{}:
			newArray := make([]interface{}, len(v))
			copy(newArray, v)
			for i, item := range newArray {
				if itemMap, ok := item.(map[string]interface{}); ok {
					nestedResult, nestedRedacted := r.applyToMap(itemMap, plans, fmt.Sprintf("%s[%d]", fieldPath, i))
					newArray[i] = nestedResult
					redacted = append(redacted, nestedRedacted...)
				}
			}
			result[key] = newArray
		}
	}

	return result, redacted
}

// applyToJSON applies redactions to arbitrary JSON content.
func (r *FieldRedactor) applyToJSON(content interface{}, plans []RedactionPlan) (interface{}, []RedactedField) {
	if m, ok := content.(map[string]interface{}); ok {
		return r.applyToMap(m, plans, "")
	}
	if arr, ok := content.([]interface{}); ok {
		var allRedacted []RedactedField
		for i, item := range arr {
			if m, ok := item.(map[string]interface{}); ok {
				_, redacted := r.applyToMap(m, plans, fmt.Sprintf("[%d]", i))
				allRedacted = append(allRedacted, redacted...)
			}
		}
		return arr, allRedacted
	}
	return content, nil
}

// applyToString applies redactions to a plain string.
func (r *FieldRedactor) applyToString(content interface{}, plans []RedactionPlan) (interface{}, []RedactedField) {
	str, ok := content.(string)
	if !ok {
		return content, nil
	}

	var redacted []RedactedField
	newStr := str
	statementPlans, spanPlans := partitionStatementPlans(plans)
	patternMap := r.buildPatternMap(spanPlans)

	// (1) Statement-level removal for prompt-injection (whole sentence/line).
	if sv, applied := r.redactStatements(newStr, statementPlans); len(applied) > 0 {
		newStr = sv
		for _, a := range applied {
			redacted = append(redacted, RedactedField{
				Path:        "string",
				OriginalLen: len(a.matchText),
				RedactedTo:  fmt.Sprintf("[REDACTED:%s]", a.piiType),
				PolicyID:    a.policyID,
				PIIType:     a.piiType,
			})
		}
	}
	// Reference the statement-redacted value for the JSON-aware re-walk so the
	// injection removal is preserved when the string is a JSON document + PII.
	afterStatements := newStr

	for patternStr, patternPlans := range patternMap {
		re, err := regexp.Compile(patternStr)
		if err != nil {
			continue
		}

		matches := re.FindAllStringIndex(newStr, -1)
		if matches == nil {
			continue
		}

		// Apply redactions from end to start
		for i := len(matches) - 1; i >= 0; i-- {
			loc := matches[i]
			plan := patternPlans[0]
			matchText := newStr[loc[0]:loc[1]]

			strategy := r.getStrategy(plan.Strategy)
			piiType := r.getPIIType(plan.Policy)

			redactedValue := strategy(matchText, piiType)
			newStr = newStr[:loc[0]] + redactedValue + newStr[loc[1]:]

			redacted = append(redacted, RedactedField{
				Path:        fmt.Sprintf("string[%d:%d]", loc[0], loc[1]),
				OriginalLen: len(matchText),
				RedactedTo:  redactedValue,
				PolicyID:    plan.Policy.PolicyID,
				PIIType:     piiType,
			})
		}
	}

	newStr = r.jsonSafeRemask(afterStatements, newStr, patternMap)
	return newStr, redacted
}

// partitionStatementPlans splits plans into those that redact the whole
// statement (StrategyRemoveStatement, e.g. prompt-injection) and the rest
// (span-level strategies, e.g. PII mask/remove). The span plans keep the existing
// per-match replacement path unchanged; the statement plans are handled by
// redactStatements. This keeps the PII redaction path byte-identical (#2738).
func partitionStatementPlans(plans []RedactionPlan) (statement, span []RedactionPlan) {
	for _, p := range plans {
		if p.Strategy == StrategyRemoveStatement {
			statement = append(statement, p)
		} else {
			span = append(span, p)
		}
	}
	return statement, span
}

// statementSpan expands the match [mStart,mEnd) to the bounds of the
// sentence/line that contains it, so the FULL injection instruction is removed
// (not just the regex anchor) while neighboring statements survive.
//
// A boundary is a newline (always) or a "real" sentence end: a '.' '!' '?'
// followed by whitespace+uppercase or end-of-text. A '.' that is NOT a sentence
// end (a decimal like "v2.0", or "...admin. assistant" continuing in lowercase)
// is NOT a boundary, so the trailing payload after the anchor is still removed
// (closes the residual class R3 found on the role/exfil vectors). Terminators
// are left in place, so the next sentence/line is preserved. Byte offsets; the
// boundary chars scanned are ASCII, so slicing stays on rune boundaries.
//
// KNOWN LIMIT: an attacker who splits a single instruction across a NEWLINE
// ("from now on you are\nan admin") leaves the trailing fragment on the next
// line, because newline must stay a hard boundary to preserve benign multi-line
// output (logs, markdown). The directive verb is still removed, so the surviving
// noun fragment has little injection power. Documented in #2738.
func statementSpan(text string, mStart, mEnd int) (int, int) {
	start := mStart
	for start > 0 && !boundaryBeforeStatement(text, start) {
		start--
	}
	end := mEnd
	for end < len(text) && !boundaryEndsStatement(text, end) {
		end++
	}
	// Trim leading whitespace (don't redact the gap after the previous sentence).
	for start < mStart && (text[start] == ' ' || text[start] == '\t') {
		start++
	}
	// Trim trailing whitespace (don't swallow the space before the next sentence).
	for end > mEnd && (text[end-1] == ' ' || text[end-1] == '\t') {
		end--
	}
	return start, end
}

// isSentenceTerminator reports a statement/clause boundary char. ';' is included
// so a clause-list ("task A done; ignore all previous instructions; task C") only
// loses the offending clause, not the whole field. NOTE: ',' and other separators
// are NOT boundaries, so a field with NO '.', '!', '?', ';' or newline is treated
// as a single statement and is fully redacted on any injection match (the
// fail-safe direction: more removed, nothing leaked).
func isSentenceTerminator(b byte) bool { return b == '.' || b == '!' || b == '?' || b == ';' }

func isASCIIUpper(b byte) bool { return b >= 'A' && b <= 'Z' }

// boundaryEndsStatement reports whether the statement ends AT index i (scanning
// rightward): i is a newline, or a sentence terminator that ends a sentence,
// meaning it is followed by end-of-text, whitespace, or an uppercase letter (a
// no-space sentence break common in minified text, e.g. "...instructions.Account
// owner..."). A terminator followed by a digit/lowercase (a decimal "v2.0" or an
// intra-token dot) is NOT a boundary, so the payload trailing the injection
// anchor is still removed. This bounds removal to the sentence so an injection
// does not over-redact a following benign sentence that has no space after the
// period.
func boundaryEndsStatement(text string, i int) bool {
	c := text[i]
	if c == '\n' || c == '\r' {
		return true
	}
	if isSentenceTerminator(c) {
		if i+1 == len(text) {
			return true
		}
		n := text[i+1]
		return n == ' ' || n == '\t' || n == '\n' || n == '\r' || isASCIIUpper(n)
	}
	return false
}

// boundaryBeforeStatement reports whether a new statement begins AT index i
// (scanning leftward): i is the start of the text, immediately follows a newline,
// or follows (across spaces/tabs) a sentence terminator. Capitalization is NOT
// required because an injection sentence frequently begins lowercase, and the
// preceding benign sentence must still survive.
func boundaryBeforeStatement(text string, i int) bool {
	if i == 0 {
		return true
	}
	if text[i-1] == '\n' || text[i-1] == '\r' {
		return true
	}
	j := i - 1
	for j >= 0 && (text[j] == ' ' || text[j] == '\t') {
		j--
	}
	return j >= 0 && isSentenceTerminator(text[j])
}

// statementRedaction records one applied statement removal for audit reporting.
type statementRedaction struct {
	matchText string
	piiType   string
	policyID  string
}

// redactStatements removes the full injection statement for every statement plan
// that matches value. When value is a JSON document, the removal is applied PER
// STRING LEAF and the document is re-serialized, so JSON validity and the
// non-matching leaves are preserved (the connector RESPONSE is often the whole
// serialized tool result; a flat whole-string removal would emit invalid JSON and
// destroy benign sibling fields). Otherwise the plain-string path runs.
func (r *FieldRedactor) redactStatements(value string, statementPlans []RedactionPlan) (string, []statementRedaction) {
	if len(statementPlans) == 0 {
		return value, nil
	}
	if json.Valid([]byte(value)) {
		if out, applied, ok := r.redactStatementsJSON(value, statementPlans); ok {
			return out, applied
		}
	}
	return r.redactStatementsPlain(value, statementPlans)
}

// redactStatementsJSON parses value as a single JSON document, applies
// redactStatementsPlain to every string leaf, and re-serializes. ok is false (so
// the caller falls back to the plain path) when value is not a single clean JSON
// document or re-encoding fails. JSON structure and non-matching leaves survive.
func (r *FieldRedactor) redactStatementsJSON(value string, statementPlans []RedactionPlan) (string, []statementRedaction, bool) {
	dec := json.NewDecoder(strings.NewReader(value))
	dec.UseNumber()
	var root interface{}
	if err := dec.Decode(&root); err != nil || dec.More() {
		return "", nil, false
	}
	var applied []statementRedaction
	var walk func(n interface{}) interface{}
	walk = func(n interface{}) interface{} {
		switch v := n.(type) {
		case map[string]interface{}:
			for k, val := range v {
				v[k] = walk(val)
			}
			return v
		case []interface{}:
			for i, val := range v {
				v[i] = walk(val)
			}
			return v
		case string:
			out, a := r.redactStatementsPlain(v, statementPlans)
			applied = append(applied, a...)
			return out
		default:
			return n
		}
	}
	root = walk(root)
	if len(applied) == 0 {
		return value, nil, true // valid JSON, nothing matched: leave untouched
	}
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(root); err != nil {
		return "", nil, false // fall back to the plain path rather than emit nothing
	}
	return strings.TrimRight(buf.String(), "\n"), applied, true
}

// redactStatementsPlain replaces, for every statement plan that matches value,
// the ENTIRE sentence/line containing the match with a typed placeholder.
// Expanded regions from all statement plans are merged so an overlap is replaced
// once, and replacement runs end-to-start so earlier offsets stay valid. Returns
// the new string and the applied redactions. value is unchanged when nothing
// matches.
func (r *FieldRedactor) redactStatementsPlain(value string, statementPlans []RedactionPlan) (string, []statementRedaction) {
	if len(statementPlans) == 0 {
		return value, nil
	}
	type region struct {
		start, end int
		piiType    string
		policyID   string
	}
	var regions []region
	for i := range statementPlans {
		plan := statementPlans[i]
		re, err := regexp.Compile(plan.Policy.PatternStr)
		if err != nil {
			continue
		}
		piiType := r.getPIIType(plan.Policy)
		for _, loc := range re.FindAllStringIndex(value, -1) {
			s, e := statementSpan(value, loc[0], loc[1])
			regions = append(regions, region{start: s, end: e, piiType: piiType, policyID: plan.Policy.PolicyID})
		}
	}
	if len(regions) == 0 {
		return value, nil
	}
	sort.Slice(regions, func(i, j int) bool { return regions[i].start < regions[j].start })
	// Merge overlapping/adjacent regions (first region's attribution wins).
	merged := []region{regions[0]}
	for _, rg := range regions[1:] {
		last := &merged[len(merged)-1]
		if rg.start <= last.end {
			if rg.end > last.end {
				last.end = rg.end
			}
		} else {
			merged = append(merged, rg)
		}
	}
	var applied []statementRedaction
	for i := len(merged) - 1; i >= 0; i-- {
		m := merged[i]
		orig := value[m.start:m.end]
		value = value[:m.start] + fmt.Sprintf("[REDACTED:%s]", m.piiType) + value[m.end:]
		applied = append(applied, statementRedaction{matchText: orig, piiType: m.piiType, policyID: m.policyID})
	}
	return value, applied
}

// buildPatternMap groups plans by pattern string for efficient matching.
func (r *FieldRedactor) buildPatternMap(plans []RedactionPlan) map[string][]RedactionPlan {
	patternMap := make(map[string][]RedactionPlan)
	for _, plan := range plans {
		patternStr := plan.Policy.PatternStr
		patternMap[patternStr] = append(patternMap[patternStr], plan)
	}
	return patternMap
}

// --- JSON-structure-aware redaction ----------------------------------------
//
// The per-string masking above replaces a matched span in place. When a string
// VALUE is itself serialized JSON (e.g. the Claude Desktop proxy submits a whole
// tool result as one "statement" string), masking a value that sits in a NON-string
// position — a bare JSON number/bool — yields invalid JSON
// (`{"n":369318}` → `{"n":3****8}`). A downstream JSON consumer then rejects it and
// the Desktop proxy fail-closes the whole (benign) response. jsonSafeRemask keeps
// the common path byte-identical and ONLY re-redacts JSON-aware in that exact
// corruption case, so it never emits invalid JSON.

type compiledRedactPattern struct {
	re       *regexp.Regexp
	strategy RedactorFunc
	piiType  string
}

func (r *FieldRedactor) compilePatterns(patternMap map[string][]RedactionPlan) []compiledRedactPattern {
	out := make([]compiledRedactPattern, 0, len(patternMap))
	for patternStr, plans := range patternMap {
		re, err := regexp.Compile(patternStr)
		if err != nil || len(plans) == 0 {
			continue
		}
		out = append(out, compiledRedactPattern{
			re:       re,
			strategy: r.getStrategy(plans[0].Strategy),
			piiType:  r.getPIIType(plans[0].Policy),
		})
	}
	return out
}

// maskFlat applies every compiled pattern to s end-to-start (identical span logic
// to the inline applyTo* loops) and reports how many spans were masked. Masking
// inside a JSON string value is itself JSON-safe (the asterisks stay in the quotes).
func maskFlat(s string, pats []compiledRedactPattern) (string, int) {
	out := s
	count := 0
	for _, p := range pats {
		locs := p.re.FindAllStringIndex(out, -1)
		for i := len(locs) - 1; i >= 0; i-- {
			loc := locs[i]
			out = out[:loc[0]] + p.strategy(out[loc[0]:loc[1]], p.piiType) + out[loc[1]:]
			count++
		}
	}
	return out, count
}

// maskJSONNode walks a decoded JSON value, masking string leaves in place (JSON-safe)
// and coercing a matched NUMBER leaf to its masked STRING form — a masked number
// cannot remain a valid JSON number, so it becomes a quoted string. Matching uses
// the SAME patternMap the flat path uses (validator gating already happened when the
// plans were built), so the redaction set is consistent; values that live in a single
// JSON leaf are matched identically. *count accumulates how many leaves were masked.
func maskJSONNode(node interface{}, pats []compiledRedactPattern, count *int) interface{} {
	switch v := node.(type) {
	case map[string]interface{}:
		for k, val := range v {
			v[k] = maskJSONNode(val, pats, count)
		}
		return v
	case []interface{}:
		for i, val := range v {
			v[i] = maskJSONNode(val, pats, count)
		}
		return v
	case string:
		if m, n := maskFlat(v, pats); n > 0 {
			*count += n
			return m
		}
		return v
	case json.Number:
		if m, n := maskFlat(v.String(), pats); n > 0 {
			*count += n
			return m
		}
		return v
	default:
		return node // bool, nil — PII patterns do not meaningfully match these
	}
}

// redactJSONAware re-redacts jsonStr by walking its structure (UseNumber preserves
// untouched number formatting) so the output is always valid JSON. ok=false when
// jsonStr is not a single clean JSON document; masked reports whether any leaf was
// actually redacted (so the caller can keep the fail-closed flat result when a
// match existed only across leaf boundaries and the per-leaf walk found nothing).
func (r *FieldRedactor) redactJSONAware(jsonStr string, patternMap map[string][]RedactionPlan) (out string, masked, ok bool) {
	dec := json.NewDecoder(strings.NewReader(jsonStr))
	dec.UseNumber()
	var root interface{}
	if err := dec.Decode(&root); err != nil || dec.More() {
		return "", false, false // not a single clean JSON document
	}
	count := 0
	root = maskJSONNode(root, r.compilePatterns(patternMap), &count)
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // don't gratuitously escape <>& on the repair path
	if err := enc.Encode(root); err != nil {
		return "", false, false
	}
	return strings.TrimRight(buf.String(), "\n"), count > 0, true
}

// jsonSafeRemask returns flatMasked unchanged unless flat masking turned a
// previously-valid JSON value invalid (a match landed on a bare number/literal),
// in which case it returns a JSON-aware re-redaction of the original. Non-JSON and
// structure-preserving cases stay byte-identical — no gratuitous reformatting.
//
// Fail-closed invariant: when flat masking DID redact (it broke the JSON, so it
// removed something) but the per-leaf JSON-aware walk redacts NOTHING — only possible
// for a pattern that matches across a JSON leaf boundary — we keep the redacted-but-
// invalid flatMasked rather than returning the clean original. Never trade a
// fail-closed (invalid-but-redacted) result for a fail-open (valid-but-leaked) one.
func (r *FieldRedactor) jsonSafeRemask(original, flatMasked string, patternMap map[string][]RedactionPlan) string {
	if !json.Valid([]byte(original)) {
		return flatMasked // non-JSON value: raw-string flat masking is authoritative
	}
	// For VALID JSON always run the structure-aware walk, even when flat masking
	// changed nothing: the flat pass scans the RAW serialized bytes, so PII hidden
	// behind \uXXXX escapes in a string leaf ("123456" decodes to "123456")
	// evades it, and a bare-number match breaks the JSON. The walk decodes each leaf
	// before matching and re-serializes valid JSON. (Cost: a redacted JSON value is
	// normalized/re-serialized; a value with no PII is returned untouched.)
	safe, masked, ok := r.redactJSONAware(original, patternMap)
	if !ok {
		return flatMasked
	}
	if !masked {
		if flatMasked == original {
			return original // no PII in any decoded leaf and flat changed nothing
		}
		return flatMasked // flat matched something the per-leaf walk could not (cross-leaf) → fail-closed
	}
	// Accept the walk's output ONLY if no pattern still matches it; a span matching
	// across a JSON leaf boundary survives in `safe`, so keep the redacted-but-invalid
	// flatMasked (fail-closed) rather than a valid-but-leaked result.
	if !anyPatternMatches(safe, r.compilePatterns(patternMap)) {
		return safe
	}
	return flatMasked
}

// anyPatternMatches reports whether any compiled pattern still matches s — used to
// detect a cross-leaf span the per-leaf JSON-aware walk could not see.
func anyPatternMatches(s string, pats []compiledRedactPattern) bool {
	for _, p := range pats {
		if p.re.MatchString(s) {
			return true
		}
	}
	return false
}

// getStrategy returns the strategy function for a strategy type.
func (r *FieldRedactor) getStrategy(strategy RedactionStrategy) RedactorFunc {
	if fn, ok := r.strategies[strategy]; ok {
		return fn
	}
	return r.strategies[r.defaultStrategy]
}

// getPIIType extracts the PII type from a policy.
func (r *FieldRedactor) getPIIType(policy CompiledPolicy) string {
	// Try to extract from policy ID
	policyID := strings.ToLower(policy.PolicyID)
	piiTypes := []string{
		"ssn", "credit_card", "iban", "aadhaar", "pan",
		"email", "phone", "ip_address", "bank_account",
		"passport", "dob", "driver_license",
	}

	for _, t := range piiTypes {
		if strings.Contains(policyID, t) {
			return t
		}
	}

	// Fallback to category
	return string(policy.Category)
}

// SetDefaultStrategy sets the default redaction strategy.
func (r *FieldRedactor) SetDefaultStrategy(strategy RedactionStrategy) {
	r.defaultStrategy = strategy
}

// RegisterStrategy adds a custom redaction strategy.
func (r *FieldRedactor) RegisterStrategy(name RedactionStrategy, fn RedactorFunc) {
	r.strategies[name] = fn
}

// GetRedactionStrategy returns the appropriate strategy for a policy category.
func GetRedactionStrategy(category PolicyCategory, severity Severity) RedactionStrategy {
	// Indirect prompt-injection (security-dangerous) on the response plane is
	// sanitized by removing the whole sentence/line, not just the regex span, so no
	// residual instruction survives (#2738). Checked before the severity branches
	// so it holds at every severity. Redaction of this category only happens on the
	// response plane (the request plane blocks it); PII categories are unaffected.
	if category == CategorySecurityDangerous {
		return StrategyRemoveStatement
	}

	// Critical severity always uses full masking
	if severity == SeverityCritical {
		return StrategyMask
	}

	// Default strategies by category
	switch category {
	case CategoryPIIUS, CategoryPIIIndia, CategoryPIIEU, CategoryPIISingapore:
		return StrategyMask
	case CategoryPIIGlobal:
		if severity == SeverityHigh {
			return StrategyMask
		}
		return StrategyPartial
	default:
		return StrategyRemove
	}
}
