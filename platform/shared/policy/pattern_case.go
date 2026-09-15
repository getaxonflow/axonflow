// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import "regexp"

// THE CASE RULE FOR STORED PATTERNS (#4131).
//
// No engine added (?i) to a stored pattern, so a pattern matched only the case
// its author typed: drop_table_prevention's `drop\s+table` let `DROP TABLE
// users` through (technical-docs/designs/DETECTOR_REGISTRY_DESIGN.md). The
// SQL-injection and destructive-command families are keywords a caller writes
// in either case, and every system row in them already carries (?i) except
// sys_sqli_string_term_comment, whose pattern has no letter for case to
// change. The organization template's rows in those families did not. So the
// families compile case-insensitively here, where a stored pattern becomes the
// one the evaluator matches and the redactor masks.
//
// Every other family keeps its stored case. Several PII and compliance patterns
// carry [A-Z] classes (a passport number, a loyalty number), which (?i) would
// widen to lower-case letters; their case is the author's, and a row that
// misses only on case is reported on #4131 rather than changed here.

// caseInsensitiveCategories are the pattern families EffectivePattern compiles
// case-insensitively: the canonical SQL-injection and destructive-command
// categories and the two pre-canonical spellings the template's rows carry.
var caseInsensitiveCategories = map[PolicyCategory]bool{
	CategorySecuritySQLi:           true,
	CategorySecurityDangerous:      true,
	CategoryLegacySQLInjection:     true,
	CategoryLegacyDangerousQueries: true,
}

// caseInsensitiveFlag is the RE2 flag group EffectivePattern prefixes.
const caseInsensitiveFlag = "(?i)"

// leadingCaseInsensitive matches a pattern that already opens with a flag group
// setting i, such as (?i) or (?im). Nine system SQL-injection rows open with
// (?im), and prefixing another (?i) to them would change nothing but the
// pattern string.
var leadingCaseInsensitive = regexp.MustCompile(`^\(\?[a-zA-Z]*i[a-zA-Z]*\)`)

// IsCaseInsensitiveCategory reports whether a category's stored patterns
// compile case-insensitively (EffectivePattern).
func IsCaseInsensitiveCategory(cat PolicyCategory) bool {
	return caseInsensitiveCategories[cat]
}

// EffectivePattern is the pattern a stored row compiles to: the stored pattern,
// prefixed with (?i) when its category is a case-insensitive family and the
// pattern does not already open with a flag group setting i. RE2 applies a
// leading flag group to the whole expression, and a second flag group after it
// - (?m), say - still applies, so the prefix changes case and nothing else.
func EffectivePattern(cat PolicyCategory, stored string) string {
	if !IsCaseInsensitiveCategory(cat) || leadingCaseInsensitive.MatchString(stored) {
		return stored
	}
	return caseInsensitiveFlag + stored
}
