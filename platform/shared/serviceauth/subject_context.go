// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package serviceauth

import "context"

// The authenticated subject travels in the request context, and it lives HERE
// rather than in the middleware package for a structural reason: the
// customer-portal middleware package imports the api package, so api cannot
// import middleware back. Both already depend on this one.
//
// The key type is UNEXPORTED, so no other package can put a subject into a
// context. That is the property that makes SubjectFromContext an answer about
// what the middleware AUTHENTICATED rather than about what some earlier handler
// happened to write: a caller that could set the value could assert any
// identity, which is the defect the subject binding exists to close, moved one
// layer in.

type subjectContextKey struct{}

// ContextWithAuthenticatedSubject records the subject a validated
// subject-bound token was checked against. Only auth middleware should call it.
func ContextWithAuthenticatedSubject(ctx context.Context, subject string) context.Context {
	return context.WithValue(ctx, subjectContextKey{}, subject)
}

// SubjectFromContext reports the authenticated subject, and whether there was
// one at all.
//
// The two-value return is load-bearing. A caller that took only the string
// would compare "" against a claimed identity and, for an endpoint whose
// claimed identity is also empty, find them equal - so "nobody authenticated"
// would satisfy an identity check. The boolean forces the absent case to be
// handled as absence rather than as an empty value; see
// feedback: an absent field is not an empty field.
func SubjectFromContext(ctx context.Context) (string, bool) {
	s, ok := ctx.Value(subjectContextKey{}).(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}
