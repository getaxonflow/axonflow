//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package renderer is Enterprise-only: the compliance report facade it serves
// is an Enterprise feature, so every implementation file carries
// `//go:build enterprise`.
//
// This file exists so the package is not EMPTY in a community build. A package
// directory whose files are all excluded by build constraints makes `go vet`,
// `go test` and coverage tooling report "build constraints exclude all Go files
// in ..." for that path; `go build ./...` happens to skip it silently, which is
// exactly the kind of tool-dependent difference that shows up as a surprise CI
// failure later. No other package in this tree has that property, and this one
// should not be the first.
//
// It deliberately declares NO exported symbols: the community stub of the
// parent package (compliancereport_community.go) is a no-op module that never
// renders anything, so there is nothing here for it to call.
package renderer
