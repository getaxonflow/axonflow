//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// editionSeams are the community build's own enforcing seams: none. The
// Enterprise build's are in cowork_ingest_enforcing_seam.go.
var editionSeams []enforcingSeam
