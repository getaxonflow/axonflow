//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package edition

// Current is the edition of THIS build. The enterprise tag is NOT set, so the
// enterprise source files were excluded. See edition.go for what this constant
// does and does not answer — in particular, that it describes the compilation
// and not the deployment.
const Current = Community
