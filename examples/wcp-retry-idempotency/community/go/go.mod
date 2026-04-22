module github.com/getaxonflow/axonflow-enterprise/examples/wcp-retry-idempotency/community/go

go 1.23

// Phase 1 + Phase 2 of Issue #1673 land in Go SDK v5.6.0.
// Update this require line and delete the `replace` below once v5.6.0
// publishes to the Go module proxy.
require github.com/getaxonflow/axonflow-sdk-go/v5 v5.6.0

// Temporary local replace — resolves to the sibling SDK worktree where
// feat/1673-retry-context-and-idempotency-key is checked out. Remove
// when SDK v5.6.0 publishes. The path assumes a sibling layout:
//   ~/Development/axonflow-enterprise-1673/examples/...  (this file)
//   ~/Development/axonflow-sdk-go-1673/                  (SDK worktree)
replace github.com/getaxonflow/axonflow-sdk-go/v5 => ../../../../../axonflow-sdk-go-1673
