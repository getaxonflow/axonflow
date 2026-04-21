module github.com/getaxonflow/axonflow-enterprise/examples/wcp-retry-idempotency/evaluation/go

go 1.23

require github.com/getaxonflow/axonflow-sdk-go/v5 v5.5.0

// Temporary local replace — remove when SDK v5.6.0 publishes.
replace github.com/getaxonflow/axonflow-sdk-go/v5 => ../../../../../axonflow-sdk-go-1673
