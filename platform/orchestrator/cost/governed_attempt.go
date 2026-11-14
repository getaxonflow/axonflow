// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cost

import (
	"context"
	"fmt"
	"time"
)

// GovernedModelAttempt is the durable intent/outcome journal around an
// Agent-to-Orchestrator forward. It exists before network I/O, so a truncated
// response or process interruption remains reconcilable as possibly charged.
type GovernedModelAttempt struct {
	RequestID        string
	OrgID            string
	TenantID         string
	TraceID          string
	Module           string
	CaseID           string
	EvidenceVersion  string
	InvestigationKey string
	Status           string
	ProviderInfo     map[string]any
	UsageReceipt     map[string]any
	Error            string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type governedModelAttemptRepository interface {
	BeginGovernedModelAttempt(context.Context, *GovernedModelAttempt) error
	FinishGovernedModelAttempt(context.Context, *GovernedModelAttempt) error
}

type governedModelAttemptLookupRepository interface {
	GetGovernedModelAttempt(context.Context, string, string, string, time.Duration) (*GovernedModelAttempt, error)
}

type governedModelAttemptReadinessRepository interface {
	CheckGovernedModelAttemptJournal(context.Context, string, string) error
}

// CheckGovernedModelAttemptJournal verifies the tenant-scoped durable journal
// without creating an attempt or invoking a provider. Hosted startup uses this
// to prove the recovery boundary before any model forward.
func (s *Service) CheckGovernedModelAttemptJournal(ctx context.Context, orgID, tenantID string) error {
	repo, ok := s.repo.(governedModelAttemptReadinessRepository)
	if !ok {
		return fmt.Errorf("governed model attempt journal is unavailable")
	}
	return repo.CheckGovernedModelAttemptJournal(ctx, orgID, tenantID)
}

func (s *Service) GetGovernedModelAttempt(ctx context.Context, orgID, tenantID, requestID string,
	staleAfter time.Duration) (*GovernedModelAttempt, error) {
	repo, ok := s.repo.(governedModelAttemptLookupRepository)
	if !ok {
		return nil, fmt.Errorf("governed model attempt journal is unavailable")
	}
	return repo.GetGovernedModelAttempt(ctx, orgID, tenantID, requestID, staleAfter)
}

func (s *Service) BeginGovernedModelAttempt(ctx context.Context, attempt *GovernedModelAttempt) error {
	repo, ok := s.repo.(governedModelAttemptRepository)
	if !ok {
		return fmt.Errorf("governed model attempt journal is unavailable")
	}
	return repo.BeginGovernedModelAttempt(ctx, attempt)
}

func (s *Service) FinishGovernedModelAttempt(ctx context.Context, attempt *GovernedModelAttempt) error {
	repo, ok := s.repo.(governedModelAttemptRepository)
	if !ok {
		return fmt.Errorf("governed model attempt journal is unavailable")
	}
	return repo.FinishGovernedModelAttempt(ctx, attempt)
}
