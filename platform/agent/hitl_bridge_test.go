// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// MockHITLService is a test mock for the HITLService interface.
type MockHITLService struct {
	requests        map[uuid.UUID]*HITLApprovalRequest
	createErr       error
	getErr          error
	createCallCount int
	getCallCount    int
}

func NewMockHITLService() *MockHITLService {
	return &MockHITLService{
		requests: make(map[uuid.UUID]*HITLApprovalRequest),
	}
}

func (m *MockHITLService) CreateApprovalRequest(ctx context.Context, input HITLCreateInput) (*HITLApprovalRequest, error) {
	m.createCallCount++
	if m.createErr != nil {
		return nil, m.createErr
	}

	req := &HITLApprovalRequest{
		RequestID: uuid.New(),
		OrgID:     input.OrgID,
		TenantID:  input.TenantID,
		Status:    "pending",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	m.requests[req.RequestID] = req
	return req, nil
}

func (m *MockHITLService) GetApprovalRequest(ctx context.Context, requestID uuid.UUID) (*HITLApprovalRequest, error) {
	m.getCallCount++
	if m.getErr != nil {
		return nil, m.getErr
	}

	req, ok := m.requests[requestID]
	if !ok {
		// Return a default pending request for unknown IDs
		return &HITLApprovalRequest{
			RequestID: requestID,
			Status:    "pending",
		}, nil
	}
	return req, nil
}

func (m *MockHITLService) SetStatus(requestID uuid.UUID, status string) {
	if req, ok := m.requests[requestID]; ok {
		req.Status = status
	}
}

func TestNewHITLBridge(t *testing.T) {
	mock := NewMockHITLService()
	bridge := NewHITLBridge(mock)

	if bridge == nil {
		t.Fatal("Expected non-nil bridge")
	}
	if bridge.service == nil {
		t.Fatal("Expected non-nil service in bridge")
	}
}

func TestHITLBridge_CreateApprovalFromPolicy(t *testing.T) {
	mock := NewMockHITLService()
	bridge := NewHITLBridge(mock)

	ctx := context.Background()
	req, err := bridge.CreateApprovalFromPolicy(
		ctx,
		"org-123",
		"tenant-456",
		"client-789",
		"user-abc",
		"SELECT * FROM users WHERE admin=true",
		"llm_chat",
		"policy-001",
		"Admin Access Detection",
		"Query contains admin access pattern",
		"high",
		"EU AI Act",  // complianceFramework
		"Article 14", // complianceArticle
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if req == nil {
		t.Fatal("Expected non-nil request")
	}
	if req.Status != "pending" {
		t.Errorf("Expected status 'pending', got '%s'", req.Status)
	}
	if req.OrgID != "org-123" {
		t.Errorf("Expected OrgID 'org-123', got '%s'", req.OrgID)
	}
	if mock.createCallCount != 1 {
		t.Errorf("Expected 1 create call, got %d", mock.createCallCount)
	}
}

func TestHITLBridge_CreateApprovalFromPolicy_NilService(t *testing.T) {
	bridge := &HITLBridge{service: nil}

	ctx := context.Background()
	_, err := bridge.CreateApprovalFromPolicy(
		ctx, "org", "tenant", "client", "user",
		"query", "type", "policy", "name", "reason", "high",
		"", "", // use defaults for compliance framework/article
	)

	if err == nil {
		t.Fatal("Expected error for nil service")
	}
}

func TestHITLBridge_GetApprovalStatus(t *testing.T) {
	mock := NewMockHITLService()
	bridge := NewHITLBridge(mock)
	ctx := context.Background()

	// Create a request first
	req, _ := bridge.CreateApprovalFromPolicy(
		ctx, "org", "tenant", "client", "user",
		"query", "type", "policy", "name", "reason", "high",
		"", "", // use defaults
	)

	// Get status
	status, err := bridge.GetApprovalStatus(ctx, req.RequestID)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if status != "pending" {
		t.Errorf("Expected status 'pending', got '%s'", status)
	}

	// Update status and check again
	mock.SetStatus(req.RequestID, "approved")
	status, err = bridge.GetApprovalStatus(ctx, req.RequestID)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if status != "approved" {
		t.Errorf("Expected status 'approved', got '%s'", status)
	}
}

func TestHITLBridge_IsApproved(t *testing.T) {
	mock := NewMockHITLService()
	bridge := NewHITLBridge(mock)
	ctx := context.Background()

	req, _ := bridge.CreateApprovalFromPolicy(
		ctx, "org", "tenant", "client", "user",
		"query", "type", "policy", "name", "reason", "high",
		"", "", // use defaults
	)

	// Initially pending
	approved, err := bridge.IsApproved(ctx, req.RequestID)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if approved {
		t.Error("Expected not approved initially")
	}

	// After approval
	mock.SetStatus(req.RequestID, "approved")
	approved, err = bridge.IsApproved(ctx, req.RequestID)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !approved {
		t.Error("Expected approved after status change")
	}

	// Override also counts as approved
	mock.SetStatus(req.RequestID, "overridden")
	approved, err = bridge.IsApproved(ctx, req.RequestID)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !approved {
		t.Error("Expected approved for overridden status")
	}
}

func TestHITLBridge_IsRejected(t *testing.T) {
	mock := NewMockHITLService()
	bridge := NewHITLBridge(mock)
	ctx := context.Background()

	req, _ := bridge.CreateApprovalFromPolicy(
		ctx, "org", "tenant", "client", "user",
		"query", "type", "policy", "name", "reason", "high",
		"", "", // use defaults
	)

	// Initially pending
	rejected, err := bridge.IsRejected(ctx, req.RequestID)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if rejected {
		t.Error("Expected not rejected initially")
	}

	// After rejection
	mock.SetStatus(req.RequestID, "rejected")
	rejected, err = bridge.IsRejected(ctx, req.RequestID)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !rejected {
		t.Error("Expected rejected after status change")
	}
}

func TestHITLBridge_IsPending(t *testing.T) {
	mock := NewMockHITLService()
	bridge := NewHITLBridge(mock)
	ctx := context.Background()

	req, _ := bridge.CreateApprovalFromPolicy(
		ctx, "org", "tenant", "client", "user",
		"query", "type", "policy", "name", "reason", "high",
		"", "", // use defaults
	)

	// Initially pending
	pending, err := bridge.IsPending(ctx, req.RequestID)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !pending {
		t.Error("Expected pending initially")
	}

	// After approval
	mock.SetStatus(req.RequestID, "approved")
	pending, err = bridge.IsPending(ctx, req.RequestID)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if pending {
		t.Error("Expected not pending after approval")
	}
}

func TestMapSeverityToRisk(t *testing.T) {
	tests := []struct {
		severity string
		expected string
	}{
		{"critical", "high-risk"},
		{"high", "high-risk"},
		{"medium", "limited-risk"},
		{"low", "minimal-risk"},
		{"unknown", "high-risk"}, // Default to high-risk
		{"", "high-risk"},        // Empty defaults to high-risk
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			result := mapSeverityToRisk(tt.severity)
			if result != tt.expected {
				t.Errorf("mapSeverityToRisk(%s) = %s, expected %s", tt.severity, result, tt.expected)
			}
		})
	}
}

func TestNoOpHITLService_CreateApprovalRequest(t *testing.T) {
	service := &NoOpHITLService{}
	ctx := context.Background()

	req, err := service.CreateApprovalRequest(ctx, HITLCreateInput{
		OrgID:    "org-123",
		TenantID: "tenant-456",
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if req == nil {
		t.Fatal("Expected non-nil request")
	}
	if req.Status != "approved" {
		t.Errorf("NoOp service should auto-approve, got status '%s'", req.Status)
	}
	if req.OrgID != "org-123" {
		t.Errorf("Expected OrgID 'org-123', got '%s'", req.OrgID)
	}
}

func TestNoOpHITLService_GetApprovalRequest(t *testing.T) {
	service := &NoOpHITLService{}
	ctx := context.Background()

	requestID := uuid.New()
	req, err := service.GetApprovalRequest(ctx, requestID)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if req == nil {
		t.Fatal("Expected non-nil request")
	}
	if req.Status != "approved" {
		t.Errorf("NoOp service should return approved, got status '%s'", req.Status)
	}
	if req.RequestID != requestID {
		t.Errorf("Expected RequestID %s, got %s", requestID, req.RequestID)
	}
}
