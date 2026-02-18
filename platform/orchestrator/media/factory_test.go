// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package media

import (
	"errors"
	"testing"
)

const testFactoryAnalyzerType = MediaAnalyzerType("test-factory-analyzer")

// testAnalyzerFactory creates a MockMediaAnalyzer from config.
func testAnalyzerFactory(config AnalyzerConfig) (MediaAnalyzer, error) {
	return &MockMediaAnalyzer{
		name:         config.Name,
		analyzerType: config.Type,
	}, nil
}

// failingAnalyzerFactory always returns an error.
func failingAnalyzerFactory(config AnalyzerConfig) (MediaAnalyzer, error) {
	return nil, errors.New("factory creation intentionally failed")
}

// --- Global registry tests ---

func TestGlobalRegistry_RegisterGetHasUnregisterList(t *testing.T) {
	// Clean up global registry after test.
	t.Cleanup(func() {
		UnregisterAnalyzerFactory(testFactoryAnalyzerType)
	})

	// Should not exist before registration.
	if HasAnalyzerFactory(testFactoryAnalyzerType) {
		t.Fatal("factory should not exist before registration")
	}

	if f := GetAnalyzerFactory(testFactoryAnalyzerType); f != nil {
		t.Fatal("GetAnalyzerFactory should return nil for unregistered type")
	}

	// Register.
	RegisterAnalyzerFactory(testFactoryAnalyzerType, testAnalyzerFactory)

	// Has should return true.
	if !HasAnalyzerFactory(testFactoryAnalyzerType) {
		t.Fatal("HasAnalyzerFactory should return true after registration")
	}

	// Get should return non-nil.
	factory := GetAnalyzerFactory(testFactoryAnalyzerType)
	if factory == nil {
		t.Fatal("GetAnalyzerFactory should return non-nil after registration")
	}

	// Verify the factory works.
	analyzer, err := factory(AnalyzerConfig{Name: "test", Type: testFactoryAnalyzerType})
	if err != nil {
		t.Fatalf("factory returned unexpected error: %v", err)
	}
	if analyzer.Name() != "test" {
		t.Errorf("analyzer name = %q, want %q", analyzer.Name(), "test")
	}

	// List should include our type.
	types := ListAnalyzerFactories()
	found := false
	for _, at := range types {
		if at == testFactoryAnalyzerType {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListAnalyzerFactories() did not include %q", testFactoryAnalyzerType)
	}

	// Unregister should return true.
	if !UnregisterAnalyzerFactory(testFactoryAnalyzerType) {
		t.Error("UnregisterAnalyzerFactory should return true for existing type")
	}

	// Should no longer exist.
	if HasAnalyzerFactory(testFactoryAnalyzerType) {
		t.Error("factory should not exist after unregistration")
	}

	// Unregister again should return false.
	if UnregisterAnalyzerFactory(testFactoryAnalyzerType) {
		t.Error("UnregisterAnalyzerFactory should return false for already-removed type")
	}
}

// --- CreateAnalyzer tests ---

func TestCreateAnalyzer_Success(t *testing.T) {
	t.Cleanup(func() {
		UnregisterAnalyzerFactory(testFactoryAnalyzerType)
	})

	RegisterAnalyzerFactory(testFactoryAnalyzerType, testAnalyzerFactory)

	analyzer, err := CreateAnalyzer(AnalyzerConfig{
		Name: "my-analyzer",
		Type: testFactoryAnalyzerType,
	})
	if err != nil {
		t.Fatalf("CreateAnalyzer returned unexpected error: %v", err)
	}
	if analyzer.Name() != "my-analyzer" {
		t.Errorf("analyzer name = %q, want %q", analyzer.Name(), "my-analyzer")
	}
	if analyzer.Type() != testFactoryAnalyzerType {
		t.Errorf("analyzer type = %q, want %q", analyzer.Type(), testFactoryAnalyzerType)
	}
}

func TestCreateAnalyzer_MissingType(t *testing.T) {
	_, err := CreateAnalyzer(AnalyzerConfig{
		Name: "no-type",
		Type: "",
	})
	if err == nil {
		t.Fatal("CreateAnalyzer should return error when type is empty")
	}

	var factoryErr *FactoryError
	if !errors.As(err, &factoryErr) {
		t.Fatalf("expected *FactoryError, got %T", err)
	}
	if factoryErr.Code != ErrFactoryMissingType {
		t.Errorf("error code = %q, want %q", factoryErr.Code, ErrFactoryMissingType)
	}
}

func TestCreateAnalyzer_NotRegistered(t *testing.T) {
	unregisteredType := MediaAnalyzerType("not-registered-analyzer")

	_, err := CreateAnalyzer(AnalyzerConfig{
		Name: "missing",
		Type: unregisteredType,
	})
	if err == nil {
		t.Fatal("CreateAnalyzer should return error for unregistered type")
	}

	var factoryErr *FactoryError
	if !errors.As(err, &factoryErr) {
		t.Fatalf("expected *FactoryError, got %T", err)
	}
	if factoryErr.Code != ErrFactoryNotRegistered {
		t.Errorf("error code = %q, want %q", factoryErr.Code, ErrFactoryNotRegistered)
	}
	if factoryErr.AnalyzerType != unregisteredType {
		t.Errorf("error analyzer type = %q, want %q", factoryErr.AnalyzerType, unregisteredType)
	}
}

func TestCreateAnalyzer_FactoryReturnsError(t *testing.T) {
	failType := MediaAnalyzerType("fail-factory-analyzer")
	t.Cleanup(func() {
		UnregisterAnalyzerFactory(failType)
	})

	RegisterAnalyzerFactory(failType, failingAnalyzerFactory)

	_, err := CreateAnalyzer(AnalyzerConfig{
		Name: "will-fail",
		Type: failType,
	})
	if err == nil {
		t.Fatal("CreateAnalyzer should return error when factory fails")
	}

	var factoryErr *FactoryError
	if !errors.As(err, &factoryErr) {
		t.Fatalf("expected *FactoryError, got %T", err)
	}
	if factoryErr.Code != ErrFactoryCreationFailed {
		t.Errorf("error code = %q, want %q", factoryErr.Code, ErrFactoryCreationFailed)
	}
	if factoryErr.AnalyzerType != failType {
		t.Errorf("error analyzer type = %q, want %q", factoryErr.AnalyzerType, failType)
	}

	// Verify Unwrap returns the underlying error.
	cause := factoryErr.Unwrap()
	if cause == nil {
		t.Fatal("FactoryError.Unwrap() should return the underlying cause")
	}
	if cause.Error() != "factory creation intentionally failed" {
		t.Errorf("unwrapped error = %q, want %q", cause.Error(), "factory creation intentionally failed")
	}
}

// --- AnalyzerFactoryManager tests ---

func TestAnalyzerFactoryManager_Register(t *testing.T) {
	mgr := NewAnalyzerFactoryManager()

	if mgr.Has(testFactoryAnalyzerType) {
		t.Fatal("new manager should not have any factories")
	}
	if mgr.Count() != 0 {
		t.Fatalf("new manager count = %d, want 0", mgr.Count())
	}

	mgr.Register(testFactoryAnalyzerType, testAnalyzerFactory)

	if !mgr.Has(testFactoryAnalyzerType) {
		t.Error("manager should have factory after registration")
	}
	if mgr.Count() != 1 {
		t.Errorf("manager count = %d, want 1", mgr.Count())
	}
}

func TestAnalyzerFactoryManager_Get(t *testing.T) {
	mgr := NewAnalyzerFactoryManager()

	// Get on empty manager returns nil.
	if f := mgr.Get(testFactoryAnalyzerType); f != nil {
		t.Error("Get should return nil for unregistered type")
	}

	mgr.Register(testFactoryAnalyzerType, testAnalyzerFactory)

	factory := mgr.Get(testFactoryAnalyzerType)
	if factory == nil {
		t.Fatal("Get should return non-nil for registered type")
	}

	// Verify the returned factory produces correct analyzers.
	analyzer, err := factory(AnalyzerConfig{Name: "mgr-test", Type: testFactoryAnalyzerType})
	if err != nil {
		t.Fatalf("factory returned unexpected error: %v", err)
	}
	if analyzer.Name() != "mgr-test" {
		t.Errorf("analyzer name = %q, want %q", analyzer.Name(), "mgr-test")
	}
}

func TestAnalyzerFactoryManager_Has(t *testing.T) {
	mgr := NewAnalyzerFactoryManager()

	if mgr.Has(testFactoryAnalyzerType) {
		t.Error("Has should return false for empty manager")
	}

	mgr.Register(testFactoryAnalyzerType, testAnalyzerFactory)

	if !mgr.Has(testFactoryAnalyzerType) {
		t.Error("Has should return true after registration")
	}

	otherType := MediaAnalyzerType("other-type")
	if mgr.Has(otherType) {
		t.Error("Has should return false for unregistered type")
	}
}

func TestAnalyzerFactoryManager_List(t *testing.T) {
	mgr := NewAnalyzerFactoryManager()

	// Empty manager returns empty list.
	if types := mgr.List(); len(types) != 0 {
		t.Errorf("List on empty manager returned %d items, want 0", len(types))
	}

	type1 := MediaAnalyzerType("list-type-1")
	type2 := MediaAnalyzerType("list-type-2")
	mgr.Register(type1, testAnalyzerFactory)
	mgr.Register(type2, testAnalyzerFactory)

	types := mgr.List()
	if len(types) != 2 {
		t.Fatalf("List returned %d items, want 2", len(types))
	}

	typeSet := make(map[MediaAnalyzerType]bool)
	for _, at := range types {
		typeSet[at] = true
	}
	if !typeSet[type1] {
		t.Errorf("List should include %q", type1)
	}
	if !typeSet[type2] {
		t.Errorf("List should include %q", type2)
	}
}

func TestAnalyzerFactoryManager_Create(t *testing.T) {
	mgr := NewAnalyzerFactoryManager()
	mgr.Register(testFactoryAnalyzerType, testAnalyzerFactory)

	// Successful creation.
	analyzer, err := mgr.Create(AnalyzerConfig{
		Name: "mgr-create",
		Type: testFactoryAnalyzerType,
	})
	if err != nil {
		t.Fatalf("Create returned unexpected error: %v", err)
	}
	if analyzer.Name() != "mgr-create" {
		t.Errorf("analyzer name = %q, want %q", analyzer.Name(), "mgr-create")
	}

	// Missing type.
	_, err = mgr.Create(AnalyzerConfig{Name: "no-type", Type: ""})
	if err == nil {
		t.Fatal("Create should return error when type is empty")
	}
	var missingErr *FactoryError
	if !errors.As(err, &missingErr) {
		t.Fatalf("expected *FactoryError, got %T", err)
	}
	if missingErr.Code != ErrFactoryMissingType {
		t.Errorf("error code = %q, want %q", missingErr.Code, ErrFactoryMissingType)
	}

	// Not registered.
	_, err = mgr.Create(AnalyzerConfig{Name: "no-factory", Type: MediaAnalyzerType("unknown")})
	if err == nil {
		t.Fatal("Create should return error for unregistered type")
	}
	var notRegErr *FactoryError
	if !errors.As(err, &notRegErr) {
		t.Fatalf("expected *FactoryError, got %T", err)
	}
	if notRegErr.Code != ErrFactoryNotRegistered {
		t.Errorf("error code = %q, want %q", notRegErr.Code, ErrFactoryNotRegistered)
	}

	// Factory returns error.
	failType := MediaAnalyzerType("mgr-fail-type")
	mgr.Register(failType, failingAnalyzerFactory)
	_, err = mgr.Create(AnalyzerConfig{Name: "will-fail", Type: failType})
	if err == nil {
		t.Fatal("Create should return error when factory fails")
	}
	var failErr *FactoryError
	if !errors.As(err, &failErr) {
		t.Fatalf("expected *FactoryError, got %T", err)
	}
	if failErr.Code != ErrFactoryCreationFailed {
		t.Errorf("error code = %q, want %q", failErr.Code, ErrFactoryCreationFailed)
	}
}

func TestAnalyzerFactoryManager_CopyFromGlobal(t *testing.T) {
	globalType := MediaAnalyzerType("copy-global-test")
	t.Cleanup(func() {
		UnregisterAnalyzerFactory(globalType)
	})

	RegisterAnalyzerFactory(globalType, testAnalyzerFactory)

	mgr := NewAnalyzerFactoryManager()
	if mgr.Has(globalType) {
		t.Fatal("manager should not have global type before CopyFromGlobal")
	}

	mgr.CopyFromGlobal()

	if !mgr.Has(globalType) {
		t.Error("manager should have global type after CopyFromGlobal")
	}

	// Verify the copied factory works.
	analyzer, err := mgr.Create(AnalyzerConfig{Name: "from-global", Type: globalType})
	if err != nil {
		t.Fatalf("Create from copied factory returned unexpected error: %v", err)
	}
	if analyzer.Name() != "from-global" {
		t.Errorf("analyzer name = %q, want %q", analyzer.Name(), "from-global")
	}
}

func TestAnalyzerFactoryManager_Count(t *testing.T) {
	mgr := NewAnalyzerFactoryManager()

	if mgr.Count() != 0 {
		t.Errorf("empty manager count = %d, want 0", mgr.Count())
	}

	mgr.Register(MediaAnalyzerType("count-1"), testAnalyzerFactory)
	if mgr.Count() != 1 {
		t.Errorf("manager count = %d, want 1", mgr.Count())
	}

	mgr.Register(MediaAnalyzerType("count-2"), testAnalyzerFactory)
	if mgr.Count() != 2 {
		t.Errorf("manager count = %d, want 2", mgr.Count())
	}

	// Re-registering the same type should not increase count.
	mgr.Register(MediaAnalyzerType("count-1"), testAnalyzerFactory)
	if mgr.Count() != 2 {
		t.Errorf("manager count after re-register = %d, want 2", mgr.Count())
	}
}

func TestAnalyzerFactoryManager_Clear(t *testing.T) {
	mgr := NewAnalyzerFactoryManager()
	mgr.Register(MediaAnalyzerType("clear-1"), testAnalyzerFactory)
	mgr.Register(MediaAnalyzerType("clear-2"), testAnalyzerFactory)

	if mgr.Count() != 2 {
		t.Fatalf("manager count before clear = %d, want 2", mgr.Count())
	}

	mgr.Clear()

	if mgr.Count() != 0 {
		t.Errorf("manager count after clear = %d, want 0", mgr.Count())
	}
	if mgr.Has(MediaAnalyzerType("clear-1")) {
		t.Error("manager should not have clear-1 after Clear")
	}
	if mgr.Has(MediaAnalyzerType("clear-2")) {
		t.Error("manager should not have clear-2 after Clear")
	}
}
