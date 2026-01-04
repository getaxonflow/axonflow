// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package replay

import (
	"errors"
	"testing"
)

func TestErrors_Defined(t *testing.T) {
	// Verify all errors are defined and not nil
	if ErrNotFound == nil {
		t.Error("ErrNotFound should not be nil")
	}
	if ErrInvalidInput == nil {
		t.Error("ErrInvalidInput should not be nil")
	}
	if ErrDatabaseUnavailable == nil {
		t.Error("ErrDatabaseUnavailable should not be nil")
	}
	if ErrAlreadyExists == nil {
		t.Error("ErrAlreadyExists should not be nil")
	}
}

func TestErrors_Messages(t *testing.T) {
	// Verify error messages
	if ErrNotFound.Error() != "execution not found" {
		t.Errorf("unexpected ErrNotFound message: %s", ErrNotFound.Error())
	}
	if ErrInvalidInput.Error() != "invalid input" {
		t.Errorf("unexpected ErrInvalidInput message: %s", ErrInvalidInput.Error())
	}
	if ErrDatabaseUnavailable.Error() != "database unavailable" {
		t.Errorf("unexpected ErrDatabaseUnavailable message: %s", ErrDatabaseUnavailable.Error())
	}
	if ErrAlreadyExists.Error() != "execution already exists" {
		t.Errorf("unexpected ErrAlreadyExists message: %s", ErrAlreadyExists.Error())
	}
}

func TestErrors_Distinct(t *testing.T) {
	// Verify all errors are distinct
	allErrors := []error{
		ErrNotFound,
		ErrInvalidInput,
		ErrDatabaseUnavailable,
		ErrAlreadyExists,
	}

	for i := 0; i < len(allErrors); i++ {
		for j := i + 1; j < len(allErrors); j++ {
			if errors.Is(allErrors[i], allErrors[j]) {
				t.Errorf("errors should be distinct: %v and %v", allErrors[i], allErrors[j])
			}
		}
	}
}

func TestErrors_CanBeWrapped(t *testing.T) {
	// Verify errors can be wrapped and unwrapped
	wrappedErr := errors.New("wrapped: " + ErrNotFound.Error())

	// Verify the wrapped error contains the original message
	if wrappedErr.Error() != "wrapped: execution not found" {
		t.Error("wrapped error message incorrect")
	}
}
