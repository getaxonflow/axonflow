// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package replay

import "errors"

var (
	// ErrNotFound is returned when a requested execution or snapshot is not found
	ErrNotFound = errors.New("execution not found")

	// ErrInvalidInput is returned when input validation fails
	ErrInvalidInput = errors.New("invalid input")

	// ErrDatabaseUnavailable is returned when the database connection fails
	ErrDatabaseUnavailable = errors.New("database unavailable")

	// ErrAlreadyExists is returned when trying to create a duplicate entry
	ErrAlreadyExists = errors.New("execution already exists")
)
