// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cost

import "errors"

var (
	// ErrBudgetNotFound is returned when a budget is not found
	ErrBudgetNotFound = errors.New("budget not found")

	// ErrBudgetExists is returned when trying to create a budget that already exists
	ErrBudgetExists = errors.New("budget already exists")

	// ErrInvalidBudgetID is returned for invalid budget ID
	ErrInvalidBudgetID = errors.New("invalid budget ID")

	// ErrInvalidBudgetName is returned for invalid budget name
	ErrInvalidBudgetName = errors.New("invalid budget name")

	// ErrInvalidBudgetLimit is returned for invalid budget limit
	ErrInvalidBudgetLimit = errors.New("budget limit must be greater than 0")

	// ErrInvalidBudgetScope is returned for invalid budget scope
	ErrInvalidBudgetScope = errors.New("invalid budget scope")

	// ErrInvalidBudgetPeriod is returned for invalid budget period
	ErrInvalidBudgetPeriod = errors.New("invalid budget period")

	// ErrInvalidOnExceed is returned for invalid on_exceed action
	ErrInvalidOnExceed = errors.New("invalid on_exceed action")

	// ErrInvalidGroupBy is returned for invalid group_by value
	ErrInvalidGroupBy = errors.New("invalid group_by value: must be provider, model, agent, team, user, or workflow")

	// ErrBudgetExceeded is returned when a budget is exceeded and action is block
	ErrBudgetExceeded = errors.New("budget exceeded")

	// ErrInvalidInput is returned for general invalid input
	ErrInvalidInput = errors.New("invalid input")

	// ErrDatabaseError is returned for database errors
	ErrDatabaseError = errors.New("database error")
)
