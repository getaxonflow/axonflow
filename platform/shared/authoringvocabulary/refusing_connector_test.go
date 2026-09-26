// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringvocabulary_test

import (
	"context"
	"database/sql/driver"
	"errors"
)

// refusingConnector backs a non-nil *sql.DB that fails any use: the deployment
// derivation is documented as doing no I/O, and a connection attempt fails the
// test rather than dialling anything.
type refusingConnector struct{}

func (refusingConnector) Connect(context.Context) (driver.Conn, error) {
	return nil, errors.New("the deployment derivation must not open a connection")
}
func (refusingConnector) Driver() driver.Driver { return nil }
