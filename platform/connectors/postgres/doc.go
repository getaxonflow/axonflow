// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Package postgres provides a PostgreSQL connector implementing the MCP
(Model Context Protocol) Connector interface.

# Overview

The PostgreSQL connector allows AI applications to execute SQL queries and
commands against PostgreSQL databases through the AxonFlow platform.

# Features

  - Connection pooling with configurable pool sizes
  - Query execution with positional parameters ($1, $2, etc.)
  - Command execution (INSERT, UPDATE, DELETE)
  - Health checking with connection statistics
  - Automatic retry on transient failures

# Configuration

The connector accepts the following options:

	config := &base.ConnectorConfig{
	    Name:          "main-postgres",
	    Type:          "postgres",
	    ConnectionURL: "postgres://user:pass@host:5432/database?sslmode=require",
	    Timeout:       5 * time.Second,
	    MaxRetries:    3,
	    Options: map[string]interface{}{
	        "max_open_conns":    25,      // Maximum open connections
	        "max_idle_conns":    5,       // Maximum idle connections
	        "conn_max_lifetime": "5m",    // Connection max lifetime
	    },
	}

# Usage

Create and connect:

	connector := postgres.NewPostgresConnector()
	err := connector.Connect(ctx, config)
	if err != nil {
	    log.Fatal(err)
	}
	defer connector.Disconnect(ctx)

Execute a query:

	result, err := connector.Query(ctx, &base.Query{
	    Statement:  "SELECT name, email FROM users WHERE role = $1",
	    Parameters: map[string]interface{}{"1": "admin"},
	    Limit:      100,
	})

Execute a command:

	result, err := connector.Execute(ctx, &base.Command{
	    Action:     "INSERT",
	    Statement:  "INSERT INTO logs (message) VALUES ($1)",
	    Parameters: map[string]interface{}{"1": "User logged in"},
	})

Note: Parameters are passed positionally to the driver. Use numeric keys
("1", "2") to indicate order when multiple parameters are needed.

# Thread Safety

PostgresConnector is safe for concurrent use. The underlying database/sql
connection pool handles concurrent access.
*/
package postgres
