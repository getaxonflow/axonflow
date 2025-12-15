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
Package config provides configuration loading for MCP connectors from
environment variables and other sources.

# Overview

The config package simplifies connector configuration by providing
standardized loaders for each connector type. It reads configuration
from environment variables following a consistent naming convention.

# Environment Variable Convention

Connector configuration uses the prefix MCP_<CONNECTOR_NAME>_:

	MCP_POSTGRES_URL=postgres://user:pass@host:5432/db
	MCP_POSTGRES_TIMEOUT=10s
	MCP_POSTGRES_MAX_RETRIES=5
	MCP_POSTGRES_TENANT_ID=tenant-123

# Generic Configuration Loading

Load any connector type from environment variables:

	config, err := config.LoadFromEnv("MYDB", "postgres")
	if err != nil {
	    log.Fatal(err)
	}

Required environment variables:
  - MCP_<NAME>_URL: Connection URL or endpoint

Optional environment variables:
  - MCP_<NAME>_TIMEOUT: Operation timeout (default: 5s)
  - MCP_<NAME>_MAX_RETRIES: Retry count (default: 3)
  - MCP_<NAME>_TENANT_ID: Tenant ID for multi-tenancy (default: *)
  - MCP_<NAME>_USERNAME: Username credential
  - MCP_<NAME>_PASSWORD: Password credential
  - MCP_<NAME>_API_KEY: API key credential

# Connector-Specific Loaders

PostgreSQL:

	config, err := config.LoadPostgresConfig("maindb")
	// Falls back to DATABASE_URL if MCP_MAINDB_URL not set

Cassandra:

	config, err := config.LoadCassandraConfig("events")
	// Supports: MCP_EVENTS_KEYSPACE, MCP_EVENTS_CONSISTENCY

Slack:

	config, err := config.LoadSlackConfig("notifications")
	// Requires: MCP_NOTIFICATIONS_BOT_TOKEN

Salesforce:

	config, err := config.LoadSalesforceConfig("crm")
	// Requires: CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD

Snowflake:

	config, err := config.LoadSnowflakeConfig("warehouse")
	// Supports password or private key authentication

Amadeus:

	config, err := config.LoadAmadeusConfig("travel")
	// Supports test and production environments

# Configuration Validation

Validate configuration before use:

	if err := config.ValidateConfig(cfg); err != nil {
	    log.Fatalf("Invalid config: %v", err)
	}

# Thread Safety

All functions in this package are safe for concurrent use.
*/
package config
