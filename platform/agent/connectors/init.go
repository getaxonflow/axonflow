//go:build enterprise

// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Enterprise Connector Factory Registration
// This package registers enterprise connectors with the factory.

package connectors

import (
	"log"

	"axonflow/platform/agent"
	"axonflow/platform/connectors/amadeus"
	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/hubspot"
	"axonflow/platform/connectors/jira"
	"axonflow/platform/connectors/salesforce"
	"axonflow/platform/connectors/servicenow"
	"axonflow/platform/connectors/slack"
	"axonflow/platform/connectors/snowflake"
)

func init() {
	RegisterEnterpriseConnectors()
}

// RegisterEnterpriseConnectors registers all Enterprise connector creators.
// These connectors require an AxonFlow Enterprise license.
func RegisterEnterpriseConnectors() {
	factory := agent.GetDefaultConnectorFactory()
	logger := log.Default()

	logger.Println("[CONNECTOR_FACTORY] Registering Enterprise connectors...")

	// Slack - Messaging and notifications
	factory.RegisterOrReplace(agent.ConnectorSlack, func() base.Connector {
		return slack.NewSlackConnector()
	})

	// Salesforce - CRM integration
	factory.RegisterOrReplace(agent.ConnectorSalesforce, func() base.Connector {
		return salesforce.NewSalesforceConnector()
	})

	// Amadeus - Travel APIs
	factory.RegisterOrReplace(agent.ConnectorAmadeus, func() base.Connector {
		return amadeus.NewAmadeusConnector()
	})

	// Snowflake - Data warehouse
	factory.RegisterOrReplace(agent.ConnectorSnowflake, func() base.Connector {
		return snowflake.NewSnowflakeConnector()
	})

	// HubSpot - Marketing automation
	factory.RegisterOrReplace(agent.ConnectorHubSpot, func() base.Connector {
		return hubspot.NewHubSpotConnector()
	})

	// Jira - Issue tracking
	factory.RegisterOrReplace(agent.ConnectorJira, func() base.Connector {
		return jira.NewJiraConnector()
	})

	// ServiceNow - IT service management
	factory.RegisterOrReplace(agent.ConnectorServiceNow, func() base.Connector {
		return servicenow.NewServiceNowConnector()
	})

	logger.Printf("[CONNECTOR_FACTORY] Registered 7 Enterprise connectors (total: %d)", factory.Count())
}
