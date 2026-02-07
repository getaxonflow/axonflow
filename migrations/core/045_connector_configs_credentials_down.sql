-- Migration 045 Down: Revert connector_configs credentials column and connector types

ALTER TABLE connector_configs
    DROP CONSTRAINT IF EXISTS check_connector_type;

-- Remove connector rows that are not valid under the legacy constraint.
DELETE FROM connector_configs
WHERE connector_type IN (
    'http', 'mysql', 'mongodb', 'redis', 's3', 'azureblob', 'gcs',
    'hubspot', 'jira', 'servicenow'
);

ALTER TABLE connector_configs
    ADD CONSTRAINT check_connector_type CHECK (connector_type IN (
        'postgres', 'cassandra', 'salesforce', 'amadeus', 'slack', 'snowflake', 'custom'
    ));

ALTER TABLE connector_configs
    DROP COLUMN IF EXISTS credentials;
