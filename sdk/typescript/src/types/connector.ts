/**
 * MCP Connector types for AxonFlow SDK
 */

export interface ConnectorMetadata {
  id: string;
  name: string;
  type: string;
  version: string;
  description: string;
  category: string;
  icon: string;
  tags: string[];
  capabilities: string[];
  configSchema: Record<string, any>;
  installed: boolean;
  healthy?: boolean;
}

export interface ConnectorInstallRequest {
  connector_id: string;
  name: string;
  tenant_id: string;
  options: Record<string, any>;
  credentials: Record<string, string>;
}

export interface ConnectorResponse {
  success: boolean;
  data: any;
  error?: string;
  meta?: Record<string, any>;
}
