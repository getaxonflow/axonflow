import React, { useState } from 'react';
import './PolicyConfig.css';

function PolicyConfig({ user, onBack, token, apiBase }) {
  const [showAddProviderModal, setShowAddProviderModal] = useState(false);
  const [showAddRoleModal, setShowAddRoleModal] = useState(false);
  const [showEditPolicyModal, setShowEditPolicyModal] = useState(false);

  const handleAddIdentityProvider = () => {
    alert('Demo: Add Identity Provider\n\nIn Production, this would open:\n- Provider type selection (SAML/OAuth/LDAP)\n- Configuration wizard\n- Test connection tool');
  };

  const handleAddNewRole = () => {
    alert('Demo: Add New Role\n\nIn Production, this would open a form with:\n- Role Name\n- Base Permission template\n- Custom permission builder');
  };

  const handleEditPolicy = (policyName) => {
    alert(`Demo: Edit Policy - ${policyName}\n\nIn Production, this would open:\n- Visual policy builder\n- Condition editor\n- Action designer\n- Test & validate tool`);
  };

  const handleConfigureProvider = (providerName) => {
    alert(`Demo: Configure ${providerName}\n\nIn Production, this would open:\n- Connection settings\n- Attribute mapping\n- User provisioning rules\n- Security certificates`);
  };

  const handleEditRole = (roleName) => {
    alert(`Demo: Edit Role - ${roleName}\n\nIn Production, this would open:\n- Permission matrix\n- Resource access controls\n- Inheritance settings\n- User assignment`);
  };

  const handleActivateTemplate = (templateName) => {
    alert(`Demo: Activate ${templateName} Template\n\nIn Production, this would:\n- Install compliance ruleset\n- Configure monitoring\n- Set up reporting\n- Enable audit trails`);
  };
  return (
    <div className="policy-config-page">
      <div className="policy-header">
        <button className="back-button" onClick={onBack}>← Back to Dashboard</button>
        <h1>🔧 Policy Configuration</h1>
        <p>Manage access controls, identity providers, and compliance policies</p>
        <div style={{marginTop: '15px', textAlign: 'center'}}>
          <a 
            href="/policy-overview.html" 
            style={{
              display: 'inline-block',
              background: '#805ad5',
              color: 'white',
              padding: '8px 16px',
              borderRadius: '6px',
              textDecoration: 'none',
              fontSize: '0.9rem',
              fontWeight: '500',
              transition: 'background 0.2s'
            }}
            onMouseOver={(e) => e.target.style.background = '#6b46c1'}
            onMouseOut={(e) => e.target.style.background = '#805ad5'}
          >
            📖 View Live Policy Documentation
          </a>
        </div>
      </div>
      
      <div className="policy-grid">
        <div className="policy-section">
          <h2>👥 Role-Based Access Control</h2>
          <div className="role-list">
            <div className="role-card">
              <div className="role-header">
                <h3>Support Agent</h3>
                <span className="user-count">12 users</span>
              </div>
              <div className="permissions">
                <span className="permission-tag">read:customers:assigned</span>
                <span className="permission-tag">read:tickets:all</span>
              </div>
              <button className="edit-role-btn" onClick={() => handleEditRole('Support Agent')}>Edit Role</button>
            </div>
            
            <div className="role-card">
              <div className="role-header">
                <h3>Manager</h3>
                <span className="user-count">3 users</span>
              </div>
              <div className="permissions">
                <span className="permission-tag">read:customers:all</span>
                <span className="permission-tag">read:pii:redacted</span>
                <span className="permission-tag">write:tickets</span>
              </div>
              <button className="edit-role-btn" onClick={() => handleEditRole('Manager')}>Edit Role</button>
            </div>
            
            <div className="role-card">
              <div className="role-header">
                <h3>Admin</h3>
                <span className="user-count">1 users</span>
              </div>
              <div className="permissions">
                <span className="permission-tag">*:all</span>
              </div>
              <button className="edit-role-btn" onClick={() => handleEditRole('Admin')}>Edit Role</button>
            </div>
            
            <button className="add-role-btn" onClick={handleAddNewRole}>+ Add New Role</button>
          </div>
        </div>

        <div className="policy-section">
          <h2>🔐 Identity Providers</h2>
          <div className="provider-list">
            <div className="provider-card">
              <div className="provider-info">
                <h3>Active Directory</h3>
                <span className="provider-type">SAML</span>
              </div>
              <div className="provider-stats">
                <span className="status connected">✅ Connected</span>
                <span className="user-count">1,247 users</span>
              </div>
              <button className="configure-btn" onClick={() => handleConfigureProvider('Active Directory')}>Configure</button>
            </div>
            
            <div className="provider-card">
              <div className="provider-info">
                <h3>Okta SSO</h3>
                <span className="provider-type">OAuth</span>
              </div>
              <div className="provider-stats">
                <span className="status connected">✅ Connected</span>
                <span className="user-count">856 users</span>
              </div>
              <button className="configure-btn" onClick={() => handleConfigureProvider('Okta SSO')}>Configure</button>
            </div>
            
            <div className="provider-card">
              <div className="provider-info">
                <h3>Google Workspace</h3>
                <span className="provider-type">OAuth</span>
              </div>
              <div className="provider-stats">
                <span className="status pending">⏳ Pending</span>
                <span className="user-count">Not configured users</span>
              </div>
              <button className="configure-btn" onClick={() => handleConfigureProvider('Google Workspace')}>Configure</button>
            </div>
            
            <button className="add-provider-btn" onClick={handleAddIdentityProvider}>+ Add Identity Provider</button>
          </div>
        </div>

        <div className="policy-section full-width">
          <h2>⚡ Dynamic Policy Rules</h2>
          <div className="policy-rules">
            <div className="policy-rule">
              <div className="rule-header">
                <h3>PII Auto-Redaction</h3>
                <label className="switch">
                  <input type="checkbox" defaultChecked />
                  <span className="slider"></span>
                </label>
              </div>
              <div className="rule-condition">
                <strong>If:</strong> <code>!"read_pii" in user.permissions</code>
              </div>
              <div className="rule-action">
                <strong>Then:</strong> <code>redact SSN, phone, email</code>
              </div>
              <button className="edit-policy-btn" onClick={() => handleEditPolicy('PII Auto-Redaction')}>Edit Policy</button>
            </div>
            
            <div className="policy-rule">
              <div className="rule-header">
                <h3>Regional Data Access</h3>
                <label className="switch">
                  <input type="checkbox" defaultChecked />
                  <span className="slider"></span>
                </label>
              </div>
              <div className="rule-condition">
                <strong>If:</strong> <code>!"admin" in user.permissions && user.region != "global"</code>
              </div>
              <div className="rule-action">
                <strong>Then:</strong> <code>filter data by user.region</code>
              </div>
              <button className="edit-policy-btn" onClick={() => handleEditPolicy('Regional Data Access')}>Edit Policy</button>
            </div>
            
            <div className="policy-rule">
              <div className="rule-header">
                <h3>LLM Model Permissions</h3>
                <label className="switch">
                  <input type="checkbox" defaultChecked />
                  <span className="slider"></span>
                </label>
              </div>
              <div className="rule-condition">
                <strong>If:</strong> <code>user.role == "agent"</code>
              </div>
              <div className="rule-action">
                <strong>Then:</strong> <code>route to Anthropic (restricted from OpenAI)</code>
              </div>
              <button className="edit-policy-btn" onClick={() => handleEditPolicy('LLM Model Permissions')}>Edit Policy</button>
            </div>
            
            <div className="policy-rule">
              <div className="rule-header">
                <h3>Confidential Query Routing</h3>
                <label className="switch">
                  <input type="checkbox" defaultChecked />
                  <span className="slider"></span>
                </label>
              </div>
              <div className="rule-condition">
                <strong>If:</strong> <code>query.contains("confidential|internal|proprietary")</code>
              </div>
              <div className="rule-action">
                <strong>Then:</strong> <code>route to Anthropic (safety-focused)</code>
              </div>
              <button className="edit-policy-btn" onClick={() => handleEditPolicy('Confidential Query Routing')}>Edit Policy</button>
            </div>
            
            <div className="policy-rule">
              <div className="rule-header">
                <h3>EU GDPR Compliance</h3>
                <label className="switch">
                  <input type="checkbox" defaultChecked />
                  <span className="slider"></span>
                </label>
              </div>
              <div className="rule-condition">
                <strong>If:</strong> <code>user.region.startsWith("eu")</code>
              </div>
              <div className="rule-action">
                <strong>Then:</strong> <code>route to LOCAL model (GDPR compliance)</code>
              </div>
              <button className="edit-policy-btn" onClick={() => handleEditPolicy('EU GDPR Compliance')}>Edit Policy</button>
            </div>
            
            <div className="policy-rule">
              <div className="rule-header">
                <h3>High-Security PII Queries</h3>
                <label className="switch">
                  <input type="checkbox" defaultChecked />
                  <span className="slider"></span>
                </label>
              </div>
              <div className="rule-condition">
                <strong>If:</strong> <code>query.contains("ssn|credit|phone") || query.hasPII()</code>
              </div>
              <div className="rule-action">
                <strong>Then:</strong> <code>route to LOCAL model (highest security)</code>
              </div>
              <button className="edit-policy-btn" onClick={() => handleEditPolicy('High-Security PII Queries')}>Edit Policy</button>
            </div>
            
            <button className="add-policy-btn" onClick={() => handleEditPolicy('New Policy Rule')}>+ Add New Policy Rule</button>
          </div>
        </div>

        <div className="policy-section">
          <h2>📋 Compliance Templates</h2>
          <div className="template-grid">
            <div className="template-card active">
              <h3>HIPAA</h3>
              <p>23 rules</p>
              <span className="template-status">✅ Active</span>
              <button className="configure-template-btn" onClick={() => handleConfigureProvider('HIPAA Template')}>Configure</button>
            </div>
            
            <div className="template-card active">
              <h3>GDPR</h3>
              <p>31 rules</p>
              <span className="template-status">✅ Active</span>
              <button className="configure-template-btn" onClick={() => handleConfigureProvider('GDPR Template')}>Configure</button>
            </div>
            
            <div className="template-card available">
              <h3>SOX</h3>
              <p>18 rules</p>
              <span className="template-status">📦 Available</span>
              <button className="activate-btn" onClick={() => handleActivateTemplate('SOX')}>Activate</button>
            </div>
            
            <div className="template-card available">
              <h3>PCI DSS</h3>
              <p>22 rules</p>
              <span className="template-status">📦 Available</span>
              <button className="activate-btn" onClick={() => handleActivateTemplate('PCI DSS')}>Activate</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default PolicyConfig;