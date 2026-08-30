-- V7: Widen API key prefix + Policy, Gatekeeper, Alert, Audit tables

ALTER TABLE api_keys ALTER COLUMN key_prefix TYPE VARCHAR(20);

-- ===================== POLICY ENGINE =====================
CREATE TABLE security_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    policy_type VARCHAR(50) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_policy_scope CHECK (
        (organization_id IS NOT NULL AND project_id IS NULL)
        OR (organization_id IS NULL AND project_id IS NOT NULL)
        OR (organization_id IS NOT NULL AND project_id IS NOT NULL)
    )
);

CREATE INDEX idx_security_policies_org ON security_policies(organization_id);
CREATE INDEX idx_security_policies_project ON security_policies(project_id);
CREATE INDEX idx_security_policies_type ON security_policies(policy_type);

CREATE TABLE policy_evaluation_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    policy_id UUID NOT NULL REFERENCES security_policies(id) ON DELETE CASCADE,
    passed BOOLEAN NOT NULL,
    failure_reason TEXT,
    evaluated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_policy_eval_project ON policy_evaluation_results(project_id);
CREATE INDEX idx_policy_eval_policy ON policy_evaluation_results(policy_id);

-- ===================== GATEKEEPER =====================
CREATE TABLE gate_checks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    requested_by UUID REFERENCES users(id),
    result VARCHAR(20) NOT NULL,
    failure_reasons TEXT,
    risk_score DECIMAL(5,2),
    risk_grade VARCHAR(5),
    policies_evaluated INT NOT NULL DEFAULT 0,
    policies_failed INT NOT NULL DEFAULT 0,
    metadata_json TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_gate_checks_project ON gate_checks(project_id);
CREATE INDEX idx_gate_checks_result ON gate_checks(result);
CREATE INDEX idx_gate_checks_created ON gate_checks(created_at);

-- ===================== ALERTS =====================
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    alert_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    title VARCHAR(500) NOT NULL,
    message TEXT NOT NULL,
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    acknowledged_by UUID REFERENCES users(id),
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    metadata_json TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_project ON alerts(project_id);
CREATE INDEX idx_alerts_acknowledged ON alerts(acknowledged);
CREATE INDEX idx_alerts_type ON alerts(alert_type);
CREATE INDEX idx_alerts_created ON alerts(created_at);

-- ===================== AUDIT LOGS =====================
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    organization_id UUID,
    project_id UUID,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(100),
    result VARCHAR(20) NOT NULL DEFAULT 'SUCCESS',
    ip_address VARCHAR(100),
    metadata_json TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_org ON audit_logs(organization_id);
CREATE INDEX idx_audit_logs_project ON audit_logs(project_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at);
