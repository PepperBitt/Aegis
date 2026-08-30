-- V6: Risk module tables
CREATE TABLE project_risk (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL UNIQUE REFERENCES projects(id) ON DELETE CASCADE,
    risk_score DECIMAL(5,2) NOT NULL DEFAULT 0.00,
    risk_grade VARCHAR(5) NOT NULL DEFAULT 'A',
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    calculated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_project_risk_project_id ON project_risk(project_id);

CREATE TABLE project_risk_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    risk_score DECIMAL(5,2) NOT NULL,
    risk_grade VARCHAR(5) NOT NULL,
    calculated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_risk_history_project_id ON project_risk_history(project_id);
