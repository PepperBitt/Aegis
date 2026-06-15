-- V3: SBOM module tables
CREATE TABLE sbom_documents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    format VARCHAR(50) NOT NULL DEFAULT 'CYCLONEDX',
    spec_version VARCHAR(20),
    serial_number VARCHAR(255),
    supplier VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'PROCESSING',
    component_count INTEGER NOT NULL DEFAULT 0,
    file_path VARCHAR(500),
    file_size_bytes BIGINT,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sbom_documents_project_id ON sbom_documents(project_id);
CREATE INDEX idx_sbom_documents_status ON sbom_documents(status);

CREATE TABLE sbom_components (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sbom_id UUID NOT NULL REFERENCES sbom_documents(id) ON DELETE CASCADE,
    name VARCHAR(500) NOT NULL,
    version VARCHAR(200),
    purl VARCHAR(1000),
    cpe VARCHAR(500),
    component_type VARCHAR(100) DEFAULT 'LIBRARY',
    group_name VARCHAR(255),
    supplier VARCHAR(255),
    license_expression VARCHAR(500),
    hash_sha256 VARCHAR(64),
    hash_sha1 VARCHAR(40),
    hash_md5 VARCHAR(32),
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sbom_components_sbom_id ON sbom_components(sbom_id);
CREATE INDEX idx_sbom_components_purl ON sbom_components(purl);
CREATE INDEX idx_sbom_components_name ON sbom_components(name);

CREATE TABLE sbom_dependencies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sbom_id UUID NOT NULL REFERENCES sbom_documents(id) ON DELETE CASCADE,
    parent_component_id UUID NOT NULL REFERENCES sbom_components(id) ON DELETE CASCADE,
    child_component_id UUID NOT NULL REFERENCES sbom_components(id) ON DELETE CASCADE,
    UNIQUE(sbom_id, parent_component_id, child_component_id)
);

CREATE INDEX idx_sbom_dependencies_parent ON sbom_dependencies(parent_component_id);
CREATE INDEX idx_sbom_dependencies_child ON sbom_dependencies(child_component_id);
