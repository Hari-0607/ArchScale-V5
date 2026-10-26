-- =============================================================================
-- Migration 003: Data-Driven Roles, Permissions, Templates, and Access Profiles
-- ArchScale V05 Authentication & Authorisation Layer
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Permissions Catalogue (Exact registered keys; unknown keys are rejected)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS permissions (
    key TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    min_aal aal_level NOT NULL DEFAULT 'aal1',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE permissions ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Roles Table (Roles as data with integer level ceilings)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
    key TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    portal portal_type NOT NULL,
    level INT NOT NULL CHECK (level >= 0 AND level <= 100),
    min_aal aal_level NOT NULL DEFAULT 'aal1',
    max_duration INTERVAL,
    expiry_required BOOLEAN NOT NULL DEFAULT false,
    requires_approval BOOLEAN NOT NULL DEFAULT true,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE roles ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Role Tenant Types (Which roles are allowed in which tenant types)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS role_tenant_types (
    role_key TEXT NOT NULL REFERENCES roles(key) ON DELETE CASCADE,
    tenant_type_key TEXT NOT NULL REFERENCES tenant_types(key) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (role_key, tenant_type_key)
);

ALTER TABLE role_tenant_types ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Role Permissions (Permission grants per role)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS role_permissions (
    role_key TEXT NOT NULL REFERENCES roles(key) ON DELETE CASCADE,
    permission_key TEXT NOT NULL REFERENCES permissions(key) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (role_key, permission_key)
);

ALTER TABLE role_permissions ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Tenant Role Permission Templates (Default templates per tenant type x role)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenant_role_permission_templates (
    tenant_type_key TEXT NOT NULL REFERENCES tenant_types(key) ON DELETE CASCADE,
    role_key TEXT NOT NULL REFERENCES roles(key) ON DELETE CASCADE,
    permission_key TEXT NOT NULL REFERENCES permissions(key) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_type_key, role_key, permission_key)
);

ALTER TABLE tenant_role_permission_templates ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Access Profiles (Extensible custom profiles within role families, e.g. manager_coordinator)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS access_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    parent_role_key TEXT NOT NULL REFERENCES roles(key) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_access_profile_org_name UNIQUE (organisation_id, name)
);

CREATE INDEX IF NOT EXISTS idx_access_profiles_org ON access_profiles(organisation_id);

ALTER TABLE access_profiles ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Access Profile Permissions (Granular permissions bundled in an access profile)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS access_profile_permissions (
    profile_id UUID NOT NULL REFERENCES access_profiles(id) ON DELETE CASCADE,
    permission_key TEXT NOT NULL REFERENCES permissions(key) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (profile_id, permission_key)
);

ALTER TABLE access_profile_permissions ENABLE ROW LEVEL SECURITY;


