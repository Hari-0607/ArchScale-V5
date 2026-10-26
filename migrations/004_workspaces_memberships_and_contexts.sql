-- =============================================================================
-- Migration 004: Workspaces, Memberships, Contexts, and Invitations
-- ArchScale V05 Authentication & Authorisation Layer
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Workspaces Table (Scoped workspaces / branches within an organisation)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS workspaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    is_default BOOLEAN NOT NULL DEFAULT false,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_workspace_org_name UNIQUE (organisation_id, name)
);

CREATE INDEX IF NOT EXISTS idx_workspaces_org_id ON workspaces(organisation_id);

ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Memberships Table (Binds User + Organisation; Roles attach HERE, never to person)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    role_key TEXT NOT NULL REFERENCES roles(key) ON DELETE RESTRICT,
    profile_id UUID REFERENCES access_profiles(id) ON DELETE RESTRICT,
    status membership_status NOT NULL DEFAULT 'PENDING_APPROVAL',
    expires_at TIMESTAMPTZ,
    is_primary_owner BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Invariant: One membership per person per organisation
    CONSTRAINT uq_membership_user_org UNIQUE (user_id, organisation_id)
);

CREATE INDEX IF NOT EXISTS idx_memberships_org_status ON memberships(organisation_id, status);
CREATE INDEX IF NOT EXISTS idx_memberships_user_status ON memberships(user_id, status);

ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Membership Seats (Explicit seat allocation per membership and app)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS membership_seats (
    membership_id UUID NOT NULL REFERENCES memberships(id) ON DELETE CASCADE,
    app_key TEXT NOT NULL REFERENCES app_catalogue(app_key) ON DELETE RESTRICT,
    allocated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (membership_id, app_key)
);

ALTER TABLE membership_seats ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Access Contexts (Validated 24h context binding User + Session + Org + Workspace + Membership)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS access_contexts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL,
    organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    membership_id UUID NOT NULL REFERENCES memberships(id) ON DELETE CASCADE,
    aal_level aal_level NOT NULL DEFAULT 'aal1',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Invariant: Hard cap of 24 hours on context lifetime
    CONSTRAINT chk_context_max_24h CHECK (expires_at <= created_at + interval '24 hours')
);

CREATE INDEX IF NOT EXISTS idx_access_contexts_lookup 
    ON access_contexts(id, user_id, organisation_id, revoked_at, expires_at);

ALTER TABLE access_contexts ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Context Validation Function (Single SQL authority for context validation)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION is_context_valid(p_context_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM access_contexts ac
        JOIN memberships m ON m.id = ac.membership_id
        JOIN organisations o ON o.id = ac.organisation_id
        JOIN workspaces w ON w.id = ac.workspace_id
        WHERE ac.id = p_context_id
          AND ac.revoked_at IS NULL
          AND ac.expires_at > now()
          AND m.status = 'ACTIVE'
          AND (m.expires_at IS NULL OR m.expires_at > now())
          AND o.status = 'ACTIVE'
          AND w.is_active = true
    );
$$;

-- -----------------------------------------------------------------------------
-- Invitations Table (Hashed, expiring invitations)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    target_role_key TEXT NOT NULL REFERENCES roles(key) ON DELETE RESTRICT,
    access_profile_id UUID REFERENCES access_profiles(id) ON DELETE RESTRICT,
    invited_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACCEPTED', 'EXPIRED', 'REVOKED')),
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_invitations_token ON invitations(token_hash);
CREATE INDEX IF NOT EXISTS idx_invitations_org ON invitations(organisation_id, status);

ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Role Assignment History (Audited record of role/profile mutations)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS role_assignment_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    membership_id UUID NOT NULL REFERENCES memberships(id) ON DELETE CASCADE,
    old_role_key TEXT REFERENCES roles(key) ON DELETE RESTRICT,
    new_role_key TEXT NOT NULL REFERENCES roles(key) ON DELETE RESTRICT,
    old_profile_id UUID REFERENCES access_profiles(id) ON DELETE RESTRICT,
    new_profile_id UUID REFERENCES access_profiles(id) ON DELETE RESTRICT,
    changed_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    justification TEXT NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_role_assignment_history_membership ON role_assignment_history(membership_id);

ALTER TABLE role_assignment_history ENABLE ROW LEVEL SECURITY;
