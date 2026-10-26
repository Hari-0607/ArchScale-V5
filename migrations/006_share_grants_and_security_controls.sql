-- =============================================================================
-- Migration 006: Share Grants, Auth Rate Limits, and Account Lockouts
-- ArchScale V05 Authentication & Authorisation Layer
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Share Grants Table (Cross-org and external sharing)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS share_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    target_org_id UUID REFERENCES organisations(id) ON DELETE CASCADE,
    target_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    granted_by UUID NOT NULL REFERENCES memberships(id) ON DELETE RESTRICT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Invariant: Exactly one target reference must be non-null
    CONSTRAINT chk_share_grant_target_one CHECK (num_nonnulls(target_org_id, target_user_id) = 1),
    CONSTRAINT chk_share_grant_expiry CHECK (expires_at > started_at)
);

CREATE INDEX IF NOT EXISTS idx_share_grants_source ON share_grants(source_organisation_id, revoked_at, expires_at);
CREATE INDEX IF NOT EXISTS idx_share_grants_target_org ON share_grants(target_org_id) WHERE target_org_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_share_grants_target_user ON share_grants(target_user_id) WHERE target_user_id IS NOT NULL;

ALTER TABLE share_grants ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Auth Rate Limits Table (Atomic database store for rate limiting)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS auth_rate_limits (
    key TEXT PRIMARY KEY,
    counter INT NOT NULL DEFAULT 1,
    window_start TIMESTAMPTZ NOT NULL DEFAULT now(),
    window_expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON auth_rate_limits(window_expires_at);

ALTER TABLE auth_rate_limits ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Account Lockouts Table (Threshold-based lockout with administrative unlock)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS account_lockouts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    identifier TEXT NOT NULL,
    failed_attempts INT NOT NULL DEFAULT 1,
    locked_until TIMESTAMPTZ,
    unlock_reason TEXT,
    unlocked_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_account_lockout_identifier UNIQUE (identifier)
);

CREATE INDEX IF NOT EXISTS idx_account_lockouts_locked ON account_lockouts(identifier, locked_until);

ALTER TABLE account_lockouts ENABLE ROW LEVEL SECURITY;
