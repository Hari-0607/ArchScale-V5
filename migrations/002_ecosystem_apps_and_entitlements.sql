-- =============================================================================
-- Migration 002: Ecosystem Apps, Organisation Entitlements, and Seat Accounting
-- ArchScale V05 Authentication & Authorisation Layer
-- =============================================================================

-- -----------------------------------------------------------------------------
-- App Catalogue (Ecosystem applications registered to plug into ArchScale)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_catalogue (
    app_key TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    allowed_tenant_types TEXT[] NOT NULL DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE app_catalogue ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Organisation Entitlements (App licensing per organisation)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS organisation_entitlements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    app_key TEXT NOT NULL REFERENCES app_catalogue(app_key) ON DELETE RESTRICT,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_organisation_app_entitlement UNIQUE (organisation_id, app_key)
);

CREATE INDEX IF NOT EXISTS idx_org_entitlements_org_id ON organisation_entitlements(organisation_id);

ALTER TABLE organisation_entitlements ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Organisation Seats (Purchased vs Allocated capacity per app and role)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS organisation_seats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    app_key TEXT NOT NULL REFERENCES app_catalogue(app_key) ON DELETE RESTRICT,
    role_key TEXT NOT NULL,
    seat_limit INT NOT NULL CHECK (seat_limit >= 0),
    allocated_seats INT NOT NULL DEFAULT 0 CHECK (allocated_seats >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Invariant: Allocated seats can never exceed the purchased seat limit
    CONSTRAINT chk_seats_allocated_lte_limit CHECK (allocated_seats <= seat_limit),
    CONSTRAINT uq_organisation_seat_allocation UNIQUE (organisation_id, app_key, role_key)
);

CREATE INDEX IF NOT EXISTS idx_org_seats_org_app ON organisation_seats(organisation_id, app_key);

ALTER TABLE organisation_seats ENABLE ROW LEVEL SECURITY;
