-- =============================================================================
-- Migration 001: Core Types, Tenant Types, Organisations, and Identity Mirror
-- ArchScale V05 Authentication & Authorisation Layer
-- =============================================================================

-- Ensure uuid generation is available (gen_random_uuid() is built-in for PG 13+)
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS "pgcrypto";
EXCEPTION WHEN OTHERS THEN
    -- pgcrypto not bundled; PostgreSQL 13+ provides native gen_random_uuid()
    NULL;
END $$;

-- Fixed Lifecycles and Core Classifications
DO $$
BEGIN
    IF to_regtype('public.org_status') IS NULL THEN
        CREATE TYPE org_status AS ENUM (
            'APPLIED',
            'PENDING_REVIEW',
            'APPROVED',
            'ACTIVE',
            'SUSPENDED',
            'OFFBOARDED'
        );
    END IF;

    IF to_regtype('public.membership_status') IS NULL THEN
        CREATE TYPE membership_status AS ENUM (
            'INVITED',
            'REQUESTED',
            'PENDING_APPROVAL',
            'APPROVED',
            'REJECTED',
            'ACTIVE',
            'SUSPENDED',
            'EXPIRED',
            'REVOKED'
        );
    END IF;

    IF to_regtype('public.request_status') IS NULL THEN
        CREATE TYPE request_status AS ENUM (
            'PENDING',
            'APPROVED',
            'REJECTED',
            'CANCELLED'
        );
    END IF;

    IF to_regtype('public.portal_type') IS NULL THEN
        CREATE TYPE portal_type AS ENUM (
            'platform',
            'subscriber'
        );
    END IF;

    IF to_regtype('public.aal_level') IS NULL THEN
        CREATE TYPE aal_level AS ENUM (
            'aal1',
            'aal2',
            'aal3'
        );
    END IF;
END $$;

-- -----------------------------------------------------------------------------
-- Tenant Types Table (Founder-extensible data, not an enum)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenant_types (
    key TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE tenant_types ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Organisations Table (Root entity of all tenancy, policies, and data ownership)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS organisations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    portal portal_type NOT NULL,
    tenant_type_key TEXT REFERENCES tenant_types(key) ON UPDATE CASCADE ON DELETE RESTRICT,
    status org_status NOT NULL DEFAULT 'APPLIED',
    reviewed_by UUID,
    reviewed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Invariant: organisations.tenant_type_key is NULL iff portal = 'platform'
    CONSTRAINT chk_org_portal_tenant_type CHECK (
        (portal = 'platform' AND tenant_type_key IS NULL) OR
        (portal = 'subscriber' AND tenant_type_key IS NOT NULL)
    )
);

-- Invariant: Exactly one platform organisation exists across the entire system
CREATE UNIQUE INDEX IF NOT EXISTS idx_single_platform_org
    ON organisations ((true))
    WHERE portal = 'platform';

ALTER TABLE organisations ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Users Table (Identity mirror with user_code; holds NO roles, tenants, or standing)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_code TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    phone TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
