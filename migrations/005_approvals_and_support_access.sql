-- =============================================================================
-- Migration 005: Approvals, Multi-Step Routing, and Support Access Grants
-- ArchScale V05 Authentication & Authorisation Layer
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Approval Policies Table
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS approval_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    role_key TEXT NOT NULL REFERENCES roles(key) ON DELETE CASCADE,
    min_approver_level INT NOT NULL CHECK (min_approver_level >= 0),
    requires_two_step BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_approval_policy_org_role UNIQUE (organisation_id, role_key)
);

CREATE INDEX IF NOT EXISTS idx_approval_policies_org ON approval_policies(organisation_id);

ALTER TABLE approval_policies ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Access Requests Table (Handles BOTH organisation and membership requests)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS access_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_type TEXT NOT NULL CHECK (request_type IN ('organisation', 'membership')),
    requester_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organisation_id UUID REFERENCES organisations(id) ON DELETE CASCADE,
    target_role_key TEXT REFERENCES roles(key) ON DELETE SET NULL,
    target_profile_id UUID REFERENCES access_profiles(id) ON DELETE SET NULL,
    requested_apps TEXT[] NOT NULL DEFAULT '{}',
    justification TEXT NOT NULL CHECK (length(trim(justification)) > 0),
    requested_duration INTERVAL,
    status request_status NOT NULL DEFAULT 'PENDING',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_org_request_targets CHECK (
        (request_type = 'organisation' AND target_role_key IS NULL) OR
        (request_type = 'membership' AND target_role_key IS NOT NULL AND organisation_id IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_access_requests_org_status ON access_requests(organisation_id, status);
CREATE INDEX IF NOT EXISTS idx_access_requests_requester ON access_requests(requester_user_id);

ALTER TABLE access_requests ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Approval Steps Table (Multi-step routing; decisions, reason, decider live here)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS approval_steps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES access_requests(id) ON DELETE CASCADE,
    step_number INT NOT NULL CHECK (step_number >= 1),
    required_role_key TEXT REFERENCES roles(key) ON DELETE RESTRICT,
    min_level INT NOT NULL DEFAULT 0,
    decided_by UUID REFERENCES memberships(id) ON DELETE RESTRICT, -- acting membership id
    decision request_status NOT NULL DEFAULT 'PENDING',
    reason TEXT,
    decided_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_approval_step_request_step UNIQUE (request_id, step_number)
);

CREATE INDEX IF NOT EXISTS idx_approval_steps_request ON approval_steps(request_id);

ALTER TABLE approval_steps ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Trigger: Separation of Duties & Level Ceiling Invariants on approval_steps
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_trg_check_approval_step_invariants()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_requester_id UUID;
    v_target_role_key TEXT;
    v_target_level INT;
    v_approver_user_id UUID;
    v_approver_role_key TEXT;
    v_approver_level INT;
    v_request_type TEXT;
BEGIN
    -- Only evaluate when a decision is made
    IF NEW.decision IN ('APPROVED', 'REJECTED') THEN
        IF NEW.decided_by IS NULL THEN
            RAISE EXCEPTION 'Approval step decision requires an acting membership in decided_by';
        END IF;

        IF NEW.decided_at IS NULL THEN
            NEW.decided_at := now();
        END IF;

        -- Fetch request details
        SELECT requester_user_id, target_role_key, request_type
        INTO v_requester_id, v_target_role_key, v_request_type
        FROM access_requests
        WHERE id = NEW.request_id;

        -- Fetch approver membership details
        SELECT m.user_id, m.role_key, r.level
        INTO v_approver_user_id, v_approver_role_key, v_approver_level
        FROM memberships m
        JOIN roles r ON r.key = m.role_key
        WHERE m.id = NEW.decided_by;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'Acting approver membership % not found', NEW.decided_by;
        END IF;

        -- Invariant 1: Separation of duties (approver != requester)
        IF v_approver_user_id = v_requester_id THEN
            RAISE EXCEPTION 'Separation of duties violation: approver (%) cannot approve their own request', v_approver_user_id;
        END IF;

        -- Invariant 2: Approver level strictly above target role level (for membership requests)
        IF NEW.decision = 'APPROVED' AND v_request_type = 'membership' AND v_target_role_key IS NOT NULL THEN
            SELECT level INTO v_target_level FROM roles WHERE key = v_target_role_key;
            
            IF v_approver_level <= v_target_level THEN
                RAISE EXCEPTION 'Level ceiling violation: approver level (%) must be strictly greater than target role level (%)',
                    v_approver_level, v_target_level;
            END IF;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_approval_step_invariants ON approval_steps;
CREATE TRIGGER trg_approval_step_invariants
    BEFORE INSERT OR UPDATE ON approval_steps
    FOR EACH ROW
    EXECUTE FUNCTION fn_trg_check_approval_step_invariants();

-- -----------------------------------------------------------------------------
-- Support Access Grants Table (Platform staff access into tenant data)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS support_access_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    staff_membership_id UUID NOT NULL REFERENCES memberships(id) ON DELETE RESTRICT,
    target_organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE RESTRICT,
    reason TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    justification TEXT,
    approved_by_founder_id UUID REFERENCES memberships(id) ON DELETE RESTRICT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Invariant: Support access is strictly capped at 24 hours
    CONSTRAINT chk_support_grant_max_24h CHECK (expires_at <= started_at + interval '24 hours')
);

CREATE INDEX IF NOT EXISTS idx_support_grants_target ON support_access_grants(target_organisation_id, revoked_at, expires_at);

ALTER TABLE support_access_grants ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Trigger: Invariants on support_access_grants
-- (Staff must be in platform org; target must be a subscriber org)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_trg_check_support_grant_invariants()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_staff_portal portal_type;
    v_target_portal portal_type;
BEGIN
    SELECT o.portal INTO v_staff_portal
    FROM memberships m
    JOIN organisations o ON o.id = m.organisation_id
    WHERE m.id = NEW.staff_membership_id;

    IF v_staff_portal IS NULL OR v_staff_portal <> 'platform' THEN
        RAISE EXCEPTION 'Support grant staff membership % must belong to the platform organisation', NEW.staff_membership_id;
    END IF;

    SELECT portal INTO v_target_portal
    FROM organisations
    WHERE id = NEW.target_organisation_id;

    IF v_target_portal IS NULL OR v_target_portal <> 'subscriber' THEN
        RAISE EXCEPTION 'Support grant target organisation % must be a subscriber organisation', NEW.target_organisation_id;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_support_grant_invariants ON support_access_grants;
CREATE TRIGGER trg_support_grant_invariants
    BEFORE INSERT OR UPDATE ON support_access_grants
    FOR EACH ROW
    EXECUTE FUNCTION fn_trg_check_support_grant_invariants();
