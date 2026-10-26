-- =============================================================================
-- Migration 008: Database Invariant Triggers and Transactional Approval Functions
-- ArchScale V05 Authentication & Authorisation Layer
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Invariant: Last Active Founder & Last Active Business Owner Protection
-- (Must NOT block changes caused by organisation suspension or offboarding)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_trg_custodian_protection()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_org_portal portal_type;
    v_org_status org_status;
    v_remaining_count INT;
BEGIN
    -- Determine parent organisation portal and status
    SELECT portal, status INTO v_org_portal, v_org_status
    FROM organisations
    WHERE id = OLD.organisation_id;

    -- If parent organisation is being suspended or offboarded, exempt from custodian check
    IF v_org_status IN ('SUSPENDED', 'OFFBOARDED') THEN
        RETURN COALESCE(NEW, OLD);
    END IF;

    -- Case A: Platform Founder protection
    IF OLD.role_key = 'founder' AND v_org_portal = 'platform' AND OLD.status = 'ACTIVE' THEN
        -- If record is being deleted OR deactivated
        IF (TG_OP = 'DELETE') OR (TG_OP = 'UPDATE' AND NEW.status <> 'ACTIVE') THEN
            SELECT count(*) INTO v_remaining_count
            FROM memberships
            WHERE organisation_id = OLD.organisation_id
              AND role_key = 'founder'
              AND status = 'ACTIVE'
              AND id <> OLD.id;

            IF v_remaining_count = 0 THEN
                RAISE EXCEPTION 'Cannot remove or suspend the last active founder of an active platform organisation';
            END IF;
        END IF;
    END IF;

    -- Case B: Subscriber Business Owner protection
    IF OLD.role_key = 'business_owner' AND v_org_portal = 'subscriber' AND OLD.status = 'ACTIVE' THEN
        -- If record is being deleted OR deactivated
        IF (TG_OP = 'DELETE') OR (TG_OP = 'UPDATE' AND NEW.status <> 'ACTIVE') THEN
            SELECT count(*) INTO v_remaining_count
            FROM memberships
            WHERE organisation_id = OLD.organisation_id
              AND role_key = 'business_owner'
              AND status = 'ACTIVE'
              AND id <> OLD.id;

            IF v_remaining_count = 0 THEN
                RAISE EXCEPTION 'Cannot remove or suspend the last active business_owner of an active subscriber organisation';
            END IF;
        END IF;
    END IF;

    RETURN COALESCE(NEW, OLD);
END;
$$;

DROP TRIGGER IF EXISTS trg_memberships_custodian_protection ON memberships;
CREATE TRIGGER trg_memberships_custodian_protection
    BEFORE UPDATE OR DELETE ON memberships
    FOR EACH ROW
    EXECUTE FUNCTION fn_trg_custodian_protection();

-- -----------------------------------------------------------------------------
-- 2. Invariant: Expiry Date Enforcement for Roles Requiring Expiry
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_trg_membership_expiry_enforcement()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_expiry_required BOOLEAN;
BEGIN
    SELECT expiry_required INTO v_expiry_required
    FROM roles
    WHERE key = NEW.role_key;

    IF v_expiry_required IS TRUE AND NEW.expires_at IS NULL THEN
        RAISE EXCEPTION 'Membership for role % requires an expiration date (expires_at cannot be null)', NEW.role_key;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_memberships_expiry_enforcement ON memberships;
CREATE TRIGGER trg_memberships_expiry_enforcement
    BEFORE INSERT OR UPDATE OF role_key, expires_at ON memberships
    FOR EACH ROW
    EXECUTE FUNCTION fn_trg_membership_expiry_enforcement();

-- -----------------------------------------------------------------------------
-- 3. Invariant: No Membership ACTIVE Unless Organisation is ACTIVE
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_trg_membership_org_active_check()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_org_status org_status;
BEGIN
    IF NEW.status = 'ACTIVE' THEN
        SELECT status INTO v_org_status
        FROM organisations
        WHERE id = NEW.organisation_id;

        IF v_org_status IS NULL OR v_org_status <> 'ACTIVE' THEN
            RAISE EXCEPTION 'Cannot activate membership %: parent organisation is in % status (must be ACTIVE)',
                NEW.id, COALESCE(v_org_status::text, 'UNKNOWN');
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_memberships_org_active_check ON memberships;
CREATE TRIGGER trg_memberships_org_active_check
    BEFORE INSERT OR UPDATE OF status, organisation_id ON memberships
    FOR EACH ROW
    EXECUTE FUNCTION fn_trg_membership_org_active_check();

-- -----------------------------------------------------------------------------
-- 4. Invariant: Organisation Suspension/Offboarding Cascade
-- (Revokes all contexts and suspends all memberships in the same transaction)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_trg_org_suspension_cascade()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    -- If organisation transitions from ACTIVE to SUSPENDED or OFFBOARDED
    IF OLD.status = 'ACTIVE' AND NEW.status IN ('SUSPENDED', 'OFFBOARDED') THEN
        -- Revoke all active access contexts immediately
        UPDATE access_contexts
        SET revoked_at = now()
        WHERE organisation_id = NEW.id
          AND revoked_at IS NULL;

        -- Suspend all active memberships
        UPDATE memberships
        SET status = 'SUSPENDED',
            updated_at = now()
        WHERE organisation_id = NEW.id
          AND status = 'ACTIVE';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_org_suspension_cascade ON organisations;
CREATE TRIGGER trg_org_suspension_cascade
    AFTER UPDATE OF status ON organisations
    FOR EACH ROW
    EXECUTE FUNCTION fn_trg_org_suspension_cascade();

-- -----------------------------------------------------------------------------
-- 5. Stored Transactional Function: fn_approve_organisation
-- (Atomic: org activation, entitlements, seats, initial business_owner, audit)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_approve_organisation(
    p_request_id UUID,
    p_acting_membership_id UUID,
    p_tenant_type_key TEXT,
    p_licensed_apps TEXT[],
    p_seat_limits JSONB, -- Array of {app_key: string, role_key: string, seat_limit: int}
    p_owner_user_id UUID,
    p_reason TEXT
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_actor_user_id UUID;
    v_actor_role_key TEXT;
    v_actor_level INT;
    v_actor_portal portal_type;
    v_actor_org_status org_status;
    v_request RECORD;
    v_org_id UUID;
    v_workspace_id UUID;
    v_owner_membership_id UUID;
    v_app_key TEXT;
    v_seat RECORD;
BEGIN
    -- A. Re-validate acting membership authority server-side
    SELECT m.user_id, m.role_key, r.level, o.portal, o.status
    INTO v_actor_user_id, v_actor_role_key, v_actor_level, v_actor_portal, v_actor_org_status
    FROM memberships m
    JOIN roles r ON r.key = m.role_key
    JOIN organisations o ON o.id = m.organisation_id
    WHERE m.id = p_acting_membership_id
      AND m.status = 'ACTIVE';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Acting membership % is not found or not active', p_acting_membership_id;
    END IF;

    IF v_actor_portal <> 'platform' OR v_actor_org_status <> 'ACTIVE' OR v_actor_role_key <> 'founder' THEN
        RAISE EXCEPTION 'Unauthorized: only an active platform founder can approve organisation onboarding';
    END IF;

    -- B. Fetch and lock access request
    SELECT * INTO v_request
    FROM access_requests
    WHERE id = p_request_id AND request_type = 'organisation' AND status = 'PENDING'
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Organisation access request % not found or not pending', p_request_id;
    END IF;

    -- C. Separation of duties
    IF v_actor_user_id = v_request.requester_user_id THEN
        RAISE EXCEPTION 'Separation of duties violation: founder cannot approve their own organisation application';
    END IF;

    v_org_id := v_request.organisation_id;
    IF v_org_id IS NULL THEN
        RAISE EXCEPTION 'Access request % is missing target organisation_id', p_request_id;
    END IF;

    -- Verify tenant type exists
    IF NOT EXISTS (SELECT 1 FROM tenant_types WHERE key = p_tenant_type_key AND is_active = true) THEN
        RAISE EXCEPTION 'Tenant type % is invalid or inactive', p_tenant_type_key;
    END IF;

    -- D. Update organisation to ACTIVE
    UPDATE organisations
    SET tenant_type_key = p_tenant_type_key,
        status = 'ACTIVE',
        reviewed_by = v_actor_user_id,
        reviewed_at = now(),
        updated_at = now()
    WHERE id = v_org_id;

    -- E. Create licensed app entitlements
    FOREACH v_app_key IN ARRAY p_licensed_apps
    LOOP
        INSERT INTO organisation_entitlements (organisation_id, app_key, is_enabled)
        VALUES (v_org_id, v_app_key, true)
        ON CONFLICT (organisation_id, app_key) DO UPDATE SET is_enabled = true;
    END LOOP;

    -- F. Provision seat capacity pools
    IF p_seat_limits IS NOT NULL AND jsonb_array_length(p_seat_limits) > 0 THEN
        FOR v_seat IN SELECT * FROM jsonb_to_recordset(p_seat_limits) AS x(app_key TEXT, role_key TEXT, seat_limit INT)
        LOOP
            INSERT INTO organisation_seats (organisation_id, app_key, role_key, seat_limit, allocated_seats)
            VALUES (v_org_id, v_seat.app_key, v_seat.role_key, v_seat.seat_limit, 0)
            ON CONFLICT (organisation_id, app_key, role_key) DO UPDATE SET seat_limit = v_seat.seat_limit;
        END LOOP;
    END IF;

    -- G. Create Default Workspace
    INSERT INTO workspaces (organisation_id, name, is_default, is_active)
    VALUES (v_org_id, 'Default Workspace', true, true)
    ON CONFLICT (organisation_id, name) DO NOTHING
    RETURNING id INTO v_workspace_id;

    -- H. Create initial business_owner membership
    INSERT INTO memberships (user_id, organisation_id, role_key, status, is_primary_owner)
    VALUES (p_owner_user_id, v_org_id, 'business_owner', 'ACTIVE', true)
    ON CONFLICT (user_id, organisation_id) DO UPDATE SET status = 'ACTIVE', role_key = 'business_owner', is_primary_owner = true
    RETURNING id INTO v_owner_membership_id;

    -- Allocate seat for business_owner on licensed apps if seat pool exists
    FOREACH v_app_key IN ARRAY p_licensed_apps
    LOOP
        IF EXISTS (SELECT 1 FROM organisation_seats WHERE organisation_id = v_org_id AND app_key = v_app_key AND role_key = 'business_owner') THEN
            UPDATE organisation_seats 
            SET allocated_seats = allocated_seats + 1 
            WHERE organisation_id = v_org_id AND app_key = v_app_key AND role_key = 'business_owner';

            INSERT INTO membership_seats (membership_id, app_key)
            VALUES (v_owner_membership_id, v_app_key)
            ON CONFLICT DO NOTHING;
        END IF;
    END LOOP;

    -- I. Record approval step
    INSERT INTO approval_steps (request_id, step_number, required_role_key, min_level, decided_by, decision, reason, decided_at)
    VALUES (p_request_id, 1, 'founder', 100, p_acting_membership_id, 'APPROVED', p_reason, now());

    -- J. Finalize request
    UPDATE access_requests
    SET status = 'APPROVED', updated_at = now()
    WHERE id = p_request_id;

    -- K. Write append-only audit log
    INSERT INTO audit_logs (actor_user_id, actor_membership_id, organisation_id, action, target_entity, target_id, diff)
    VALUES (
        v_actor_user_id,
        p_acting_membership_id,
        v_org_id,
        'organisation.approve',
        'organisation',
        v_org_id::text,
        jsonb_build_object(
            'tenant_type_key', p_tenant_type_key,
            'licensed_apps', p_licensed_apps,
            'owner_user_id', p_owner_user_id,
            'reason', p_reason
        )
    );

    RETURN v_org_id;
END;
$$;

-- -----------------------------------------------------------------------------
-- 6. Stored Transactional Function: fn_approve_membership
-- (Atomic: seat check under FOR UPDATE, role grant, membership activation, audit)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_approve_membership(
    p_request_id UUID,
    p_acting_membership_id UUID,
    p_reason TEXT
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_actor_user_id UUID;
    v_actor_org_id UUID;
    v_actor_role_key TEXT;
    v_actor_level INT;
    v_actor_org_status org_status;
    v_request RECORD;
    v_target_level INT;
    v_membership_id UUID;
    v_app_key TEXT;
    v_seat RECORD;
BEGIN
    -- A. Re-validate acting approver authority server-side
    SELECT m.user_id, m.organisation_id, m.role_key, r.level, o.status
    INTO v_actor_user_id, v_actor_org_id, v_actor_role_key, v_actor_level, v_actor_org_status
    FROM memberships m
    JOIN roles r ON r.key = m.role_key
    JOIN organisations o ON o.id = m.organisation_id
    WHERE m.id = p_acting_membership_id
      AND m.status = 'ACTIVE';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Acting approver membership % is not found or not active', p_acting_membership_id;
    END IF;

    IF v_actor_org_status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'Acting approver organisation is in % status (must be ACTIVE)', v_actor_org_status;
    END IF;

    -- B. Fetch and lock access request
    SELECT * INTO v_request
    FROM access_requests
    WHERE id = p_request_id AND request_type = 'membership' AND status = 'PENDING'
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Membership access request % not found or not pending', p_request_id;
    END IF;

    -- Approver must belong to the same organisation
    IF v_actor_org_id <> v_request.organisation_id THEN
        RAISE EXCEPTION 'Scope violation: approver organisation (%) does not match request organisation (%)',
            v_actor_org_id, v_request.organisation_id;
    END IF;

    -- C. Separation of duties
    IF v_actor_user_id = v_request.requester_user_id THEN
        RAISE EXCEPTION 'Separation of duties violation: user cannot approve their own membership request';
    END IF;

    -- D. Level ceiling check
    SELECT level INTO v_target_level FROM roles WHERE key = v_request.target_role_key;
    IF v_actor_level <= v_target_level THEN
        RAISE EXCEPTION 'Level ceiling violation: approver level (%) must be strictly greater than target role level (%)',
            v_actor_level, v_target_level;
    END IF;

    -- E. Seat Accounting Check under FOR UPDATE lock
    IF v_request.requested_apps IS NOT NULL AND array_length(v_request.requested_apps, 1) > 0 THEN
        FOREACH v_app_key IN ARRAY v_request.requested_apps
        LOOP
            SELECT * INTO v_seat
            FROM organisation_seats
            WHERE organisation_id = v_request.organisation_id
              AND app_key = v_app_key
              AND role_key = v_request.target_role_key
            FOR UPDATE;

            IF NOT FOUND THEN
                RAISE EXCEPTION 'No seat capacity configured for app % and role %', v_app_key, v_request.target_role_key;
            END IF;

            IF v_seat.allocated_seats + 1 > v_seat.seat_limit THEN
                RAISE EXCEPTION 'Seat capacity exceeded for app % and role %: limit is %, allocated is %',
                    v_app_key, v_request.target_role_key, v_seat.seat_limit, v_seat.allocated_seats;
            END IF;

            -- Increment allocated seats
            UPDATE organisation_seats
            SET allocated_seats = allocated_seats + 1,
                updated_at = now()
            WHERE id = v_seat.id;
        END LOOP;
    END IF;

    -- F. Activate / Create Membership
    INSERT INTO memberships (
        user_id,
        organisation_id,
        role_key,
        profile_id,
        status,
        expires_at
    )
    VALUES (
        v_request.requester_user_id,
        v_request.organisation_id,
        v_request.target_role_key,
        v_request.target_profile_id,
        'ACTIVE',
        CASE WHEN v_request.requested_duration IS NOT NULL THEN now() + v_request.requested_duration ELSE NULL END
    )
    ON CONFLICT (user_id, organisation_id) DO UPDATE
    SET role_key = v_request.target_role_key,
        profile_id = v_request.target_profile_id,
        status = 'ACTIVE',
        expires_at = CASE WHEN v_request.requested_duration IS NOT NULL THEN now() + v_request.requested_duration ELSE memberships.expires_at END,
        updated_at = now()
    RETURNING id INTO v_membership_id;

    -- G. Allocate Membership Seats
    IF v_request.requested_apps IS NOT NULL AND array_length(v_request.requested_apps, 1) > 0 THEN
        FOREACH v_app_key IN ARRAY v_request.requested_apps
        LOOP
            INSERT INTO membership_seats (membership_id, app_key)
            VALUES (v_membership_id, v_app_key)
            ON CONFLICT (membership_id, app_key) DO NOTHING;
        END LOOP;
    END IF;

    -- H. Record approval step
    INSERT INTO approval_steps (request_id, step_number, required_role_key, min_level, decided_by, decision, reason, decided_at)
    VALUES (p_request_id, 1, v_actor_role_key, v_actor_level, p_acting_membership_id, 'APPROVED', p_reason, now());

    -- I. Finalize request
    UPDATE access_requests
    SET status = 'APPROVED', updated_at = now()
    WHERE id = p_request_id;

    -- J. Write append-only audit log
    INSERT INTO audit_logs (actor_user_id, actor_membership_id, organisation_id, action, target_entity, target_id, diff)
    VALUES (
        v_actor_user_id,
        p_acting_membership_id,
        v_actor_org_id,
        'membership.approve',
        'membership',
        v_membership_id::text,
        jsonb_build_object(
            'target_role_key', v_request.target_role_key,
            'target_profile_id', v_request.target_profile_id,
            'allocated_apps', v_request.requested_apps,
            'reason', p_reason
        )
    );

    RETURN v_membership_id;
END;
$$;
