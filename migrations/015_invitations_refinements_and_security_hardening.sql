-- =============================================================================
-- Migration 015: Invitations Refinements and Security Hardening
-- ArchScale V05 Authentication & Authorisation Layer
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Expiry Split on Invitations (B0.1)
-- -----------------------------------------------------------------------------
ALTER TABLE public.invitations
    ADD COLUMN IF NOT EXISTS invitation_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS membership_expires_at TIMESTAMPTZ;

-- Drop NOT NULL on legacy expires_at column
ALTER TABLE public.invitations
    ALTER COLUMN expires_at DROP NOT NULL,
    ALTER COLUMN expires_at SET DEFAULT (now() + interval '7 days');

-- Migrate existing rows
UPDATE public.invitations
SET invitation_expires_at = COALESCE(expires_at, created_at + interval '7 days')
WHERE invitation_expires_at IS NULL;

-- Set default for new rows
ALTER TABLE public.invitations
    ALTER COLUMN invitation_expires_at SET DEFAULT (now() + interval '7 days'),
    ALTER COLUMN invitation_expires_at SET NOT NULL;

-- Populate membership_expires_at from existing expires_at where applicable
UPDATE public.invitations
SET membership_expires_at = expires_at
WHERE target_role_key IN ('intern', 'collaborator', 'guest')
  AND membership_expires_at IS NULL
  AND expires_at IS NOT NULL;

-- -----------------------------------------------------------------------------
-- 2. Stale Invitation Expiration Helpers (B0.3)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_mark_invitation_expired(p_raw_token TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_token_hash TEXT;
BEGIN
    IF p_raw_token IS NULL OR trim(p_raw_token) = '' THEN
        RETURN false;
    END IF;

    -- B0.4: UTF-8 encoding
    v_token_hash := encode(sha256(convert_to(p_raw_token, 'UTF8')), 'hex');

    UPDATE public.invitations
    SET status = 'Expired'
    WHERE token_hash = v_token_hash
      AND status IN ('Pending', 'Sent')
      AND invitation_expires_at <= now();

    RETURN FOUND;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_mark_invitation_expired(TEXT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_mark_invitation_expired(TEXT) TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 3. Update fn_list_org_invitations to auto-expire and return new columns (B0.1, B0.3)
-- -----------------------------------------------------------------------------
DROP FUNCTION IF EXISTS fn_list_org_invitations();
CREATE OR REPLACE FUNCTION fn_list_org_invitations()
RETURNS TABLE (
    id UUID,
    email TEXT,
    target_role_key TEXT,
    department TEXT,
    job_role TEXT,
    status TEXT,
    invitation_expires_at TIMESTAMPTZ,
    membership_expires_at TIMESTAMPTZ,
    sent_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_context_id UUID;
    v_org_id UUID;
    v_perms TEXT[];
    v_is_support BOOLEAN;
BEGIN
    v_context_id := fn_current_context_id();
    IF v_context_id IS NULL OR NOT is_context_valid(v_context_id) THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_INVALID: Valid application context required' USING ERRCODE = 'P0001';
    END IF;

    v_org_id := fn_current_context_org_id();

    SELECT (ac.support_grant_id IS NOT NULL) INTO v_is_support
    FROM public.access_contexts ac
    WHERE ac.id = v_context_id;

    -- Support contexts require platform.support.read on platform membership
    IF COALESCE(v_is_support, false) THEN
        IF NOT EXISTS (
            SELECT 1
            FROM public.access_contexts ac
            JOIN public.support_access_grants sag ON sag.id = ac.support_grant_id
            JOIN public.memberships sm ON sm.user_id = ac.user_id AND sm.organisation_id = '00000000-0000-0000-0000-000000000001'::uuid
            JOIN public.role_permissions srp ON srp.role_key = sm.role_key
            WHERE ac.id = v_context_id
              AND sm.status = 'ACTIVE'
              AND srp.permission_key = 'platform.support.read'
        ) THEN
            RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Support context requires platform.support.read'
                USING ERRCODE = '42501';
        END IF;
    ELSE
        v_perms := fn_get_effective_permissions();
        IF NOT ('org.members.invite' = ANY(v_perms)) THEN
            RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Missing required permission org.members.invite'
                USING ERRCODE = '42501';
        END IF;
    END IF;

    -- B0.3: Automatically mark expired invitations in this organisation
    UPDATE public.invitations inv
    SET status = 'Expired'
    WHERE inv.organisation_id = v_org_id
      AND inv.status IN ('Pending', 'Sent')
      AND inv.invitation_expires_at <= now();

    RETURN QUERY
    SELECT 
        i.id,
        i.email,
        i.target_role_key,
        i.department,
        i.job_role,
        i.status,
        i.invitation_expires_at,
        i.membership_expires_at,
        i.sent_at
    FROM public.invitations i
    WHERE i.organisation_id = v_org_id
    ORDER BY i.created_at DESC;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_list_org_invitations() FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_list_org_invitations() TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 4. Revert fn_audit_append no-context allowlist (B0.2)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_audit_append(
    p_action TEXT,
    p_target_entity TEXT,
    p_target_id TEXT,
    p_diff JSONB DEFAULT NULL,
    p_user_id UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_id UUID;
    v_actor_user_id UUID;
    v_actor_membership_id UUID;
    v_org_id UUID;
    v_diff_len INT;
BEGIN
    v_diff_len := octet_length(COALESCE(p_diff::text, ''));
    IF v_diff_len > 2048 THEN
        RAISE EXCEPTION 'AUTH_AUDIT_PAYLOAD_TOO_LARGE: Audit diff exceeds 2 KB limit (% bytes)', v_diff_len
            USING ERRCODE = 'P0001';
    END IF;

    IF is_context_valid() THEN
        v_actor_user_id := fn_current_context_user_id();
        v_actor_membership_id := fn_current_context_membership_id();
        v_org_id := fn_current_context_org_id();
    ELSE
        -- Strict unauthenticated allowlist: only authentication failure/revocation telemetry
        IF p_action NOT IN (
            'AUTH_SIGNIN_FAILED',
            'AUTH_CONTEXT_DENIED',
            'AUTH_TOKEN_TAMPERED',
            'AUTH_SESSION_REVOKED'
        ) THEN
            RAISE EXCEPTION 'AUTH_AUDIT_UNAUTHORIZED: Action % is not permitted without a validated context', p_action
                USING ERRCODE = 'P0001';
        END IF;

        v_actor_user_id := p_user_id;
        v_actor_membership_id := NULL;
        v_org_id := NULL;
    END IF;

    v_id := gen_random_uuid();
    INSERT INTO public.audit_logs (
        id,
        action,
        actor_user_id,
        actor_membership_id,
        organisation_id,
        target_entity,
        target_id,
        diff,
        created_at
    ) VALUES (
        v_id,
        p_action,
        v_actor_user_id,
        v_actor_membership_id,
        v_org_id,
        p_target_entity,
        p_target_id,
        p_diff,
        now()
    );

    RETURN v_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_audit_append(TEXT, TEXT, TEXT, JSONB, UUID) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_audit_append(TEXT, TEXT, TEXT, JSONB, UUID) TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 5. fn_create_invitation with Expiry Split and Dynamic roles.expiry_required (B0.1)
-- -----------------------------------------------------------------------------
DROP FUNCTION IF EXISTS fn_create_invitation(TEXT, TEXT, UUID, TEXT, TEXT, UUID, TIMESTAMPTZ, TEXT);
CREATE OR REPLACE FUNCTION fn_create_invitation(
    p_target_email TEXT,
    p_target_role_key TEXT,
    p_access_profile_id UUID DEFAULT NULL,
    p_department TEXT DEFAULT NULL,
    p_job_role TEXT DEFAULT NULL,
    p_reporting_manager_membership_id UUID DEFAULT NULL,
    p_invitation_expires_at TIMESTAMPTZ DEFAULT NULL,
    p_membership_expires_at TIMESTAMPTZ DEFAULT NULL,
    p_token_hash TEXT DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_ctx_id UUID;
    v_caller_mem_id UUID;
    v_org_id UUID;
    v_caller_role_key TEXT;
    v_caller_level INT;
    v_target_level INT;
    v_expiry_required BOOLEAN;
    v_inv_expires_at TIMESTAMPTZ := p_invitation_expires_at;
    v_inv_id UUID;
    v_clean_email TEXT;
BEGIN
    v_ctx_id := fn_current_context_id();
    IF v_ctx_id IS NULL OR NOT is_context_valid(v_ctx_id) THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_INVALID: Valid application context required' USING ERRCODE = 'P0001';
    END IF;

    PERFORM fn_assert_not_support_context();

    v_org_id := fn_current_context_org_id();
    v_caller_mem_id := fn_current_context_membership_id();

    IF NOT ('org.members.invite' = ANY(fn_get_effective_permissions())) THEN
        RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Missing required permission org.members.invite'
            USING ERRCODE = '42501';
    END IF;

    v_clean_email := lower(trim(p_target_email));
    IF v_clean_email IS NULL OR v_clean_email = '' OR position('@' in v_clean_email) = 0 THEN
        RAISE EXCEPTION 'Invalid target email address' USING ERRCODE = '22023';
    END IF;

    -- Approver ceiling: caller level must be strictly > target level
    SELECT r.level, m.role_key INTO v_caller_level, v_caller_role_key
    FROM public.memberships m
    JOIN public.roles r ON r.key = m.role_key
    WHERE m.id = v_caller_mem_id;

    -- Query target role metadata from roles table (no hardcoded role names!)
    SELECT r.level, r.expiry_required INTO v_target_level, v_expiry_required
    FROM public.roles r
    WHERE r.key = p_target_role_key AND r.portal = 'subscriber';

    IF v_target_level IS NULL THEN
        RAISE EXCEPTION 'Invalid target subscriber role: %', p_target_role_key USING ERRCODE = 'P0002';
    END IF;

    IF v_caller_level <= v_target_level THEN
        RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Approver level (%) must be strictly greater than target role level (%)',
            v_caller_level, v_target_level USING ERRCODE = '42501';
    END IF;

    -- Validate invitation validity (default 7 days, max 30 days)
    IF v_inv_expires_at IS NULL THEN
        v_inv_expires_at := now() + interval '7 days';
    END IF;

    IF v_inv_expires_at <= now() THEN
        RAISE EXCEPTION 'invitation_expires_at must be in the future' USING ERRCODE = '22023';
    END IF;

    IF v_inv_expires_at > (now() + interval '30 days') THEN
        RAISE EXCEPTION 'invitation_expires_at validity cannot exceed 30 days' USING ERRCODE = '22023';
    END IF;

    -- Validate membership_expires_at via roles.expiry_required
    IF v_expiry_required THEN
        IF p_membership_expires_at IS NULL THEN
            RAISE EXCEPTION 'Target role % requires an explicit membership_expires_at', p_target_role_key USING ERRCODE = '22023';
        END IF;
        IF p_membership_expires_at <= now() THEN
            RAISE EXCEPTION 'membership_expires_at must be in the future' USING ERRCODE = '22023';
        END IF;
    END IF;

    IF p_access_profile_id IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM public.access_profiles
            WHERE id = p_access_profile_id
              AND organisation_id = v_org_id
              AND role_key = p_target_role_key
        ) THEN
            RAISE EXCEPTION 'Access profile does not match target role and organisation' USING ERRCODE = 'P0001';
        END IF;
    END IF;

    IF p_reporting_manager_membership_id IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM public.memberships
            WHERE id = p_reporting_manager_membership_id
              AND organisation_id = v_org_id
              AND status = 'ACTIVE'
        ) THEN
            RAISE EXCEPTION 'Reporting manager must be an ACTIVE member in the same organisation' USING ERRCODE = 'P0001';
        END IF;
    END IF;

    INSERT INTO public.invitations (
        email,
        organisation_id,
        target_role_key,
        access_profile_id,
        department,
        job_role,
        reporting_manager_membership_id,
        invited_by_membership_id,
        token_hash,
        invitation_expires_at,
        membership_expires_at,
        expires_at,
        status
    ) VALUES (
        v_clean_email,
        v_org_id,
        p_target_role_key,
        p_access_profile_id,
        p_department,
        p_job_role,
        p_reporting_manager_membership_id,
        v_caller_mem_id,
        COALESCE(p_token_hash, encode(gen_random_bytes(32), 'hex')),
        v_inv_expires_at,
        p_membership_expires_at,
        v_inv_expires_at,
        'Pending'
    )
    RETURNING id INTO v_inv_id;

    PERFORM fn_audit_append(
        'invitation.created',
        'invitations',
        v_inv_id::text,
        jsonb_build_object(
            'email', v_clean_email,
            'target_role_key', p_target_role_key,
            'department', p_department,
            'job_role', p_job_role,
            'invitation_expires_at', v_inv_expires_at,
            'membership_expires_at', p_membership_expires_at
        )
    );

    RETURN v_inv_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_create_invitation(TEXT, TEXT, UUID, TEXT, TEXT, UUID, TIMESTAMPTZ, TIMESTAMPTZ, TEXT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_create_invitation(TEXT, TEXT, UUID, TEXT, TEXT, UUID, TIMESTAMPTZ, TIMESTAMPTZ, TEXT) TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 6. fn_accept_invitation UTF-8, Membership Expiry, Direct Audit (B0.1, B0.2, B0.3, B0.4)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_accept_invitation(
    p_raw_token TEXT,
    p_user_id UUID
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_token_hash TEXT;
    v_inv RECORD;
    v_user_email TEXT;
    v_inviter_status public.membership_status;
    v_org_status public.org_status;
    v_request_id UUID;
    v_membership_id UUID;
    v_requested_duration INTERVAL;
BEGIN
    IF p_raw_token IS NULL OR trim(p_raw_token) = '' THEN
        RAISE EXCEPTION 'Token is required' USING ERRCODE = '22023';
    END IF;

    -- B0.4: convert_to(p_raw_token, 'UTF8')
    v_token_hash := encode(sha256(convert_to(p_raw_token, 'UTF8')), 'hex');

    SELECT * INTO v_inv
    FROM public.invitations
    WHERE token_hash = v_token_hash
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'AUTH_INVITATION_NOT_FOUND: Invalid invitation token' USING ERRCODE = 'P0002';
    END IF;

    -- B0.3: Check expiry against invitation_expires_at
    IF v_inv.invitation_expires_at <= now() THEN
        UPDATE public.invitations SET status = 'Expired' WHERE id = v_inv.id;
        RAISE EXCEPTION 'AUTH_INVITATION_EXPIRED: Invitation has expired' USING ERRCODE = 'P0001';
    END IF;

    IF v_inv.status <> 'Sent' THEN
        RAISE EXCEPTION 'AUTH_INVITATION_INVALID_STATUS: Invitation status is %, cannot be accepted', v_inv.status
            USING ERRCODE = 'P0001';
    END IF;

    IF v_inv.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'AUTH_INVITATION_REVOKED: Invitation has been revoked' USING ERRCODE = 'P0001';
    END IF;

    SELECT email INTO v_user_email
    FROM public.users
    WHERE id = p_user_id;

    IF v_user_email IS NULL OR lower(v_user_email) <> lower(v_inv.email) THEN
        RAISE EXCEPTION 'AUTH_INVITATION_EMAIL_MISMATCH: Authenticated user email does not match invitation'
            USING ERRCODE = '42501';
    END IF;

    SELECT m.status, o.status
    INTO v_inviter_status, v_org_status
    FROM public.memberships m
    JOIN public.organisations o ON o.id = m.organisation_id
    WHERE m.id = v_inv.invited_by_membership_id;

    IF v_inviter_status IS NULL OR v_inviter_status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'AUTH_INVITATION_INVITER_INACTIVE: Inviting member is no longer active'
            USING ERRCODE = 'P0001';
    END IF;

    IF v_org_status IS NULL OR v_org_status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'AUTH_INVITATION_ORG_INACTIVE: Target organisation is not active'
            USING ERRCODE = 'P0001';
    END IF;

    -- B0.1: Duration computed directly from membership_expires_at (no hardcoded CASE)
    IF v_inv.membership_expires_at IS NOT NULL THEN
        v_requested_duration := (v_inv.membership_expires_at - now());
    ELSE
        v_requested_duration := NULL;
    END IF;

    INSERT INTO public.access_requests (
        request_type,
        requester_user_id,
        organisation_id,
        target_role_key,
        target_profile_id,
        justification,
        requested_duration,
        status
    ) VALUES (
        'membership',
        p_user_id,
        v_inv.organisation_id,
        v_inv.target_role_key,
        v_inv.access_profile_id,
        'Accepted invitation ' || v_inv.id::text,
        v_requested_duration,
        'PENDING'
    )
    RETURNING id INTO v_request_id;

    -- Approval path enforces seat checks and ceiling
    v_membership_id := fn_approve_membership(
        v_request_id,
        v_inv.invited_by_membership_id,
        'Invitation token accepted'
    );

    -- Apply membership_expires_at, department, job_role, reporting manager
    UPDATE public.memberships
    SET department = v_inv.department,
        job_role = v_inv.job_role,
        reporting_manager_membership_id = v_inv.reporting_manager_membership_id,
        expires_at = v_inv.membership_expires_at
    WHERE id = v_membership_id;

    UPDATE public.invitations
    SET status = 'Accepted',
        accepted_at = now()
    WHERE id = v_inv.id;

    -- B0.2: Direct audit logging inside SECURITY DEFINER without opening fn_audit_append allowlist
    INSERT INTO public.audit_logs (
        id,
        action,
        actor_user_id,
        actor_membership_id,
        organisation_id,
        target_entity,
        target_id,
        diff,
        created_at
    ) VALUES (
        gen_random_uuid(),
        'invitation.accepted',
        p_user_id,
        v_membership_id,
        v_inv.organisation_id,
        'invitations',
        v_inv.id::text,
        jsonb_build_object(
            'invitation_id', v_inv.id,
            'membership_id', v_membership_id,
            'user_id', p_user_id,
            'organisation_id', v_inv.organisation_id,
            'membership_expires_at', v_inv.membership_expires_at
        ),
        now()
    );

    RETURN v_membership_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_accept_invitation(TEXT, UUID) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_accept_invitation(TEXT, UUID) TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 7. Backstage Administration Functions (B0.6)
-- -----------------------------------------------------------------------------

-- Backstage Approve Organisation
CREATE OR REPLACE FUNCTION fn_platform_approve_organisation(
    p_target_org_id UUID,
    p_reason TEXT DEFAULT 'Approved by platform administrator'
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_ctx_id UUID;
BEGIN
    v_ctx_id := fn_current_context_id();
    IF v_ctx_id IS NULL OR NOT is_context_valid(v_ctx_id) THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_INVALID: Valid application context required' USING ERRCODE = 'P0001';
    END IF;

    PERFORM fn_assert_not_support_context();

    IF NOT ('platform.organisations.manage' = ANY(fn_get_effective_permissions())) THEN
        RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Missing required permission platform.organisations.manage'
            USING ERRCODE = '42501';
    END IF;

    UPDATE public.organisations
    SET status = 'ACTIVE',
        updated_at = now()
    WHERE id = p_target_org_id AND portal = 'subscriber';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Subscriber organisation not found' USING ERRCODE = 'P0002';
    END IF;

    -- Ensure a default workspace exists for the active subscriber org
    INSERT INTO public.workspaces (organisation_id, name, is_active)
    SELECT p_target_org_id, 'Default Workspace', true
    WHERE NOT EXISTS (
        SELECT 1 FROM public.workspaces WHERE organisation_id = p_target_org_id
    );

    PERFORM fn_audit_append(
        'platform.org.approved',
        'organisations',
        p_target_org_id::text,
        jsonb_build_object('reason', p_reason)
    );

    RETURN true;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_platform_approve_organisation(UUID, TEXT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_platform_approve_organisation(UUID, TEXT) TO archscale_app_runtime;

-- Backstage Invite Tenant Admin
CREATE OR REPLACE FUNCTION fn_platform_invite_tenant_admin(
    p_target_org_id UUID,
    p_target_email TEXT,
    p_invitation_expires_at TIMESTAMPTZ DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_ctx_id UUID;
    v_caller_mem_id UUID;
    v_org_status public.org_status;
    v_clean_email TEXT;
    v_inv_expires_at TIMESTAMPTZ := p_invitation_expires_at;
    v_inv_id UUID;
BEGIN
    v_ctx_id := fn_current_context_id();
    IF v_ctx_id IS NULL OR NOT is_context_valid(v_ctx_id) THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_INVALID: Valid application context required' USING ERRCODE = 'P0001';
    END IF;

    PERFORM fn_assert_not_support_context();

    IF NOT ('platform.organisations.manage' = ANY(fn_get_effective_permissions())) THEN
        RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Missing required permission platform.organisations.manage'
            USING ERRCODE = '42501';
    END IF;

    SELECT status INTO v_org_status
    FROM public.organisations
    WHERE id = p_target_org_id AND portal = 'subscriber';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Target subscriber organisation not found' USING ERRCODE = 'P0002';
    END IF;

    v_caller_mem_id := fn_current_context_membership_id();
    v_clean_email := lower(trim(p_target_email));
    IF v_clean_email IS NULL OR v_clean_email = '' OR position('@' in v_clean_email) = 0 THEN
        RAISE EXCEPTION 'Invalid target email address' USING ERRCODE = '22023';
    END IF;

    IF v_inv_expires_at IS NULL THEN
        v_inv_expires_at := now() + interval '7 days';
    END IF;

    INSERT INTO public.invitations (
        email,
        organisation_id,
        target_role_key,
        department,
        job_role,
        invited_by_membership_id,
        token_hash,
        invitation_expires_at,
        expires_at,
        status
    ) VALUES (
        v_clean_email,
        p_target_org_id,
        'business_owner',
        'Executive',
        'Business Owner',
        v_caller_mem_id,
        encode(gen_random_bytes(32), 'hex'),
        v_inv_expires_at,
        v_inv_expires_at,
        'Pending'
    )
    RETURNING id INTO v_inv_id;

    PERFORM fn_audit_append(
        'platform.org.admin_invited',
        'invitations',
        v_inv_id::text,
        jsonb_build_object(
            'target_org_id', p_target_org_id,
            'email', v_clean_email,
            'target_role_key', 'business_owner'
        )
    );

    RETURN v_inv_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_platform_invite_tenant_admin(UUID, TEXT, TIMESTAMPTZ) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_platform_invite_tenant_admin(UUID, TEXT, TIMESTAMPTZ) TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 8. Frontstage Support Grants List for Tenant Admin (B0.6)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_list_org_support_grants()
RETURNS TABLE (
    id UUID,
    staff_membership_id UUID,
    reason TEXT,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_ctx_id UUID;
    v_org_id UUID;
BEGIN
    v_ctx_id := fn_current_context_id();
    IF v_ctx_id IS NULL OR NOT is_context_valid(v_ctx_id) THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_INVALID: Valid application context required' USING ERRCODE = 'P0001';
    END IF;

    PERFORM fn_assert_not_support_context();

    IF NOT ('org.settings.manage' = ANY(fn_get_effective_permissions())) THEN
        RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Missing required permission org.settings.manage'
            USING ERRCODE = '42501';
    END IF;

    v_org_id := fn_current_context_org_id();

    RETURN QUERY
    SELECT
        sag.id,
        sag.staff_membership_id,
        sag.reason,
        sag.expires_at,
        sag.created_at,
        sag.revoked_at
    FROM public.support_access_grants sag
    WHERE sag.target_organisation_id = v_org_id
    ORDER BY sag.created_at DESC;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_list_org_support_grants() FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_list_org_support_grants() TO archscale_app_runtime;
