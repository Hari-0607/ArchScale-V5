-- =============================================================================
-- Migration 013: Context-Bound RLS, Authorisation Functions, and Support Contexts
-- ArchScale V05 Authentication & Authorisation Layer
-- =============================================================================
-- Binding document: docs/PHASE2_RLS_DESIGN.md
-- Key guarantees:
--   1. support_grant_id added to access_contexts; continuous grant validation
--   2. fn_set_app_context(context_id, user_id, session_id) validates anchors
--   3. is_context_valid(uuid) is SECURITY DEFINER with safe NULLIF GUC casts
--   4. Pre-context listing functions with minimum column exposure
--   5. Atomic fn_create_access_context, renew, revoke with 24h hard cap
--   6. fn_assert_not_support_context() enforces fail-closed read-only support
--   7. fn_audit_append derives context actors; allowlist for unauthenticated
--   8. fn_read_audit_logs permission-gated; direct audit SELECT revoked
--   9. Table RLS policies: all re-check is_context_valid; no bare GUC trusted
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Schema Additions
-- -----------------------------------------------------------------------------
ALTER TABLE public.access_contexts
    ADD COLUMN IF NOT EXISTS support_grant_id UUID REFERENCES public.support_access_grants(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_access_contexts_support_grant
    ON public.access_contexts(support_grant_id);

-- -----------------------------------------------------------------------------
-- 2. Context Helper Functions
-- -----------------------------------------------------------------------------

-- Extract UUID from transaction-local GUC safely without throwing on empty string
CREATE OR REPLACE FUNCTION fn_current_context_id()
RETURNS UUID
LANGUAGE sql
STABLE
AS $$
    SELECT NULLIF(current_setting('archscale.current_context_id', true), '')::uuid;
$$;

REVOKE EXECUTE ON FUNCTION fn_current_context_id() FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_current_context_id() TO archscale_app_runtime;

-- Central context validity checker (SECURITY DEFINER, public + extensions + pg_temp)
CREATE OR REPLACE FUNCTION is_context_valid(p_context_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_ctx RECORD;
    v_grant RECORD;
BEGIN
    IF p_context_id IS NULL THEN
        RETURN FALSE;
    END IF;

    SELECT
        ac.id,
        ac.revoked_at,
        ac.expires_at,
        ac.support_grant_id,
        m.status AS membership_status,
        m.expires_at AS membership_expires_at,
        o.status AS org_status,
        w.is_active AS workspace_active
    INTO v_ctx
    FROM access_contexts ac
    JOIN memberships m ON m.id = ac.membership_id
    JOIN organisations o ON o.id = ac.organisation_id
    JOIN workspaces w ON w.id = ac.workspace_id
    WHERE ac.id = p_context_id;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    -- Fundamental invariants
    IF v_ctx.revoked_at IS NOT NULL THEN
        RETURN FALSE;
    END IF;
    IF v_ctx.expires_at <= now() THEN
        RETURN FALSE;
    END IF;
    IF v_ctx.org_status <> 'ACTIVE' THEN
        RETURN FALSE;
    END IF;
    IF v_ctx.membership_status <> 'ACTIVE' THEN
        RETURN FALSE;
    END IF;
    IF v_ctx.membership_expires_at IS NOT NULL AND v_ctx.membership_expires_at <= now() THEN
        RETURN FALSE;
    END IF;
    IF v_ctx.workspace_active IS NOT TRUE THEN
        RETURN FALSE;
    END IF;

    -- Support context verification: re-check support grant on every call
    IF v_ctx.support_grant_id IS NOT NULL THEN
        SELECT sag.id, sag.revoked_at, sag.expires_at
        INTO v_grant
        FROM support_access_grants sag
        WHERE sag.id = v_ctx.support_grant_id;

        IF NOT FOUND THEN
            RETURN FALSE;
        END IF;
        IF v_grant.revoked_at IS NOT NULL THEN
            RETURN FALSE;
        END IF;
        IF v_grant.expires_at <= now() THEN
            RETURN FALSE;
        END IF;
    END IF;

    RETURN TRUE;
END;
$$;

REVOKE EXECUTE ON FUNCTION is_context_valid(UUID) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION is_context_valid(UUID) TO archscale_app_runtime;

-- Parameterless is_context_valid() for RLS policies
CREATE OR REPLACE FUNCTION is_context_valid()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
    SELECT COALESCE(is_context_valid(fn_current_context_id()), false);
$$;

REVOKE EXECUTE ON FUNCTION is_context_valid() FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION is_context_valid() TO archscale_app_runtime;

-- Transaction context user ID
CREATE OR REPLACE FUNCTION fn_current_context_user_id()
RETURNS UUID
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_ctx_id UUID;
    v_user_id UUID;
BEGIN
    v_ctx_id := fn_current_context_id();
    IF v_ctx_id IS NULL OR NOT is_context_valid(v_ctx_id) THEN
        RETURN NULL;
    END IF;

    SELECT user_id INTO v_user_id
    FROM access_contexts
    WHERE id = v_ctx_id;

    RETURN v_user_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_current_context_user_id() FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_current_context_user_id() TO archscale_app_runtime;

-- Transaction context organisation ID
CREATE OR REPLACE FUNCTION fn_current_context_org_id()
RETURNS UUID
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_ctx_id UUID;
    v_org_id UUID;
BEGIN
    v_ctx_id := fn_current_context_id();
    IF v_ctx_id IS NULL OR NOT is_context_valid(v_ctx_id) THEN
        RETURN NULL;
    END IF;

    SELECT organisation_id INTO v_org_id
    FROM access_contexts
    WHERE id = v_ctx_id;

    RETURN v_org_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_current_context_org_id() FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_current_context_org_id() TO archscale_app_runtime;

-- Transaction context membership ID
CREATE OR REPLACE FUNCTION fn_current_context_membership_id()
RETURNS UUID
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_ctx_id UUID;
    v_membership_id UUID;
BEGIN
    v_ctx_id := fn_current_context_id();
    IF v_ctx_id IS NULL OR NOT is_context_valid(v_ctx_id) THEN
        RETURN NULL;
    END IF;

    SELECT membership_id INTO v_membership_id
    FROM access_contexts
    WHERE id = v_ctx_id;

    RETURN v_membership_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_current_context_membership_id() FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_current_context_membership_id() TO archscale_app_runtime;

-- Assert that current context is not a support context (read-only enforcement)
CREATE OR REPLACE FUNCTION fn_assert_not_support_context()
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_ctx_id UUID;
    v_grant_id UUID;
BEGIN
    v_ctx_id := fn_current_context_id();
    IF v_ctx_id IS NOT NULL THEN
        SELECT support_grant_id INTO v_grant_id
        FROM access_contexts
        WHERE id = v_ctx_id;

        IF v_grant_id IS NOT NULL THEN
            RAISE EXCEPTION 'AUTH_SUPPORT_READ_ONLY: Support contexts are read-only and cannot perform mutations or approvals'
                USING ERRCODE = 'P0001';
        END IF;
    END IF;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_assert_not_support_context() FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_assert_not_support_context() TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 3. Transaction-Local Context Setter (3-anchor validation)
-- -----------------------------------------------------------------------------
DROP FUNCTION IF EXISTS fn_set_app_context(UUID);

CREATE OR REPLACE FUNCTION fn_set_app_context(
    p_context_id UUID,
    p_user_id UUID,
    p_session_id TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_ctx RECORD;
BEGIN
    IF p_context_id IS NULL OR p_user_id IS NULL OR p_session_id IS NULL OR trim(p_session_id) = '' THEN
        RAISE EXCEPTION 'ARCHSCALE_INVALID_CONTEXT: Missing context_id, user_id, or session_id'
            USING ERRCODE = 'P0001';
    END IF;

    SELECT id INTO v_ctx
    FROM access_contexts
    WHERE id = p_context_id
      AND user_id = p_user_id
      AND session_id = p_session_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'ARCHSCALE_INVALID_CONTEXT: Context binding mismatch for context %', p_context_id
            USING ERRCODE = 'P0001';
    END IF;

    IF NOT is_context_valid(p_context_id) THEN
        RAISE EXCEPTION 'ARCHSCALE_INVALID_CONTEXT: Context % is invalid, expired, or revoked', p_context_id
            USING ERRCODE = 'P0001';
    END IF;

    PERFORM set_config('archscale.current_context_id', p_context_id::text, true);
    RETURN true;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_set_app_context(UUID, UUID, TEXT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_set_app_context(UUID, UUID, TEXT) TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 4. Pre-Context Listing Functions (Login / Selection Time)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_list_principal_memberships(p_user_id UUID)
RETURNS TABLE (
    membership_id UUID,
    organisation_id UUID,
    organisation_name TEXT,
    role_key TEXT,
    portal portal_type,
    tenant_type_key TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
BEGIN
    IF p_user_id IS NULL THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT
        m.id AS membership_id,
        o.id AS organisation_id,
        o.name AS organisation_name,
        m.role_key,
        o.portal,
        o.tenant_type_key
    FROM memberships m
    JOIN organisations o ON o.id = m.organisation_id
    WHERE m.user_id = p_user_id
      AND m.status = 'ACTIVE'
      AND o.status = 'ACTIVE'
      AND (m.expires_at IS NULL OR m.expires_at > now())
    ORDER BY o.name ASC;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_list_principal_memberships(UUID) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_list_principal_memberships(UUID) TO archscale_app_runtime;

CREATE OR REPLACE FUNCTION fn_list_org_workspaces_for_principal(
    p_user_id UUID,
    p_organisation_id UUID
)
RETURNS TABLE (
    workspace_id UUID,
    workspace_name TEXT,
    is_default BOOLEAN,
    is_active BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
BEGIN
    IF p_user_id IS NULL OR p_organisation_id IS NULL THEN
        RETURN;
    END IF;

    -- Principal must have active membership in this org, OR an active support grant targeting this org
    IF NOT EXISTS (
        SELECT 1 FROM memberships
        WHERE user_id = p_user_id
          AND organisation_id = p_organisation_id
          AND status = 'ACTIVE'
          AND (expires_at IS NULL OR expires_at > now())
    ) AND NOT EXISTS (
        SELECT 1 FROM support_access_grants sag
        JOIN memberships m ON m.id = sag.staff_membership_id
        WHERE m.user_id = p_user_id
          AND sag.target_organisation_id = p_organisation_id
          AND sag.revoked_at IS NULL
          AND sag.expires_at > now()
    ) THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT
        w.id AS workspace_id,
        w.name AS workspace_name,
        w.is_default,
        w.is_active
    FROM workspaces w
    WHERE w.organisation_id = p_organisation_id
      AND w.is_active = true
    ORDER BY w.is_default DESC, w.name ASC;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_list_org_workspaces_for_principal(UUID, UUID) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_list_org_workspaces_for_principal(UUID, UUID) TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 5. Context Lifecycle Management Functions
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION fn_active_support_grant(p_target_org_id UUID)
RETURNS UUID
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_staff_membership_id UUID;
    v_grant_id UUID;
BEGIN
    v_staff_membership_id := fn_current_context_membership_id();
    IF v_staff_membership_id IS NULL OR p_target_org_id IS NULL THEN
        RETURN NULL;
    END IF;

    SELECT sag.id INTO v_grant_id
    FROM support_access_grants sag
    WHERE sag.staff_membership_id = v_staff_membership_id
      AND sag.target_organisation_id = p_target_org_id
      AND sag.revoked_at IS NULL
      AND sag.expires_at > now()
    LIMIT 1;

    RETURN v_grant_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_active_support_grant(UUID) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_active_support_grant(UUID) TO archscale_app_runtime;

-- Create Access Context
CREATE OR REPLACE FUNCTION fn_create_access_context(
    p_user_id UUID,
    p_session_id TEXT,
    p_organisation_id UUID,
    p_workspace_id UUID,
    p_aal TEXT DEFAULT 'aal1',
    p_support_grant_id UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_user_exists BOOLEAN;
    v_org RECORD;
    v_workspace RECORD;
    v_membership RECORD;
    v_grant RECORD;
    v_context_id UUID;
    v_expires_at TIMESTAMPTZ;
    v_aal aal_level;
BEGIN
    v_aal := COALESCE(p_aal::aal_level, 'aal1'::aal_level);
    -- 1. Validate User
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: Missing user id' USING ERRCODE = 'P0001';
    END IF;
    SELECT EXISTS(SELECT 1 FROM public.users WHERE id = p_user_id) INTO v_user_exists;
    IF NOT v_user_exists THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: User does not exist' USING ERRCODE = 'P0001';
    END IF;

    -- 2. Validate Session ID
    IF p_session_id IS NULL OR trim(p_session_id) = '' THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: Missing or empty session id' USING ERRCODE = 'P0001';
    END IF;

    -- 3. Validate Organisation
    SELECT * INTO v_org
    FROM organisations
    WHERE id = p_organisation_id;
    IF NOT FOUND OR v_org.status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: Organisation not found or inactive' USING ERRCODE = 'P0001';
    END IF;

    -- 4. Validate Workspace
    SELECT * INTO v_workspace
    FROM workspaces
    WHERE id = p_workspace_id AND organisation_id = p_organisation_id;
    IF NOT FOUND OR v_workspace.is_active IS NOT TRUE THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: Workspace not found, inactive, or org mismatch' USING ERRCODE = 'P0001';
    END IF;

    -- 5. Validate Membership and Support Grant
    IF p_support_grant_id IS NULL THEN
        -- Standard context path
        SELECT m.*, r.portal AS role_portal INTO v_membership
        FROM memberships m
        JOIN roles r ON r.key = m.role_key
        WHERE m.user_id = p_user_id
          AND m.organisation_id = p_organisation_id;

        IF NOT FOUND OR v_membership.status <> 'ACTIVE' THEN
            RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: Membership not found or inactive' USING ERRCODE = 'P0001';
        END IF;

        IF v_membership.expires_at IS NOT NULL AND v_membership.expires_at <= now() THEN
            RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: Membership has expired' USING ERRCODE = 'P0001';
        END IF;

        IF v_membership.role_portal <> v_org.portal THEN
            RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: Role portal does not match organisation portal' USING ERRCODE = 'P0001';
        END IF;

        IF v_org.portal = 'subscriber' THEN
            -- Check role tenant types
            IF NOT EXISTS (
                SELECT 1 FROM role_tenant_types
                WHERE role_key = v_membership.role_key AND tenant_type_key = v_org.tenant_type_key
            ) THEN
                RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: Role not permitted for tenant type' USING ERRCODE = 'P0001';
            END IF;

            -- Check at least one enabled entitlement
            IF NOT EXISTS (
                SELECT 1 FROM organisation_entitlements
                WHERE organisation_id = p_organisation_id AND is_enabled = true
            ) THEN
                RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: Organisation has no active entitlements' USING ERRCODE = 'P0001';
            END IF;
        END IF;

        v_expires_at := LEAST(
            now() + interval '24 hours',
            COALESCE(v_membership.expires_at, now() + interval '24 hours')
        );
    ELSE
        -- Support context path (Platform staff servicing subscriber org)
        IF v_org.portal <> 'subscriber' THEN
            RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: Support grant targets non-subscriber organisation' USING ERRCODE = 'P0001';
        END IF;

        -- Fetch staff membership in platform org
        SELECT m.*, r.portal AS role_portal, o.portal AS org_portal
        INTO v_membership
        FROM memberships m
        JOIN roles r ON r.key = m.role_key
        JOIN organisations o ON o.id = m.organisation_id
        WHERE m.user_id = p_user_id AND o.portal = 'platform' AND m.status = 'ACTIVE';

        IF NOT FOUND THEN
            RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: Platform staff membership not found' USING ERRCODE = 'P0001';
        END IF;

        IF v_membership.expires_at IS NOT NULL AND v_membership.expires_at <= now() THEN
            RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: Platform staff membership expired' USING ERRCODE = 'P0001';
        END IF;

        -- Verify grant
        SELECT * INTO v_grant
        FROM support_access_grants
        WHERE id = p_support_grant_id
          AND staff_membership_id = v_membership.id
          AND target_organisation_id = p_organisation_id;

        IF NOT FOUND OR v_grant.revoked_at IS NOT NULL OR v_grant.expires_at <= now() THEN
            RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: Active support grant required' USING ERRCODE = 'P0001';
        END IF;

        v_expires_at := LEAST(
            now() + interval '24 hours',
            COALESCE(v_membership.expires_at, now() + interval '24 hours'),
            v_grant.expires_at
        );
    END IF;

    -- 6. Insert access context
    v_context_id := gen_random_uuid();
    INSERT INTO access_contexts (
        id,
        user_id,
        session_id,
        organisation_id,
        workspace_id,
        membership_id,
        aal_level,
        created_at,
        expires_at,
        support_grant_id
    ) VALUES (
        v_context_id,
        p_user_id,
        p_session_id,
        p_organisation_id,
        p_workspace_id,
        v_membership.id,
        COALESCE(v_aal, 'aal1'::aal_level),
        now(),
        v_expires_at,
        p_support_grant_id
    );

    -- 7. Audit context creation
    INSERT INTO audit_logs (
        actor_user_id,
        actor_membership_id,
        organisation_id,
        action,
        target_entity,
        target_id,
        diff
    ) VALUES (
        p_user_id,
        v_membership.id,
        p_organisation_id,
        'context.create',
        'access_context',
        v_context_id::text,
        jsonb_build_object(
            'workspace_id', p_workspace_id,
            'is_support', p_support_grant_id IS NOT NULL,
            'aal_level', v_aal
        )
    );

    RETURN v_context_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_create_access_context(UUID, TEXT, UUID, UUID, TEXT, UUID) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_create_access_context(UUID, TEXT, UUID, UUID, TEXT, UUID) TO archscale_app_runtime;

-- Renew Access Context
CREATE OR REPLACE FUNCTION fn_renew_access_context(
    p_context_id UUID,
    p_user_id UUID,
    p_session_id TEXT
)
RETURNS TABLE (
    context_id UUID,
    expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_ctx RECORD;
    v_membership RECORD;
    v_org RECORD;
    v_grant RECORD;
    v_new_expires_at TIMESTAMPTZ;
BEGIN
    SELECT * INTO v_ctx
    FROM access_contexts
    WHERE id = p_context_id
      AND user_id = p_user_id
      AND session_id = p_session_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: Context not found or session mismatch' USING ERRCODE = 'P0001';
    END IF;

    -- Hard 24h lifetime bound from original creation
    IF v_ctx.created_at + interval '24 hours' <= now() THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: Context has reached hard 24h lifetime cap; new context required'
            USING ERRCODE = 'P0001';
    END IF;

    IF v_ctx.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: Context has been revoked' USING ERRCODE = 'P0001';
    END IF;

    -- Re-validate organisation
    SELECT * INTO v_org FROM organisations WHERE id = v_ctx.organisation_id;
    IF NOT FOUND OR v_org.status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: Organisation is inactive' USING ERRCODE = 'P0001';
    END IF;

    -- Re-validate workspace
    IF NOT EXISTS (SELECT 1 FROM workspaces WHERE id = v_ctx.workspace_id AND is_active = true) THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: Workspace is inactive' USING ERRCODE = 'P0001';
    END IF;

    -- Re-validate membership
    SELECT * INTO v_membership FROM memberships WHERE id = v_ctx.membership_id;
    IF NOT FOUND OR v_membership.status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: Membership is inactive' USING ERRCODE = 'P0001';
    END IF;

    IF v_membership.expires_at IS NOT NULL AND v_membership.expires_at <= now() THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: Membership has expired' USING ERRCODE = 'P0001';
    END IF;

    -- Re-validate support grant if support context
    IF v_ctx.support_grant_id IS NOT NULL THEN
        SELECT * INTO v_grant FROM support_access_grants WHERE id = v_ctx.support_grant_id;
        IF NOT FOUND OR v_grant.revoked_at IS NOT NULL OR v_grant.expires_at <= now() THEN
            RAISE EXCEPTION 'AUTH_CONTEXT_DENIED: Support grant has expired or been revoked' USING ERRCODE = 'P0001';
        END IF;

        v_new_expires_at := LEAST(
            now() + interval '24 hours',
            COALESCE(v_membership.expires_at, now() + interval '24 hours'),
            v_grant.expires_at,
            v_ctx.created_at + interval '24 hours'
        );
    ELSE
        v_new_expires_at := LEAST(
            now() + interval '24 hours',
            COALESCE(v_membership.expires_at, now() + interval '24 hours'),
            v_ctx.created_at + interval '24 hours'
        );
    END IF;

    UPDATE access_contexts
    SET expires_at = v_new_expires_at,
        last_active_at = now()
    WHERE id = p_context_id;

    -- Audit context renewal
    INSERT INTO audit_logs (
        actor_user_id,
        actor_membership_id,
        organisation_id,
        action,
        target_entity,
        target_id,
        diff
    ) VALUES (
        p_user_id,
        v_ctx.membership_id,
        v_ctx.organisation_id,
        'context.renew',
        'access_context',
        p_context_id::text,
        jsonb_build_object('new_expires_at', v_new_expires_at)
    );

    RETURN QUERY SELECT p_context_id, v_new_expires_at;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_renew_access_context(UUID, UUID, TEXT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_renew_access_context(UUID, UUID, TEXT) TO archscale_app_runtime;

-- Revoke Access Context
CREATE OR REPLACE FUNCTION fn_revoke_access_context(
    p_context_id UUID,
    p_user_id UUID,
    p_session_id TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_ctx RECORD;
BEGIN
    SELECT * INTO v_ctx
    FROM access_contexts
    WHERE id = p_context_id
      AND user_id = p_user_id
      AND session_id = p_session_id
      AND revoked_at IS NULL;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    UPDATE access_contexts
    SET revoked_at = now()
    WHERE id = p_context_id;

    -- Audit context revocation
    INSERT INTO audit_logs (
        actor_user_id,
        actor_membership_id,
        organisation_id,
        action,
        target_entity,
        target_id,
        diff
    ) VALUES (
        p_user_id,
        v_ctx.membership_id,
        v_ctx.organisation_id,
        'context.revoke',
        'access_context',
        p_context_id::text,
        jsonb_build_object('revoked_at', now())
    );

    RETURN TRUE;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_revoke_access_context(UUID, UUID, TEXT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_revoke_access_context(UUID, UUID, TEXT) TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 6. Audit Trail Functions & Privileges
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
    -- Size cap enforcement on free-text / diff (2 KB)
    v_diff_len := octet_length(COALESCE(p_diff::text, ''));
    IF v_diff_len > 2048 THEN
        RAISE EXCEPTION 'AUTH_AUDIT_PAYLOAD_TOO_LARGE: Audit diff exceeds 2 KB limit (% bytes)', v_diff_len
            USING ERRCODE = 'P0001';
    END IF;

    -- If a valid context exists, derive actor and organisation strictly from database state
    IF is_context_valid() THEN
        v_actor_user_id := fn_current_context_user_id();
        v_actor_membership_id := fn_current_context_membership_id();
        v_org_id := fn_current_context_org_id();
    ELSE
        -- No valid context: enforce strict action allowlist
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
    INSERT INTO audit_logs (
        id,
        actor_user_id,
        actor_membership_id,
        organisation_id,
        action,
        target_entity,
        target_id,
        diff,
        created_at
    ) VALUES (
        v_id,
        v_actor_user_id,
        v_actor_membership_id,
        v_org_id,
        p_action,
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

-- Read audit logs (permission-gated)
CREATE OR REPLACE FUNCTION fn_read_audit_logs(
    p_limit INT DEFAULT 50,
    p_offset INT DEFAULT 0
)
RETURNS TABLE (
    id UUID,
    actor_user_id UUID,
    actor_membership_id UUID,
    organisation_id UUID,
    action TEXT,
    target_entity TEXT,
    target_id TEXT,
    diff JSONB,
    created_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_ctx_id UUID;
    v_org_id UUID;
    v_role_key TEXT;
    v_has_perm BOOLEAN := false;
BEGIN
    v_ctx_id := fn_current_context_id();
    IF v_ctx_id IS NULL OR NOT is_context_valid(v_ctx_id) THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_INVALID: Audit read requires a valid context' USING ERRCODE = 'P0001';
    END IF;

    v_org_id := fn_current_context_org_id();

    SELECT m.role_key INTO v_role_key
    FROM access_contexts ac
    JOIN memberships m ON m.id = ac.membership_id
    WHERE ac.id = v_ctx_id;

    -- Verify permission: org.audit.read, org.audit.view, or platform.audit.read
    SELECT EXISTS (
        SELECT 1 FROM role_permissions rp
        WHERE rp.role_key = v_role_key
          AND rp.permission_key IN ('org.audit.read', 'org.audit.view', 'platform.audit.read')
    ) INTO v_has_perm;

    IF NOT v_has_perm THEN
        RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Caller lacks audit read permission' USING ERRCODE = 'P0001';
    END IF;

    RETURN QUERY
    SELECT
        a.id,
        a.actor_user_id,
        a.actor_membership_id,
        a.organisation_id,
        a.action,
        a.target_entity,
        a.target_id,
        a.diff,
        a.created_at
    FROM audit_logs a
    WHERE a.organisation_id = v_org_id
    ORDER BY a.created_at DESC
    LIMIT LEAST(p_limit, 100) OFFSET GREATEST(p_offset, 0);
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_read_audit_logs(INT, INT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_read_audit_logs(INT, INT) TO archscale_app_runtime;

-- Complete revocation of direct mutations and direct reads on audit_logs from runtime role
REVOKE ALL ON public.audit_logs FROM archscale_app_runtime;

-- Drop legacy open policies from migration 007
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'audit_logs' AND policyname = 'audit_logs_read') THEN
        DROP POLICY audit_logs_read ON public.audit_logs;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'audit_logs' AND policyname = 'audit_logs_append') THEN
        DROP POLICY audit_logs_append ON public.audit_logs;
    END IF;
END $$;

ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs FORCE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- 7. Recreate fn_approve_organisation & fn_approve_membership with Read-Only Assert
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION fn_approve_organisation(
    p_request_id UUID,
    p_acting_membership_id UUID,
    p_tenant_type_key TEXT,
    p_licensed_apps TEXT[],
    p_owner_user_id UUID,
    p_seat_limits JSONB,
    p_reason TEXT
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_actor_user_id UUID;
    v_actor_role_key TEXT;
    v_actor_portal portal_type;
    v_org_id UUID;
    v_app_key TEXT;
    v_seat RECORD;
    v_workspace_id UUID;
    v_owner_membership_id UUID;
BEGIN
    -- Support contexts are strictly read-only
    PERFORM fn_assert_not_support_context();

    -- A. Validate acting member authority (must be platform founder)
    SELECT m.user_id, m.role_key, o.portal
    INTO v_actor_user_id, v_actor_role_key, v_actor_portal
    FROM memberships m
    JOIN organisations o ON o.id = m.organisation_id
    WHERE m.id = p_acting_membership_id
      AND m.status = 'ACTIVE';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Acting membership % is not found or not active', p_acting_membership_id;
    END IF;

    IF v_actor_portal <> 'platform' OR v_actor_role_key <> 'founder' THEN
        RAISE EXCEPTION 'Only active platform founders can approve organisation applications (caller is % / %)',
            v_actor_role_key, v_actor_portal;
    END IF;

    -- B. Fetch and lock access request
    SELECT organisation_id INTO v_org_id
    FROM access_requests
    WHERE id = p_request_id AND request_type = 'organisation' AND status = 'PENDING'
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Organisation access request % not found or not pending', p_request_id;
    END IF;

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

REVOKE EXECUTE ON FUNCTION fn_approve_organisation(UUID, UUID, TEXT, TEXT[], UUID, JSONB, TEXT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_approve_organisation(UUID, UUID, TEXT, TEXT[], UUID, JSONB, TEXT) TO archscale_app_runtime;

CREATE OR REPLACE FUNCTION fn_approve_membership(
    p_request_id UUID,
    p_acting_membership_id UUID,
    p_reason TEXT
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
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
    -- Support contexts are strictly read-only
    PERFORM fn_assert_not_support_context();

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
        END LOOP;
    END IF;

    -- F. Upsert/Activate Membership Record
    INSERT INTO memberships (
        user_id,
        organisation_id,
        role_key,
        profile_id,
        status,
        expires_at
    ) VALUES (
        v_request.requester_user_id,
        v_request.organisation_id,
        v_request.target_role_key,
        v_request.target_profile_id,
        'ACTIVE',
        CASE WHEN v_request.requested_duration IS NOT NULL THEN now() + v_request.requested_duration ELSE NULL END
    )
    ON CONFLICT (user_id, organisation_id) DO UPDATE SET
        role_key = EXCLUDED.role_key,
        profile_id = EXCLUDED.profile_id,
        status = 'ACTIVE',
        expires_at = EXCLUDED.expires_at,
        updated_at = now()
    RETURNING id INTO v_membership_id;

    -- G. Increment Seat Allocations & Bind membership_seats
    IF v_request.requested_apps IS NOT NULL AND array_length(v_request.requested_apps, 1) > 0 THEN
        FOREACH v_app_key IN ARRAY v_request.requested_apps
        LOOP
            UPDATE organisation_seats
            SET allocated_seats = allocated_seats + 1
            WHERE organisation_id = v_request.organisation_id
              AND app_key = v_app_key
              AND role_key = v_request.target_role_key;

            INSERT INTO membership_seats (membership_id, app_key)
            VALUES (v_membership_id, v_app_key)
            ON CONFLICT (membership_id, app_key) DO NOTHING;
        END LOOP;
    END IF;

    -- H. Record approval step
    INSERT INTO approval_steps (
        request_id,
        step_number,
        required_role_key,
        min_level,
        decided_by,
        decision,
        reason,
        decided_at
    ) VALUES (
        p_request_id,
        1,
        v_actor_role_key,
        v_actor_level,
        p_acting_membership_id,
        'APPROVED',
        p_reason,
        now()
    );

    -- I. Finalize request
    UPDATE access_requests
    SET status = 'APPROVED', updated_at = now()
    WHERE id = p_request_id;

    -- J. Append-only audit record
    INSERT INTO audit_logs (
        actor_user_id,
        actor_membership_id,
        organisation_id,
        action,
        target_entity,
        target_id,
        diff
    ) VALUES (
        v_actor_user_id,
        p_acting_membership_id,
        v_request.organisation_id,
        'membership.approve',
        'membership',
        v_membership_id::text,
        jsonb_build_object(
            'role_key', v_request.target_role_key,
            'requester_user_id', v_request.requester_user_id,
            'apps', v_request.requested_apps,
            'reason', p_reason
        )
    );

    RETURN v_membership_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_approve_membership(UUID, UUID, TEXT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_approve_membership(UUID, UUID, TEXT) TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 8. Context-Bound RLS Policies & Privilege Revocation
-- -----------------------------------------------------------------------------

-- Revoke direct table mutations on all public tables from runtime role
REVOKE INSERT, UPDATE, DELETE ON public.access_contexts FROM archscale_app_runtime;
REVOKE INSERT, UPDATE, DELETE ON public.memberships FROM archscale_app_runtime;
REVOKE INSERT, UPDATE, DELETE ON public.workspaces FROM archscale_app_runtime;
REVOKE INSERT, UPDATE, DELETE ON public.organisations FROM archscale_app_runtime;
REVOKE INSERT, UPDATE, DELETE ON public.access_profiles FROM archscale_app_runtime;
REVOKE INSERT, UPDATE, DELETE ON public.access_profile_permissions FROM archscale_app_runtime;
REVOKE INSERT, UPDATE, DELETE ON public.organisation_entitlements FROM archscale_app_runtime;
REVOKE INSERT, UPDATE, DELETE ON public.organisation_seats FROM archscale_app_runtime;
REVOKE INSERT, UPDATE, DELETE ON public.membership_seats FROM archscale_app_runtime;
REVOKE INSERT, UPDATE, DELETE ON public.support_access_grants FROM archscale_app_runtime;
REVOKE INSERT, UPDATE, DELETE ON public.share_grants FROM archscale_app_runtime;
REVOKE INSERT, UPDATE, DELETE ON public.approval_policies FROM archscale_app_runtime;
REVOKE INSERT, UPDATE, DELETE ON public.access_requests FROM archscale_app_runtime;
REVOKE INSERT, UPDATE, DELETE ON public.approval_steps FROM archscale_app_runtime;

-- Grant SELECT only to runtime role on tables covered by RLS
GRANT SELECT ON public.access_contexts TO archscale_app_runtime;
GRANT SELECT ON public.memberships TO archscale_app_runtime;
GRANT SELECT ON public.workspaces TO archscale_app_runtime;
GRANT SELECT ON public.organisations TO archscale_app_runtime;
GRANT SELECT ON public.access_profiles TO archscale_app_runtime;
GRANT SELECT ON public.access_profile_permissions TO archscale_app_runtime;
GRANT SELECT ON public.organisation_entitlements TO archscale_app_runtime;
GRANT SELECT ON public.organisation_seats TO archscale_app_runtime;
GRANT SELECT ON public.membership_seats TO archscale_app_runtime;
GRANT SELECT ON public.share_grants TO archscale_app_runtime;
GRANT SELECT ON public.approval_policies TO archscale_app_runtime;
GRANT SELECT ON public.access_requests TO archscale_app_runtime;
GRANT SELECT ON public.approval_steps TO archscale_app_runtime;

-- Global reference catalogues: SELECT-only with USING (true)
GRANT SELECT ON public.tenant_types TO archscale_app_runtime;
GRANT SELECT ON public.roles TO archscale_app_runtime;
GRANT SELECT ON public.permissions TO archscale_app_runtime;
GRANT SELECT ON public.role_permissions TO archscale_app_runtime;
GRANT SELECT ON public.role_tenant_types TO archscale_app_runtime;
GRANT SELECT ON public.tenant_role_permission_templates TO archscale_app_runtime;
GRANT SELECT ON public.app_catalogue TO archscale_app_runtime;

-- Drop any conflicting old policies on runtime role
DO $$
DECLARE
    pol RECORD;
BEGIN
    FOR pol IN
        SELECT tablename, policyname
        FROM pg_policies
        WHERE schemaname = 'public'
          AND policyname LIKE '%runtime%'
          AND tablename NOT IN ('users')
    LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I;', pol.policyname, pol.tablename);
    END LOOP;
END $$;

-- 1. memberships policy
CREATE POLICY memberships_runtime_policy ON public.memberships
    FOR SELECT TO archscale_app_runtime
    USING (
        is_context_valid()
        AND user_id = fn_current_context_user_id()
        AND organisation_id = fn_current_context_org_id()
    );

-- 2. workspaces policy
CREATE POLICY workspaces_runtime_policy ON public.workspaces
    FOR SELECT TO archscale_app_runtime
    USING (
        is_context_valid()
        AND organisation_id = fn_current_context_org_id()
    );

-- 3. organisations policy
CREATE POLICY organisations_runtime_policy ON public.organisations
    FOR SELECT TO archscale_app_runtime
    USING (
        is_context_valid()
        AND id = fn_current_context_org_id()
    );

-- 4. access_contexts own-row policy
CREATE POLICY access_contexts_runtime_policy ON public.access_contexts
    FOR SELECT TO archscale_app_runtime
    USING (
        is_context_valid()
        AND id = fn_current_context_id()
        AND user_id = fn_current_context_user_id()
    );

-- 5. access_profiles policy
CREATE POLICY access_profiles_runtime_policy ON public.access_profiles
    FOR SELECT TO archscale_app_runtime
    USING (
        is_context_valid()
        AND organisation_id = fn_current_context_org_id()
    );

-- 6. access_profile_permissions policy
CREATE POLICY access_profile_permissions_runtime_policy ON public.access_profile_permissions
    FOR SELECT TO archscale_app_runtime
    USING (
        is_context_valid()
        AND profile_id IN (
            SELECT ap.id FROM public.access_profiles ap
            WHERE ap.organisation_id = fn_current_context_org_id()
        )
    );

-- 7. organisation_entitlements policy
CREATE POLICY organisation_entitlements_runtime_policy ON public.organisation_entitlements
    FOR SELECT TO archscale_app_runtime
    USING (
        is_context_valid()
        AND organisation_id = fn_current_context_org_id()
    );

-- 8. organisation_seats policy
CREATE POLICY organisation_seats_runtime_policy ON public.organisation_seats
    FOR SELECT TO archscale_app_runtime
    USING (
        is_context_valid()
        AND organisation_id = fn_current_context_org_id()
    );

-- 9. membership_seats policy
CREATE POLICY membership_seats_runtime_policy ON public.membership_seats
    FOR SELECT TO archscale_app_runtime
    USING (
        is_context_valid()
        AND membership_id = fn_current_context_membership_id()
    );

-- 10. share_grants policy
CREATE POLICY share_grants_runtime_policy ON public.share_grants
    FOR SELECT TO archscale_app_runtime
    USING (
        is_context_valid()
        AND (
            source_organisation_id = fn_current_context_org_id()
            OR target_org_id = fn_current_context_org_id()
        )
    );

-- 11. approval_policies policy
CREATE POLICY approval_policies_runtime_policy ON public.approval_policies
    FOR SELECT TO archscale_app_runtime
    USING (
        is_context_valid()
        AND organisation_id = fn_current_context_org_id()
    );

-- 12. access_requests policy
CREATE POLICY access_requests_runtime_policy ON public.access_requests
    FOR SELECT TO archscale_app_runtime
    USING (
        is_context_valid()
        AND (
            organisation_id = fn_current_context_org_id()
            OR requester_user_id = fn_current_context_user_id()
        )
    );

-- 13. approval_steps policy
CREATE POLICY approval_steps_runtime_policy ON public.approval_steps
    FOR SELECT TO archscale_app_runtime
    USING (
        is_context_valid()
        AND request_id IN (
            SELECT ar.id FROM public.access_requests ar
            WHERE ar.organisation_id = fn_current_context_org_id()
               OR ar.requester_user_id = fn_current_context_user_id()
        )
    );

-- Global reference catalogues SELECT policies
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'tenant_types' AND policyname = 'tenant_types_runtime_select') THEN
        CREATE POLICY tenant_types_runtime_select ON public.tenant_types FOR SELECT TO archscale_app_runtime USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'roles' AND policyname = 'roles_runtime_select') THEN
        CREATE POLICY roles_runtime_select ON public.roles FOR SELECT TO archscale_app_runtime USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'permissions' AND policyname = 'permissions_runtime_select') THEN
        CREATE POLICY permissions_runtime_select ON public.permissions FOR SELECT TO archscale_app_runtime USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'role_permissions' AND policyname = 'role_permissions_runtime_select') THEN
        CREATE POLICY role_permissions_runtime_select ON public.role_permissions FOR SELECT TO archscale_app_runtime USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'role_tenant_types' AND policyname = 'role_tenant_types_runtime_select') THEN
        CREATE POLICY role_tenant_types_runtime_select ON public.role_tenant_types FOR SELECT TO archscale_app_runtime USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'tenant_role_permission_templates' AND policyname = 'tenant_role_permission_templates_runtime_select') THEN
        CREATE POLICY tenant_role_permission_templates_runtime_select ON public.tenant_role_permission_templates FOR SELECT TO archscale_app_runtime USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'app_catalogue' AND policyname = 'app_catalogue_runtime_select') THEN
        CREATE POLICY app_catalogue_runtime_select ON public.app_catalogue FOR SELECT TO archscale_app_runtime USING (true);
    END IF;
END $$;

-- Enable and force RLS on all sensitive tables
ALTER TABLE public.access_contexts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.access_contexts FORCE ROW LEVEL SECURITY;
ALTER TABLE public.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE public.workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspaces FORCE ROW LEVEL SECURITY;
ALTER TABLE public.organisations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organisations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.access_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.access_profiles FORCE ROW LEVEL SECURITY;
ALTER TABLE public.access_profile_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.access_profile_permissions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.organisation_entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organisation_entitlements FORCE ROW LEVEL SECURITY;
ALTER TABLE public.organisation_seats ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organisation_seats FORCE ROW LEVEL SECURITY;
ALTER TABLE public.membership_seats ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.membership_seats FORCE ROW LEVEL SECURITY;
ALTER TABLE public.support_access_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.support_access_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE public.share_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.share_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE public.approval_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.approval_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE public.access_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.access_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE public.approval_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.approval_steps FORCE ROW LEVEL SECURITY;
