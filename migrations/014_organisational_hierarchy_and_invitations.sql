-- =============================================================================
-- Migration 014: Organisational Hierarchy, Invitations Lifecycle, and Multi-Level Security
-- ArchScale V05 Authentication & Authorisation Layer
-- =============================================================================
-- Features:
--   1. memberships: department, job_role, reporting_manager_membership_id
--      - CHECK: manager must belong to same organisation
--      - CHECK: manager cannot be self
--      - TRIGGER: cycle detection prevents circular chains
--      - CONSTRAINT / TRIGGER: manager must be ACTIVE
--   2. invitations table upgraded:
--      - Status enum: 'Pending', 'Sent', 'Accepted', 'Expired', 'Revoked'
--      - target role, department, job_role, reporting_manager, access_profile_id
--      - invited_by_membership_id
--      - UNIQUE index on (organisation_id, lower(email)) WHERE status = 'Pending'
--      - sent_at, accepted_at, revoked_at, resend_count
--   3. organisations:
--      - member_min_aal ('aal1' | 'aal2', default 'aal2')
--      - fn_set_organisation_mfa_requirement() Security Definer function
--   4. access_profiles & effective permissions:
--      - fn_get_effective_permissions(membership_id UUID) merges role + profile permissions
--   5. Security Definer functions for invitations & member updates
--      - Enforces fn_assert_not_support_context()
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Organisation additions: member_min_aal
-- -----------------------------------------------------------------------------
ALTER TABLE public.organisations
    ADD COLUMN IF NOT EXISTS member_min_aal TEXT NOT NULL DEFAULT 'aal2'
    CHECK (member_min_aal IN ('aal1', 'aal2'));

-- -----------------------------------------------------------------------------
-- 2. Memberships additions: department, job_role, reporting_manager_membership_id
-- -----------------------------------------------------------------------------
ALTER TABLE public.memberships
    ADD COLUMN IF NOT EXISTS department TEXT,
    ADD COLUMN IF NOT EXISTS job_role TEXT,
    ADD COLUMN IF NOT EXISTS reporting_manager_membership_id UUID REFERENCES public.memberships(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_memberships_department ON public.memberships(organisation_id, department);
CREATE INDEX IF NOT EXISTS idx_memberships_reporting ON public.memberships(reporting_manager_membership_id);

    -- Constraint: Manager cannot be self
ALTER TABLE public.memberships
    DROP CONSTRAINT IF EXISTS chk_membership_reporting_not_self;
ALTER TABLE public.memberships
    ADD CONSTRAINT chk_membership_reporting_not_self
    CHECK (reporting_manager_membership_id IS NULL OR reporting_manager_membership_id <> id);

-- Trigger function: Validate manager same org, active status, and cycle detection
CREATE OR REPLACE FUNCTION trg_fn_validate_reporting_manager()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_mgr_org_id UUID;
    v_mgr_status public.membership_status;
    v_curr UUID;
    v_depth INT := 0;
BEGIN
    IF NEW.reporting_manager_membership_id IS NOT NULL THEN
        -- 0. Check not self
        IF NEW.reporting_manager_membership_id = NEW.id THEN
            RAISE EXCEPTION 'chk_membership_reporting_not_self: Reporting manager cannot be self'
                USING ERRCODE = 'P0001';
        END IF;
        -- 1. Manager must belong to same organisation and be ACTIVE
        SELECT organisation_id, status
        INTO v_mgr_org_id, v_mgr_status
        FROM public.memberships
        WHERE id = NEW.reporting_manager_membership_id;

        IF v_mgr_org_id IS NULL THEN
            RAISE EXCEPTION 'Reporting manager does not exist' USING ERRCODE = 'P0002';
        END IF;

        IF v_mgr_org_id <> NEW.organisation_id THEN
            RAISE EXCEPTION 'chk_membership_reporting_same_org: Reporting manager must belong to the same organisation'
                USING ERRCODE = 'P0001';
        END IF;

        IF v_mgr_status <> 'ACTIVE' THEN
            RAISE EXCEPTION 'Reporting manager must have ACTIVE membership status'
                USING ERRCODE = 'P0001';
        END IF;

        -- 2. Cycle detection: walk up reporting hierarchy
        v_curr := NEW.reporting_manager_membership_id;
        WHILE v_curr IS NOT NULL LOOP
            IF v_curr = NEW.id THEN
                RAISE EXCEPTION 'Circular reporting relationship detected in memberships hierarchy'
                    USING ERRCODE = 'P0001';
            END IF;

            v_depth := v_depth + 1;
            IF v_depth > 50 THEN
                RAISE EXCEPTION 'Reporting hierarchy depth exceeded limit (> 50)'
                    USING ERRCODE = 'P0001';
            END IF;

            SELECT reporting_manager_membership_id INTO v_curr
            FROM public.memberships
            WHERE id = v_curr;
        END LOOP;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_memberships_reporting_manager ON public.memberships;
CREATE TRIGGER trg_memberships_reporting_manager
    BEFORE INSERT OR UPDATE OF reporting_manager_membership_id, organisation_id, status
    ON public.memberships
    FOR EACH ROW
    EXECUTE FUNCTION trg_fn_validate_reporting_manager();

-- -----------------------------------------------------------------------------
-- 3. Invitations Table Upgrades
-- -----------------------------------------------------------------------------
-- If table exists with old status constraint, drop and re-add columns
ALTER TABLE public.invitations
    ADD COLUMN IF NOT EXISTS invited_by_membership_id UUID REFERENCES public.memberships(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS department TEXT,
    ADD COLUMN IF NOT EXISTS job_role TEXT,
    ADD COLUMN IF NOT EXISTS reporting_manager_membership_id UUID REFERENCES public.memberships(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS sent_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS accepted_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS resend_count INT NOT NULL DEFAULT 0;

-- Update status check constraint to support Pending, Sent, Accepted, Expired, Revoked
ALTER TABLE public.invitations
    DROP CONSTRAINT IF EXISTS invitations_status_check;
ALTER TABLE public.invitations
    ADD CONSTRAINT invitations_status_check
    CHECK (status IN ('Pending', 'Sent', 'Accepted', 'Expired', 'Revoked', 'PENDING', 'ACCEPTED', 'EXPIRED', 'REVOKED'));

-- Unique Pending invitation per organisation and lower(email)
CREATE UNIQUE INDEX IF NOT EXISTS uq_invitations_pending_org_email
    ON public.invitations (organisation_id, lower(email))
    WHERE status IN ('Pending', 'Sent', 'PENDING');

-- -----------------------------------------------------------------------------
-- 4. Effective Permissions Calculation (Roles + Access Profiles)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_get_effective_permissions(p_membership_id UUID)
RETURNS TEXT[]
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_role_key TEXT;
    v_profile_id UUID;
    v_perms TEXT[];
BEGIN
    SELECT role_key, profile_id
    INTO v_role_key, v_profile_id
    FROM public.memberships
    WHERE id = p_membership_id;

    IF v_role_key IS NULL THEN
        RETURN '{}'::TEXT[];
    END IF;

    -- Union of base role permissions and profile permissions
    SELECT COALESCE(array_agg(DISTINCT perm ORDER BY perm), '{}'::TEXT[])
    INTO v_perms
    FROM (
        -- Base role permissions
        SELECT permission_key AS perm
        FROM public.role_permissions
        WHERE role_key = v_role_key
        UNION
        -- Access profile permissions
        SELECT app.permission_key AS perm
        FROM public.access_profile_permissions app
        WHERE app.profile_id = v_profile_id
    ) q;

    RETURN v_perms;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_get_effective_permissions(UUID) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_get_effective_permissions(UUID) TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 5. Organization MFA Requirement Setting Function
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_set_organisation_mfa_requirement(
    p_context_id UUID,
    p_min_aal TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_org_id UUID;
    v_user_id UUID;
    v_role_key TEXT;
    v_aal TEXT;
    v_support_grant_id UUID;
    v_old_setting TEXT;
BEGIN
    -- 1. Assert context validity and extract caller attributes
    IF NOT is_context_valid(p_context_id) THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_INVALID: Invalid context' USING ERRCODE = 'P0001';
    END IF;

    SELECT ac.organisation_id, ac.user_id, m.role_key, ac.aal_level, ac.support_grant_id
    INTO v_org_id, v_user_id, v_role_key, v_aal, v_support_grant_id
    FROM public.access_contexts ac
    JOIN public.memberships m ON m.id = ac.membership_id
    WHERE ac.id = p_context_id;

    -- 2. Reject support contexts (support contexts are strictly read-only)
    IF v_support_grant_id IS NOT NULL THEN
        RAISE EXCEPTION 'AUTH_SUPPORT_READONLY: fn_assert_not_support_context rejected mutation'
            USING ERRCODE = 'P0001';
    END IF;

    -- 3. Only business_owner at AAL2 may alter tenant MFA settings
    IF v_role_key <> 'business_owner' THEN
        RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Only business_owner may change tenant MFA setting'
            USING ERRCODE = '42501';
    END IF;

    IF v_aal <> 'aal2' THEN
        RAISE EXCEPTION 'AUTH_AAL: Modifying organization MFA requirement requires AAL2 verification'
            USING ERRCODE = 'P0001';
    END IF;

    IF p_min_aal NOT IN ('aal1', 'aal2') THEN
        RAISE EXCEPTION 'Invalid MFA setting value (expected aal1 or aal2)' USING ERRCODE = '22023';
    END IF;

    SELECT member_min_aal INTO v_old_setting FROM public.organisations WHERE id = v_org_id;

    -- 4. Apply update
    UPDATE public.organisations
    SET member_min_aal = p_min_aal, updated_at = now()
    WHERE id = v_org_id;

    -- 5. Audit log entry (ensure GUC is set for fn_audit_append to derive context)
    PERFORM set_config('archscale.current_context_id', p_context_id::text, true);
    PERFORM fn_audit_append(
        'org.mfa.updated',
        'organisations',
        v_org_id::text,
        jsonb_build_object(
            'old_setting', v_old_setting,
            'new_setting', p_min_aal,
            'actor_user_id', v_user_id
        ),
        v_user_id
    );

    RETURN jsonb_build_object(
        'organisation_id', v_org_id,
        'member_min_aal', p_min_aal,
        'previous_setting', v_old_setting
    );
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_set_organisation_mfa_requirement(UUID, TEXT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_set_organisation_mfa_requirement(UUID, TEXT) TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 6. RLS Policies on Memberships & Invitations using is_context_valid
-- -----------------------------------------------------------------------------
DROP POLICY IF EXISTS invitations_context_read_policy ON public.invitations;
CREATE POLICY invitations_context_read_policy ON public.invitations
    FOR SELECT TO archscale_app_runtime
    USING (
        is_context_valid() AND
        organisation_id = fn_current_context_org_id()
    );

DROP POLICY IF EXISTS memberships_hierarchy_read_policy ON public.memberships;
CREATE POLICY memberships_hierarchy_read_policy ON public.memberships
    FOR SELECT TO archscale_app_runtime
    USING (
        is_context_valid() AND
        organisation_id = fn_current_context_org_id()
    );

-- Rate limits table additions for auth rate limits (key, action, counter, reset_at)
ALTER TABLE public.auth_rate_limits
    ADD COLUMN IF NOT EXISTS action TEXT NOT NULL DEFAULT 'signin',
    ADD COLUMN IF NOT EXISTS attempts INT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS reset_at TIMESTAMPTZ DEFAULT (now() + interval '15 minutes');

CREATE INDEX IF NOT EXISTS idx_rate_limits_action_reset ON public.auth_rate_limits(key, action, reset_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.auth_rate_limits TO archscale_app_runtime;
