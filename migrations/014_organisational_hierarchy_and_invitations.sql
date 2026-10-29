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
--      - Status enum: 'Pending', 'Sent', 'Accepted', 'Expired', 'Revoked' (single spelling)
--      - target role, department, job_role, reporting_manager, access_profile_id
--      - invited_by_membership_id (replaces invited_by; used_at replaced by accepted_at)
--      - UNIQUE index on (organisation_id, lower(email)) WHERE status IN ('Pending', 'Sent')
--      - sent_at, accepted_at, revoked_at, resend_count
--      - All direct runtime table access revoked; reads only through fn_list_org_invitations
--   3. organisations:
--      - member_min_aal ('aal1' | 'aal2', default 'aal2')
--      - fn_set_organisation_mfa_requirement(p_min_aal) Security Definer function
--        (derives actor/role/org strictly from active context)
--   4. access_profiles & effective permissions:
--      - role_key on access_profiles (subscriber roles)
--      - memberships.profile_id validated against role_key and organisation_id
--      - fn_get_effective_permissions() merges role + profile permissions
--        (restricted to caller's active organisation)
--   5. Security Definer functions for listing members and invitations:
--      - fn_list_org_members() (requires org.members.read)
--      - fn_list_org_invitations() (requires org.members.invite; never returns token_hash)
--      - Support context permitted to read; write operations blocked
--   6. auth_rate_limits:
--      - Direct DML revoked from runtime; composite primary key (key, action)
--      - fn_rate_limit_hit(key, action, max_attempts, window_seconds) Security Definer
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Organisation additions: member_min_aal
-- -----------------------------------------------------------------------------
ALTER TABLE public.organisations
    ADD COLUMN IF NOT EXISTS member_min_aal TEXT NOT NULL DEFAULT 'aal2'
    CHECK (member_min_aal IN ('aal1', 'aal2'));

COMMENT ON COLUMN public.organisations.member_min_aal IS
'Effective minimum AAL is the higher of roles.min_aal and organisations.member_min_aal. Setting member_min_aal = ''aal1'' never lowers a role whose roles.min_aal is aal2. Setting member_min_aal = ''aal2'' requires all tenant members (including intern) to authenticate at aal2.';

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
-- 3. Access Profiles Upgrades: subscriber role_key and membership validation
-- -----------------------------------------------------------------------------
ALTER TABLE public.access_profiles
    ADD COLUMN IF NOT EXISTS role_key TEXT REFERENCES public.roles(key);

UPDATE public.access_profiles
SET role_key = parent_role_key
WHERE role_key IS NULL;

-- Trigger to validate access_profile role belongs to subscriber portal
CREATE OR REPLACE FUNCTION trg_fn_validate_access_profile_role()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_portal public.portal_type;
BEGIN
    IF NEW.role_key IS NOT NULL THEN
        SELECT portal INTO v_portal FROM public.roles WHERE key = NEW.role_key;
        IF v_portal <> 'subscriber' THEN
            RAISE EXCEPTION 'Access profiles can only attach to subscriber roles (got % for portal %)', NEW.role_key, v_portal
                USING ERRCODE = 'P0001';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_access_profiles_role ON public.access_profiles;
CREATE TRIGGER trg_access_profiles_role
    BEFORE INSERT OR UPDATE OF role_key ON public.access_profiles
    FOR EACH ROW
    EXECUTE FUNCTION trg_fn_validate_access_profile_role();

-- Trigger on memberships: memberships.profile_id must match membership.role_key AND membership.organisation_id
CREATE OR REPLACE FUNCTION trg_fn_validate_membership_profile()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_profile_role_key TEXT;
    v_profile_org_id UUID;
BEGIN
    IF NEW.profile_id IS NOT NULL THEN
        SELECT role_key, organisation_id INTO v_profile_role_key, v_profile_org_id
        FROM public.access_profiles
        WHERE id = NEW.profile_id;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'Access profile % does not exist', NEW.profile_id
                USING ERRCODE = 'P0002';
        END IF;

        IF v_profile_org_id <> NEW.organisation_id THEN
            RAISE EXCEPTION 'Access profile organisation (%) does not match membership organisation (%)', v_profile_org_id, NEW.organisation_id
                USING ERRCODE = 'P0001';
        END IF;

        IF v_profile_role_key <> NEW.role_key THEN
            RAISE EXCEPTION 'Access profile role (%) does not match membership role (%)', v_profile_role_key, NEW.role_key
                USING ERRCODE = 'P0001';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_memberships_profile ON public.memberships;
CREATE TRIGGER trg_memberships_profile
    BEFORE INSERT OR UPDATE OF profile_id, role_key, organisation_id ON public.memberships
    FOR EACH ROW
    EXECUTE FUNCTION trg_fn_validate_membership_profile();

-- -----------------------------------------------------------------------------
-- 4. Invitations Table Upgrades & Deduplication
-- -----------------------------------------------------------------------------
ALTER TABLE public.invitations
    ADD COLUMN IF NOT EXISTS invited_by_membership_id UUID REFERENCES public.memberships(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS department TEXT,
    ADD COLUMN IF NOT EXISTS job_role TEXT,
    ADD COLUMN IF NOT EXISTS reporting_manager_membership_id UUID REFERENCES public.memberships(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS sent_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS accepted_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS resend_count INT NOT NULL DEFAULT 0;

-- Migrate used_at to accepted_at if used_at exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'invitations' AND column_name = 'used_at'
    ) THEN
        EXECUTE 'UPDATE public.invitations SET accepted_at = used_at WHERE accepted_at IS NULL AND used_at IS NOT NULL;';
    END IF;
END $$;

-- Migrate invited_by (user_id) to invited_by_membership_id if invited_by exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'invitations' AND column_name = 'invited_by'
    ) THEN
        EXECUTE 'UPDATE public.invitations i
                 SET invited_by_membership_id = m.id
                 FROM public.memberships m
                 WHERE i.invited_by_membership_id IS NULL
                   AND i.invited_by IS NOT NULL
                   AND m.user_id = i.invited_by
                   AND m.organisation_id = i.organisation_id;';
    END IF;
END $$;

-- Drop redundant duplicate columns (invited_by and used_at)
ALTER TABLE public.invitations
    DROP COLUMN IF EXISTS invited_by,
    DROP COLUMN IF EXISTS used_at;

-- Migrate existing uppercase rows
UPDATE public.invitations
SET status = CASE status
    WHEN 'PENDING' THEN 'Pending'
    WHEN 'ACCEPTED' THEN 'Accepted'
    WHEN 'EXPIRED' THEN 'Expired'
    WHEN 'REVOKED' THEN 'Revoked'
    ELSE status
END;

-- One status spelling only: Pending, Sent, Accepted, Expired, Revoked
ALTER TABLE public.invitations
    DROP CONSTRAINT IF EXISTS invitations_status_check;
ALTER TABLE public.invitations
    ADD CONSTRAINT invitations_status_check
    CHECK (status IN ('Pending', 'Sent', 'Accepted', 'Expired', 'Revoked'));

ALTER TABLE public.invitations
    ALTER COLUMN status SET DEFAULT 'Pending';

-- Unique pending index covers exactly status IN ('Pending', 'Sent') per (organisation_id, lower(email))
DROP INDEX IF EXISTS uq_invitations_pending_org_email;
CREATE UNIQUE INDEX uq_invitations_pending_org_email
    ON public.invitations (organisation_id, lower(email))
    WHERE status IN ('Pending', 'Sent');

-- -----------------------------------------------------------------------------
-- 5. Seed Permissions & Roles for MFA, Admin, and Support
-- -----------------------------------------------------------------------------
INSERT INTO public.permissions (key, name, description, min_aal)
VALUES 
    ('org.settings.manage', 'Manage Organisation Settings', 'Manage organisation security settings and MFA requirements', 'aal2'),
    ('org.members.manage', 'Manage Members', 'Change member roles, suspend, or reactivate memberships', 'aal2'),
    ('platform.support.read', 'Support Read Access', 'Read-only inspection access during active support grant', 'aal2'),
    ('platform.support.manage', 'Manage Support Grants', 'Issue and revoke platform support grants', 'aal2'),
    ('platform.organisations.manage', 'Manage Platform Organisations', 'Create, approve, and suspend organisations', 'aal2')
ON CONFLICT (key) DO UPDATE SET min_aal = EXCLUDED.min_aal;

INSERT INTO public.role_permissions (role_key, permission_key)
VALUES 
    ('business_owner', 'org.settings.manage'),
    ('business_owner', 'org.members.manage'),
    ('founder', 'platform.support.read'),
    ('founder', 'platform.support.manage'),
    ('founder', 'platform.organisations.manage'),
    ('client_servicing', 'platform.support.read'),
    ('client_servicing', 'platform.support.manage')
ON CONFLICT (role_key, permission_key) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 6. Effective Permissions Calculation (Roles + Access Profiles)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_get_effective_permissions(p_membership_id UUID DEFAULT NULL)
RETURNS TEXT[]
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_target_mem_id UUID;
    v_ctx_id UUID;
    v_caller_org_id UUID;
    v_caller_mem_id UUID;
    v_mem_org_id UUID;
    v_role_key TEXT;
    v_profile_id UUID;
    v_mem_status public.membership_status;
    v_mem_expires_at TIMESTAMPTZ;
    v_perms TEXT[];
BEGIN
    v_ctx_id := fn_current_context_id();
    IF v_ctx_id IS NULL OR NOT is_context_valid(v_ctx_id) THEN
        RETURN '{}'::TEXT[];
    END IF;

    v_caller_org_id := fn_current_context_org_id();
    v_caller_mem_id := fn_current_context_membership_id();

    IF p_membership_id IS NULL THEN
        v_target_mem_id := v_caller_mem_id;
    ELSE
        v_target_mem_id := p_membership_id;
    END IF;

    IF v_target_mem_id IS NULL THEN
        RETURN '{}'::TEXT[];
    END IF;

    -- Fetch membership, ensuring it belongs to caller's active organisation
    SELECT organisation_id, role_key, profile_id, status, expires_at
    INTO v_mem_org_id, v_role_key, v_profile_id, v_mem_status, v_mem_expires_at
    FROM public.memberships
    WHERE id = v_target_mem_id;

    -- If membership not found or belongs to another organisation, return empty
    IF v_mem_org_id IS NULL OR v_mem_org_id <> v_caller_org_id THEN
        RETURN '{}'::TEXT[];
    END IF;

    -- If target membership is not ACTIVE or is expired, return empty list
    IF v_mem_status <> 'ACTIVE' OR (v_mem_expires_at IS NOT NULL AND v_mem_expires_at <= now()) THEN
        RETURN '{}'::TEXT[];
    END IF;

    -- F5: If inspecting another member's permissions, caller must hold org.members.read
    IF v_target_mem_id <> v_caller_mem_id THEN
        IF NOT EXISTS (
            SELECT 1 FROM public.access_contexts ac
            JOIN public.memberships cm ON cm.id = ac.membership_id
            LEFT JOIN public.role_permissions crp ON crp.role_key = cm.role_key AND crp.permission_key = 'org.members.read'
            LEFT JOIN public.access_profile_permissions capp ON capp.profile_id = cm.profile_id AND capp.permission_key = 'org.members.read'
            WHERE ac.id = v_ctx_id
              AND (crp.permission_key IS NOT NULL OR capp.permission_key IS NOT NULL)
        ) THEN
            RETURN '{}'::TEXT[];
        END IF;
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
-- 7. Organization MFA Requirement Setting Function (F3)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_set_organisation_mfa_requirement(
    p_min_aal TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_context_id UUID;
    v_org_id UUID;
    v_user_id UUID;
    v_role_key TEXT;
    v_aal TEXT;
    v_old_setting TEXT;
BEGIN
    -- 1. Derive active validated context
    v_context_id := fn_current_context_id();
    IF v_context_id IS NULL OR NOT is_context_valid(v_context_id) THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_INVALID: Valid application context required' USING ERRCODE = 'P0001';
    END IF;

    -- 2. Reject support contexts (read-only)
    PERFORM fn_assert_not_support_context();

    SELECT ac.organisation_id, ac.user_id, m.role_key, ac.aal_level
    INTO v_org_id, v_user_id, v_role_key, v_aal
    FROM public.access_contexts ac
    JOIN public.memberships m ON m.id = ac.membership_id
    WHERE ac.id = v_context_id;

    -- 3. F3: Permission check org.settings.manage (seeded for business_owner)
    IF NOT ('org.settings.manage' = ANY(fn_get_effective_permissions())) THEN
        RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Missing required permission org.settings.manage'
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

    -- 5. Audit log entry (derived actor from active context)
    PERFORM fn_audit_append(
        'org.mfa.updated',
        'organisations',
        v_org_id::text,
        jsonb_build_object(
            'old_setting', v_old_setting,
            'new_setting', p_min_aal
        )
    );

    RETURN jsonb_build_object(
        'organisation_id', v_org_id,
        'member_min_aal', p_min_aal,
        'previous_setting', v_old_setting
    );
END;
$$;

DROP FUNCTION IF EXISTS fn_set_organisation_mfa_requirement(UUID, TEXT);
REVOKE EXECUTE ON FUNCTION fn_set_organisation_mfa_requirement(TEXT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_set_organisation_mfa_requirement(TEXT) TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 8. RLS Policies on Memberships and Invitations
-- -----------------------------------------------------------------------------
-- Direct SELECT on memberships: member sees ONLY their own row
DROP POLICY IF EXISTS memberships_hierarchy_read_policy ON public.memberships;
DROP POLICY IF EXISTS memberships_runtime_policy ON public.memberships;
CREATE POLICY memberships_runtime_policy ON public.memberships
    FOR SELECT TO archscale_app_runtime
    USING (
        is_context_valid()
        AND user_id = fn_current_context_user_id()
        AND organisation_id = fn_current_context_org_id()
    );

-- Invitations: revoke all direct runtime access; no runtime SELECT policy exists
DROP POLICY IF EXISTS invitations_context_read_policy ON public.invitations;
DROP POLICY IF EXISTS invitations_runtime_policy ON public.invitations;
REVOKE ALL ON public.invitations FROM PUBLIC, archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 9. Definer Functions for Listing Org Members and Invitations (F4)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_list_org_members()
RETURNS TABLE (
    id UUID,
    user_id UUID,
    role_key TEXT,
    department TEXT,
    job_role TEXT,
    reporting_manager_membership_id UUID,
    status public.membership_status
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

    -- F4: Support contexts require platform.support.read on platform membership
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
        IF NOT ('org.members.read' = ANY(v_perms)) THEN
            RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Missing required permission org.members.read'
                USING ERRCODE = '42501';
        END IF;
    END IF;

    RETURN QUERY
    SELECT 
        m.id,
        m.user_id,
        m.role_key,
        m.department,
        m.job_role,
        m.reporting_manager_membership_id,
        m.status
    FROM public.memberships m
    WHERE m.organisation_id = v_org_id
    ORDER BY m.created_at ASC;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_list_org_members() FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_list_org_members() TO archscale_app_runtime;

CREATE OR REPLACE FUNCTION fn_list_org_invitations()
RETURNS TABLE (
    id UUID,
    email TEXT,
    target_role_key TEXT,
    department TEXT,
    job_role TEXT,
    status TEXT,
    expires_at TIMESTAMPTZ,
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

    -- F4: Support contexts require platform.support.read on platform membership
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

    RETURN QUERY
    SELECT 
        i.id,
        i.email,
        i.target_role_key,
        i.department,
        i.job_role,
        i.status,
        i.expires_at,
        i.sent_at
    FROM public.invitations i
    WHERE i.organisation_id = v_org_id
    ORDER BY i.created_at DESC;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_list_org_invitations() FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_list_org_invitations() TO archscale_app_runtime;
        i.department,
        i.job_role,
        i.status,
        i.expires_at,
        i.sent_at
    FROM public.invitations i
    WHERE i.organisation_id = v_org_id
    ORDER BY i.created_at DESC;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_list_org_invitations() FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_list_org_invitations() TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 9. Rate Limits: Atomic definer function and revoked direct runtime access
-- -----------------------------------------------------------------------------
ALTER TABLE public.auth_rate_limits
    ADD COLUMN IF NOT EXISTS action TEXT NOT NULL DEFAULT 'signin',
    ADD COLUMN IF NOT EXISTS attempts INT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS reset_at TIMESTAMPTZ DEFAULT (now() + interval '15 minutes');

-- Deduplicate any collisions before creating composite primary key (key, action)
DELETE FROM public.auth_rate_limits a
USING public.auth_rate_limits b
WHERE a.ctid < b.ctid
  AND a.key = b.key
  AND COALESCE(a.action, 'signin') = COALESCE(b.action, 'signin');

-- Ensure primary key is (key, action)
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'auth_rate_limits_pkey'
    ) THEN
        ALTER TABLE public.auth_rate_limits DROP CONSTRAINT auth_rate_limits_pkey;
    END IF;
    ALTER TABLE public.auth_rate_limits ADD PRIMARY KEY (key, action);
EXCEPTION WHEN others THEN
    NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_rate_limits_action_reset ON public.auth_rate_limits(key, action, reset_at);

-- Revoke direct DML from runtime
REVOKE INSERT, UPDATE, DELETE, SELECT ON public.auth_rate_limits FROM archscale_app_runtime;

CREATE OR REPLACE FUNCTION fn_rate_limit_hit(
    p_key TEXT,
    p_action TEXT,
    p_max_attempts INT,
    p_window_seconds INT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_allowed BOOLEAN;
    v_now TIMESTAMPTZ := clock_timestamp();
    v_window INTERVAL := (p_window_seconds || ' seconds')::interval;
BEGIN
    -- Strict allowlist check
    IF p_action NOT IN ('signin', 'recovery', 'mfa_verify', 'invite_resend') THEN
        RAISE EXCEPTION 'AUTH_RATE_LIMIT_INVALID_ACTION: Action % is not permitted for rate limiting', p_action
            USING ERRCODE = '22023';
    END IF;

    -- Atomic single statement upsert: resets if window expired, increments if within window
    INSERT INTO public.auth_rate_limits (
        key,
        action,
        counter,
        attempts,
        window_start,
        window_expires_at,
        reset_at,
        updated_at
    )
    VALUES (
        p_key,
        p_action,
        1,
        1,
        v_now,
        v_now + v_window,
        v_now + v_window,
        v_now
    )
    ON CONFLICT (key, action) DO UPDATE
    SET
        attempts = CASE
            WHEN clock_timestamp() > auth_rate_limits.reset_at THEN 1
            ELSE auth_rate_limits.attempts + 1
        END,
        counter = CASE
            WHEN clock_timestamp() > auth_rate_limits.reset_at THEN 1
            ELSE auth_rate_limits.attempts + 1
        END,
        window_start = CASE
            WHEN clock_timestamp() > auth_rate_limits.reset_at THEN clock_timestamp()
            ELSE auth_rate_limits.window_start
        END,
        reset_at = CASE
            WHEN clock_timestamp() > auth_rate_limits.reset_at THEN clock_timestamp() + v_window
            ELSE auth_rate_limits.reset_at
        END,
        window_expires_at = CASE
            WHEN clock_timestamp() > auth_rate_limits.reset_at THEN clock_timestamp() + v_window
            ELSE auth_rate_limits.reset_at
        END,
        updated_at = clock_timestamp()
    RETURNING (attempts <= p_max_attempts) INTO v_allowed;

    RETURN v_allowed;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_rate_limit_hit(TEXT, TEXT, INT, INT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_rate_limit_hit(TEXT, TEXT, INT, INT) TO archscale_app_runtime;
