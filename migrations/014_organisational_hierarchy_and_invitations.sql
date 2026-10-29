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
SELECT v.role_key, v.perm_key
FROM (VALUES
    ('business_owner', 'org.settings.manage'),
    ('business_owner', 'org.members.manage'),
    ('founder', 'platform.support.read'),
    ('founder', 'platform.support.manage'),
    ('founder', 'platform.organisations.manage'),
    ('client_servicing', 'platform.support.read'),
    ('client_servicing', 'platform.support.manage')
) AS v(role_key, perm_key)
JOIN public.roles r ON r.key = v.role_key
JOIN public.permissions p ON p.key = v.perm_key
ON CONFLICT DO NOTHING;

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

-- -----------------------------------------------------------------------------
-- 10. Rate Limits: Atomic definer function and revoked direct runtime access (F2)
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

-- Ensure primary key is (key, action).
-- F2: Any failure to create primary key must propagate and fail migration.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'auth_rate_limits_pkey'
    ) THEN
        ALTER TABLE public.auth_rate_limits DROP CONSTRAINT auth_rate_limits_pkey;
    END IF;
    ALTER TABLE public.auth_rate_limits ADD PRIMARY KEY (key, action);
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

-- -----------------------------------------------------------------------------
-- 11. Invitations Engine Definer Functions (A3)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_create_invitation(
    p_target_email TEXT,
    p_target_role_key TEXT,
    p_access_profile_id UUID DEFAULT NULL,
    p_department TEXT DEFAULT NULL,
    p_job_role TEXT DEFAULT NULL,
    p_reporting_manager_membership_id UUID DEFAULT NULL,
    p_expires_at TIMESTAMPTZ DEFAULT NULL,
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
    v_expires_at TIMESTAMPTZ := p_expires_at;
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

    -- Expiry requirement for time-bound roles
    IF v_expiry_required OR p_target_role_key IN ('intern', 'collaborator', 'guest') THEN
        IF v_expires_at IS NULL THEN
            RAISE EXCEPTION 'Target role % requires an explicit expiry date', p_target_role_key USING ERRCODE = '22023';
        END IF;
        IF v_expires_at <= now() THEN
            RAISE EXCEPTION 'Expiry date must be in the future' USING ERRCODE = '22023';
        END IF;
    ELSE
        IF v_expires_at IS NULL THEN
            v_expires_at := now() + interval '7 days';
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
        v_expires_at,
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
            'expires_at', v_expires_at
        )
    );

    RETURN v_inv_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_create_invitation(TEXT, TEXT, UUID, TEXT, TEXT, UUID, TIMESTAMPTZ, TEXT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_create_invitation(TEXT, TEXT, UUID, TEXT, TEXT, UUID, TIMESTAMPTZ, TEXT) TO archscale_app_runtime;

CREATE OR REPLACE FUNCTION fn_mark_invitation_sent(p_invitation_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
BEGIN
    UPDATE public.invitations
    SET status = 'Sent',
        sent_at = now()
    WHERE id = p_invitation_id AND status = 'Pending';

    RETURN FOUND;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_mark_invitation_sent(UUID) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_mark_invitation_sent(UUID) TO archscale_app_runtime;

CREATE OR REPLACE FUNCTION fn_revoke_invitation(p_invitation_id UUID)
RETURNS BOOLEAN
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
    v_org_id := fn_current_context_org_id();

    IF NOT ('org.members.invite' = ANY(fn_get_effective_permissions())) THEN
        RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Missing required permission org.members.invite'
            USING ERRCODE = '42501';
    END IF;

    UPDATE public.invitations
    SET status = 'Revoked',
        revoked_at = now()
    WHERE id = p_invitation_id
      AND organisation_id = v_org_id
      AND status IN ('Pending', 'Sent');

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invitation not found or cannot be revoked' USING ERRCODE = 'P0002';
    END IF;

    PERFORM fn_audit_append(
        'invitation.revoked',
        'invitations',
        p_invitation_id::text,
        jsonb_build_object('invitation_id', p_invitation_id)
    );

    RETURN true;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_revoke_invitation(UUID) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_revoke_invitation(UUID) TO archscale_app_runtime;

CREATE OR REPLACE FUNCTION fn_resend_invitation(p_invitation_id UUID, p_new_token_hash TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_ctx_id UUID;
    v_org_id UUID;
    v_inv RECORD;
BEGIN
    v_ctx_id := fn_current_context_id();
    IF v_ctx_id IS NULL OR NOT is_context_valid(v_ctx_id) THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_INVALID: Valid application context required' USING ERRCODE = 'P0001';
    END IF;

    PERFORM fn_assert_not_support_context();
    v_org_id := fn_current_context_org_id();

    IF NOT ('org.members.invite' = ANY(fn_get_effective_permissions())) THEN
        RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Missing required permission org.members.invite'
            USING ERRCODE = '42501';
    END IF;

    IF NOT fn_rate_limit_hit(p_invitation_id::text, 'invite_resend', 5, 300) THEN
        RAISE EXCEPTION 'AUTH_RATE_LIMIT_EXCEEDED: Resend rate limit exceeded for this invitation'
            USING ERRCODE = 'P0001';
    END IF;

    SELECT * INTO v_inv
    FROM public.invitations
    WHERE id = p_invitation_id
      AND organisation_id = v_org_id
      AND status IN ('Pending', 'Sent')
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invitation not found or cannot be resent' USING ERRCODE = 'P0002';
    END IF;

    UPDATE public.invitations
    SET token_hash = p_new_token_hash,
        status = 'Sent',
        sent_at = now(),
        resend_count = resend_count + 1
    WHERE id = p_invitation_id;

    PERFORM fn_audit_append(
        'invitation.resent',
        'invitations',
        p_invitation_id::text,
        jsonb_build_object(
            'invitation_id', p_invitation_id,
            'resend_count', v_inv.resend_count + 1
        )
    );

    RETURN true;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_resend_invitation(UUID, TEXT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_resend_invitation(UUID, TEXT) TO archscale_app_runtime;

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
BEGIN
    IF p_raw_token IS NULL OR trim(p_raw_token) = '' THEN
        RAISE EXCEPTION 'Token is required' USING ERRCODE = '22023';
    END IF;

    -- sha256 of raw_token
    v_token_hash := encode(sha256(p_raw_token::bytea), 'hex');

    SELECT * INTO v_inv
    FROM public.invitations
    WHERE token_hash = v_token_hash
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'AUTH_INVITATION_NOT_FOUND: Invalid invitation token' USING ERRCODE = 'P0002';
    END IF;

    IF v_inv.status <> 'Sent' THEN
        RAISE EXCEPTION 'AUTH_INVITATION_INVALID_STATUS: Invitation status is %, cannot be accepted', v_inv.status
            USING ERRCODE = 'P0001';
    END IF;

    IF v_inv.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'AUTH_INVITATION_REVOKED: Invitation has been revoked' USING ERRCODE = 'P0001';
    END IF;

    IF v_inv.expires_at <= now() THEN
        UPDATE public.invitations SET status = 'Expired' WHERE id = v_inv.id;
        RAISE EXCEPTION 'AUTH_INVITATION_EXPIRED: Invitation has expired' USING ERRCODE = 'P0001';
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
        CASE 
            WHEN v_inv.target_role_key = 'intern' THEN interval '180 days'
            WHEN v_inv.target_role_key = 'collaborator' THEN interval '90 days'
            WHEN v_inv.target_role_key = 'guest' THEN interval '30 days'
            ELSE NULL
        END,
        'PENDING'
    )
    RETURNING id INTO v_request_id;

    v_membership_id := fn_approve_membership(
        v_request_id,
        v_inv.invited_by_membership_id,
        'Invitation token accepted'
    );

    UPDATE public.memberships
    SET department = v_inv.department,
        job_role = v_inv.job_role,
        reporting_manager_membership_id = v_inv.reporting_manager_membership_id
    WHERE id = v_membership_id;

    UPDATE public.invitations
    SET status = 'Accepted',
        accepted_at = now()
    WHERE id = v_inv.id;

    PERFORM fn_audit_append(
        'invitation.accepted',
        'invitations',
        v_inv.id::text,
        jsonb_build_object(
            'invitation_id', v_inv.id,
            'membership_id', v_membership_id,
            'user_id', p_user_id,
            'organisation_id', v_inv.organisation_id
        )
    );

    RETURN v_membership_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_accept_invitation(TEXT, UUID) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_accept_invitation(TEXT, UUID) TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 12. Frontstage Tenant Administration Functions (A5)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_update_member_role(
    p_target_membership_id UUID,
    p_new_role_key TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_ctx_id UUID;
    v_org_id UUID;
    v_caller_mem_id UUID;
    v_caller_level INT;
    v_target_level INT;
    v_new_level INT;
    v_old_role TEXT;
    v_target_user UUID;
BEGIN
    v_ctx_id := fn_current_context_id();
    IF v_ctx_id IS NULL OR NOT is_context_valid(v_ctx_id) THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_INVALID: Valid application context required' USING ERRCODE = 'P0001';
    END IF;

    PERFORM fn_assert_not_support_context();
    v_org_id := fn_current_context_org_id();
    v_caller_mem_id := fn_current_context_membership_id();

    IF NOT ('org.members.manage' = ANY(fn_get_effective_permissions())) THEN
        RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Missing required permission org.members.manage' USING ERRCODE = '42501';
    END IF;

    SELECT r.level INTO v_caller_level
    FROM public.memberships m JOIN public.roles r ON r.key = m.role_key
    WHERE m.id = v_caller_mem_id;

    SELECT m.role_key, r.level, m.user_id INTO v_old_role, v_target_level, v_target_user
    FROM public.memberships m JOIN public.roles r ON r.key = m.role_key
    WHERE m.id = p_target_membership_id AND m.organisation_id = v_org_id;

    IF v_old_role IS NULL THEN
        RAISE EXCEPTION 'Member not found in organisation' USING ERRCODE = 'P0002';
    END IF;

    SELECT level INTO v_new_level FROM public.roles WHERE key = p_new_role_key AND portal = 'subscriber';
    IF v_new_level IS NULL THEN
        RAISE EXCEPTION 'Invalid new role key: %', p_new_role_key USING ERRCODE = 'P0002';
    END IF;

    IF v_caller_level <= v_target_level OR v_caller_level <= v_new_level THEN
        RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Cannot modify members with role level equal to or greater than caller' USING ERRCODE = '42501';
    END IF;

    UPDATE public.memberships
    SET role_key = p_new_role_key,
        updated_at = now()
    WHERE id = p_target_membership_id;

    PERFORM fn_audit_append(
        'member.role.updated',
        'memberships',
        p_target_membership_id::text,
        jsonb_build_object('old_role', v_old_role, 'new_role', p_new_role_key)
    );

    RETURN true;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_update_member_role(UUID, TEXT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_update_member_role(UUID, TEXT) TO archscale_app_runtime;

CREATE OR REPLACE FUNCTION fn_suspend_member(
    p_target_membership_id UUID,
    p_reason TEXT DEFAULT 'Suspended by tenant administrator'
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_ctx_id UUID;
    v_org_id UUID;
    v_caller_mem_id UUID;
    v_caller_level INT;
    v_target_level INT;
    v_target_user UUID;
BEGIN
    v_ctx_id := fn_current_context_id();
    IF v_ctx_id IS NULL OR NOT is_context_valid(v_ctx_id) THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_INVALID: Valid application context required' USING ERRCODE = 'P0001';
    END IF;

    PERFORM fn_assert_not_support_context();
    v_org_id := fn_current_context_org_id();
    v_caller_mem_id := fn_current_context_membership_id();

    IF NOT ('org.members.manage' = ANY(fn_get_effective_permissions())) THEN
        RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Missing required permission org.members.manage' USING ERRCODE = '42501';
    END IF;

    SELECT r.level, m.user_id INTO v_target_level, v_target_user
    FROM public.memberships m JOIN public.roles r ON r.key = m.role_key
    WHERE m.id = p_target_membership_id AND m.organisation_id = v_org_id;

    IF v_target_level IS NULL THEN
        RAISE EXCEPTION 'Member not found in organisation' USING ERRCODE = 'P0002';
    END IF;

    SELECT r.level INTO v_caller_level
    FROM public.memberships m JOIN public.roles r ON r.key = m.role_key
    WHERE m.id = v_caller_mem_id;

    IF v_caller_level <= v_target_level THEN
        RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Cannot suspend members with role level equal to or greater than caller' USING ERRCODE = '42501';
    END IF;

    UPDATE public.memberships
    SET status = 'SUSPENDED',
        updated_at = now()
    WHERE id = p_target_membership_id;

    -- Invalidate any active contexts for suspended member in this org
    UPDATE public.access_contexts
    SET is_valid = false
    WHERE membership_id = p_target_membership_id;

    PERFORM fn_audit_append(
        'member.suspended',
        'memberships',
        p_target_membership_id::text,
        jsonb_build_object('reason', p_reason)
    );

    RETURN true;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_suspend_member(UUID, TEXT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_suspend_member(UUID, TEXT) TO archscale_app_runtime;

CREATE OR REPLACE FUNCTION fn_reactivate_member(
    p_target_membership_id UUID,
    p_reason TEXT DEFAULT 'Reactivated by tenant administrator'
)
RETURNS BOOLEAN
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
    v_org_id := fn_current_context_org_id();

    IF NOT ('org.members.manage' = ANY(fn_get_effective_permissions())) THEN
        RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Missing required permission org.members.manage' USING ERRCODE = '42501';
    END IF;

    UPDATE public.memberships
    SET status = 'ACTIVE',
        updated_at = now()
    WHERE id = p_target_membership_id AND organisation_id = v_org_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Member not found in organisation' USING ERRCODE = 'P0002';
    END IF;

    PERFORM fn_audit_append(
        'member.reactivated',
        'memberships',
        p_target_membership_id::text,
        jsonb_build_object('reason', p_reason)
    );

    RETURN true;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_reactivate_member(UUID, TEXT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_reactivate_member(UUID, TEXT) TO archscale_app_runtime;

CREATE OR REPLACE FUNCTION fn_update_member_profile(
    p_target_membership_id UUID,
    p_new_profile_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_ctx_id UUID;
    v_org_id UUID;
    v_mem_role TEXT;
    v_prof_role TEXT;
    v_prof_org UUID;
BEGIN
    v_ctx_id := fn_current_context_id();
    IF v_ctx_id IS NULL OR NOT is_context_valid(v_ctx_id) THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_INVALID: Valid application context required' USING ERRCODE = 'P0001';
    END IF;

    PERFORM fn_assert_not_support_context();
    v_org_id := fn_current_context_org_id();

    IF NOT ('org.members.manage' = ANY(fn_get_effective_permissions())) THEN
        RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Missing required permission org.members.manage' USING ERRCODE = '42501';
    END IF;

    SELECT role_key INTO v_mem_role
    FROM public.memberships
    WHERE id = p_target_membership_id AND organisation_id = v_org_id;

    IF v_mem_role IS NULL THEN
        RAISE EXCEPTION 'Member not found in organisation' USING ERRCODE = 'P0002';
    END IF;

    IF p_new_profile_id IS NOT NULL THEN
        SELECT role_key, organisation_id INTO v_prof_role, v_prof_org
        FROM public.access_profiles
        WHERE id = p_new_profile_id;

        IF v_prof_org <> v_org_id OR v_prof_role <> v_mem_role THEN
            RAISE EXCEPTION 'Access profile does not match member role and organisation' USING ERRCODE = 'P0001';
        END IF;
    END IF;

    UPDATE public.memberships
    SET profile_id = p_new_profile_id,
        updated_at = now()
    WHERE id = p_target_membership_id;

    PERFORM fn_audit_append(
        'member.profile.updated',
        'memberships',
        p_target_membership_id::text,
        jsonb_build_object('profile_id', p_new_profile_id)
    );

    RETURN true;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_update_member_profile(UUID, UUID) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_update_member_profile(UUID, UUID) TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 13. Backstage Platform Administration Functions (A5)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_platform_create_organisation(
    p_name TEXT,
    p_tenant_type_key TEXT
)
RETURNS UUID
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

    IF NOT ('platform.organisations.manage' = ANY(fn_get_effective_permissions())) THEN
        RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Missing required permission platform.organisations.manage' USING ERRCODE = '42501';
    END IF;

    INSERT INTO public.organisations (
        name,
        portal,
        tenant_type_key,
        status,
        member_min_aal
    ) VALUES (
        p_name,
        'subscriber',
        p_tenant_type_key,
        'PENDING',
        'aal2'
    )
    RETURNING id INTO v_org_id;

    PERFORM fn_audit_append(
        'platform.org.created',
        'organisations',
        v_org_id::text,
        jsonb_build_object('name', p_name, 'tenant_type_key', p_tenant_type_key)
    );

    RETURN v_org_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_platform_create_organisation(TEXT, TEXT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_platform_create_organisation(TEXT, TEXT) TO archscale_app_runtime;

CREATE OR REPLACE FUNCTION fn_platform_suspend_organisation(
    p_target_org_id UUID,
    p_reason TEXT DEFAULT 'Suspended by platform administrator'
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
        RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Missing required permission platform.organisations.manage' USING ERRCODE = '42501';
    END IF;

    UPDATE public.organisations
    SET status = 'SUSPENDED',
        updated_at = now()
    WHERE id = p_target_org_id AND portal = 'subscriber';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Subscriber organisation not found' USING ERRCODE = 'P0002';
    END IF;

    -- Invalidate all active contexts in target org
    UPDATE public.access_contexts
    SET is_valid = false
    WHERE organisation_id = p_target_org_id;

    PERFORM fn_audit_append(
        'platform.org.suspended',
        'organisations',
        p_target_org_id::text,
        jsonb_build_object('reason', p_reason)
    );

    RETURN true;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_platform_suspend_organisation(UUID, TEXT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_platform_suspend_organisation(UUID, TEXT) TO archscale_app_runtime;

CREATE OR REPLACE FUNCTION fn_create_support_grant(
    p_target_org_id UUID,
    p_reason TEXT,
    p_hours INT DEFAULT 4
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_ctx_id UUID;
    v_caller_mem_id UUID;
    v_grant_id UUID;
    v_hours INT := LEAST(GREATEST(p_hours, 1), 24);
BEGIN
    v_ctx_id := fn_current_context_id();
    IF v_ctx_id IS NULL OR NOT is_context_valid(v_ctx_id) THEN
        RAISE EXCEPTION 'AUTH_CONTEXT_INVALID: Valid application context required' USING ERRCODE = 'P0001';
    END IF;

    PERFORM fn_assert_not_support_context();
    v_caller_mem_id := fn_current_context_membership_id();

    IF NOT ('platform.support.manage' = ANY(fn_get_effective_permissions())) THEN
        RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Missing required permission platform.support.manage' USING ERRCODE = '42501';
    END IF;

    INSERT INTO public.support_access_grants (
        staff_membership_id,
        target_organisation_id,
        reason,
        started_at,
        expires_at
    ) VALUES (
        v_caller_mem_id,
        p_target_org_id,
        p_reason,
        now(),
        now() + (v_hours || ' hours')::interval
    )
    RETURNING id INTO v_grant_id;

    PERFORM fn_audit_append(
        'platform.support.grant.created',
        'support_access_grants',
        v_grant_id::text,
        jsonb_build_object('target_organisation_id', p_target_org_id, 'reason', p_reason, 'duration_hours', v_hours)
    );

    RETURN v_grant_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_create_support_grant(UUID, TEXT, INT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_create_support_grant(UUID, TEXT, INT) TO archscale_app_runtime;

CREATE OR REPLACE FUNCTION fn_revoke_support_grant(
    p_grant_id UUID
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

    IF NOT ('platform.support.manage' = ANY(fn_get_effective_permissions())) THEN
        RAISE EXCEPTION 'AUTH_PERMISSION_DENIED: Missing required permission platform.support.manage' USING ERRCODE = '42501';
    END IF;

    UPDATE public.support_access_grants
    SET revoked_at = now()
    WHERE id = p_grant_id AND revoked_at IS NULL;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Support grant not found or already revoked' USING ERRCODE = 'P0002';
    END IF;

    -- Invalidate any active context tied to this grant
    UPDATE public.access_contexts
    SET is_valid = false
    WHERE support_grant_id = p_grant_id;

    PERFORM fn_audit_append(
        'platform.support.grant.revoked',
        'support_access_grants',
        p_grant_id::text,
        jsonb_build_object('grant_id', p_grant_id)
    );

    RETURN true;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_revoke_support_grant(UUID) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_revoke_support_grant(UUID) TO archscale_app_runtime;
