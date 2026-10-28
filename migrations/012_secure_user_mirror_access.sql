-- =============================================================================
-- Migration 012: Secure User Mirror Access for archscale_app_runtime
-- ArchScale V05 Authentication & Authorisation Layer
-- =============================================================================
-- Purpose
--   Migration 011 granted the runtime role unrestricted SELECT, INSERT, UPDATE
--   on public.users via USING (true) / WITH CHECK (true).  That violates the
--   least-privilege principle: any connection without a context can enumerate
--   all emails, and any INSERT/UPDATE is unconstrained.
--
--   This migration:
--     1. Drops users_runtime_policy (the open policy from 011)
--     2. Revokes the direct table privileges on public.users granted in 010/011
--     3. Adds fn_resolve_user_code -- SECURITY DEFINER, returns email or NULL
--     4. Adds fn_upsert_user_mirror -- SECURITY DEFINER, creates/updates only
--        id, user_code, email, phone; never roles or tenant data
--     5. Adds a context-bound RLS SELECT-only policy for the runtime role
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Drop the open policy from migration 011
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'users'
          AND policyname = 'users_runtime_policy'
    ) THEN
        DROP POLICY users_runtime_policy ON public.users;
    END IF;
END $$;

-- -----------------------------------------------------------------------------
-- 2. Revoke direct write privileges; grant SELECT so the RLS policy can evaluate.
--    The context-bound RLS policy (Section 5) restricts SELECT to the caller's own row.
--    Direct INSERT and UPDATE remain completely revoked.
-- -----------------------------------------------------------------------------
REVOKE ALL PRIVILEGES ON public.users FROM archscale_app_runtime;
GRANT SELECT ON public.users TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 3. fn_resolve_user_code
--    Given an AS-... code, return the sign-in email or NULL.
--    Does NOT require a context -- this is the pre-auth path.
--    Only resolves codes matching the AS-... pattern.
--    Returns NULL for unknown codes (never raises).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_resolve_user_code(p_code TEXT)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_email TEXT;
BEGIN
    IF p_code IS NULL OR trim(p_code) = '' THEN
        RETURN NULL;
    END IF;

    -- Only resolve AS-... pattern; prevents general email lookup via this function
    IF lower(trim(p_code)) NOT LIKE 'as-%' THEN
        RETURN NULL;
    END IF;

    SELECT email INTO v_email
    FROM public.users
    WHERE lower(user_code) = lower(trim(p_code))
    LIMIT 1;

    RETURN v_email;  -- NULL if not found; caller handles the unresolved case
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_resolve_user_code(TEXT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_resolve_user_code(TEXT) TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 4. fn_upsert_user_mirror
--    Creates or updates the public.users row for a verified principal.
--    Writes ONLY id, user_code, email, phone.  Never writes role_key,
--    organisation_id, or any tenant-scoped column.
--    The ON CONFLICT path is scoped to the row whose id = p_id,
--    preventing cross-principal overwrites.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_upsert_user_mirror(
    p_id        UUID,
    p_email     TEXT,
    p_user_code TEXT DEFAULT NULL,
    p_phone     TEXT DEFAULT NULL
)
RETURNS TABLE (
    id         UUID,
    user_code  TEXT,
    email      TEXT,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
#variable_conflict use_column
DECLARE
    v_code TEXT;
BEGIN
    IF p_id IS NULL THEN
        RAISE EXCEPTION 'fn_upsert_user_mirror: p_id must not be NULL'
            USING ERRCODE = 'P0001';
    END IF;

    IF p_email IS NULL OR trim(p_email) = '' THEN
        RAISE EXCEPTION 'fn_upsert_user_mirror: p_email must not be NULL or blank'
            USING ERRCODE = 'P0001';
    END IF;

    v_code := COALESCE(
        NULLIF(trim(p_user_code), ''),
        'AS-' || upper(substring(encode(gen_random_bytes(4), 'hex'), 1, 8))
    );

    INSERT INTO public.users (id, user_code, email, phone)
    VALUES (p_id, v_code, lower(trim(p_email)), p_phone)
    ON CONFLICT (id) DO UPDATE
        SET email      = lower(trim(EXCLUDED.email)),
            phone      = COALESCE(EXCLUDED.phone, public.users.phone),
            updated_at = now()
        WHERE public.users.id = p_id;  -- scoped to this principal's row only

    RETURN QUERY
        SELECT u.id, u.user_code::TEXT, u.email, u.created_at, u.updated_at
        FROM public.users u
        WHERE u.id = p_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_upsert_user_mirror(UUID, TEXT, TEXT, TEXT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_upsert_user_mirror(UUID, TEXT, TEXT, TEXT) TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 5. Context-bound SELECT policy for public.users
--
--    The runtime role may SELECT only the row whose id is the user_id of
--    the currently validated access_context.  is_context_valid() is called
--    every time the policy fires -- no GUC is trusted on its own.
--
--    INSERT and UPDATE are not in this policy; they must go through
--    fn_upsert_user_mirror (SECURITY DEFINER) which bypasses RLS as definer.
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'users'
          AND policyname = 'users_own_row_context_policy'
    ) THEN
        CREATE POLICY users_own_row_context_policy ON public.users
            FOR SELECT
            TO archscale_app_runtime
            USING (
                id = (
                    SELECT ac.user_id
                    FROM access_contexts ac
                    WHERE ac.id = current_setting('archscale.current_context_id', true)::uuid
                      AND is_context_valid(ac.id)
                    LIMIT 1
                )
            );
    END IF;
END $$;

-- Ensure RLS remains enabled and forced (idempotent)
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users FORCE ROW LEVEL SECURITY;
