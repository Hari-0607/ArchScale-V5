-- =============================================================================
-- Migration 012: Secure User Mirror Access for archscale_app_runtime
-- ArchScale V05 Authentication & Authorisation Layer
-- =============================================================================
-- Purpose
--   Migration 011 granted the runtime role unrestricted SELECT, INSERT, UPDATE
--   on public.users via USING (true) / WITH CHECK (true). That violates the
--   least-privilege principle: any connection without a context can enumerate
--   all emails, and any INSERT/UPDATE is unconstrained.
--
--   This migration:
--     1. Drops users_runtime_policy (the open policy from 011)
--     2. Revokes direct write privileges on public.users; grants SELECT only so
--        context-bound RLS can evaluate.
--     3. Adds fn_resolve_user_code -- SECURITY DEFINER, returns email or NULL
--     4. Adds fn_upsert_user_mirror -- SECURITY DEFINER, creates identity record;
--        on conflict updates phone ONLY (never rewrites email, never writes roles)
--     5. Adds context-bound RLS SELECT-only policy using safe NULLIF cast on GUC
--     6. Adds parameterless is_context_valid() helper with safe NULLIF GUC cast
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
--    On insert: writes id, user_code, email, phone.
--    On conflict (id): updates phone and updated_at ONLY.
--    p_email is NEVER updated on conflict -- preventing callers from rewriting
--    an existing user's email.
--    Never writes roles or tenant data (public.users has no such columns).
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
        SET phone      = COALESCE(EXCLUDED.phone, public.users.phone),
            updated_at = now()
        WHERE public.users.id = p_id;  -- email is NOT updated; remains immutable on conflict

    RETURN QUERY
        SELECT u.id, u.user_code::TEXT, u.email, u.created_at, u.updated_at
        FROM public.users u
        WHERE u.id = p_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_upsert_user_mirror(UUID, TEXT, TEXT, TEXT) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION fn_upsert_user_mirror(UUID, TEXT, TEXT, TEXT) TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 5. Parameterless is_context_valid() helper with safe NULLIF GUC cast
--    Avoids invalid input syntax for type uuid: "" when GUC is empty string.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION is_context_valid()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
    SELECT COALESCE(
        is_context_valid(NULLIF(current_setting('archscale.current_context_id', true), '')::uuid),
        false
    );
$$;

REVOKE EXECUTE ON FUNCTION is_context_valid() FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION is_context_valid() TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 6. Helper: fn_current_context_user_id()
--    Returns the user_id bound to the current transaction context if and only
--    if is_context_valid() is true. Returns NULL if context is missing, empty,
--    or invalid. SECURITY DEFINER ensures access_contexts is read securely.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_current_context_user_id()
RETURNS UUID
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_ctx_id UUID;
    v_user_id UUID;
BEGIN
    v_ctx_id := NULLIF(current_setting('archscale.current_context_id', true), '')::uuid;
    IF v_ctx_id IS NULL THEN
        RETURN NULL;
    END IF;

    IF NOT is_context_valid(v_ctx_id) THEN
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

-- -----------------------------------------------------------------------------
-- 7. Context-bound SELECT policy for public.users
--
--    The runtime role may SELECT only the row whose id is the user_id of
--    the currently validated access_context. is_context_valid() is verified
--    every time the policy fires.
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
                id = fn_current_context_user_id()
            );
    END IF;
END $$;

-- Ensure RLS remains enabled and forced (idempotent)
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users FORCE ROW LEVEL SECURITY;
