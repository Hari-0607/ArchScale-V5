-- =============================================================================
-- Migration 010: Supabase Staging Compatibility & PostgREST Lockdown
-- ArchScale V05 Authentication & Authorisation Layer
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Ensure archscale_app_runtime Role Exists (NO passwords in SQL file)
-- Password is set via runtime setup script reading strictly from .env
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'archscale_app_runtime') THEN
        CREATE ROLE archscale_app_runtime WITH 
            LOGIN 
            NOSUPERUSER 
            NOCREATEDB 
            NOCREATEROLE 
            NOBYPASSRLS;
    END IF;
END $$;

-- Explicitly allow connection to database and usage of public schema
GRANT CONNECT ON DATABASE postgres TO archscale_app_runtime;
GRANT USAGE ON SCHEMA public TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 2. Transaction-Local Context Setter for Least-Privilege Session Execution
-- Must be transaction-local (set_config is_local = true)
-- Must validate via is_context_valid(); raises exception on invalid context
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_set_app_context(p_context_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    -- Validate context strictly through central function
    IF NOT is_context_valid(p_context_id) THEN
        RAISE EXCEPTION 'ARCHSCALE_INVALID_CONTEXT: Context % is invalid, expired, or revoked', p_context_id
            USING ERRCODE = 'P0001';
    END IF;

    -- Set transaction-local GUC (is_local = true ensures auto-clear on commit/rollback)
    PERFORM set_config('archscale.current_context_id', p_context_id::text, true);
    RETURN true;
END;
$$;

REVOKE EXECUTE ON FUNCTION fn_set_app_context(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fn_set_app_context(UUID) TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 3. Total Revocation of PostgREST / Public Client Access
-- Protects all ArchScale tables from direct anon or authenticated API leakage
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    r RECORD;
BEGIN
    -- Revoke all table privileges from Supabase client roles
    FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public') LOOP
        EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.%I FROM anon, authenticated, PUBLIC;', r.tablename);
    END LOOP;

    -- Revoke all sequence privileges
    FOR r IN (SELECT sequencename FROM pg_sequences WHERE schemaname = 'public') LOOP
        EXECUTE format('REVOKE ALL PRIVILEGES ON SEQUENCE public.%I FROM anon, authenticated, PUBLIC;', r.sequencename);
    END LOOP;

    -- Revoke all function executions
    FOR r IN (SELECT routine_name, specific_name FROM information_schema.routines WHERE routine_schema = 'public') LOOP
        EXECUTE format('REVOKE ALL PRIVILEGES ON ROUTINE public.%I FROM anon, authenticated, PUBLIC;', r.routine_name);
    END LOOP;
END $$;

-- Re-grant operational privileges to archscale_app_runtime only
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO archscale_app_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM archscale_app_runtime, PUBLIC;
GRANT SELECT, INSERT ON audit_logs TO archscale_app_runtime;
GRANT EXECUTE ON FUNCTION is_context_valid(UUID) TO archscale_app_runtime;
GRANT EXECUTE ON FUNCTION fn_approve_organisation TO archscale_app_runtime;
GRANT EXECUTE ON FUNCTION fn_approve_membership TO archscale_app_runtime;
GRANT EXECUTE ON FUNCTION fn_set_app_context(UUID) TO archscale_app_runtime;
