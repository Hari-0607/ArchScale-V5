-- =============================================================================
-- Migration 011: User Mirror RLS Policy for Application Runtime Role
-- ArchScale V05 Authentication & Authorisation Layer
-- =============================================================================

-- Enable archscale_app_runtime to SELECT, INSERT, and UPDATE on public.users
-- users is a pure identity mirror with NO tenant data, roles, or standing.
-- PostgREST (anon, authenticated, PUBLIC) remains strictly revoked.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies 
        WHERE schemaname = 'public' 
          AND tablename = 'users' 
          AND policyname = 'users_runtime_policy'
    ) THEN
        CREATE POLICY users_runtime_policy ON public.users
            FOR ALL
            TO archscale_app_runtime
            USING (true)
            WITH CHECK (true);
    END IF;
END $$;
