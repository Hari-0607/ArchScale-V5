-- =============================================================================
-- Migration 009: Least-Privilege Dedicated Runtime Role (archscale_app_runtime)
-- ArchScale V05 Authentication & Authorisation Layer
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Create Dedicated Runtime Database Role
-- (NO SUPERUSER, NO CREATEDB, NO CREATEROLE, NO BYPASSRLS)
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'archscale_app_runtime') THEN
        CREATE ROLE archscale_app_runtime WITH 
            LOGIN 
            PASSWORD 'archscale_runtime_local_pass'
            NOSUPERUSER 
            NOCREATEDB 
            NOCREATEROLE 
            NOBYPASSRLS;
    END IF;
END $$;

-- -----------------------------------------------------------------------------
-- 2. Schema Privileges (Usage only, NO schema creation/DDL rights)
-- -----------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO archscale_app_runtime;
REVOKE CREATE ON SCHEMA public FROM archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 3. Table Privileges (SELECT, INSERT, UPDATE only on operational tables)
-- -----------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE ON 
    tenant_types,
    organisations,
    users,
    app_catalogue,
    organisation_entitlements,
    organisation_seats,
    permissions,
    roles,
    role_tenant_types,
    role_permissions,
    tenant_role_permission_templates,
    access_profiles,
    access_profile_permissions,
    workspaces,
    memberships,
    membership_seats,
    access_contexts,
    invitations,
    role_assignment_history,
    approval_policies,
    access_requests,
    approval_steps,
    support_access_grants,
    share_grants,
    auth_rate_limits,
    account_lockouts
TO archscale_app_runtime;

-- -----------------------------------------------------------------------------
-- 4. Audit Log Privileges: Append-only (SELECT, INSERT only; forbid mutation)
-- -----------------------------------------------------------------------------
GRANT SELECT, INSERT ON audit_logs TO archscale_app_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM archscale_app_runtime, PUBLIC;

-- -----------------------------------------------------------------------------
-- 5. Stored Function Execution Privileges
-- -----------------------------------------------------------------------------
REVOKE EXECUTE ON FUNCTION fn_approve_organisation FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION fn_approve_membership FROM PUBLIC;

GRANT EXECUTE ON FUNCTION fn_approve_organisation TO archscale_app_runtime;
GRANT EXECUTE ON FUNCTION fn_approve_membership TO archscale_app_runtime;
GRANT EXECUTE ON FUNCTION is_context_valid TO archscale_app_runtime;
