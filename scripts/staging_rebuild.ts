import fs from 'fs';
import path from 'path';
import pg from 'pg';
import readline from 'readline';

// Native .env parser — never prints secrets
if (fs.existsSync('.env')) {
    const lines = fs.readFileSync('.env', 'utf-8').split(/\r?\n/);
    for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#')) {
            const idx = trimmed.indexOf('=');
            if (idx !== -1) {
                const k = trimmed.substring(0, idx).trim();
                const v = trimmed.substring(idx + 1).trim();
                if (!process.env[k]) process.env[k] = v;
            }
        }
    }
}

/**
 * Migration objects catalogue created across migrations 001 to 012.
 * Drops occur strictly in reverse dependency order:
 * 1. Functions / procedures
 * 2. Tables (with foreign keys and triggers)
 * 3. Enums / types
 *
 * PRESERVED (NEVER DROPPED):
 * - rls_auto_enable() function (Supabase staging safety helper)
 * - ensure_rls trigger on pg_catalog / public
 */
const MIGRATION_FUNCTIONS = [
    'fn_current_context_user_id()',
    'fn_upsert_user_mirror(UUID, TEXT, TEXT, TEXT)',
    'fn_resolve_user_code(TEXT)',
    'fn_set_app_context(UUID)',
    'is_context_valid(UUID)',
    'is_context_valid()',
    'fn_approve_membership(UUID, UUID, INET, TEXT)',
    'fn_approve_organisation(UUID, UUID, INET, TEXT)',
    'fn_allocate_seats(UUID, TEXT, TEXT, INTEGER, UUID)',
    'trg_audit_logs_immutable()',
    'trg_check_approval_step_invariants()',
    'trg_check_memberships_expiry()',
    'trg_check_membership_active_org()',
    'trg_check_cascade_org_status()',
    'trg_check_last_founder_and_owner()',
    'trg_check_single_platform_org()'
];

const MIGRATION_TABLES = [
    // Dependents first
    'audit_logs',
    'share_grants',
    'support_access_grants',
    'approval_steps',
    'approval_requests',
    'membership_seats',
    'access_contexts',
    'invitations',
    'role_assignment_history',
    'memberships',
    'workspaces',
    'access_profile_permissions',
    'access_profiles',
    'tenant_role_permission_templates',
    'role_permissions',
    'role_tenant_types',
    'roles',
    'permissions',
    'organisation_seats',
    'organisation_entitlements',
    'app_catalogue',
    'organisations',
    'tenant_types',
    'users'
];

const MIGRATION_TYPES = [
    'org_status',
    'membership_status',
    'request_status',
    'portal_type',
    'aal_level'
];

const MIGRATIONS_TO_APPLY = [
    '001_core_types_and_identities.sql',
    '002_ecosystem_apps_and_entitlements.sql',
    '003_data_driven_roles_and_permissions.sql',
    '004_workspaces_memberships_and_contexts.sql',
    '005_approvals_and_support_access.sql',
    '006_share_grants_and_security_controls.sql',
    '007_append_only_audit_log.sql',
    '008_database_invariants_and_functions.sql',
    '009_least_privilege_runtime_role.sql',
    '010_supabase_staging_compatibility.sql',
    '012_secure_user_mirror_access.sql'
];

async function confirmWithUser(promptText: string): Promise<boolean> {
    // If running in non-interactive CI or without flag, fail-safe to false
    if (process.argv.includes('--execute') && process.argv.includes('--approved-by-user')) {
        return true;
    }

    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise(resolve => {
        rl.question(`${promptText} [type 'YES' to proceed]: `, answer => {
            rl.close();
            resolve(answer.trim() === 'YES');
        });
    });
}

export async function stagingRebuildPlan(dryRunOnly = true) {
    const adminUrl = process.env.SUPABASE_DB_ADMIN_URL;
    if (!adminUrl) throw new Error('Missing SUPABASE_DB_ADMIN_URL in .env');

    const client = new pg.Client({ connectionString: adminUrl, ssl: { rejectUnauthorized: false } });
    await client.connect();

    console.log('================================================================');
    console.log('ArchScale V05: Staging Clean Rebuild Plan');
    console.log('================================================================\n');

    try {
        // 1. Inspect and list all existing public objects
        console.log('[Phase 1] Current public schema objects catalogue:');

        const tables = await client.query(
            `SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;`
        );
        console.log(`\n  Tables (${tables.rowCount}):`);
        for (const t of tables.rows) {
            const isMigrationObj = MIGRATION_TABLES.includes(t.tablename);
            console.log(`    - ${t.tablename} [${isMigrationObj ? 'MANAGED: will be dropped' : 'PRESERVED: keep'}]`);
        }

        const functions = await client.query(
            `SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS args
             FROM pg_proc p
             JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = 'public'
             ORDER BY p.proname;`
        );
        console.log(`\n  Functions (${functions.rowCount}):`);
        for (const f of functions.rows) {
            const isPreserved = f.proname === 'rls_auto_enable' || f.proname.includes('ensure_rls');
            console.log(`    - ${f.proname}(${f.args}) [${isPreserved ? 'PRESERVED: system guard' : 'MANAGED: will be dropped'}]`);
        }

        const types = await client.query(
            `SELECT typname FROM pg_type t
             JOIN pg_namespace n ON n.oid = t.typnamespace
             WHERE n.nspname = 'public' AND t.typtype = 'e'
             ORDER BY typname;`
        );
        console.log(`\n  Enums (${types.rowCount}):`);
        for (const t of types.rows) {
            console.log(`    - ${t.typname} [MANAGED]`);
        }

        console.log('\n================================================================');
        console.log('[Phase 2] Execution Plan:');
        console.log('  1. DROP TABLES: 24 managed tables in dependency order (CASCADE)');
        console.log('     * NOTE ON AUDIT LOG: audit_logs will be dropped via DROP TABLE public.audit_logs CASCADE.');
        console.log('       Because triggers only intercept DML (UPDATE/DELETE/TRUNCATE), DROP TABLE succeeds');
        console.log('       and permanently purges the historical TEST_LOG row from staging.');
        console.log('  2. DROP TYPES: 5 custom ENUM types in reverse dependency order');
        console.log('  3. DROP FUNCTIONS: 16 migration functions (preserves rls_auto_enable)');
        console.log('  4. RE-APPLY MIGRATIONS: sequentially apply 001-012');
        console.log('  5. CONFIGURE RUNTIME ROLE: set archscale_app_runtime password from .env');
        console.log('================================================================\n');

        if (dryRunOnly) {
            console.log('[PLAN ONLY] Halting execution. No changes made to staging database.');
            return;
        }

        // Wait for explicit user confirmation before any mutation
        const confirmed = await confirmWithUser('WARNING: Destructive rebuild requested. Proceed with dropping and rebuilding staging?');
        if (!confirmed) {
            console.log('ABORTED: Rebuild was not confirmed by user. Zero changes made.');
            return;
        }

        // Execution logic (only reachable when dryRunOnly = false AND user confirmed):
        console.log('Starting approved rebuild execution...');
        // Drops and reapplies would run here
    } finally {
        await client.end();
    }
}

// Default execution: plan only
if (import.meta.url === `file://${process.argv[1].replace(/\\/g, '/')}`) {
    stagingRebuildPlan(true).catch(err => {
        console.error('Fatal plan error:', err.message);
        process.exit(1);
    });
}
