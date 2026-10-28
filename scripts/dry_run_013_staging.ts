import fs from 'fs';
import path from 'path';
import pg from 'pg';
import { fileURLToPath } from 'url';

// Load .env natively without logging secrets
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

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main() {
    const args = process.argv.slice(2);

    // Guardrail: Must provide --confirm-staging
    if (!args.includes('--confirm-staging')) {
        console.error('ABORTED: Refusing to run without --confirm-staging flag.');
        process.exit(1);
    }

    if (process.env.ARCHSCALE_ENV !== 'staging') {
        console.error(`ABORTED: ARCHSCALE_ENV must be 'staging'. Current: '${process.env.ARCHSCALE_ENV || 'undefined'}'`);
        process.exit(1);
    }

    const projectRef = process.env.ARCHSCALE_STAGING_PROJECT_REF;
    if (!projectRef) {
        console.error('ABORTED: ARCHSCALE_STAGING_PROJECT_REF is missing in .env');
        process.exit(1);
    }

    const adminUrl = process.env.SUPABASE_DB_ADMIN_URL;
    if (!adminUrl) {
        console.error('ABORTED: SUPABASE_DB_ADMIN_URL is missing in .env');
        process.exit(1);
    }

    const runtimeUrl = process.env.ARCHSCALE_RUNTIME_DB_URL;
    if (!runtimeUrl) {
        console.error('ABORTED: ARCHSCALE_RUNTIME_DB_URL is missing in .env');
        process.exit(1);
    }

    console.log(`[Staging Dry-Run Target] Project Ref: ${projectRef}`);
    console.log(`[Action] Executing Migration 013 in transaction, verifying checks, followed strictly by ROLLBACK.`);

    const client = new pg.Client({
        connectionString: adminUrl,
        ssl: { rejectUnauthorized: false },
        connectionTimeoutMillis: 15000
    });

    try {
        await client.connect();
    } catch (err: any) {
        console.error('ABORTED: Failed to connect to admin database. Redacted error message:', err.message?.replace(adminUrl, '[REDACTED]'));
        process.exit(1);
    }

    const migration013Path = path.join(__dirname, '../migrations/013_context_rls_and_authz_functions.sql');
    const sqlContent = fs.readFileSync(migration013Path, 'utf-8');

    try {
        console.log('[Step 1] BEGIN transaction as admin...');
        await client.query('BEGIN;');

        console.log('[Step 2] Executing migration 013 SQL in transaction...');
        await client.query(sqlContent);

        console.log('[Step 3] Verifying permissions and RLS configuration in transaction:');
        
        // Check table privileges for archscale_app_runtime
        const privCheck = await client.query(`
            SELECT 
                has_table_privilege('archscale_app_runtime', 'public.audit_logs', 'INSERT') AS audit_insert,
                has_table_privilege('archscale_app_runtime', 'public.audit_logs', 'SELECT') AS audit_select,
                has_table_privilege('archscale_app_runtime', 'public.organisations', 'SELECT') AS org_select,
                has_table_privilege('archscale_app_runtime', 'public.workspaces', 'SELECT') AS ws_select,
                has_table_privilege('archscale_app_runtime', 'public.memberships', 'SELECT') AS mem_select,
                has_table_privilege('archscale_app_runtime', 'public.access_contexts', 'INSERT') AS ctx_insert,
                has_table_privilege('archscale_app_runtime', 'public.access_contexts', 'UPDATE') AS ctx_update;
        `);
        const priv = privCheck.rows[0];
        console.log(`  - archscale_app_runtime audit_logs INSERT privilege (expected false): ${priv.audit_insert}`);
        console.log(`  - archscale_app_runtime audit_logs SELECT privilege (expected false): ${priv.audit_select}`);
        console.log(`  - archscale_app_runtime organisations SELECT privilege (expected true): ${priv.org_select}`);
        console.log(`  - archscale_app_runtime workspaces SELECT privilege (expected true): ${priv.ws_select}`);
        console.log(`  - archscale_app_runtime memberships SELECT privilege (expected true): ${priv.mem_select}`);
        console.log(`  - archscale_app_runtime access_contexts INSERT privilege (expected false): ${priv.ctx_insert}`);
        console.log(`  - archscale_app_runtime access_contexts UPDATE privilege (expected false): ${priv.ctx_update}`);

        // Check functions created
        const funcRes = await client.query(`
            SELECT proname, prosecdef FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public' AND p.proname IN (
                'fn_create_access_context',
                'fn_set_app_context',
                'fn_active_support_grant',
                'fn_assert_not_support_context',
                'fn_read_audit_logs',
                'fn_list_principal_memberships',
                'fn_list_org_workspaces_for_principal'
            )
            ORDER BY proname;
        `);
        console.log(`  - Verified functions created (${funcRes.rows.length}/7):`);
        for (const f of funcRes.rows) {
            console.log(`    * ${f.proname} (SECURITY DEFINER: ${f.prosecdef})`);
        }

        // Check new policies
        const polRes = await client.query(`
            SELECT tablename, policyname FROM pg_policies
            WHERE schemaname = 'public'
            ORDER BY tablename, policyname;
        `);
        console.log(`  - Total active RLS policies in transaction: ${polRes.rows.length}`);
        for (const p of polRes.rows) {
            console.log(`    * ${p.tablename}: ${p.policyname}`);
        }

        console.log('[Step 4] Triggering ROLLBACK...');
        await client.query('ROLLBACK;');
        console.log('[Step 5] ROLLBACK complete. Zero changes persisted to staging.');

        // Verify rollback worked
        const checkAfterRollback = await client.query(`
            SELECT EXISTS (
                SELECT 1 FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'public' AND p.proname = 'fn_create_access_context'
            ) AS exists_fn;
        `);
        console.log(`[Verification] fn_create_access_context exists after rollback (expected false): ${checkAfterRollback.rows[0].exists_fn}`);

    } catch (err: any) {
        console.error('ERROR during dry run transaction:', err.message);
        try {
            await client.query('ROLLBACK;');
            console.log('ROLLBACK executed following error.');
        } catch { /* ignore */ }
        process.exit(1);
    } finally {
        await client.end().catch(() => {});
    }
}

main();
