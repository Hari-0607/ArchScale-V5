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

    console.log(`[Staging Dry-Run Target] Project Ref: ${projectRef}`);
    console.log(`[Action] Executing Migration 013 in transaction, verifying checks as runtime role, followed strictly by ROLLBACK.`);

    const client = new pg.Client({
        connectionString: adminUrl,
        ssl: { rejectUnauthorized: false },
        connectionTimeoutMillis: 15000
    });

    try {
        await client.connect();
    } catch (err: any) {
        console.error('ABORTED: Failed to connect to database. Redacted error message:', err.message?.replace(adminUrl, '[REDACTED]'));
        process.exit(1);
    }

    const migration013Path = path.join(__dirname, '../migrations/013_context_rls_and_authz_functions.sql');
    const sqlContent = fs.readFileSync(migration013Path, 'utf-8');

    try {
        console.log('[Step 1] BEGIN transaction...');
        await client.query('BEGIN;');

        console.log('[Step 2] Executing migration 013 SQL in transaction...');
        await client.query(sqlContent);

        console.log('[Step 3] Switching transaction session to role archscale_app_runtime...');
        await client.query(`SET ROLE archscale_app_runtime;`);

        console.log('[Step 4] Running verification checks as archscale_app_runtime:');
        
        // 1. Direct table reads without context (must return 0 rows)
        const auditRes = await client.query(`SELECT COUNT(*) AS c FROM public.audit_logs;`);
        const orgRes = await client.query(`SELECT COUNT(*) AS c FROM public.organisations;`);
        const wsRes = await client.query(`SELECT COUNT(*) AS c FROM public.workspaces;`);
        const memRes = await client.query(`SELECT COUNT(*) AS c FROM public.memberships;`);
        console.log(`  - Direct SELECT public.audit_logs without context: ${auditRes.rows[0].c} rows (expected: 0)`);
        console.log(`  - Direct SELECT public.organisations without context: ${orgRes.rows[0].c} rows (expected: 0)`);
        console.log(`  - Direct SELECT public.workspaces without context: ${wsRes.rows[0].c} rows (expected: 0)`);
        console.log(`  - Direct SELECT public.memberships without context: ${memRes.rows[0].c} rows (expected: 0)`);

        // 2. Direct INSERT on audit_logs must fail
        let directInsertBlocked = false;
        try {
            await client.query(`
                INSERT INTO public.audit_logs (actor_user_id, action, target_type)
                VALUES ('00000000-0000-0000-0000-000000000001', 'FORGED_AUDIT', 'organisations');
            `);
        } catch (e: any) {
            directInsertBlocked = true;
            console.log(`  - Direct INSERT public.audit_logs: BLOCKED (Error: ${e.code || e.message})`);
        }
        if (!directInsertBlocked) {
            throw new Error('Direct INSERT on public.audit_logs was not blocked!');
        }

        // 3. Switch back to postgres admin to verify functions exist
        await client.query(`RESET ROLE;`);

        const funcRes = await client.query(`
            SELECT proname, prosecdef FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public' AND p.proname IN (
                'fn_create_access_context',
                'fn_set_app_context',
                'fn_active_support_grant',
                'fn_assert_not_support_context',
                'fn_read_audit_logs'
            );
        `);
        console.log(`  - Verified functions created: ${funcRes.rows.map(r => `${r.proname} (secdef: ${r.prosecdef})`).join(', ')}`);

        console.log('[Step 5] Triggering ROLLBACK...');
        await client.query('ROLLBACK;');
        console.log('[Step 6] ROLLBACK complete. Zero changes persisted to staging.');

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
