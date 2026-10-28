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

    // 1. Guardrail: Must provide --confirm-staging
    if (!args.includes('--confirm-staging')) {
        console.error('ABORTED: Refusing to run without --confirm-staging flag.');
        process.exit(1);
    }

    // 2. Identify migration file
    const fileArg = args.find(a => !a.startsWith('--'));
    if (!fileArg) {
        console.error('ABORTED: Missing migration file argument.');
        console.error('Usage: npx tsx scripts/apply_one_migration.ts <migration-file> --confirm-staging');
        process.exit(1);
    }

    let migrationFilePath = fileArg;
    if (!fs.existsSync(migrationFilePath)) {
        // Try resolving relative to migrations/
        const resolved = path.join(__dirname, '../migrations', fileArg);
        if (fs.existsSync(resolved)) {
            migrationFilePath = resolved;
        } else {
            console.error(`ABORTED: Migration file not found: ${fileArg}`);
            process.exit(1);
        }
    }

    // 3. Staging environment verification
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

    // Print ONLY the project ref (never connection strings or secrets)
    console.log(`[Staging Migration Target] Project Ref: ${projectRef}`);
    console.log(`[Migration File] ${path.basename(migrationFilePath)}`);

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

    const sqlContent = fs.readFileSync(migrationFilePath, 'utf-8');

    console.log('[1/3] Starting migration inside a single transaction...');
    try {
        await client.query('BEGIN;');

        await client.query(sqlContent);
        console.log('[2/3] Migration SQL executed. Running read-only post-checks...');

        const basename = path.basename(migrationFilePath);

        if (basename.includes('012')) {
            // Post-checks specifically for Migration 012
            const checkRes = await client.query(`
                SELECT
                    EXISTS (
                        SELECT 1 FROM pg_proc p
                        JOIN pg_namespace n ON n.oid = p.pronamespace
                        WHERE n.nspname = 'public' AND p.proname = 'fn_resolve_user_code'
                    ) AS has_fn_resolve,
                    EXISTS (
                        SELECT 1 FROM pg_proc p
                        JOIN pg_namespace n ON n.oid = p.pronamespace
                        WHERE n.nspname = 'public' AND p.proname = 'fn_upsert_user_mirror'
                    ) AS has_fn_upsert,
                    EXISTS (
                        SELECT 1 FROM pg_policies
                        WHERE schemaname = 'public' AND tablename = 'users' AND policyname = 'users_own_row_context_policy'
                    ) AS has_context_policy,
                    EXISTS (
                        SELECT 1 FROM pg_policies
                        WHERE schemaname = 'public' AND tablename = 'users' AND policyname = 'users_runtime_policy'
                    ) AS has_old_runtime_policy,
                    has_table_privilege('archscale_app_runtime', 'public.users', 'INSERT') AS runtime_insert,
                    has_table_privilege('archscale_app_runtime', 'public.users', 'UPDATE') AS runtime_update,
                    has_table_privilege('archscale_app_runtime', 'public.users', 'SELECT') AS runtime_select;
            `);

            const row = checkRes.rows[0];
            console.log('[Post-Check Results]:');
            console.log(`  - fn_resolve_user_code exists: ${row.has_fn_resolve}`);
            console.log(`  - fn_upsert_user_mirror exists: ${row.has_fn_upsert}`);
            console.log(`  - users_own_row_context_policy exists: ${row.has_context_policy}`);
            console.log(`  - users_runtime_policy exists (expected false): ${row.has_old_runtime_policy}`);
            console.log(`  - archscale_app_runtime INSERT privilege (expected false): ${row.runtime_insert}`);
            console.log(`  - archscale_app_runtime UPDATE privilege (expected false): ${row.runtime_update}`);
            console.log(`  - archscale_app_runtime SELECT privilege (expected true): ${row.runtime_select}`);

            const allPassed =
                row.has_fn_resolve === true &&
                row.has_fn_upsert === true &&
                row.has_context_policy === true &&
                row.has_old_runtime_policy === false &&
                row.runtime_insert === false &&
                row.runtime_update === false &&
                row.runtime_select === true;

            if (!allPassed) {
                console.error('FAILED: One or more post-checks failed! Rolling back transaction.');
                await client.query('ROLLBACK;');
                process.exit(1);
            }
        } else {
            console.log('[Post-Check]: General migration applied without specialized assertions.');
        }

        await client.query('COMMIT;');
        console.log('[3/3] Transaction COMMITTED successfully. Migration applied cleanly.');
    } catch (err: any) {
        console.error('ERROR during migration execution. Rolling back...');
        try {
            await client.query('ROLLBACK;');
        } catch { /* ignore rollback error */ }
        console.error(`Error details: ${err.message}`);
        process.exit(1);
    } finally {
        await client.end().catch(() => {});
    }
}

main();
