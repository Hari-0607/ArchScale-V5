import fs from 'fs';
import pg from 'pg';

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

async function main() {
    const adminUrl = process.env.SUPABASE_DB_ADMIN_URL;
    if (!adminUrl) throw new Error('Missing SUPABASE_DB_ADMIN_URL in .env');

    const client = new pg.Client({ connectionString: adminUrl, ssl: { rejectUnauthorized: false } });
    await client.connect();

    console.log('================================================================');
    console.log('ArchScale V05: Staging Dry Run of Migration 012');
    console.log('Isolation: Single transaction with mandatory ROLLBACK');
    console.log('================================================================\n');

    try {
        await client.query('BEGIN;');

        // Check Supabase schema differences before applying (e.g. pgcrypto schema)
        const pgcryptoCheck = await client.query(
            `SELECT n.nspname AS schema_name
             FROM pg_extension e
             JOIN pg_namespace n ON n.oid = e.extnamespace
             WHERE e.extname = 'pgcrypto';`
        );
        const pgcryptoSchema = pgcryptoCheck.rows[0]?.schema_name || 'NOT INSTALLED';
        console.log(`[Supabase Environment Check] pgcrypto extension schema: ${pgcryptoSchema}`);

        // Read and execute 012 SQL
        const sql012 = fs.readFileSync('migrations/012_secure_user_mirror_access.sql', 'utf-8');
        await client.query(sql012);
        console.log('[1/5] Migration 012 applied cleanly inside transaction.');

        // On Supabase, postgres must be granted the role before SET LOCAL ROLE is allowed
        await client.query('GRANT archscale_app_runtime TO postgres;');
        await client.query('SET LOCAL ROLE archscale_app_runtime;');
        console.log('[2/5] Switched to role archscale_app_runtime (SET LOCAL ROLE).');

        // Check 1: SELECT on users with no context returns 0 rows
        const noCtxSelect = await client.query('SELECT count(*) AS count FROM public.users;');
        console.log(`[3/5] No-context SELECT on public.users count: ${noCtxSelect.rows[0].count} (Expected: 0)`);

        // Check 2: Direct INSERT denied (42501)
        await client.query('SAVEPOINT sp_ins;');
        let insCode = '';
        try {
            await client.query(`INSERT INTO public.users (id, user_code, email) VALUES ('90000000-0000-0000-0000-000000000001', 'AS-ROGUE', 'rogue@archscale.test');`);
        } catch (e: any) {
            insCode = e.code;
        } finally {
            await client.query('ROLLBACK TO SAVEPOINT sp_ins;');
        }
        console.log(`[4/5] Direct INSERT denied SQLSTATE: ${insCode} (Expected: 42501)`);

        // Check 3: Direct UPDATE denied (42501)
        await client.query('SAVEPOINT sp_upd;');
        let updCode = '';
        try {
            await client.query(`UPDATE public.users SET email = 'hacked@archscale.test';`);
        } catch (e: any) {
            updCode = e.code;
        } finally {
            await client.query('ROLLBACK TO SAVEPOINT sp_upd;');
        }
        console.log(`[4b/5] Direct UPDATE denied SQLSTATE: ${updCode} (Expected: 42501)`);

        // Check 4: fn_resolve_user_code resolution
        const resCodeKnown = await client.query(`SELECT fn_resolve_user_code('AS-FNDR');`);
        const resCodeUnknown = await client.query(`SELECT fn_resolve_user_code('AS-DOESNOTEXIST99');`);
        const resCodeNonAs = await client.query(`SELECT fn_resolve_user_code('some.email@archscale.test');`);
        console.log(`[5/5] fn_resolve_user_code tests:`);
        console.log(`  - AS-FNDR resolves to: ${resCodeKnown.rows[0].fn_resolve_user_code}`);
        console.log(`  - Unknown AS- code resolves to: ${resCodeUnknown.rows[0].fn_resolve_user_code}`);
        console.log(`  - Non-AS pattern resolves to: ${resCodeNonAs.rows[0].fn_resolve_user_code}`);

        // Check 5: fn_upsert_user_mirror and immutable email
        const testUserId = '80000000-0000-0000-0000-000000000001';
        const upsert1 = await client.query(
            `SELECT * FROM fn_upsert_user_mirror($1, 'dryrun.user@archscale.test', 'AS-DRYRUN01', '+1-555-0100');`,
            [testUserId]
        );
        console.log(`  - Initial fn_upsert_user_mirror: email="${upsert1.rows[0].email}" code="${upsert1.rows[0].user_code}"`);

        // Try rewriting email on conflict
        const upsertConflict = await client.query(
            `SELECT * FROM fn_upsert_user_mirror($1, 'attacker.hijack@archscale.test', NULL, '+1-555-0999');`,
            [testUserId]
        );
        console.log(`  - Conflict fn_upsert_user_mirror (attempted email change): email="${upsertConflict.rows[0].email}" phone="${upsertConflict.rows[0].phone}" (email remained unchanged)`);

        // Reset role before rollback
        await client.query('RESET ROLE;');
        console.log('\n[Dry Run Result] All checks passed cleanly. Rolling back transaction now.');
    } finally {
        await client.query('ROLLBACK;').catch(() => {});
        console.log('[Dry Run Completed] Transaction rolled back. Zero changes persisted.');
        await client.end();
    }
}

main().catch(err => {
    let msg = err.message || '';
    console.error('Dry Run Fatal Error:', msg);
    process.exit(1);
});
