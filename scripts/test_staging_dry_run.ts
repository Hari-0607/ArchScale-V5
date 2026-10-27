import fs from 'fs';
import path from 'path';
import pg from 'pg';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Parse .env natively
if (fs.existsSync('.env')) {
    const envLines = fs.readFileSync('.env', 'utf-8').split(/\r?\n/);
    for (const line of envLines) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#')) {
            const idx = trimmed.indexOf('=');
            if (idx !== -1) {
                const key = trimmed.substring(0, idx).trim();
                const val = trimmed.substring(idx + 1).trim();
                if (!process.env[key]) process.env[key] = val;
            }
        }
    }
}

async function testAll() {
    const adminUrl = process.env.SUPABASE_DB_ADMIN_URL!;
    const client = new pg.Client({
        connectionString: adminUrl,
        ssl: { rejectUnauthorized: false }
    });

    await client.connect();
    console.log('--- Connected to Supabase Staging DB for dry-run ---');
    await client.query('BEGIN;');

    // 1. Simulate creating public.aal_level
    await client.query(`
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_type t 
                JOIN pg_namespace n ON n.oid = t.typnamespace 
                WHERE t.typname = 'aal_level' AND n.nspname = 'public'
            ) THEN
                CREATE TYPE public.aal_level AS ENUM ('aal1', 'aal2', 'aal3');
            END IF;
        END $$;
    `);

    const files = [
        '003_data_driven_roles_and_permissions.sql',
        '004_workspaces_memberships_and_contexts.sql',
        '005_approvals_and_support_access.sql',
        '006_share_grants_and_security_controls.sql',
        '007_append_only_audit_log.sql',
        '008_database_invariants_and_functions.sql',
        '009_least_privilege_runtime_role.sql'
    ];

    for (const f of files) {
        process.stdout.write(`Testing ${f}... `);
        const sql = fs.readFileSync(path.join(__dirname, '../migrations', f), 'utf-8');
        try {
            await client.query(sql);
            console.log('PASSED');
        } catch (e: any) {
            console.log(`FAILED: [${e.code}] ${e.message}`);
        }
    }

    await client.query('ROLLBACK;');
    await client.end();
}

testAll().catch(console.error);
