import fs from 'fs';
import path from 'path';
import pg from 'pg';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

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

    console.log('Applying migrations/011_user_mirror_rls_policy.sql to staging...');
    const sqlPath = path.join(__dirname, '../migrations/011_user_mirror_rls_policy.sql');
    const sql = fs.readFileSync(sqlPath, 'utf-8');

    await client.query(sql);
    console.log('Migration 011 applied successfully.');

    // Verify policy in pg_policies
    const res = await client.query(
        "SELECT policyname, tablename, roles, cmd FROM pg_policies WHERE tablename = 'users';"
    );
    console.log('USERS POLICIES IN STAGING:', res.rows);

    await client.end();
}

main().catch(err => {
    console.error('Migration failed:', err.message);
    process.exit(1);
});
