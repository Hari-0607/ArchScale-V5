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
    const client = new pg.Client({ connectionString: adminUrl, ssl: { rejectUnauthorized: false } });
    await client.connect();
    const res = await client.query('SELECT id, name, portal, status FROM organisations;');
    console.log('ORGS IN DB:', JSON.stringify(res.rows, null, 2));
    await client.end();
}

main().catch(console.error);
