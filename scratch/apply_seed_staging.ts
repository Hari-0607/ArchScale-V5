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
    if (!adminUrl) throw new Error('Missing SUPABASE_DB_ADMIN_URL');

    const client = new pg.Client({ connectionString: adminUrl, ssl: { rejectUnauthorized: false } });
    await client.connect();

    const seedPath = path.join(__dirname, '../seeds/001_seed_initial_data.sql');
    const sql = fs.readFileSync(seedPath, 'utf-8');

    console.log('Applying seeds/001_seed_initial_data.sql to Supabase staging...');
    await client.query(sql);
    console.log('Seed applied successfully.');

    await client.end();
}

main().catch(err => {
    console.error('Seed application failed:', err.message);
    process.exit(1);
});
