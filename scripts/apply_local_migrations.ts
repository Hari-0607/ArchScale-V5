import pg from 'pg';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from '../src/config/env.js';

const here = path.dirname(fileURLToPath(import.meta.url));

async function main() {
    if (config.env !== 'development') throw new Error('Local migration runner requires ARCHSCALE_ENV=development.');
    const adminUrl = new URL(config.supabaseDbAdminUrl);
    if (!['localhost','127.0.0.1','::1'].includes(adminUrl.hostname)) {
        throw new Error('Refusing migrations: SUPABASE_DB_ADMIN_URL must be loopback.');
    }
    const client = new pg.Client({ connectionString: config.supabaseDbAdminUrl });
    await client.connect();
    try {
        const migrationsDir = path.resolve(here, '../migrations');
        const migrations = (await fs.readdir(migrationsDir)).filter(f => /^\d{3}_.*\.sql$/.test(f)).sort();
        for (const file of migrations) {
            process.stdout.write(`Applying ${file}\n`);
            await client.query(await fs.readFile(path.join(migrationsDir, file), 'utf8'));
        }
        const seedsDir = path.resolve(here, '../seeds');
        const seeds = (await fs.readdir(seedsDir)).filter(f => /^\d{3}_.*\.sql$/.test(f)).sort();
        for (const file of seeds) {
            process.stdout.write(`Seeding ${file}\n`);
            await client.query(await fs.readFile(path.join(seedsDir, file), 'utf8'));
        }
    } finally {
        await client.end();
    }
}

main().catch(error => {
    // Error messages from Postgres can contain connection details: report only
    // the safe error code/name and let the operator inspect local logs privately.
    process.stderr.write(`Local migration failed (${error?.code || error?.name || 'unknown error'}).\n`);
    process.exitCode = 1;
});
