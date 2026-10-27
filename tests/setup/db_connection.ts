import pg from 'pg';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const { Pool, Client } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Load .env natively
const envPath = path.resolve(__dirname, '../../.env');
if (fs.existsSync(envPath)) {
    const lines = fs.readFileSync(envPath, 'utf-8').split(/\r?\n/);
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

const testDbUrl = process.env.ARCHSCALE_TEST_DB_URL;
if (!testDbUrl) {
    throw new Error(
        'Missing ARCHSCALE_TEST_DB_URL in .env. Local tests require ARCHSCALE_TEST_DB_URL to be set (e.g. postgresql://<user>:<password>@127.0.0.1:<port>/postgres).'
    );
}

const parsedUrl = new URL(testDbUrl);

export const DB_CONFIG: pg.PoolConfig = {
    host: parsedUrl.hostname,
    port: parseInt(parsedUrl.port || '5432', 10),
    user: parsedUrl.username,
    password: decodeURIComponent(parsedUrl.password),
    database: parsedUrl.pathname.replace('/', '') || 'postgres'
};

export const RUNTIME_CONFIG: pg.PoolConfig = {
    host: parsedUrl.hostname,
    port: parseInt(parsedUrl.port || '5432', 10),
    user: 'archscale_app_runtime',
    password: 'archscale_runtime_local_pass',
    database: parsedUrl.pathname.replace('/', '') || 'postgres'
};

export async function createIsolatedTestDatabase(testDbName: string): Promise<pg.Pool> {
    // 1. Connect to default database to drop/create the isolated test DB
    const adminClient = new Client(DB_CONFIG);
    await adminClient.connect();
    
    // Terminate existing connections and recreate test DB
    await adminClient.query(`
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE datname = '${testDbName}' AND pid <> pg_backend_pid();
    `);
    await adminClient.query(`DROP DATABASE IF EXISTS ${testDbName};`);
    await adminClient.query(`CREATE DATABASE ${testDbName};`);
    await adminClient.end();

    // 2. Connect to the fresh isolated test DB and run all migrations & seeds
    const testPool = new Pool({
        ...DB_CONFIG,
        database: testDbName,
        max: 20
    });

    const migrationFiles = [
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
        '011_user_mirror_rls_policy.sql'
    ];

    for (const file of migrationFiles) {
        const filePath = path.join(__dirname, '../../migrations', file);
        const sql = fs.readFileSync(filePath, 'utf-8');
        await testPool.query(sql);
    }

    // Apply seed data
    const seedPath = path.join(__dirname, '../../seeds/001_seed_initial_data.sql');
    const seedSql = fs.readFileSync(seedPath, 'utf-8');
    await testPool.query(seedSql);

    return testPool;
}
