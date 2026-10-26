import pg from 'pg';
import * as fs from 'fs';
import * as path from 'path';

const { Pool, Client } = pg;

export const DB_CONFIG: pg.PoolConfig = {
    host: process.env.PGHOST || '127.0.0.1',
    port: parseInt(process.env.PGPORT || '5433', 10),
    user: process.env.PGUSER || 'postgres',
    password: process.env.PGPASSWORD || '',
    database: 'postgres'
};

export const RUNTIME_CONFIG: pg.PoolConfig = {
    host: process.env.PGHOST || '127.0.0.1',
    port: parseInt(process.env.PGPORT || '5433', 10),
    user: 'archscale_app_runtime',
    password: 'archscale_runtime_local_pass',
    database: 'postgres'
};

export async function createIsolatedTestDatabase(testDbName: string): Promise<pg.Pool> {
    // 1. Connect to default postgres database to drop/create the isolated test DB
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
        '009_least_privilege_runtime_role.sql'
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
