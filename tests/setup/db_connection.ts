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

import { assertLocalTestDatabaseGuard } from '../../src/db/index.js';

const testDbUrl = process.env.ARCHSCALE_TEST_DB_URL;
const parsedUrl = assertLocalTestDatabaseGuard(testDbUrl);

export const DB_CONFIG: pg.PoolConfig = {
    host: parsedUrl.hostname,
    port: parseInt(parsedUrl.port || '5432', 10),
    user: parsedUrl.username,
    password: decodeURIComponent(parsedUrl.password),
    database: parsedUrl.pathname.replace('/', '') || 'postgres'
};

import * as crypto from 'crypto';

const localRuntimePassword = process.env.ARCHSCALE_LOCAL_RUNTIME_PASSWORD || 'local_test_pass';
process.env.ARCHSCALE_LOCAL_RUNTIME_PASSWORD = localRuntimePassword;

export const RUNTIME_CONFIG: pg.PoolConfig = {
    host: parsedUrl.hostname,
    port: parseInt(parsedUrl.port || '5432', 10),
    user: 'archscale_app_runtime',
    password: localRuntimePassword,
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

    // Ensure archscale_app_runtime role password matches localRuntimePassword
    await testPool.query(`
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'archscale_app_runtime') THEN
                CREATE ROLE archscale_app_runtime WITH LOGIN PASSWORD '${localRuntimePassword}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
            ELSE
                ALTER ROLE archscale_app_runtime WITH PASSWORD '${localRuntimePassword}';
            END IF;
        END $$;
    `);

    // Create minimal stand-in auth.users schema & table for local test isolation
    await testPool.query(`
        CREATE SCHEMA IF NOT EXISTS auth;
        CREATE TABLE IF NOT EXISTS auth.users (
            id UUID PRIMARY KEY,
            email TEXT UNIQUE NOT NULL
        );
        GRANT USAGE ON SCHEMA auth TO archscale_app_runtime;
        GRANT SELECT ON auth.users TO archscale_app_runtime;
    `);

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
        '011_user_mirror_rls_policy.sql',
        '012_secure_user_mirror_access.sql',
        '013_context_rls_and_authz_functions.sql',
        '014_organisational_hierarchy_and_invitations.sql',
        '015_invitations_refinements_and_security_hardening.sql'
    ];

    for (const file of migrationFiles) {
        const filePath = path.join(__dirname, '../../migrations', file);
        const sql = fs.readFileSync(filePath, 'utf-8');
        await testPool.query(sql);
    }

    // Apply seed data
    const seedFiles = [
        '001_seed_initial_data.sql',
        '002_phase2_permissions.sql'
    ];

    for (const seedFile of seedFiles) {
        const seedPath = path.join(__dirname, '../../seeds', seedFile);
        if (fs.existsSync(seedPath)) {
            const seedSql = fs.readFileSync(seedPath, 'utf-8');
            await testPool.query(seedSql);
        }
    }

    // Migration 016 creates task/attendance policy rows that reference seeded
    // application roles, so load the baseline roles and permissions first.
    const appDataMigration = path.join(__dirname, '../../migrations', '016_tasks_attendance_modules.sql');
    await testPool.query(fs.readFileSync(appDataMigration, 'utf-8'));

    return testPool;
}
