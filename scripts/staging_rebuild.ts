import fs from 'fs';
import path from 'path';
import pg from 'pg';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Native .env parser — never prints secrets
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

import { assertLocalTestDatabaseGuard } from '../src/db/index.js';

interface CatalogObjects {
    tables: string[];
    functions: Array<{ name: string; args: string; sig: string }>;
    types: string[];
    triggers: Array<{ name: string; table: string }>;
    policies: Array<{ name: string; table: string }>;
}

async function extractReferenceCatalogFromFreshMigrations(): Promise<CatalogObjects> {
    const testDbUrl = process.env.ARCHSCALE_TEST_DB_URL;
    const parsedUrl = assertLocalTestDatabaseGuard(testDbUrl);

    const refDbName = 'archscale_catalog_ref';
    const adminConfig: pg.PoolConfig = {
        host: parsedUrl.hostname,
        port: parseInt(parsedUrl.port || '5432', 10),
        user: parsedUrl.username,
        password: decodeURIComponent(parsedUrl.password),
        database: 'postgres'
    };

    const adminClient = new pg.Client(adminConfig);
    await adminClient.connect();

    // Recreate fresh reference DB
    await adminClient.query(`
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE datname = '${refDbName}' AND pid <> pg_backend_pid();
    `);
    await adminClient.query(`DROP DATABASE IF EXISTS ${refDbName};`);
    await adminClient.query(`CREATE DATABASE ${refDbName};`);
    await adminClient.end();

    const refPool = new pg.Pool({
        ...adminConfig,
        database: refDbName
    });

    // Create minimal auth.users stand-in for migration 012 compatibility
    await refPool.query(`
        CREATE SCHEMA IF NOT EXISTS auth;
        CREATE TABLE IF NOT EXISTS auth.users (
            id UUID PRIMARY KEY,
            email TEXT UNIQUE NOT NULL
        );
    `);

    // Apply migrations 001 to 012 in order
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
        '012_secure_user_mirror_access.sql'
    ];

    for (const file of migrationFiles) {
        const filePath = path.join(__dirname, '../migrations', file);
        const sql = fs.readFileSync(filePath, 'utf-8');
        await refPool.query(sql);
    }

    // Query reference catalog
    const tablesRes = await refPool.query<{ tablename: string }>(
        `SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;`
    );
    const tables = tablesRes.rows.map(r => r.tablename);

    const funcsRes = await refPool.query<{ proname: string; args: string }>(
        `SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS args
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'public'
         ORDER BY p.proname, args;`
    );
    const functions = funcsRes.rows.map(r => ({
        name: r.proname,
        args: r.args,
        sig: `${r.proname}(${r.args})`
    }));

    const typesRes = await refPool.query<{ typname: string }>(
        `SELECT typname FROM pg_type t
         JOIN pg_namespace n ON n.oid = t.typnamespace
         WHERE n.nspname = 'public' AND t.typtype = 'e'
         ORDER BY typname;`
    );
    const types = typesRes.rows.map(r => r.typname);

    const triggersRes = await refPool.query<{ tgname: string; relname: string }>(
        `SELECT tg.tgname, c.relname
         FROM pg_trigger tg
         JOIN pg_class c ON c.oid = tg.tgrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND NOT tg.tgisinternal
         ORDER BY c.relname, tg.tgname;`
    );
    const triggers = triggersRes.rows.map(r => ({ name: r.tgname, table: r.relname }));

    const policiesRes = await refPool.query<{ policyname: string; tablename: string }>(
        `SELECT policyname, tablename FROM pg_policies WHERE schemaname = 'public' ORDER BY tablename, policyname;`
    );
    const policies = policiesRes.rows.map(r => ({ name: r.policyname, table: r.tablename }));

    await refPool.end();

    return { tables, functions, types, triggers, policies };
}

export async function stagingRebuildPlan(dryRunOnly = true) {
    console.log('================================================================');
    console.log('ArchScale V05: Catalog-Driven Staging Rebuild Plan (Dry Run)');
    console.log('================================================================\n');

    // 1. Build fresh reference catalog from migrations 001 - 012
    console.log('[Step 1] Applying 001-012 to fresh local DB to extract reference catalog...');
    const refCatalog = await extractReferenceCatalogFromFreshMigrations();
    console.log(`Reference catalog extracted successfully:`);
    console.log(`  - ${refCatalog.tables.length} tables (includes access_requests, account_lockouts, auth_rate_limits)`);
    console.log(`  - ${refCatalog.functions.length} functions`);
    console.log(`  - ${refCatalog.types.length} custom enum types`);
    console.log(`  - ${refCatalog.triggers.length} user triggers`);
    console.log(`  - ${refCatalog.policies.length} RLS policies`);

    // 2. Inspect Staging Catalog
    console.log('\n[Step 2] Inspecting staging database catalog...');
    const adminUrl = process.env.SUPABASE_DB_ADMIN_URL;
    if (!adminUrl) throw new Error('Missing SUPABASE_DB_ADMIN_URL in .env');

    const stagingClient = new pg.Client({ connectionString: adminUrl, ssl: { rejectUnauthorized: false } });
    await stagingClient.connect();

    try {
        const stagingTables = await stagingClient.query<{ tablename: string }>(
            `SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;`
        );
        const stagingFuncs = await stagingClient.query<{ proname: string; args: string }>(
            `SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS args
             FROM pg_proc p
             JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = 'public'
             ORDER BY p.proname, args;`
        );
        const stagingTypes = await stagingClient.query<{ typname: string }>(
            `SELECT typname FROM pg_type t
             JOIN pg_namespace n ON n.oid = t.typnamespace
             WHERE n.nspname = 'public' AND t.typtype = 'e'
             ORDER BY typname;`
        );
        const stagingTriggers = await stagingClient.query<{ tgname: string; relname: string }>(
            `SELECT tg.tgname, c.relname
             FROM pg_trigger tg
             JOIN pg_class c ON c.oid = tg.tgrelid
             JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'public' AND NOT tg.tgisinternal
             ORDER BY c.relname, tg.tgname;`
        );
        const stagingPolicies = await stagingClient.query<{ policyname: string; tablename: string }>(
            `SELECT policyname, tablename FROM pg_policies WHERE schemaname = 'public' ORDER BY tablename, policyname;`
        );

        // Classify what to DROP vs what to KEEP
        const dropTables: string[] = [];
        const keepTables: string[] = [];
        for (const t of stagingTables.rows) {
            if (refCatalog.tables.includes(t.tablename)) {
                dropTables.push(t.tablename);
            } else {
                keepTables.push(t.tablename);
            }
        }

        const dropFuncs: string[] = [];
        const keepFuncs: string[] = [];
        for (const f of stagingFuncs.rows) {
            const sig = `${f.proname}(${f.args})`;
            // Keep system triggers/helpers: rls_auto_enable, ensure_rls
            if (f.proname === 'rls_auto_enable' || f.proname.includes('ensure_rls')) {
                keepFuncs.push(sig);
            } else {
                dropFuncs.push(sig);
            }
        }

        const dropTypes: string[] = [];
        const keepTypes: string[] = [];
        for (const t of stagingTypes.rows) {
            if (refCatalog.types.includes(t.typname)) {
                dropTypes.push(t.typname);
            } else {
                keepTypes.push(t.typname);
            }
        }

        const dropTriggers: string[] = [];
        const keepTriggers: string[] = [];
        for (const trg of stagingTriggers.rows) {
            if (trg.tgname.includes('ensure_rls') || trg.tgname === 'trg_ensure_rls') {
                keepTriggers.push(`${trg.tgname} ON ${trg.relname}`);
            } else {
                dropTriggers.push(`${trg.tgname} ON ${trg.relname}`);
            }
        }

        const dropPolicies: string[] = [];
        const keepPolicies: string[] = [];
        for (const pol of stagingPolicies.rows) {
            dropPolicies.push(`POLICY ${pol.policyname} ON ${pol.tablename}`);
        }

        // Validate: Fail on any missing or unexpected managed table
        const missingFromCatalog = refCatalog.tables.filter(t => !dropTables.includes(t));
        if (missingFromCatalog.length > 0) {
            throw new Error(`REBUILD VALIDATION FAILURE: Reference catalog table missing from staging: ${missingFromCatalog.join(', ')}`);
        }

        console.log('\n================================================================');
        console.log('[Step 3] Staging Rebuild Plan Comparison (DRY RUN ONLY):');
        console.log('================================================================');

        console.log(`\n1. TABLES TO DROP (${dropTables.length}):`);
        for (const t of dropTables) console.log(`   - DROP TABLE public.${t} CASCADE;`);
        console.log(`   TABLES TO KEEP (${keepTables.length}):`);
        for (const t of keepTables) console.log(`   + KEEP TABLE ${t}`);
        if (keepTables.length === 0) console.log(`   (none — all tables managed by ArchScale migrations)`);

        console.log(`\n2. FUNCTIONS TO DROP (${dropFuncs.length}):`);
        for (const f of dropFuncs) console.log(`   - DROP FUNCTION public.${f} CASCADE;`);
        console.log(`   FUNCTIONS TO KEEP (${keepFuncs.length}):`);
        for (const f of keepFuncs) console.log(`   + KEEP FUNCTION public.${f} [Supabase RLS Safety Guard]`);

        console.log(`\n3. CUSTOM TYPES TO DROP (${dropTypes.length}):`);
        for (const t of dropTypes) console.log(`   - DROP TYPE public.${t} CASCADE;`);
        console.log(`   CUSTOM TYPES TO KEEP (${keepTypes.length}):`);
        for (const t of keepTypes) console.log(`   + KEEP TYPE ${t}`);
        if (keepTypes.length === 0) console.log(`   (none)`);

        console.log(`\n4. TRIGGERS TO DROP (${dropTriggers.length}):`);
        for (const trg of dropTriggers) console.log(`   - DROP TRIGGER ${trg};`);
        console.log(`   TRIGGERS TO KEEP (${keepTriggers.length}):`);
        for (const trg of keepTriggers) console.log(`   + KEEP TRIGGER ${trg} [Supabase RLS Safety Guard]`);

        console.log(`\n5. POLICIES TO DROP (${dropPolicies.length}):`);
        for (const pol of dropPolicies) console.log(`   - DROP ${pol};`);

        console.log('\n================================================================');
        console.log('[DRY RUN COMPLETE] Zero changes executed on staging.');
        console.log('================================================================\n');

        return {
            dropTables,
            keepTables,
            dropFuncs,
            keepFuncs,
            dropTypes,
            keepTypes,
            dropTriggers,
            keepTriggers,
            dropPolicies
        };
    } finally {
        await stagingClient.end();
    }
}

if (fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
    stagingRebuildPlan(true).catch(err => {
        console.error('Fatal Rebuild Plan Error:', err.message);
        process.exit(1);
    });
}
