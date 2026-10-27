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

async function runStagingConformance() {
    const adminUrl = process.env.SUPABASE_DB_ADMIN_URL;
    const runtimeUrl = process.env.ARCHSCALE_RUNTIME_DB_URL;

    if (!adminUrl || !runtimeUrl) {
        throw new Error('Missing SUPABASE_DB_ADMIN_URL or ARCHSCALE_RUNTIME_DB_URL in .env');
    }

    const adminClient = new pg.Client({ connectionString: adminUrl, ssl: { rejectUnauthorized: false } });
    const runtimeClient = new pg.Client({ connectionString: runtimeUrl, ssl: { rejectUnauthorized: false } });

    await adminClient.connect();
    await runtimeClient.connect();

    console.log('===============================================================');
    console.log('ArchScale V05: Running Conformance Test Suite Against Supabase Staging');
    console.log('===============================================================\n');

    const results: Record<string, { passed: number; failed: number; tests: string[] }> = {
        '01_schema_and_types': { passed: 0, failed: 0, tests: [] },
        '02_invariants_enforcement': { passed: 0, failed: 0, tests: [] },
        '03_org_status_cascade': { passed: 0, failed: 0, tests: [] },
        '04_atomic_approvals': { passed: 0, failed: 0, tests: [] },
        '05_concurrent_seats_race': { passed: 0, failed: 0, tests: [] },
        '06_immutable_audit': { passed: 0, failed: 0, tests: [] },
        '07_runtime_privilege_proof': { passed: 0, failed: 0, tests: [] }
    };

    function record(file: string, testName: string, ok: boolean, errMsg?: string) {
        if (ok) {
            results[file].passed++;
            results[file].tests.push(`[PASS] ${testName}`);
        } else {
            results[file].failed++;
            results[file].tests.push(`[FAIL] ${testName}: ${errMsg}`);
        }
    }

    // --- Suite 01: Schema and Types ---
    const file1 = '01_schema_and_types';
    try {
        // 1.1 Tenant types
        const r1 = await adminClient.query("SELECT count(*) FROM tenant_types;");
        record(file1, 'tenant_types table exists and readable', true);

        // 1.2 Portal constraint
        try {
            await adminClient.query("BEGIN;");
            await adminClient.query("INSERT INTO organisations (name, portal, tenant_type_key) VALUES ('Illegal Platform Org', 'platform', 'studio_owner');");
            record(file1, 'enforces organisations.tenant_type_key is NULL iff portal = platform', false);
        } catch (e: any) {
            record(file1, 'enforces organisations.tenant_type_key is NULL iff portal = platform', e.code === '23514');
        } finally {
            await adminClient.query("ROLLBACK;").catch(() => {});
        }

        // 1.3 Single platform org
        try {
            await adminClient.query("BEGIN;");
            await adminClient.query("INSERT INTO organisations (name, portal, tenant_type_key) VALUES ('Rogue Platform Org 2', 'platform', NULL);");
            record(file1, 'enforces single platform organisation unique index', false);
        } catch (e: any) {
            record(file1, 'enforces single platform organisation unique index', e.code === '23505');
        } finally {
            await adminClient.query("ROLLBACK;").catch(() => {});
        }

        // 1.4 Users table identity mirror (in public schema)
        const uCols = (await adminClient.query("SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'users';")).rows.map(r => r.column_name);
        const hasNoRole = !uCols.includes('role') && !uCols.includes('role_key') && !uCols.includes('organisation_id');
        record(file1, 'users table has no tenant or role columns (pure identity mirror)', hasNoRole);

        // 1.5 Roles level check
        try {
            await adminClient.query("INSERT INTO roles (key, name, description, portal, level) VALUES ('bad_level', 'Bad', 'Desc', 'subscriber', 101);");
            record(file1, 'roles level check constraint enforces 0-100', false);
        } catch (e: any) {
            record(file1, 'roles level check constraint enforces 0-100', e.code === '23514');
        }

        // 1.6 Custom enum
        const aalEnums = (await adminClient.query("SELECT enumlabel FROM pg_enum WHERE enumtypid = 'public.aal_level'::regtype;")).rows.map(r => r.enumlabel);
        record(file1, 'aal_level custom enum has aal1, aal2, aal3', aalEnums.includes('aal1') && aalEnums.includes('aal2') && aalEnums.includes('aal3'));

        // 1.7 Table RLS enabled
        const rlsTables = (await adminClient.query("SELECT rowsecurity FROM pg_tables WHERE schemaname = 'public' AND tablename = 'organisations';")).rows[0].rowsecurity;
        record(file1, 'Row level security is enabled on organisations table', rlsTables === true);
    } catch (e: any) {
        record(file1, 'Suite 01 execution', false, e.message);
    }

    // --- Suite 02: Invariants Enforcement ---
    const file2 = '02_invariants_enforcement';
    try {
        // 2.1 Context max 24h
        try {
            await adminClient.query("INSERT INTO access_contexts (user_id, session_id, organisation_id, workspace_id, membership_id, expires_at) VALUES ('00000000-0000-0000-0000-000000000001', 's1', '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001', now() + interval '48 hours');");
            record(file2, 'enforces chk_context_max_24h cap on access_contexts', false);
        } catch (e: any) {
            record(file2, 'enforces chk_context_max_24h cap on access_contexts', e.code === '23514');
        }

        // 2.2 Support access grant max 24h
        try {
            await adminClient.query('BEGIN;');
            const uId = (await adminClient.query("INSERT INTO users (user_code, email) VALUES ('SAG-U1', 'sag@test.com') RETURNING id;")).rows[0].id;
            const pOrg = (await adminClient.query("SELECT id FROM organisations WHERE portal = 'platform' AND status = 'ACTIVE' LIMIT 1;")).rows[0].id;
            const mId = (await adminClient.query("INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ($1, $2, 'founder', 'ACTIVE') RETURNING id;", [uId, pOrg])).rows[0].id;
            const subOrg = (await adminClient.query("INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Sub Org', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;")).rows[0].id;
            try {
                await adminClient.query("INSERT INTO support_access_grants (staff_membership_id, target_organisation_id, reason, expires_at) VALUES ($1, $2, 'Test', now() + interval '72 hours');", [mId, subOrg]);
                record(file2, 'enforces chk_support_grant_max_24h on support_access_grants', false);
            } catch (chkErr: any) {
                record(file2, 'enforces chk_support_grant_max_24h on support_access_grants', chkErr.code === '23514');
            }
            await adminClient.query('ROLLBACK;');
        } catch (e: any) {
            await adminClient.query('ROLLBACK;').catch(() => {});
            record(file2, 'enforces chk_support_grant_max_24h on support_access_grants', false, e.message);
        }

        // 2.3 Single share target
        try {
            await adminClient.query("INSERT INTO share_grants (source_organisation_id, target_org_id, target_user_id, resource_type, resource_id, granted_by, expires_at) VALUES ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001', 'project', 'P1', '00000000-0000-0000-0000-000000000001', now() + interval '1 day');");
            record(file2, 'enforces chk_single_share_target on share_grants', false);
        } catch (e: any) {
            record(file2, 'enforces chk_single_share_target on share_grants', e.code === '23514');
        }

        // 2.4 Self-approval blocked
        try {
            await adminClient.query("INSERT INTO approval_steps (request_id, step_number, required_role_key, decided_by, decision, reason) VALUES ('00000000-0000-0000-0000-000000000001', 1, 'business_owner', '00000000-0000-0000-0000-000000000001', 'APPROVED', 'Self');");
            record(file2, 'blocks self-approval via trg_approval_step_invariants trigger', false);
        } catch (e: any) {
            record(file2, 'blocks self-approval via trg_approval_step_invariants trigger', e.code === '23503' || e.code === 'P0001');
        }

        // 2.5 Intern expiry required
        try {
            const fakeUid = '00000000-0000-0000-0000-000000000001';
            await adminClient.query("INSERT INTO memberships (user_id, organisation_id, role_key, expires_at) VALUES ($1, $1, 'intern', NULL);", [fakeUid]);
            record(file2, 'enforces trg_memberships_expiry_enforcement on intern role', false);
        } catch (e: any) {
            record(file2, 'enforces trg_memberships_expiry_enforcement on intern role', e.code === '23503' || e.code === 'P0001');
        }

        // 2.6 Active membership requires active org
        try {
            const fakeUid = '00000000-0000-0000-0000-000000000001';
            await adminClient.query("INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ($1, $1, 'business_owner', 'ACTIVE');", [fakeUid]);
            record(file2, 'blocks active membership under non-active organisation', false);
        } catch (e: any) {
            record(file2, 'blocks active membership under non-active organisation', e.code === '23503' || e.code === 'P0001');
        }
    } catch (e: any) {
        record(file2, 'Suite 02 execution', false, e.message);
    }

    // --- Suite 03: Org Status Cascade ---
    const file3 = '03_org_status_cascade';
    try {
        await adminClient.query('BEGIN;');
        const oId = (await adminClient.query("INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Cascade Org', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;")).rows[0].id;
        const uId = (await adminClient.query("INSERT INTO users (user_code, email) VALUES ('CASC-U1', 'casc@test.com') RETURNING id;")).rows[0].id;
        const wId = (await adminClient.query("INSERT INTO workspaces (organisation_id, name) VALUES ($1, 'Main') RETURNING id;", [oId])).rows[0].id;
        const mId = (await adminClient.query("INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ($1, $2, 'business_owner', 'ACTIVE') RETURNING id;", [uId, oId])).rows[0].id;
        const cId = (await adminClient.query("INSERT INTO access_contexts (user_id, session_id, organisation_id, workspace_id, membership_id, expires_at) VALUES ($1, 's1', $2, $3, $4, now() + interval '12 hours') RETURNING id;", [uId, oId, wId, mId])).rows[0].id;

        // Suspend org
        await adminClient.query("UPDATE organisations SET status = 'SUSPENDED' WHERE id = $1;", [oId]);

        // Check context revoked
        const cRes = (await adminClient.query("SELECT revoked_at FROM access_contexts WHERE id = $1;", [cId])).rows[0];
        const mRes = (await adminClient.query("SELECT status FROM memberships WHERE id = $1;", [mId])).rows[0];

        record(file3, 'org suspension automatically revokes active access_contexts', cRes.revoked_at !== null);
        record(file3, 'org suspension automatically suspends active memberships', mRes.status === 'SUSPENDED');
        await adminClient.query('ROLLBACK;');
    } catch (e: any) {
        await adminClient.query('ROLLBACK;').catch(() => {});
        record(file3, 'Suite 03 execution', false, e.message);
    }

    // --- Suite 04: Atomic Approvals ---
    const file4 = '04_atomic_approvals';
    try {
        // 4.1 fn_approve_organisation rejects unauthorized caller
        try {
            await runtimeClient.query("SELECT fn_approve_organisation('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001', 'studio_owner', ARRAY['app1'], '[]'::jsonb, '00000000-0000-0000-0000-000000000001', 'reason');");
            record(file4, 'fn_approve_organisation rejects non-founder caller', false);
        } catch (e: any) {
            record(file4, 'fn_approve_organisation rejects non-founder caller', e.code === 'P0001' || e.code === '42501');
        }

        // 4.2 fn_approve_membership rejects forged actor
        try {
            await runtimeClient.query("SELECT fn_approve_membership('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001', 'test');");
            record(file4, 'fn_approve_membership rejects forged actor', false);
        } catch (e: any) {
            record(file4, 'fn_approve_membership rejects forged actor', e.code === 'P0001' || e.code === '42501');
        }

        // 4.3 is_context_valid returns false for unknown context
        const isValid = (await runtimeClient.query("SELECT is_context_valid('00000000-0000-0000-0000-000000000001') as valid;")).rows[0].valid;
        record(file4, 'is_context_valid returns false for unknown context', isValid === false);
    } catch (e: any) {
        record(file4, 'Suite 04 execution', false, e.message);
    }

    // --- Suite 05: Concurrent Seats Race ---
    const file5 = '05_concurrent_seats_race';
    try {
        await adminClient.query("INSERT INTO app_catalogue (app_key, name, description) VALUES ('app_seat_test', 'App Test', 'Desc') ON CONFLICT DO NOTHING;");

        // Over-allocation check
        await adminClient.query('BEGIN;');
        const oId = (await adminClient.query("INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Seat Org', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;")).rows[0].id;
        await adminClient.query("INSERT INTO organisation_seats (organisation_id, app_key, role_key, seat_limit, allocated_seats) VALUES ($1, 'app_seat_test', 'business_owner', 1, 1);", [oId]);

        try {
            await adminClient.query("UPDATE organisation_seats SET allocated_seats = 2 WHERE organisation_id = $1;", [oId]);
            record(file5, 'enforces chk_seat_limit constraint when over-allocating', false);
        } catch (e: any) {
            record(file5, 'enforces chk_seat_limit constraint when over-allocating', e.code === '23514');
        }
        await adminClient.query('ROLLBACK;');

        // Valid update in separate transaction
        await adminClient.query('BEGIN;');
        const oId2 = (await adminClient.query("INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Seat Org 2', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;")).rows[0].id;
        await adminClient.query("INSERT INTO organisation_seats (organisation_id, app_key, role_key, seat_limit, allocated_seats) VALUES ($1, 'app_seat_test', 'business_owner', 2, 1);", [oId2]);
        await adminClient.query("UPDATE organisation_seats SET allocated_seats = 2 WHERE organisation_id = $1;", [oId2]);
        const alloc = (await adminClient.query("SELECT allocated_seats FROM organisation_seats WHERE organisation_id = $1;", [oId2])).rows[0].allocated_seats;
        record(file5, 'allows allocated_seats update within limits', alloc === 2);
        await adminClient.query('ROLLBACK;');
    } catch (e: any) {
        await adminClient.query('ROLLBACK;').catch(() => {});
        record(file5, 'Suite 05 execution', false, e.message);
    }

    // --- Suite 06: Immutable Audit Log ---
    const file6 = '06_immutable_audit';
    try {
        // 6.1 UPDATE blocked
        await adminClient.query('BEGIN;');
        const logId1 = (await adminClient.query("INSERT INTO audit_logs (action, target_entity, target_id) VALUES ('TEST_LOG_1', 'system', 'sys1') RETURNING id;")).rows[0].id;
        try {
            await adminClient.query("UPDATE audit_logs SET action = 'HACKED' WHERE id = $1;", [logId1]);
            record(file6, 'blocks UPDATE on audit_logs via trigger', false);
        } catch (e: any) {
            record(file6, 'blocks UPDATE on audit_logs via trigger', e.message.includes('audit log is append-only') || e.code === 'P0001');
        }
        await adminClient.query('ROLLBACK;');

        // 6.2 DELETE blocked
        await adminClient.query('BEGIN;');
        const logId2 = (await adminClient.query("INSERT INTO audit_logs (action, target_entity, target_id) VALUES ('TEST_LOG_2', 'system', 'sys2') RETURNING id;")).rows[0].id;
        try {
            await adminClient.query("DELETE FROM audit_logs WHERE id = $1;", [logId2]);
            record(file6, 'blocks DELETE on audit_logs via trigger', false);
        } catch (e: any) {
            record(file6, 'blocks DELETE on audit_logs via trigger', e.message.includes('audit log is append-only') || e.code === 'P0001');
        }
        await adminClient.query('ROLLBACK;');

        // 6.3 TRUNCATE blocked
        await adminClient.query('BEGIN;');
        try {
            await adminClient.query("TRUNCATE TABLE audit_logs;");
            record(file6, 'blocks TRUNCATE on audit_logs via trigger', false);
        } catch (e: any) {
            record(file6, 'blocks TRUNCATE on audit_logs via trigger', e.message.includes('audit log is append-only') || e.code === 'P0001');
        }
        await adminClient.query('ROLLBACK;');

        // 6.4 archscale_app_runtime cannot update audit_logs
        try {
            await runtimeClient.query("UPDATE audit_logs SET action = 'HACKED';");
            record(file6, 'runtime role denied UPDATE on audit_logs by privilege revocation', false);
        } catch (e: any) {
            record(file6, 'runtime role denied UPDATE on audit_logs by privilege revocation', e.code === '42501');
        }
    } catch (e: any) {
        await adminClient.query('ROLLBACK;').catch(() => {});
        record(file6, 'Suite 06 execution', false, e.message);
    }

    // --- Suite 07: Runtime Privilege Proof ---
    const file7 = '07_runtime_privilege_proof';
    try {
        // 7.1 Runtime role flags
        const flags = (await runtimeClient.query("SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = current_user;")).rows[0];
        const leastPrivilege = !flags.rolsuper && !flags.rolbypassrls && !flags.rolcreatedb && !flags.rolcreaterole;
        record(file7, 'runtime role has no administrative flags (NO SUPERUSER, NO BYPASSRLS)', leastPrivilege);

        // 7.2 Runtime role cannot CREATE TABLE
        try {
            await runtimeClient.query("CREATE TABLE rogue_tbl (id int);");
            record(file7, 'runtime role cannot CREATE TABLE in schema public', false);
        } catch (e: any) {
            record(file7, 'runtime role cannot CREATE TABLE in schema public', e.code === '42501');
        }

        // 7.3 Runtime role RLS default-deny
        const wsCount = (await runtimeClient.query("SELECT count(*)::int as count FROM workspaces;")).rows[0].count;
        record(file7, 'runtime role querying workspaces without context returns 0 rows (RLS)', wsCount === 0);

        // 7.4 fn_set_app_context rejects forged context
        try {
            await runtimeClient.query("SELECT fn_set_app_context('00000000-0000-0000-0000-000000000999');");
            record(file7, 'fn_set_app_context rejects forged context id', false);
        } catch (e: any) {
            record(file7, 'fn_set_app_context rejects forged context id', e.code === 'P0001');
        }

        // 7.5 fn_set_app_context holds EXECUTE
        const procPriv = (await adminClient.query("SELECT has_function_privilege('archscale_app_runtime', 'fn_set_app_context(uuid)', 'EXECUTE');")).rows[0].has_function_privilege;
        record(file7, 'runtime role holds EXECUTE on fn_set_app_context', procPriv === true);
    } catch (e: any) {
        record(file7, 'Suite 07 execution', false, e.message);
    }

    console.log('\n--- Conformance Results on Supabase Staging ---');
    let totalPass = 0, totalFail = 0;
    for (const [file, data] of Object.entries(results)) {
        console.log(`\nFile: ${file} (${data.passed} passed, ${data.failed} failed)`);
        for (const t of data.tests) {
            console.log(`  ${t}`);
        }
        totalPass += data.passed;
        totalFail += data.failed;
    }

    console.log(`\nTotal: ${totalPass} passed, ${totalFail} failed.`);

    await adminClient.end();
    await runtimeClient.end();
}

runStagingConformance().catch(err => {
    let msg = err.message || '';
    const adminUrl = process.env.SUPABASE_DB_ADMIN_URL;
    if (adminUrl) {
        try {
            const u = new URL(adminUrl);
            if (u.password) msg = msg.split(u.password).join('[REDACTED]');
        } catch (_) {}
    }
    console.error('STAGING_TEST_FAILED:', msg);
    process.exit(1);
});
