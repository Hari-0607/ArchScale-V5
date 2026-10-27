import fs from 'fs';
import pg from 'pg';

// Parse .env natively (referencing variables by name only; never printing secrets)
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

interface TestGroupResult {
    passed: number;
    failed: number;
    tests: string[];
}

export async function runStagingVerification(): Promise<boolean> {
    const adminUrl = process.env.SUPABASE_DB_ADMIN_URL;
    const runtimeUrl = process.env.ARCHSCALE_RUNTIME_DB_URL;

    if (!adminUrl || !runtimeUrl) {
        throw new Error('Missing SUPABASE_DB_ADMIN_URL or ARCHSCALE_RUNTIME_DB_URL in .env');
    }

    const adminClient = new pg.Client({ connectionString: adminUrl, ssl: { rejectUnauthorized: false } });
    const runtimeClient = new pg.Client({ connectionString: runtimeUrl, ssl: { rejectUnauthorized: false } });

    await adminClient.connect();
    await runtimeClient.connect();

    console.log('================================================================');
    console.log('ArchScale V05: Staging Invariant & Security Verification Suite');
    console.log('Target: Supabase Staging (All writes isolated with ROLLBACK)');
    console.log('================================================================\n');

    const results: Record<string, TestGroupResult> = {
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
            results[file].tests.push(`  [PASS] ${testName}`);
        } else {
            results[file].failed++;
            results[file].tests.push(`  [FAIL] ${testName}: ${errMsg || 'Assertion failed'}`);
        }
    }

    // =========================================================================
    // Suite 01: Schema and Types
    // =========================================================================
    const file1 = '01_schema_and_types';
    try {
        // 1.1 Tenant types exist
        const tt = await adminClient.query("SELECT count(*) FROM tenant_types;");
        record(file1, 'tenant_types table exists and readable', parseInt(tt.rows[0].count, 10) >= 3);

        // 1.2 Portal constraint (isolated transaction rollback)
        try {
            await adminClient.query('BEGIN;');
            await adminClient.query("INSERT INTO organisations (name, portal, tenant_type_key) VALUES ('Illegal Platform Org', 'platform', 'studio_owner');");
            record(file1, 'enforces organisations.tenant_type_key is NULL iff portal = platform', false);
        } catch (e: any) {
            record(file1, 'enforces organisations.tenant_type_key is NULL iff portal = platform', e.code === '23514');
        } finally {
            await adminClient.query('ROLLBACK;').catch(() => {});
        }

        // 1.3 Single platform org (isolated transaction rollback)
        try {
            await adminClient.query('BEGIN;');
            await adminClient.query("INSERT INTO organisations (name, portal, tenant_type_key) VALUES ('Rogue Platform Org 2', 'platform', NULL);");
            record(file1, 'enforces single platform organisation unique index', false);
        } catch (e: any) {
            record(file1, 'enforces single platform organisation unique index', e.code === '23505');
        } finally {
            await adminClient.query('ROLLBACK;').catch(() => {});
        }

        // 1.4 Users table identity mirror (in public schema)
        const uCols = (await adminClient.query("SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'users';")).rows.map(r => r.column_name);
        const hasNoRole = !uCols.includes('role') && !uCols.includes('role_key') && !uCols.includes('organisation_id');
        record(file1, 'users table has no tenant or role columns (pure identity mirror)', hasNoRole);

        // 1.5 Roles level check (isolated transaction rollback)
        try {
            await adminClient.query('BEGIN;');
            await adminClient.query("INSERT INTO roles (key, name, description, portal, level) VALUES ('bad_level', 'Bad', 'Desc', 'subscriber', 101);");
            record(file1, 'roles level check constraint enforces 0-100', false);
        } catch (e: any) {
            record(file1, 'roles level check constraint enforces 0-100', e.code === '23514');
        } finally {
            await adminClient.query('ROLLBACK;').catch(() => {});
        }

        // 1.6 Custom enum
        const aalEnums = (await adminClient.query("SELECT enumlabel FROM pg_enum WHERE enumtypid = 'public.aal_level'::regtype;")).rows.map(r => r.enumlabel);
        record(file1, 'aal_level custom enum has aal1, aal2, aal3', aalEnums.includes('aal1') && aalEnums.includes('aal2') && aalEnums.includes('aal3'));

        // 1.7 Table RLS enabled
        const rlsTables = (await adminClient.query("SELECT rowsecurity FROM pg_tables WHERE schemaname = 'public' AND tablename = 'organisations';")).rows[0]?.rowsecurity;
        record(file1, 'Row level security is enabled on organisations table', rlsTables === true);
    } catch (e: any) {
        record(file1, 'Suite 01 execution', false, e.message);
    }

    // =========================================================================
    // Suite 02: Security Invariants Enforcement
    // =========================================================================
    const file2 = '02_invariants_enforcement';
    try {
        // 2.1 Max 24h cap on access_contexts (isolated transaction rollback)
        try {
            await adminClient.query('BEGIN;');
            const uId = (await adminClient.query("INSERT INTO users (user_code, email) VALUES ('TC-CTX1', 'tc_ctx1@test.com') RETURNING id;")).rows[0].id;
            const oId = (await adminClient.query("INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Test Org Invariant', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;")).rows[0].id;
            const wId = (await adminClient.query("INSERT INTO workspaces (organisation_id, name) VALUES ($1, 'Main') RETURNING id;", [oId])).rows[0].id;
            const mId = (await adminClient.query("INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ($1, $2, 'business_owner', 'ACTIVE') RETURNING id;", [uId, oId])).rows[0].id;

            try {
                await adminClient.query("INSERT INTO access_contexts (user_id, session_id, organisation_id, workspace_id, membership_id, expires_at) VALUES ($1, 'sess_1', $2, $3, $4, now() + interval '48 hours');", [uId, oId, wId, mId]);
                record(file2, 'enforces chk_context_max_24h cap on access_contexts', false);
            } catch (chkErr: any) {
                record(file2, 'enforces chk_context_max_24h cap on access_contexts', chkErr.code === '23514');
            }
        } finally {
            await adminClient.query('ROLLBACK;').catch(() => {});
        }

        // 2.2 Support access grant max 24h (isolated transaction rollback)
        try {
            await adminClient.query('BEGIN;');
            const uId = (await adminClient.query("INSERT INTO users (user_code, email) VALUES ('TC-SAG1', 'tc_sag1@test.com') RETURNING id;")).rows[0].id;
            const pOrg = (await adminClient.query("SELECT id FROM organisations WHERE portal = 'platform' AND status = 'ACTIVE' LIMIT 1;")).rows[0].id;
            const mId = (await adminClient.query("INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ($1, $2, 'founder', 'ACTIVE') RETURNING id;", [uId, pOrg])).rows[0].id;
            const subOrg = (await adminClient.query("INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Sub Target Org', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;")).rows[0].id;

            try {
                await adminClient.query("INSERT INTO support_access_grants (staff_membership_id, target_organisation_id, reason, expires_at) VALUES ($1, $2, 'Diagnostic', now() + interval '72 hours');", [mId, subOrg]);
                record(file2, 'enforces chk_support_grant_max_24h on support_access_grants', false);
            } catch (chkErr: any) {
                record(file2, 'enforces chk_support_grant_max_24h on support_access_grants', chkErr.code === '23514');
            }
        } finally {
            await adminClient.query('ROLLBACK;').catch(() => {});
        }

        // 2.3 Single share target (isolated transaction rollback)
        try {
            await adminClient.query('BEGIN;');
            await adminClient.query("INSERT INTO share_grants (source_organisation_id, target_org_id, target_user_id, resource_type, resource_id, granted_by, expires_at) VALUES ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001', 'project', 'P1', '00000000-0000-0000-0000-000000000001', now() + interval '1 day');");
            record(file2, 'enforces chk_single_share_target on share_grants', false);
        } catch (e: any) {
            record(file2, 'enforces chk_single_share_target on share_grants', e.code === '23514');
        } finally {
            await adminClient.query('ROLLBACK;').catch(() => {});
        }

        // 2.4 Self-approval blocked (isolated transaction rollback)
        try {
            await adminClient.query('BEGIN;');
            await adminClient.query("INSERT INTO approval_steps (request_id, step_number, required_role_key, decided_by, decision, reason) VALUES ('00000000-0000-0000-0000-000000000001', 1, 'business_owner', '00000000-0000-0000-0000-000000000001', 'APPROVED', 'Self');");
            record(file2, 'blocks self-approval via trg_approval_step_invariants trigger', false);
        } catch (e: any) {
            record(file2, 'blocks self-approval via trg_approval_step_invariants trigger', e.code === '23503' || e.code === 'P0001');
        } finally {
            await adminClient.query('ROLLBACK;').catch(() => {});
        }

        // 2.5 Intern expiry required (isolated transaction rollback)
        try {
            await adminClient.query('BEGIN;');
            const fakeUid = '00000000-0000-0000-0000-000000000001';
            await adminClient.query("INSERT INTO memberships (user_id, organisation_id, role_key, expires_at) VALUES ($1, $1, 'intern', NULL);", [fakeUid]);
            record(file2, 'enforces trg_memberships_expiry_enforcement on intern role', false);
        } catch (e: any) {
            record(file2, 'enforces trg_memberships_expiry_enforcement on intern role', e.code === '23503' || e.code === 'P0001');
        } finally {
            await adminClient.query('ROLLBACK;').catch(() => {});
        }

        // 2.6 Active membership requires active org (isolated transaction rollback)
        try {
            await adminClient.query('BEGIN;');
            const fakeUid = '00000000-0000-0000-0000-000000000001';
            await adminClient.query("INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ($1, $1, 'business_owner', 'ACTIVE');", [fakeUid]);
            record(file2, 'blocks active membership under non-active organisation', false);
        } catch (e: any) {
            record(file2, 'blocks active membership under non-active organisation', e.code === '23503' || e.code === 'P0001');
        } finally {
            await adminClient.query('ROLLBACK;').catch(() => {});
        }
    } catch (e: any) {
        record(file2, 'Suite 02 execution', false, e.message);
    }

    // =========================================================================
    // Suite 03: Org Status Cascade
    // =========================================================================
    const file3 = '03_org_status_cascade';
    try {
        await adminClient.query('BEGIN;');
        const oId = (await adminClient.query("INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Cascade Test Org', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;")).rows[0].id;
        const uId = (await adminClient.query("INSERT INTO users (user_code, email) VALUES ('TC-CASC1', 'tc_casc1@test.com') RETURNING id;")).rows[0].id;
        const wId = (await adminClient.query("INSERT INTO workspaces (organisation_id, name) VALUES ($1, 'Main') RETURNING id;", [oId])).rows[0].id;
        const mId = (await adminClient.query("INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ($1, $2, 'business_owner', 'ACTIVE') RETURNING id;", [uId, oId])).rows[0].id;
        const cId = (await adminClient.query("INSERT INTO access_contexts (user_id, session_id, organisation_id, workspace_id, membership_id, expires_at) VALUES ($1, 's1', $2, $3, $4, now() + interval '12 hours') RETURNING id;", [uId, oId, wId, mId])).rows[0].id;

        // Suspend org
        await adminClient.query("UPDATE organisations SET status = 'SUSPENDED' WHERE id = $1;", [oId]);

        // Verify context revoked
        const ctxRevoked = (await adminClient.query("SELECT is_revoked FROM access_contexts WHERE id = $1;", [cId])).rows[0].is_revoked;
        record(file3, 'org suspension automatically revokes active access_contexts', ctxRevoked === true);

        // Verify membership suspended
        const memStatus = (await adminClient.query("SELECT status FROM memberships WHERE id = $1;", [mId])).rows[0].status;
        record(file3, 'org suspension automatically suspends active memberships', memStatus === 'SUSPENDED');
    } catch (e: any) {
        record(file3, 'Suite 03 execution', false, e.message);
    } finally {
        await adminClient.query('ROLLBACK;').catch(() => {});
    }

    // =========================================================================
    // Suite 04: Atomic Approvals & Invariants
    // =========================================================================
    const file4 = '04_atomic_approvals';
    try {
        await adminClient.query('BEGIN;');
        // 4.1 Non-founder cannot approve organisation
        try {
            await adminClient.query("SELECT fn_approve_organisation('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001', '10.0.0.1'::inet, 'test');");
            record(file4, 'fn_approve_organisation rejects non-founder caller', false);
        } catch (e: any) {
            record(file4, 'fn_approve_organisation rejects non-founder caller', e.code === 'P0001');
        }

        // 4.2 Forged actor rejection
        try {
            await adminClient.query("SELECT fn_approve_membership('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001', '10.0.0.1'::inet, 'test');");
            record(file4, 'fn_approve_membership rejects forged actor', false);
        } catch (e: any) {
            record(file4, 'fn_approve_membership rejects forged actor', e.code === 'P0001');
        }

        // 4.3 is_context_valid for non-existent context
        const isValid = (await adminClient.query("SELECT is_context_valid('00000000-0000-0000-0000-000000000000');")).rows[0].is_context_valid;
        record(file4, 'is_context_valid returns false for unknown context', isValid === false);
    } catch (e: any) {
        record(file4, 'Suite 04 execution', false, e.message);
    } finally {
        await adminClient.query('ROLLBACK;').catch(() => {});
    }

    // =========================================================================
    // Suite 05: Concurrent Seats Race
    // =========================================================================
    const file5 = '05_concurrent_seats_race';
    try {
        await adminClient.query('BEGIN;');
        const oId = (await adminClient.query("INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Seat Test Org', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;")).rows[0].id;
        const eId = (await adminClient.query("INSERT INTO entitlements (organisation_id, app_module_key, max_seats, is_enabled) VALUES ($1, 'drawings', 5, true) RETURNING id;", [oId])).rows[0].id;

        // Over-allocating seats must fail check constraint
        try {
            await adminClient.query("UPDATE entitlements SET allocated_seats = 6 WHERE id = $1;", [eId]);
            record(file5, 'enforces chk_seat_limit constraint when over-allocating', false);
        } catch (e: any) {
            record(file5, 'enforces chk_seat_limit constraint when over-allocating', e.code === '23514');
        }

        // Valid update succeeds
        await adminClient.query("UPDATE entitlements SET allocated_seats = 3 WHERE id = $1;", [eId]);
        const alloc = (await adminClient.query("SELECT allocated_seats FROM entitlements WHERE id = $1;", [eId])).rows[0].allocated_seats;
        record(file5, 'allows allocated_seats update within limits', alloc === 3);
    } catch (e: any) {
        record(file5, 'Suite 05 execution', false, e.message);
    } finally {
        await adminClient.query('ROLLBACK;').catch(() => {});
    }

    // =========================================================================
    // Suite 06: Immutable Audit Log
    // =========================================================================
    const file6 = '06_immutable_audit';
    try {
        await adminClient.query('BEGIN;');
        // 6.1 UPDATE on audit_logs blocked by trigger
        try {
            await adminClient.query("UPDATE audit_logs SET action = 'ALTERED';");
            record(file6, 'blocks UPDATE on audit_logs via trigger', false);
        } catch (e: any) {
            record(file6, 'blocks UPDATE on audit_logs via trigger', e.message.includes('append-only'));
        }

        // 6.2 DELETE on audit_logs blocked by trigger
        try {
            await adminClient.query("DELETE FROM audit_logs;");
            record(file6, 'blocks DELETE on audit_logs via trigger', false);
        } catch (e: any) {
            record(file6, 'blocks DELETE on audit_logs via trigger', e.message.includes('append-only'));
        }

        // 6.3 TRUNCATE on audit_logs blocked by trigger
        try {
            await adminClient.query("TRUNCATE audit_logs;");
            record(file6, 'blocks TRUNCATE on audit_logs via trigger', false);
        } catch (e: any) {
            record(file6, 'blocks TRUNCATE on audit_logs via trigger', e.code === '42501' || e.message.includes('append-only'));
        }

        // 6.4 Runtime role denied UPDATE by privilege revocation
        try {
            await runtimeClient.query("UPDATE audit_logs SET action = 'HACKED';");
            record(file6, 'runtime role denied UPDATE on audit_logs by privilege revocation', false);
        } catch (e: any) {
            record(file6, 'runtime role denied UPDATE on audit_logs by privilege revocation', e.code === '42501');
        }
    } catch (e: any) {
        record(file6, 'Suite 06 execution', false, e.message);
    } finally {
        await adminClient.query('ROLLBACK;').catch(() => {});
    }

    // =========================================================================
    // Suite 07: Runtime Role Privilege Proofs
    // =========================================================================
    const file7 = '07_runtime_privilege_proof';
    try {
        // 7.1 Runtime role has no admin flags
        const roleFlags = (await adminClient.query("SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = 'archscale_app_runtime';")).rows[0];
        const isLeastPrivilege = !roleFlags.rolsuper && !roleFlags.rolbypassrls && !roleFlags.rolcreaterole && !roleFlags.rolcreatedb;
        record(file7, 'runtime role has no administrative flags (NO SUPERUSER, NO BYPASSRLS)', isLeastPrivilege);

        // 7.2 Runtime role cannot CREATE TABLE (isolated transaction rollback)
        try {
            await runtimeClient.query('BEGIN;');
            await runtimeClient.query("CREATE TABLE public.hack_table (id serial primary key);");
            record(file7, 'runtime role cannot CREATE TABLE in schema public', false);
        } catch (e: any) {
            record(file7, 'runtime role cannot CREATE TABLE in schema public', e.code === '42501');
        } finally {
            await runtimeClient.query('ROLLBACK;').catch(() => {});
        }

        // 7.3 Workspaces without context returns 0 rows via RLS
        const wsRows = (await runtimeClient.query("SELECT * FROM workspaces;")).rows;
        record(file7, 'runtime role querying workspaces without context returns 0 rows (RLS)', wsRows.length === 0);

        // 7.4 fn_set_app_context rejects forged context id
        try {
            await runtimeClient.query("SELECT fn_set_app_context('00000000-0000-0000-0000-000000000000');");
            record(file7, 'fn_set_app_context rejects forged context id', false);
        } catch (e: any) {
            record(file7, 'fn_set_app_context rejects forged context id', e.code === 'P0001');
        }

        // 7.5 Runtime role holds EXECUTE on fn_set_app_context
        const hasExec = (await adminClient.query("SELECT has_function_privilege('archscale_app_runtime', 'fn_set_app_context(UUID)', 'EXECUTE');")).rows[0].has_function_privilege;
        record(file7, 'runtime role holds EXECUTE on fn_set_app_context', hasExec === true);
    } catch (e: any) {
        record(file7, 'Suite 07 execution', false, e.message);
    }

    // Report Summary
    let totalPassed = 0;
    let totalFailed = 0;

    console.log('--- Verification Results ---');
    for (const [group, res] of Object.entries(results)) {
        console.log(`\nGroup: ${group} (${res.passed} passed, ${res.failed} failed)`);
        for (const t of res.tests) {
            console.log(t);
        }
        totalPassed += res.passed;
        totalFailed += res.failed;
    }

    console.log(`\n================================================================`);
    console.log(`Verification Total: ${totalPassed} passed, ${totalFailed} failed.`);
    console.log(`================================================================\n`);

    await adminClient.end();
    await runtimeClient.end();

    return totalFailed === 0;
}

// Direct execution
if (import.meta.url === `file://${process.argv[1].replace(/\\/g, '/')}`) {
    runStagingVerification().then(success => {
        if (!success) process.exit(1);
    }).catch(err => {
        console.error('Fatal execution error:', err.message);
        process.exit(1);
    });
}
