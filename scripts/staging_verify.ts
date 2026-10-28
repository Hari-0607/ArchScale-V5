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

export interface VerificationCheckSpec {
    suite: string;
    rule: string;
    statement: string;
    expectedSqlState: string;
    expectedConstraintOrTrigger?: string;
    positiveControl: string;
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
    console.log('Isolation: Transaction-level with SAVEPOINT isolation per check');
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

    function record(file: string, testName: string, ok: boolean, detail?: string) {
        if (ok) {
            results[file].passed++;
            results[file].tests.push(`  [PASS] ${testName}`);
        } else {
            results[file].failed++;
            results[file].tests.push(`  [FAIL] ${testName}: ${detail || 'Assertion failed'}`);
        }
    }

    /**
     * Executes a failure assertion inside an isolated SAVEPOINT so 25P02 cannot poison the outer transaction.
     * Asserts exact SQLSTATE and constraint/trigger name.
     */
    async function assertSavepointFailure(
        client: pg.Client,
        file: string,
        ruleName: string,
        action: () => Promise<any>,
        expectedCode: string,
        expectedConstraint?: string
    ): Promise<boolean> {
        await client.query('SAVEPOINT sp_fail_check;');
        let thrown: any = null;
        try {
            await action();
        } catch (err: any) {
            thrown = err;
        } finally {
            await client.query('ROLLBACK TO SAVEPOINT sp_fail_check;');
            await client.query('RELEASE SAVEPOINT sp_fail_check;').catch(() => {});
        }

        if (!thrown) {
            record(file, ruleName, false, `Expected error ${expectedCode} but statement succeeded`);
            return false;
        }

        const codeMatches = thrown.code === expectedCode;
        let constraintMatches = true;
        if (expectedConstraint) {
            const msg = (thrown.message || '').toLowerCase();
            const constraint = (thrown.constraint || '').toLowerCase();
            const target = expectedConstraint.toLowerCase();
            constraintMatches = constraint.includes(target) || msg.includes(target);
        }

        const ok = codeMatches && constraintMatches;
        const detail = ok
            ? undefined
            : `Got code=${thrown.code} (expected ${expectedCode}), constraint=${thrown.constraint || 'none'} (expected ${expectedConstraint || 'any'}), msg="${thrown.message}"`;
        record(file, ruleName, ok, detail);
        return ok;
    }

    /**
     * Executes a positive control inside an isolated SAVEPOINT.
     * Statement must succeed, then rolls back.
     */
    async function assertSavepointControl(
        client: pg.Client,
        file: string,
        ruleName: string,
        action: () => Promise<any>
    ): Promise<boolean> {
        await client.query('SAVEPOINT sp_ctrl_check;');
        let thrown: any = null;
        try {
            await action();
        } catch (err: any) {
            thrown = err;
        } finally {
            await client.query('ROLLBACK TO SAVEPOINT sp_ctrl_check;');
            await client.query('RELEASE SAVEPOINT sp_ctrl_check;').catch(() => {});
        }

        const ok = !thrown;
        record(file, `[control] ${ruleName}`, ok, thrown ? `Control statement failed: ${thrown.message}` : undefined);
        return ok;
    }

    // Outer transaction: guarantees zero changes persist to staging
    await adminClient.query('BEGIN;');

    try {
        // =========================================================================
        // Suite 01: Schema and Types
        // =========================================================================
        const file1 = '01_schema_and_types';

        // 1.1 Tenant types exist
        const tt = await adminClient.query("SELECT count(*) FROM tenant_types WHERE is_active = true;");
        record(file1, 'tenant_types catalogue populated with >= 3 active rows', parseInt(tt.rows[0].count, 10) >= 3);

        // 1.2 Portal constraint: tenant_type_key IS NULL iff portal = 'platform'
        await assertSavepointFailure(
            adminClient, file1,
            'enforces chk_org_portal_tenant_type on invalid platform org',
            () => adminClient.query("INSERT INTO organisations (name, portal, tenant_type_key) VALUES ('Illegal Platform Org', 'platform', 'studio_owner');"),
            '23514', 'chk_org_portal_tenant_type'
        );
        await assertSavepointControl(
            adminClient, file1,
            'chk_org_portal_tenant_type allows valid subscriber org',
            () => adminClient.query("INSERT INTO organisations (name, portal, tenant_type_key) VALUES ('Valid Sub Org', 'subscriber', 'studio_owner');")
        );

        // 1.3 Single platform org
        await assertSavepointFailure(
            adminClient, file1,
            'enforces idx_single_platform_org unique index against duplicate platform org',
            () => adminClient.query("INSERT INTO organisations (name, portal, tenant_type_key) VALUES ('Rogue Platform Org 2', 'platform', NULL);"),
            '23505', 'idx_single_platform_org'
        );
        await assertSavepointControl(
            adminClient, file1,
            'idx_single_platform_org allows multiple distinct subscriber orgs',
            () => adminClient.query("INSERT INTO organisations (name, portal, tenant_type_key) VALUES ('Distinct Sub Org 2', 'subscriber', 'project_owner');")
        );

        // 1.4 Users table pure identity mirror
        const uCols = (await adminClient.query("SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'users';")).rows.map(r => r.column_name);
        const hasNoRole = !uCols.includes('role') && !uCols.includes('role_key') && !uCols.includes('organisation_id');
        record(file1, 'users table has no tenant or role columns (pure identity mirror)', hasNoRole);

        // 1.5 Roles level check (0-100)
        await assertSavepointFailure(
            adminClient, file1,
            'enforces chk_roles_level_range on level > 100',
            () => adminClient.query("INSERT INTO roles (key, name, description, portal, level) VALUES ('bad_level_role', 'Bad', 'Desc', 'subscriber', 101);"),
            '23514', 'chk_roles_level_range'
        );
        await assertSavepointControl(
            adminClient, file1,
            'chk_roles_level_range allows level within 0-100',
            () => adminClient.query("INSERT INTO roles (key, name, description, portal, level) VALUES ('valid_level_role', 'Valid', 'Desc', 'subscriber', 50);")
        );

        // 1.6 Custom enum
        const aalEnums = (await adminClient.query("SELECT enumlabel FROM pg_enum WHERE enumtypid = 'public.aal_level'::regtype;")).rows.map(r => r.enumlabel);
        record(file1, 'aal_level custom enum has aal1, aal2, aal3', aalEnums.includes('aal1') && aalEnums.includes('aal2') && aalEnums.includes('aal3'));

        // 1.7 Table RLS enabled
        const rlsTables = (await adminClient.query("SELECT rowsecurity FROM pg_tables WHERE schemaname = 'public' AND tablename = 'organisations';")).rows[0]?.rowsecurity;
        record(file1, 'Row level security is enabled on organisations table', rlsTables === true);

        // =========================================================================
        // Suite 02: Invariants Enforcement
        // =========================================================================
        const file2 = '02_invariants_enforcement';

        // Setup test fixtures inside a savepoint so clean entities exist for Suite 02
        await adminClient.query('SAVEPOINT sp_suite2_setup;');
        const testU1 = (await adminClient.query("INSERT INTO users (user_code, email) VALUES ('TC-VFY-U1', 'tc_vfy_u1@archscale.test') RETURNING id;")).rows[0].id;
        const testU2 = (await adminClient.query("INSERT INTO users (user_code, email) VALUES ('TC-VFY-U2', 'tc_vfy_u2@archscale.test') RETURNING id;")).rows[0].id;
        const testOrgActive = (await adminClient.query("INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('TC Active Org', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;")).rows[0].id;
        const testOrgSuspended = (await adminClient.query("INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('TC Suspended Org', 'subscriber', 'studio_owner', 'SUSPENDED') RETURNING id;")).rows[0].id;
        const testWs = (await adminClient.query("INSERT INTO workspaces (organisation_id, name) VALUES ($1, 'Main') RETURNING id;", [testOrgActive])).rows[0].id;
        const testM1 = (await adminClient.query("INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ($1, $2, 'business_owner', 'ACTIVE') RETURNING id;", [testU1, testOrgActive])).rows[0].id;
        const platformOrgId = (await adminClient.query("SELECT id FROM organisations WHERE portal = 'platform' LIMIT 1;")).rows[0].id;
        const staffMemId = (await adminClient.query("INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ($1, $2, 'founder', 'ACTIVE') RETURNING id;", [testU2, platformOrgId])).rows[0].id;

        // 2.1 Max 24h cap on access_contexts (chk_context_max_24h)
        await assertSavepointFailure(
            adminClient, file2,
            'enforces chk_context_max_24h on expires_at > 24 hours',
            () => adminClient.query("INSERT INTO access_contexts (user_id, session_id, organisation_id, workspace_id, membership_id, expires_at) VALUES ($1, 's_bad', $2, $3, $4, now() + interval '48 hours');", [testU1, testOrgActive, testWs, testM1]),
            '23514', 'chk_context_max_24h'
        );
        await assertSavepointControl(
            adminClient, file2,
            'chk_context_max_24h allows expires_at within 24 hours',
            () => adminClient.query("INSERT INTO access_contexts (user_id, session_id, organisation_id, workspace_id, membership_id, expires_at) VALUES ($1, 's_ok', $2, $3, $4, now() + interval '12 hours');", [testU1, testOrgActive, testWs, testM1])
        );

        // 2.2 Support access grant max 24h (chk_support_grant_max_24h)
        await assertSavepointFailure(
            adminClient, file2,
            'enforces chk_support_grant_max_24h on expires_at > 24 hours',
            () => adminClient.query("INSERT INTO support_access_grants (staff_membership_id, target_organisation_id, reason, expires_at) VALUES ($1, $2, 'Diag', now() + interval '72 hours');", [staffMemId, testOrgActive]),
            '23514', 'chk_support_grant_max_24h'
        );
        await assertSavepointControl(
            adminClient, file2,
            'chk_support_grant_max_24h allows expires_at within 24 hours',
            () => adminClient.query("INSERT INTO support_access_grants (staff_membership_id, target_organisation_id, reason, expires_at) VALUES ($1, $2, 'Diag', now() + interval '12 hours');", [staffMemId, testOrgActive])
        );

        // 2.3 Single share target (chk_single_share_target)
        await assertSavepointFailure(
            adminClient, file2,
            'enforces chk_single_share_target when both target_org_id and target_user_id provided',
            () => adminClient.query("INSERT INTO share_grants (source_organisation_id, target_org_id, target_user_id, resource_type, resource_id, granted_by, expires_at) VALUES ($1, $1, $2, 'project', 'P1', $2, now() + interval '1 day');", [testOrgActive, testU1]),
            '23514', 'chk_single_share_target'
        );
        await assertSavepointControl(
            adminClient, file2,
            'chk_single_share_target allows exactly one target (org-only)',
            () => adminClient.query("INSERT INTO share_grants (source_organisation_id, target_org_id, target_user_id, resource_type, resource_id, granted_by, expires_at) VALUES ($1, $1, NULL, 'project', 'P1', $2, now() + interval '1 day');", [testOrgActive, testU1])
        );

        // 2.4 Self-approval blocked (trg_approval_step_invariants)
        // Setup approval request
        const reqId = (await adminClient.query(
            "INSERT INTO approval_requests (organisation_id, requested_by_membership_id, request_type, status, payload) VALUES ($1, $2, 'MEMBERSHIP_ROLE_CHANGE', 'PENDING', '{}') RETURNING id;",
            [testOrgActive, testM1]
        )).rows[0].id;
        await assertSavepointFailure(
            adminClient, file2,
            'blocks self-approval via trg_approval_step_invariants',
            () => adminClient.query("INSERT INTO approval_steps (request_id, step_number, required_role_key, decided_by, decision, reason) VALUES ($1, 1, 'business_owner', $2, 'APPROVED', 'Self');", [reqId, testU1]),
            'P0001', 'Self-approval is strictly forbidden'
        );
        await assertSavepointControl(
            adminClient, file2,
            'trg_approval_step_invariants allows distinct decider',
            () => adminClient.query("INSERT INTO approval_steps (request_id, step_number, required_role_key, decided_by, decision, reason) VALUES ($1, 1, 'business_owner', $2, 'APPROVED', 'Valid');", [reqId, testU2])
        );

        // 2.5 Intern expiry required (trg_memberships_expiry_enforcement)
        // Uses real distinct user and real distinct organisation
        const internUser = (await adminClient.query("INSERT INTO users (user_code, email) VALUES ('TC-VFY-INT', 'tc_vfy_int@archscale.test') RETURNING id;")).rows[0].id;
        await assertSavepointFailure(
            adminClient, file2,
            'enforces trg_memberships_expiry_enforcement on intern role with NULL expires_at',
            () => adminClient.query("INSERT INTO memberships (user_id, organisation_id, role_key, expires_at) VALUES ($1, $2, 'intern', NULL);", [internUser, testOrgActive]),
            'P0001', 'must have an explicit expires_at'
        );
        await assertSavepointControl(
            adminClient, file2,
            'trg_memberships_expiry_enforcement allows intern with explicit future expiry',
            () => adminClient.query("INSERT INTO memberships (user_id, organisation_id, role_key, expires_at) VALUES ($1, $2, 'intern', now() + interval '30 days');", [internUser, testOrgActive])
        );

        // 2.6 Active membership requires active org (trg_membership_active_org_check)
        // Uses real distinct user and real SUSPENDED organisation
        const suspendedOrgUser = (await adminClient.query("INSERT INTO users (user_code, email) VALUES ('TC-VFY-SUSP', 'tc_vfy_susp@archscale.test') RETURNING id;")).rows[0].id;
        await assertSavepointFailure(
            adminClient, file2,
            'blocks active membership under non-active organisation via trg_membership_active_org_check',
            () => adminClient.query("INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ($1, $2, 'business_owner', 'ACTIVE');", [suspendedOrgUser, testOrgSuspended]),
            'P0001', 'Cannot assign or activate membership in non-active organisation'
        );
        await assertSavepointControl(
            adminClient, file2,
            'allows active membership under ACTIVE organisation',
            () => adminClient.query("INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ($1, $2, 'business_owner', 'ACTIVE');", [suspendedOrgUser, testOrgActive])
        );

        // Cleanup Suite 02 fixtures
        await adminClient.query('ROLLBACK TO SAVEPOINT sp_suite2_setup;');

        // =========================================================================
        // Suite 03: Org Status Cascade
        // =========================================================================
        const file3 = '03_org_status_cascade';
        await adminClient.query('SAVEPOINT sp_suite3;');
        const oIdCascade = (await adminClient.query("INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Cascade Org', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;")).rows[0].id;
        const uIdCascade = (await adminClient.query("INSERT INTO users (user_code, email) VALUES ('TC-CASC-U', 'tc_casc@archscale.test') RETURNING id;")).rows[0].id;
        const wIdCascade = (await adminClient.query("INSERT INTO workspaces (organisation_id, name) VALUES ($1, 'Main') RETURNING id;", [oIdCascade])).rows[0].id;
        const mIdCascade = (await adminClient.query("INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ($1, $2, 'business_owner', 'ACTIVE') RETURNING id;", [uIdCascade, oIdCascade])).rows[0].id;
        const cIdCascade = (await adminClient.query("INSERT INTO access_contexts (user_id, session_id, organisation_id, workspace_id, membership_id, expires_at) VALUES ($1, 's_casc', $2, $3, $4, now() + interval '12 hours') RETURNING id;", [uIdCascade, oIdCascade, wIdCascade, mIdCascade])).rows[0].id;

        // Suspend org
        await adminClient.query("UPDATE organisations SET status = 'SUSPENDED' WHERE id = $1;", [oIdCascade]);

        const ctxRevoked = (await adminClient.query("SELECT is_revoked FROM access_contexts WHERE id = $1;", [cIdCascade])).rows[0].is_revoked;
        record(file3, 'org suspension automatically revokes active access_contexts', ctxRevoked === true);

        const memStatus = (await adminClient.query("SELECT status FROM memberships WHERE id = $1;", [mIdCascade])).rows[0].status;
        record(file3, 'org suspension automatically suspends active memberships', memStatus === 'SUSPENDED');
        await adminClient.query('ROLLBACK TO SAVEPOINT sp_suite3;');

        // =========================================================================
        // Suite 04: Atomic Approvals
        // =========================================================================
        const file4 = '04_atomic_approvals';
        await assertSavepointFailure(
            adminClient, file4,
            'fn_approve_organisation rejects non-founder caller',
            () => adminClient.query("SELECT fn_approve_organisation('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001', '10.0.0.1'::inet, 'test');"),
            'P0001', 'Only active founders'
        );

        await assertSavepointFailure(
            adminClient, file4,
            'fn_approve_membership rejects forged actor',
            () => adminClient.query("SELECT fn_approve_membership('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001', '10.0.0.1'::inet, 'test');"),
            'P0001'
        );

        const isUnknownValid = (await adminClient.query("SELECT is_context_valid('00000000-0000-0000-0000-000000000000');")).rows[0].is_context_valid;
        record(file4, 'is_context_valid returns false for unknown context UUID', isUnknownValid === false);

        // =========================================================================
        // Suite 05: Concurrent Seats Race (Uses organisation_seats, NOT non-existent entitlements)
        // =========================================================================
        const file5 = '05_concurrent_seats_race';
        await adminClient.query('SAVEPOINT sp_suite5;');
        const oIdSeats = (await adminClient.query("INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Seat Test Org', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;")).rows[0].id;
        // Ensure app_catalogue has a test app
        await adminClient.query("INSERT INTO app_catalogue (app_key, name, description) VALUES ('app_vfy_seats', 'Seat App', 'Desc') ON CONFLICT (app_key) DO NOTHING;");
        await adminClient.query(
            "INSERT INTO organisation_seats (organisation_id, app_key, role_key, seat_limit, allocated_seats) VALUES ($1, 'app_vfy_seats', 'business_owner', 5, 0);",
            [oIdSeats]
        );

        // Failure check: over-allocating seats beyond seat_limit
        await assertSavepointFailure(
            adminClient, file5,
            'enforces chk_seats_allocated_lte_limit when allocated_seats > seat_limit',
            () => adminClient.query("UPDATE organisation_seats SET allocated_seats = 6 WHERE organisation_id = $1 AND app_key = 'app_vfy_seats';", [oIdSeats]),
            '23514', 'chk_seats_allocated_lte_limit'
        );

        // Positive control: allocating within seat_limit succeeds
        await assertSavepointControl(
            adminClient, file5,
            'chk_seats_allocated_lte_limit allows allocation within seat_limit',
            () => adminClient.query("UPDATE organisation_seats SET allocated_seats = 3 WHERE organisation_id = $1 AND app_key = 'app_vfy_seats';", [oIdSeats])
        );
        await adminClient.query('ROLLBACK TO SAVEPOINT sp_suite5;');

        // =========================================================================
        // Suite 06: Immutable Audit Log
        // =========================================================================
        const file6 = '06_immutable_audit';
        await adminClient.query('SAVEPOINT sp_suite6;');
        const auditRowId = (await adminClient.query(
            "INSERT INTO audit_logs (action, target_entity, target_id) VALUES ('TC_VERIFY_LOG', 'system', 'sys1') RETURNING id;"
        )).rows[0].id;

        await assertSavepointFailure(
            adminClient, file6,
            'blocks UPDATE on audit_logs via trg_audit_logs_immutable_update trigger',
            () => adminClient.query("UPDATE audit_logs SET action = 'ALTERED' WHERE id = $1;", [auditRowId]),
            'P0001', 'append-only'
        );

        await assertSavepointFailure(
            adminClient, file6,
            'blocks DELETE on audit_logs via trg_audit_logs_immutable_delete trigger',
            () => adminClient.query("DELETE FROM audit_logs WHERE id = $1;", [auditRowId]),
            'P0001', 'append-only'
        );

        await assertSavepointFailure(
            adminClient, file6,
            'blocks TRUNCATE on audit_logs',
            () => adminClient.query("TRUNCATE audit_logs;"),
            'P0001'
        );

        await assertSavepointFailure(
            runtimeClient, file6,
            'runtime role denied UPDATE on audit_logs by privilege revocation (42501)',
            () => runtimeClient.query("UPDATE audit_logs SET action = 'HACKED';"),
            '42501'
        );
        await adminClient.query('ROLLBACK TO SAVEPOINT sp_suite6;');

        // =========================================================================
        // Suite 07: Runtime Role Privilege Proofs
        // =========================================================================
        const file7 = '07_runtime_privilege_proof';
        const roleFlags = (await adminClient.query("SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = 'archscale_app_runtime';")).rows[0];
        const isLeastPrivilege = !roleFlags.rolsuper && !roleFlags.rolbypassrls && !roleFlags.rolcreaterole && !roleFlags.rolcreatedb;
        record(file7, 'runtime role has no administrative flags (NO SUPERUSER, NO BYPASSRLS)', isLeastPrivilege);

        await assertSavepointFailure(
            runtimeClient, file7,
            'runtime role cannot CREATE TABLE in schema public (42501)',
            () => runtimeClient.query("CREATE TABLE public.hack_table (id serial primary key);"),
            '42501'
        );

        const wsRows = (await runtimeClient.query("SELECT * FROM workspaces;")).rows;
        record(file7, 'runtime role querying workspaces without context returns 0 rows (RLS)', wsRows.length === 0);

        await assertSavepointFailure(
            runtimeClient, file7,
            'fn_set_app_context rejects forged context id',
            () => runtimeClient.query("SELECT fn_set_app_context('00000000-0000-0000-0000-000000000000');"),
            'P0001', 'ARCHSCALE_INVALID_CONTEXT'
        );

        const hasExec = (await adminClient.query("SELECT has_function_privilege('archscale_app_runtime', 'fn_set_app_context(UUID)', 'EXECUTE');")).rows[0].has_function_privilege;
        record(file7, 'runtime role holds EXECUTE on fn_set_app_context', hasExec === true);

    } finally {
        // ALWAYS rollback all writes performed by verification suite
        await adminClient.query('ROLLBACK;').catch(() => {});
        await adminClient.end();
        await runtimeClient.end();
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

    return totalFailed === 0;
}
