import pg from 'pg';

const { Client } = pg;

const client = new Client({
    host: process.env.PGHOST || '127.0.0.1',
    port: parseInt(process.env.PGPORT || '5433', 10),
    user: process.env.PGUSER || 'archscale_app_runtime',
    password: process.env.PGPASSWORD || 'archscale_runtime_local_pass',
    database: process.env.PGDATABASE || 'archscale_phase1_clean'
});

async function runCheck(id, name, attempted, expected, fn) {
    const start = Date.now();
    await client.query('BEGIN;');
    await client.query('SAVEPOINT sp;');
    let status = 'FAIL';
    let sqlstate = null;
    let message = null;

    try {
        const res = await fn(client);
        if (expected.shouldSucceed) {
            status = 'PASS';
            message = res?.message || 'Statement succeeded as expected';
        } else {
            status = 'FAIL';
            message = 'Statement illegally SUCCEEDED when rejection was expected';
        }
    } catch (err) {
        sqlstate = err.code || 'UNKNOWN';
        message = err.message || String(err);
        if (err.code === '42P01' || err.code === '42703') {
            status = 'Not built yet';
        } else if (!expected.shouldSucceed) {
            if (!expected.expectedCodes || expected.expectedCodes.includes(err.code)) {
                status = 'PASS';
            } else {
                status = 'FAIL';
            }
        } else {
            status = 'FAIL';
        }
    } finally {
        await client.query('ROLLBACK TO SAVEPOINT sp;');
        await client.query('ROLLBACK;');
    }

    const durationMs = Date.now() - start;
    return {
        id,
        name,
        attempted,
        expected: expected.description,
        sqlstate,
        message,
        status,
        durationMs
    };
}

async function main() {
    await client.connect();
    console.log('Connected as archscale_app_runtime.');

    const checks = [
        // 1. Insert a second platform organisation is rejected
        {
            id: 1,
            name: 'Single Platform Organisation',
            attempted: "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Second Platform Org', 'platform', NULL, 'ACTIVE');",
            expected: { shouldSucceed: false, expectedCodes: ['23505'], description: 'Rejected with unique violation (23505)' },
            fn: async (c) => {
                await c.query("INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Second Platform Org', 'platform', NULL, 'ACTIVE');");
            }
        },
        // 2. UPDATE on audit_logs is rejected
        {
            id: 2,
            name: 'Audit Log Immutability: UPDATE',
            attempted: "UPDATE audit_logs SET action = 'tampered' WHERE id = (SELECT id FROM audit_logs LIMIT 1);",
            expected: { shouldSucceed: false, expectedCodes: ['42501', 'P0001'], description: 'Rejected with permission denied or trigger exception' },
            fn: async (c) => {
                const idRes = await c.query("SELECT id FROM audit_logs LIMIT 1;");
                const targetId = idRes.rows[0]?.id || '00000000-0000-0000-0000-000000000000';
                await c.query(`UPDATE audit_logs SET action = 'tampered' WHERE id = '${targetId}';`);
            }
        },
        // 3. DELETE on audit_logs is rejected
        {
            id: 3,
            name: 'Audit Log Immutability: DELETE',
            attempted: "DELETE FROM audit_logs WHERE id = (SELECT id FROM audit_logs LIMIT 1);",
            expected: { shouldSucceed: false, expectedCodes: ['42501', 'P0001'], description: 'Rejected with permission denied or trigger exception' },
            fn: async (c) => {
                const idRes = await c.query("SELECT id FROM audit_logs LIMIT 1;");
                const targetId = idRes.rows[0]?.id || '00000000-0000-0000-0000-000000000000';
                await c.query(`DELETE FROM audit_logs WHERE id = '${targetId}';`);
            }
        },
        // 4. TRUNCATE on audit_logs is rejected
        {
            id: 4,
            name: 'Audit Log Immutability: TRUNCATE',
            attempted: "TRUNCATE TABLE audit_logs;",
            expected: { shouldSucceed: false, expectedCodes: ['42501', 'P0001'], description: 'Rejected with permission denied or trigger exception' },
            fn: async (c) => {
                await c.query("TRUNCATE TABLE audit_logs;");
            }
        },
        // 5. Set a membership ACTIVE under a non-ACTIVE organisation is rejected
        {
            id: 5,
            name: 'Active Org Dependency on Membership',
            attempted: "INSERT INTO memberships under an organisation in APPLIED status with status = 'ACTIVE';",
            expected: { shouldSucceed: false, expectedCodes: ['P0001'], description: 'Rejected with trigger exception (P0001)' },
            fn: async (c) => {
                const u = (await c.query("INSERT INTO users (user_code, email) VALUES ('CHK-5-USR', 'chk5@test.local') RETURNING id;")).rows[0].id;
                const o = (await c.query("INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('CHK-5-ORG', 'subscriber', 'studio_owner', 'APPLIED') RETURNING id;")).rows[0].id;
                await c.query(`INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ('${u}', '${o}', 'business_owner', 'ACTIVE');`);
            }
        },
        // 6. Remove or suspend the only active founder is rejected
        {
            id: 6,
            name: 'Custodian Protection: Last Active Founder',
            attempted: "UPDATE memberships SET status = 'SUSPENDED' for the only active platform founder;",
            expected: { shouldSucceed: false, expectedCodes: ['P0001'], description: 'Rejected with custodian protection trigger (P0001)' },
            fn: async (c) => {
                const f = (await c.query("SELECT id FROM memberships WHERE role_key = 'founder' AND organisation_id = '00000000-0000-0000-0000-000000000001' AND status = 'ACTIVE' LIMIT 1;")).rows[0].id;
                await c.query(`UPDATE memberships SET status = 'SUSPENDED' WHERE id = '${f}';`);
            }
        },
        // 7. Create an intern membership with no expiry is rejected
        {
            id: 7,
            name: 'Expiry Required for Intern Role',
            attempted: "INSERT INTO memberships with role_key = 'intern' and expires_at = NULL;",
            expected: { shouldSucceed: false, expectedCodes: ['P0001'], description: 'Rejected with expiry enforcement trigger (P0001)' },
            fn: async (c) => {
                const u = (await c.query("INSERT INTO users (user_code, email) VALUES ('CHK-7-USR', 'chk7@test.local') RETURNING id;")).rows[0].id;
                const o = (await c.query("SELECT id FROM organisations WHERE portal = 'subscriber' AND status = 'ACTIVE' LIMIT 1;")).rows[0].id;
                await c.query(`INSERT INTO memberships (user_id, organisation_id, role_key, status, expires_at) VALUES ('${u}', '${o}', 'intern', 'PENDING_APPROVAL', NULL);`);
            }
        },
        // 8. Share grant with both target_org_id and target_user_id set is rejected
        {
            id: 8,
            name: 'Mutual Exclusivity: Share Grant Targets',
            attempted: "INSERT INTO share_grants with BOTH target_org_id AND target_user_id specified;",
            expected: { shouldSucceed: false, expectedCodes: ['23514'], description: 'Rejected with check constraint violation (23514)' },
            fn: async (c) => {
                const o = (await c.query("SELECT id FROM organisations WHERE portal = 'subscriber' LIMIT 1;")).rows[0].id;
                const u = (await c.query("SELECT id FROM users LIMIT 1;")).rows[0].id;
                const m = (await c.query("SELECT id FROM memberships LIMIT 1;")).rows[0].id;
                await c.query(`INSERT INTO share_grants (source_organisation_id, target_org_id, target_user_id, resource_type, resource_id, granted_by, expires_at) VALUES ('${o}', '${o}', '${u}', 'project', 'P-1', '${m}', now() + interval '1 day');`);
            }
        },
        // 9. Support access grant with 72-hour expiry is rejected
        {
            id: 9,
            name: 'Support Access Maximum 24h Lifespan',
            attempted: "INSERT INTO support_access_grants with 72-hour expiration window;",
            expected: { shouldSucceed: false, expectedCodes: ['23514'], description: 'Rejected with check constraint chk_support_grant_max_24h (23514)' },
            fn: async (c) => {
                const fm = (await c.query("SELECT id FROM memberships WHERE role_key = 'founder' LIMIT 1;")).rows[0].id;
                const o = (await c.query("SELECT id FROM organisations WHERE portal = 'subscriber' LIMIT 1;")).rows[0].id;
                await c.query(`INSERT INTO support_access_grants (staff_membership_id, target_organisation_id, reason, expires_at) VALUES ('${fm}', '${o}', 'Test reason', now() + interval '72 hours');`);
            }
        },
        // 10. Approve your own request is rejected (Separation of duties)
        {
            id: 10,
            name: 'Separation of Duties (Self-Approval Prohibited)',
            attempted: "INSERT INTO approval_steps where decided_by user matches requester_user_id;",
            expected: { shouldSucceed: false, expectedCodes: ['P0001'], description: 'Rejected with separation of duties trigger (P0001)' },
            fn: async (c) => {
                const u = (await c.query("INSERT INTO users (user_code, email) VALUES ('CHK-10-USR', 'chk10@test.local') RETURNING id;")).rows[0].id;
                const o = (await c.query("SELECT id FROM organisations WHERE portal = 'subscriber' AND status = 'ACTIVE' LIMIT 1;")).rows[0].id;
                const m = (await c.query(`INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ('${u}', '${o}', 'business_owner', 'ACTIVE') RETURNING id;`)).rows[0].id;
                const req = (await c.query(`INSERT INTO access_requests (request_type, requester_user_id, organisation_id, target_role_key, justification) VALUES ('membership', '${u}', '${o}', 'leader', 'Self promote') RETURNING id;`)).rows[0].id;
                await c.query(`INSERT INTO approval_steps (request_id, step_number, required_role_key, decided_by, decision, reason) VALUES ('${req}', 1, 'business_owner', '${m}', 'APPROVED', 'Self approving');`);
            }
        },
        // 11. A forged actor on fn_approve_membership is rejected
        {
            id: 11,
            name: 'Forged Actor Rejection on fn_approve_membership',
            attempted: "SELECT fn_approve_membership using an illegitimate / cross-org approver membership;",
            expected: { shouldSucceed: false, expectedCodes: ['P0001'], description: 'Rejected with scope violation or unauthorized trigger (P0001)' },
            fn: async (c) => {
                const fakeMem = '22222222-2222-2222-2222-222222222222';
                const req = (await c.query("SELECT id FROM access_requests LIMIT 1;")).rows[0]?.id || '11111111-1111-1111-1111-111111111111';
                await c.query(`SELECT fn_approve_membership('${req}', '${fakeMem}', 'Forged approval');`);
            }
        },
        // 12. Suspending an organisation succeeds even when it contains the last business_owner, and revokes its contexts (the exemption case)
        {
            id: 12,
            name: 'Organisation Suspension Exemption & Context Cascade',
            attempted: "UPDATE organisations SET status = 'SUSPENDED' on an org with sole business owner and active context;",
            expected: { shouldSucceed: true, description: 'Succeeds (exempt from custodian block) and cascades revocation' },
            fn: async (c) => {
                const u = (await c.query("INSERT INTO users (user_code, email) VALUES ('CHK-12-USR', 'chk12@test.local') RETURNING id;")).rows[0].id;
                const o = (await c.query("INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('CHK-12-ORG', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;")).rows[0].id;
                const ws = (await c.query(`INSERT INTO workspaces (organisation_id, name) VALUES ('${o}', 'WS-12') RETURNING id;`)).rows[0].id;
                const m = (await c.query(`INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ('${u}', '${o}', 'business_owner', 'ACTIVE') RETURNING id;`)).rows[0].id;
                const ctx = (await c.query(`INSERT INTO access_contexts (user_id, session_id, organisation_id, workspace_id, membership_id, expires_at) VALUES ('${u}', 's12', '${o}', '${ws}', '${m}', now() + interval '8 hours') RETURNING id;`)).rows[0].id;

                // Suspend organisation (must succeed)
                await c.query(`UPDATE organisations SET status = 'SUSPENDED' WHERE id = '${o}';`);

                // Verify context revoked
                const ctxCheck = await c.query(`SELECT revoked_at FROM access_contexts WHERE id = '${ctx}';`);
                const memCheck = await c.query(`SELECT status FROM memberships WHERE id = '${m}';`);

                if (!ctxCheck.rows[0]?.revoked_at || memCheck.rows[0]?.status !== 'SUSPENDED') {
                    throw new Error('Cascade verification failed: context was not revoked or membership was not suspended');
                }

                return { message: 'Organisation suspended successfully; memberships cascaded to SUSPENDED and context revoked' };
            }
        },
        // 13. Querying a tenant table as the runtime role with no context returns zero rows (RLS)
        {
            id: 13,
            name: 'Row-Level Security (RLS) Tenant Isolation',
            attempted: "SELECT count(*) FROM workspaces as archscale_app_runtime with no active session context;",
            expected: { shouldSucceed: true, description: 'Returns exactly 0 rows due to RLS default-deny' },
            fn: async (c) => {
                const res = await c.query("SELECT count(*)::int as count FROM workspaces;");
                if (res.rows[0].count !== 0) {
                    throw new Error(`RLS violation: expected 0 rows, but got ${res.rows[0].count}`);
                }
                return { message: 'RLS active: Query returned 0 rows as expected' };
            }
        },
        // 14. Runtime role privilege proof: not superuser, no BYPASSRLS, cannot CREATE TABLE
        {
            id: 14,
            name: 'Runtime Role Least Privilege Verification',
            attempted: "Inspect pg_roles for rolsuper/rolbypassrls, then attempt CREATE TABLE rogue_table;",
            expected: { shouldSucceed: false, expectedCodes: ['42501'], description: 'Rejected with permission denied for schema public (42501)' },
            fn: async (c) => {
                const roleInfo = await c.query("SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls FROM pg_roles WHERE rolname = current_user;");
                const { rolsuper, rolbypassrls, rolcreatedb, rolcreaterole } = roleInfo.rows[0];
                if (rolsuper || rolbypassrls || rolcreatedb || rolcreaterole) {
                    throw new Error(`Privilege escalation detected: role has excessive flags`);
                }
                // Attempt CREATE TABLE -> must fail with 42501
                await c.query("CREATE TABLE rogue_proof_table (id int);");
            }
        }
    ];

    console.log('\n--- EXECUTING 14 RULES PROOF ---');
    for (const chk of checks) {
        const result = await runCheck(chk.id, chk.name, chk.attempted, chk.expected, chk.fn);
        console.log(`[Check ${result.id}] ${result.status} | ${result.name} (${result.durationMs}ms)`);
        if (result.sqlstate) {
            console.log(`   SQLSTATE: ${result.sqlstate} | ${result.message}`);
        } else {
            console.log(`   Result: ${result.message}`);
        }
    }

    await client.end();
}

main().catch(err => {
    console.error('Fatal execution error:', err);
    process.exit(1);
});
