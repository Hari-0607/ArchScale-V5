/**
 * Migration 013: Context-Bound RLS, Authorisation Functions, and Support Contexts
 * Local SQL Tests (ARCHSCALE_TEST_DB_URL)
 */

import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { createIsolatedTestDatabase, RUNTIME_CONFIG } from '../setup/db_connection.js';
import pg from 'pg';

let adminPool: pg.Pool;
let runtimeClient: pg.Client;

const USER_A_ID = '20000000-0000-0000-0000-000000000001';
const USER_B_ID = '20000000-0000-0000-0000-000000000002';
const STAFF_USER_ID = '20000000-0000-0000-0000-000000000003';

const PLATFORM_ORG_ID = '00000000-0000-0000-0000-000000000001';
const SUBSCRIBER_ORG_ID = '20000000-0000-0000-0000-000000000010';

let workspaceAId: string;
let membershipAId: string;
let staffMembershipId: string;
let validContextId: string;
let supportGrantId: string;
const SESSION_A = 'session_test_token_user_a_001';

beforeAll(async () => {
    adminPool = await createIsolatedTestDatabase('archscale_test_013');

    // Stand-in auth.users
    await adminPool.query(`
        INSERT INTO auth.users (id, email) VALUES
            ($1, 'user.a@archscale.test'),
            ($2, 'user.b@archscale.test'),
            ($3, 'staff@archscale.test')
        ON CONFLICT (id) DO NOTHING;
    `, [USER_A_ID, USER_B_ID, STAFF_USER_ID]);

    // Seed mirror users
    await adminPool.query(`
        INSERT INTO public.users (id, user_code, email) VALUES
            ($1, 'AS-TEST013A', 'user.a@archscale.test'),
            ($2, 'AS-TEST013B', 'user.b@archscale.test'),
            ($3, 'AS-TEST013S', 'staff@archscale.test')
        ON CONFLICT (id) DO NOTHING;
    `, [USER_A_ID, USER_B_ID, STAFF_USER_ID]);

    // Create a subscriber organisation
    await adminPool.query(`
        INSERT INTO public.organisations (id, name, portal, tenant_type_key, status)
        VALUES ($1, 'Acme Architecture Studio', 'subscriber', 'studio_owner', 'ACTIVE')
        ON CONFLICT (id) DO NOTHING;
    `, [SUBSCRIBER_ORG_ID]);

    // Create an app in app_catalogue
    await adminPool.query(`
        INSERT INTO public.app_catalogue (app_key, name, description)
        VALUES ('core_billing', 'Core Billing', 'Billing and subscription module')
        ON CONFLICT (app_key) DO NOTHING;
    `);

    // Entitlement for subscriber org
    await adminPool.query(`
        INSERT INTO public.organisation_entitlements (organisation_id, app_key, is_enabled)
        VALUES ($1, 'core_billing', true)
        ON CONFLICT DO NOTHING;
    `, [SUBSCRIBER_ORG_ID]);

    // Default workspace for subscriber org
    const wsRes = await adminPool.query<{ id: string }>(`
        INSERT INTO public.workspaces (organisation_id, name, is_default, is_active)
        VALUES ($1, 'Acme Main Studio', true, true)
        RETURNING id;
    `, [SUBSCRIBER_ORG_ID]);
    workspaceAId = wsRes.rows[0].id;

    // Membership for User A in subscriber org
    const memRes = await adminPool.query<{ id: string }>(`
        INSERT INTO public.memberships (user_id, organisation_id, role_key, status, is_primary_owner)
        VALUES ($1, $2, 'business_owner', 'ACTIVE', true)
        RETURNING id;
    `, [USER_A_ID, SUBSCRIBER_ORG_ID]);
    membershipAId = memRes.rows[0].id;

    // Platform workspace
    const platWsRes = await adminPool.query<{ id: string }>(`
        INSERT INTO public.workspaces (organisation_id, name, is_default, is_active)
        VALUES ($1, 'Platform Operations', true, true)
        ON CONFLICT (organisation_id, name) DO UPDATE SET is_active = true
        RETURNING id;
    `, [PLATFORM_ORG_ID]);
    const platformWsId = platWsRes.rows[0].id;

    // Staff membership in platform org (client_servicing)
    const staffMemRes = await adminPool.query<{ id: string }>(`
        INSERT INTO public.memberships (user_id, organisation_id, role_key, status)
        VALUES ($1, $2, 'client_servicing', 'ACTIVE')
        RETURNING id;
    `, [STAFF_USER_ID, PLATFORM_ORG_ID]);
    staffMembershipId = staffMemRes.rows[0].id;

    // Support grant from staff to Acme org (active for 2 hours)
    const grantRes = await adminPool.query<{ id: string }>(`
        INSERT INTO public.support_access_grants (
            staff_membership_id, target_organisation_id, reason, started_at, expires_at
        ) VALUES (
            $1, $2, 'Investigating billing discrepancy', now(), now() + interval '2 hours'
        ) RETURNING id;
    `, [staffMembershipId, SUBSCRIBER_ORG_ID]);
    supportGrantId = grantRes.rows[0].id;

    // Create a valid context for User A via fn_create_access_context
    const ctxRes = await adminPool.query<{ fn_create_access_context: string }>(`
        SELECT fn_create_access_context($1, $2, $3, $4, 'aal2');
    `, [USER_A_ID, SESSION_A, SUBSCRIBER_ORG_ID, workspaceAId]);
    validContextId = ctxRes.rows[0].fn_create_access_context;

    // Dedicated runtime client connected to the isolated test database
    const runtimeConfig = {
        ...RUNTIME_CONFIG,
        database: 'archscale_test_013'
    };
    runtimeClient = new pg.Client(runtimeConfig);
    await runtimeClient.connect();
});

afterAll(async () => {
    await runtimeClient.end().catch(() => {});
    await adminPool.end().catch(() => {});
});

afterEach(async () => {
    await runtimeClient.query('ROLLBACK;').catch(() => {});
});

describe('Migration 013: Context RLS and Authz Functions [Local]', () => {
    it('1. fn_set_app_context: validates all 3 anchors and sets GUC successfully', async () => {
        await runtimeClient.query('BEGIN;');
        const res = await runtimeClient.query(
            'SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);',
            [validContextId, USER_A_ID, SESSION_A]
        );
        expect(res.rows[0].fn_set_app_context).toBe(true);

        const gucRes = await runtimeClient.query("SELECT current_setting('archscale.current_context_id', true) AS guc;");
        expect(gucRes.rows[0].guc).toBe(validContextId);
        await runtimeClient.query('ROLLBACK;');
    });

    it('2. fn_set_app_context rejects forged context id', async () => {
        const forgedId = '90000000-0000-0000-0000-000000000099';
        await runtimeClient.query('BEGIN;');
        await expect(
            runtimeClient.query('SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);', [forgedId, USER_A_ID, SESSION_A])
        ).rejects.toThrow(/ARCHSCALE_INVALID_CONTEXT/);
        await runtimeClient.query('ROLLBACK;');
    });

    it('3. fn_set_app_context rejects another user context id (identity mismatch)', async () => {
        await runtimeClient.query('BEGIN;');
        // Context belongs to USER_A, but USER_B attempts to set it
        await expect(
            runtimeClient.query('SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);', [validContextId, USER_B_ID, SESSION_A])
        ).rejects.toThrow(/ARCHSCALE_INVALID_CONTEXT/);
        await runtimeClient.query('ROLLBACK;');
    });

    it('4. fn_set_app_context rejects mismatched session id', async () => {
        await runtimeClient.query('BEGIN;');
        await expect(
            runtimeClient.query('SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);', [validContextId, USER_A_ID, 'forged_session_token'])
        ).rejects.toThrow(/ARCHSCALE_INVALID_CONTEXT/);
        await runtimeClient.query('ROLLBACK;');
    });

    it('5. fn_set_app_context rejects expired or revoked context', async () => {
        // Create an expired context
        const expCtxRes = await adminPool.query<{ id: string }>(`
            INSERT INTO public.access_contexts (
                user_id, session_id, organisation_id, workspace_id, membership_id, expires_at, created_at
            ) VALUES (
                $1, 'expired_session', $2, $3, $4, now() - interval '1 minute', now() - interval '1 hour'
            ) RETURNING id;
        `, [USER_A_ID, SUBSCRIBER_ORG_ID, workspaceAId, membershipAId]);
        const expiredId = expCtxRes.rows[0].id;

        await runtimeClient.query('BEGIN;');
        await expect(
            runtimeClient.query('SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);', [expiredId, USER_A_ID, 'expired_session'])
        ).rejects.toThrow(/ARCHSCALE_INVALID_CONTEXT/);
        await runtimeClient.query('ROLLBACK;');
    });

    it('6. fn_create_access_context: subscriber passing a support grant id is refused', async () => {
        // User A is a subscriber member. Passing a supportGrantId must fail closed.
        await expect(
            runtimeClient.query(
                `SELECT fn_create_access_context($1::uuid, 'session_sub_grant'::text, $2::uuid, $3::uuid, 'aal1'::text, $4::uuid);`,
                [USER_A_ID, SUBSCRIBER_ORG_ID, workspaceAId, supportGrantId]
            )
        ).rejects.toThrow(/AUTH_CONTEXT_DENIED/);
    });

    it('7. fn_create_access_context: platform staff with valid grant creates support context', async () => {
        const supportCtxRes = await runtimeClient.query<{ fn_create_access_context: string }>(
            `SELECT fn_create_access_context($1::uuid, 'staff_session_01'::text, $2::uuid, $3::uuid, 'aal2'::text, $4::uuid);`,
            [STAFF_USER_ID, SUBSCRIBER_ORG_ID, workspaceAId, supportGrantId]
        );
        const supportContextId = supportCtxRes.rows[0].fn_create_access_context;
        expect(supportContextId).toBeDefined();

        // Verify in DB that support_grant_id is populated and bound to target org
        const check = await adminPool.query(
            'SELECT support_grant_id, organisation_id, membership_id FROM access_contexts WHERE id = $1;',
            [supportContextId]
        );
        expect(check.rows[0].support_grant_id).toBe(supportGrantId);
        expect(check.rows[0].organisation_id).toBe(SUBSCRIBER_ORG_ID);
        expect(check.rows[0].membership_id).toBe(staffMembershipId);
    });

    it('8. fn_create_access_context: revoked or expired support grant raises error', async () => {
        // Create an expired grant
        const deadGrantRes = await adminPool.query<{ id: string }>(`
            INSERT INTO public.support_access_grants (
                staff_membership_id, target_organisation_id, reason, started_at, expires_at
            ) VALUES (
                $1, $2, 'Expired grant', now() - interval '2 hours', now() - interval '1 hour'
            ) RETURNING id;
        `, [staffMembershipId, SUBSCRIBER_ORG_ID]);
        const deadGrantId = deadGrantRes.rows[0].id;

        await expect(
            runtimeClient.query(
                `SELECT fn_create_access_context($1::uuid, 'staff_dead_session'::text, $2::uuid, $3::uuid, 'aal2'::text, $4::uuid);`,
                [STAFF_USER_ID, SUBSCRIBER_ORG_ID, workspaceAId, deadGrantId]
            )
        ).rejects.toThrow(/AUTH_CONTEXT_DENIED/);
    });

    it('9. Support context read-only enforcement: calling fn_approve_* raises AUTH_SUPPORT_READ_ONLY', async () => {
        // Create support context
        const supportCtxRes = await runtimeClient.query<{ fn_create_access_context: string }>(
            `SELECT fn_create_access_context($1::uuid, 'staff_readonly_session'::text, $2::uuid, $3::uuid, 'aal2'::text, $4::uuid);`,
            [STAFF_USER_ID, SUBSCRIBER_ORG_ID, workspaceAId, supportGrantId]
        );
        const supportCtxId = supportCtxRes.rows[0].fn_create_access_context;

        await runtimeClient.query('BEGIN;');
        await runtimeClient.query('SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);', [
            supportCtxId,
            STAFF_USER_ID,
            'staff_readonly_session'
        ]);

        // Support context attempting to call fn_approve_organisation
        await runtimeClient.query('SAVEPOINT sp1;');
        await expect(
            runtimeClient.query(
                `SELECT fn_approve_organisation($1::uuid, $2::uuid, 'studio_owner', ARRAY['core_billing'], $3::uuid, '[]'::jsonb, 'reason');`,
                ['30000000-0000-0000-0000-000000000001', staffMembershipId, USER_A_ID]
            )
        ).rejects.toThrow(/AUTH_SUPPORT_READ_ONLY/);
        await runtimeClient.query('ROLLBACK TO SAVEPOINT sp1;');

        // Support context attempting to call fn_approve_membership
        await runtimeClient.query('SAVEPOINT sp2;');
        await expect(
            runtimeClient.query(
                `SELECT fn_approve_membership($1::uuid, $2::uuid, 'reason');`,
                ['30000000-0000-0000-0000-000000000002', staffMembershipId]
            )
        ).rejects.toThrow(/AUTH_SUPPORT_READ_ONLY/);
        await runtimeClient.query('ROLLBACK TO SAVEPOINT sp2;');

        await runtimeClient.query('ROLLBACK;');
    });

    it('10. fn_audit_append: context derivation, unauthenticated allowlist, and size cap', async () => {
        // Case A: With valid context, actor and organisation are derived automatically
        await runtimeClient.query('BEGIN;');
        await runtimeClient.query('SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);', [validContextId, USER_A_ID, SESSION_A]);

        const logIdA = await runtimeClient.query<{ fn_audit_append: string }>(
            `SELECT fn_audit_append('context.test', 'item', '101', '{"key":"val"}'::jsonb);`
        );
        expect(logIdA.rows[0].fn_audit_append).toBeDefined();
        await runtimeClient.query('COMMIT;');

        const rowA = await adminPool.query(
            'SELECT actor_user_id, actor_membership_id, organisation_id FROM audit_logs WHERE id = $1;',
            [logIdA.rows[0].fn_audit_append]
        );
        expect(rowA.rows[0].actor_user_id).toBe(USER_A_ID);
        expect(rowA.rows[0].actor_membership_id).toBe(membershipAId);
        expect(rowA.rows[0].organisation_id).toBe(SUBSCRIBER_ORG_ID);

        // Case B: With NO context, allowlisted action succeeds with organisation = NULL
        const unauthLogId = await runtimeClient.query<{ fn_audit_append: string }>(
            `SELECT fn_audit_append('AUTH_SIGNIN_FAILED', 'identity', 'AS-TEST013A', '{"ip":"127.0.0.1"}'::jsonb, $1::uuid);`,
            [USER_A_ID]
        );
        expect(unauthLogId.rows[0].fn_audit_append).toBeDefined();

        const rowB = await adminPool.query(
            'SELECT actor_user_id, organisation_id FROM audit_logs WHERE id = $1;',
            [unauthLogId.rows[0].fn_audit_append]
        );
        expect(rowB.rows[0].actor_user_id).toBe(USER_A_ID);
        expect(rowB.rows[0].organisation_id).toBeNull();

        // Case C: With NO context, non-allowlisted action raises error
        await expect(
            runtimeClient.query(`SELECT fn_audit_append('SECRET_DATA_MUTATION', 'item', '102');`)
        ).rejects.toThrow(/AUTH_AUDIT_UNAUTHORIZED/);

        // Case D: Diff size cap (> 2048 bytes raises)
        const hugePayload = JSON.stringify({ data: 'x'.repeat(2500) });
        await expect(
            runtimeClient.query(`SELECT fn_audit_append('AUTH_SIGNIN_FAILED', 'auth', '1', $1::jsonb);`, [hugePayload])
        ).rejects.toThrow(/AUTH_AUDIT_PAYLOAD_TOO_LARGE/);
    });

    it('11. Single reused connection: valid context sees rows; subsequent no-context returns 0 rows and NO error', async () => {
        // Step A: Set valid context in transaction
        await runtimeClient.query('BEGIN;');
        await runtimeClient.query('SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);', [validContextId, USER_A_ID, SESSION_A]);

        const withCtx = await runtimeClient.query('SELECT count(*)::int AS cnt FROM public.workspaces;');
        expect(withCtx.rows[0].cnt).toBeGreaterThan(0);
        await runtimeClient.query('COMMIT;');

        // Step B: Subsequent query outside transaction (no context active)
        const noCtx = await runtimeClient.query('SELECT count(*)::int AS cnt FROM public.workspaces;');
        expect(noCtx.rows[0].cnt).toBe(0); // 0 rows returned, cleanly and safely
    });

    it('12. pg_policies security scan: no policy references current_setting without is_context_valid or fn_current_context_*', async () => {
        const policies = await adminPool.query<{
            schemaname: string;
            tablename: string;
            policyname: string;
            qual: string;
        }>(`
            SELECT schemaname, tablename, policyname, qual
            FROM pg_policies
            WHERE schemaname = 'public'
              AND qual LIKE '%current_setting%';
        `);

        // Every policy using current_setting must also check is_context_valid or call fn_current_context_*
        for (const p of policies.rows) {
            const hasValidityCheck =
                p.qual.includes('is_context_valid') ||
                p.qual.includes('fn_current_context');
            expect(hasValidityCheck).toBe(true);
        }
    });
});
