/**
 * Migration 012: Secure User Mirror Access — Local Tests
 *
 * These tests run against the isolated local test database (ARCHSCALE_TEST_DB_URL).
 * They verify:
 *   1. runtime role with no context → SELECT on users returns 0 rows
 *   2. runtime role → direct INSERT on users is denied (42501)
 *   3. runtime role → direct UPDATE on users is denied (42501)
 *   4. fn_resolve_user_code returns email for a known code, NULL for unknown
 *   5. fn_resolve_user_code returns NULL for non-AS-... patterns
 *   6. fn_upsert_user_mirror inserts/updates only identity fields (no role column)
 *   7. fn_upsert_user_mirror cannot change another user's email on conflict (immutable email)
 *   8. Single-connection reuse test: valid-context query returns own row only;
 *      subsequent query after transaction commits returns 0 rows and NO error.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIsolatedTestDatabase, RUNTIME_CONFIG } from '../setup/db_connection.js';
import pg from 'pg';

let adminPool: pg.Pool;
let runtimeClient: pg.Client;

const TEST_USER_ID_A = '10000000-0000-0000-0000-000000000001';
const TEST_USER_ID_B = '10000000-0000-0000-0000-000000000002';
const TEST_CODE_A = 'AS-TESTLOCAL01';
const TEST_EMAIL_A = 'test.local.a@archscale.test';
const TEST_EMAIL_B = 'test.local.b@archscale.test';

let validContextId: string;

beforeAll(async () => {
    adminPool = await createIsolatedTestDatabase('archscale_test_012');

    // Stand-in auth.users seed (required by fn_upsert_user_mirror)
    await adminPool.query(
        `INSERT INTO auth.users (id, email) VALUES ($1, $2), ($3, $4) ON CONFLICT (id) DO NOTHING;`,
        [TEST_USER_ID_A, TEST_EMAIL_A, TEST_USER_ID_B, TEST_EMAIL_B]
    );

    // Seed two users via admin connection (bypasses RLS)
    await adminPool.query(
        `INSERT INTO public.users (id, user_code, email) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING;`,
        [TEST_USER_ID_A, TEST_CODE_A, TEST_EMAIL_A]
    );
    await adminPool.query(
        `INSERT INTO public.users (id, user_code, email) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING;`,
        [TEST_USER_ID_B, 'AS-TESTLOCAL02', TEST_EMAIL_B]
    );

    // Setup active tenant context fixtures for TEST_USER_ID_A
    const orgRes = await adminPool.query(
        `INSERT INTO organisations (name, portal, tenant_type_key, status)
         VALUES ('Test Org 012', 'subscriber', 'studio_owner', 'ACTIVE')
         RETURNING id;`
    );
    const orgId = orgRes.rows[0].id;

    const wsRes = await adminPool.query(
        `INSERT INTO workspaces (organisation_id, name) VALUES ($1, 'Main') RETURNING id;`,
        [orgId]
    );
    const wsId = wsRes.rows[0].id;

    const memRes = await adminPool.query(
        `INSERT INTO memberships (user_id, organisation_id, role_key, status)
         VALUES ($1, $2, 'business_owner', 'ACTIVE')
         RETURNING id;`,
        [TEST_USER_ID_A, orgId]
    );
    const memId = memRes.rows[0].id;

    const ctxRes = await adminPool.query(
        `INSERT INTO access_contexts (user_id, session_id, organisation_id, workspace_id, membership_id, expires_at)
         VALUES ($1, 'sess_012', $2, $3, $4, now() + interval '12 hours')
         RETURNING id;`,
        [TEST_USER_ID_A, orgId, wsId, memId]
    );
    validContextId = ctxRes.rows[0].id;

    // Connect as runtime role (uses dynamic RUNTIME_CONFIG from db_connection.ts)
    const runtimeConfig = {
        ...RUNTIME_CONFIG,
        database: 'archscale_test_012'
    };
    runtimeClient = new pg.Client(runtimeConfig);
    await runtimeClient.connect();
});

afterAll(async () => {
    await runtimeClient?.end().catch(() => {});
    await adminPool?.end().catch(() => {});
});

describe('Migration 012: Secure User Mirror Access [local]', () => {

    it('1. runtime role with no context → SELECT on users returns 0 rows (RLS)', async () => {
        // No fn_set_app_context call — no context active
        const res = await runtimeClient.query('SELECT * FROM public.users;');
        expect(res.rows.length).toBe(0);
    });

    it('2. runtime role → direct INSERT on users is denied (42501)', async () => {
        await runtimeClient.query('BEGIN;').catch(() => {});
        let errorCode: string | undefined;
        try {
            await runtimeClient.query(
                `INSERT INTO public.users (id, user_code, email) VALUES ('20000000-0000-0000-0000-000000000001', 'AS-ROGUE', 'rogue@archscale.test');`
            );
        } catch (err: any) {
            errorCode = err.code;
        } finally {
            await runtimeClient.query('ROLLBACK;').catch(() => {});
        }
        expect(errorCode).toBe('42501');
    });

    it('3. runtime role → direct UPDATE on users is denied (42501)', async () => {
        await runtimeClient.query('BEGIN;').catch(() => {});
        let errorCode: string | undefined;
        try {
            await runtimeClient.query(
                `UPDATE public.users SET email = 'hacked@archscale.test';`
            );
        } catch (err: any) {
            errorCode = err.code;
        } finally {
            await runtimeClient.query('ROLLBACK;').catch(() => {});
        }
        expect(errorCode).toBe('42501');
    });

    it('4. fn_resolve_user_code returns email for a known AS-... code', async () => {
        const res = await runtimeClient.query<{ fn_resolve_user_code: string | null }>(
            'SELECT fn_resolve_user_code($1);',
            [TEST_CODE_A]
        );
        expect(res.rows[0].fn_resolve_user_code).toBe(TEST_EMAIL_A);
    });

    it('5. fn_resolve_user_code returns NULL for an unknown AS-... code', async () => {
        const res = await runtimeClient.query<{ fn_resolve_user_code: string | null }>(
            'SELECT fn_resolve_user_code($1);',
            ['AS-DOESNOTEXIST99']
        );
        expect(res.rows[0].fn_resolve_user_code).toBeNull();
    });

    it('5b. fn_resolve_user_code returns NULL for a non-AS-... pattern (no general lookup)', async () => {
        const res = await runtimeClient.query<{ fn_resolve_user_code: string | null }>(
            'SELECT fn_resolve_user_code($1);',
            [TEST_EMAIL_A]
        );
        expect(res.rows[0].fn_resolve_user_code).toBeNull();
    });

    it('6. fn_upsert_user_mirror inserts identity fields with server-generated user_code', async () => {
        const newId = '30000000-0000-0000-0000-000000000003';
        // Register newId in auth.users first
        await adminPool.query('INSERT INTO auth.users (id, email) VALUES ($1, $2);', [newId, 'new.user@archscale.test']);

        const res = await runtimeClient.query(
            `SELECT * FROM fn_upsert_user_mirror($1, $2);`,
            [newId, 'new.user@archscale.test']
        );
        expect(res.rows.length).toBe(1);
        expect(res.rows[0].id).toBe(newId);
        expect(res.rows[0].email).toBe('new.user@archscale.test');
        expect(res.rows[0].user_code).toMatch(/^AS-[A-F0-9]{8}$/);

        // Cleanup
        await adminPool.query('DELETE FROM public.users WHERE id = $1;', [newId]);
        await adminPool.query('DELETE FROM auth.users WHERE id = $1;', [newId]);
    });

    it('7. fn_upsert_user_mirror: caller CANNOT overwrite an existing user email on conflict', async () => {
        // Attempt to hijack TEST_USER_ID_A's email by calling upsert with a mismatched email
        await expect(
            runtimeClient.query(
                `SELECT * FROM fn_upsert_user_mirror($1, 'attacker.hijack@archscale.test', '+1-555-0199');`,
                [TEST_USER_ID_A]
            )
        ).rejects.toThrow(/email mismatch with auth\.users/);

        // Valid upsert with matching email updates phone only; email and user_code remain immutable
        const res = await runtimeClient.query(
            `SELECT * FROM fn_upsert_user_mirror($1, $2, '+1-555-0199');`,
            [TEST_USER_ID_A, TEST_EMAIL_A]
        );
        expect(res.rows[0].email).toBe(TEST_EMAIL_A);
        expect(res.rows[0].user_code).toBe(TEST_CODE_A);

        const checkDb = await adminPool.query(
            `SELECT email, user_code, phone FROM public.users WHERE id = $1;`,
            [TEST_USER_ID_A]
        );
        expect(checkDb.rows[0].email).toBe(TEST_EMAIL_A);
        expect(checkDb.rows[0].user_code).toBe(TEST_CODE_A);
        expect(checkDb.rows[0].phone).toBe('+1-555-0199');
    });

    it('7b. fn_upsert_user_mirror: an id not in auth.users is rejected', async () => {
        const unauthId = '70000000-0000-0000-0000-000000000007';
        await expect(
            runtimeClient.query('SELECT * FROM fn_upsert_user_mirror($1, $2);', [unauthId, 'ghost@archscale.test'])
        ).rejects.toThrow(/does not exist in auth\.users/);
    });

    it('7c. fn_upsert_user_mirror: email cannot be taken for another id', async () => {
        const idC = '80000000-0000-0000-0000-000000000008';
        // Add idC to auth.users with its own email
        await adminPool.query('INSERT INTO auth.users (id, email) VALUES ($1, $2);', [idC, 'other.user@archscale.test']);

        // Now attempt to upsert idC with TEST_EMAIL_A (which belongs to TEST_USER_ID_A in auth.users)
        await expect(
            runtimeClient.query('SELECT * FROM fn_upsert_user_mirror($1, $2);', [idC, TEST_EMAIL_A])
        ).rejects.toThrow(/email mismatch with auth\.users|belongs to another user/);

        // Cleanup
        await adminPool.query('DELETE FROM auth.users WHERE id = $1;', [idC]);
    });

    it('8. Single reused connection: valid-context returns own row; subsequent no-context returns 0 rows and NO error', async () => {
        // Step A: In an isolated transaction on runtimeClient, set valid context
        await runtimeClient.query('BEGIN;');
        await runtimeClient.query('SELECT fn_set_app_context($1);', [validContextId]);

        // Query users: MUST return exactly TEST_USER_ID_A's row and no other row
        const inCtxRes = await runtimeClient.query('SELECT id, user_code, email FROM public.users;');
        expect(inCtxRes.rows.length).toBe(1);
        expect(inCtxRes.rows[0].id).toBe(TEST_USER_ID_A);
        expect(inCtxRes.rows[0].email).toBe(TEST_EMAIL_A);

        // End transaction — GUC archscale.current_context_id resets to empty string in session
        await runtimeClient.query('COMMIT;');

        // Step B: On the VERY SAME connection (runtimeClient), execute without a context
        // Because of NULLIF(current_setting(...), '')::uuid, this MUST NOT throw invalid UUID syntax error
        const afterCtxRes = await runtimeClient.query('SELECT * FROM public.users;');
        expect(afterCtxRes.rows.length).toBe(0); // RLS blocks all rows cleanly
    });
});
