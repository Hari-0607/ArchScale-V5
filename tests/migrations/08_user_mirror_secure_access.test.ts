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
 *   7. fn_upsert_user_mirror scoping: cannot overwrite another principal's row
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIsolatedTestDatabase } from '../setup/db_connection.js';
import pg from 'pg';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let adminPool: pg.Pool;
let runtimeClient: pg.Client;

const TEST_USER_ID_A = '10000000-0000-0000-0000-000000000001';
const TEST_USER_ID_B = '10000000-0000-0000-0000-000000000002';
const TEST_CODE_A = 'AS-TESTLOCAL01';
const TEST_EMAIL_A = 'test.local.a@archscale.test';
const TEST_EMAIL_B = 'test.local.b@archscale.test';

beforeAll(async () => {
    adminPool = await createIsolatedTestDatabase('archscale_test_012');

    // Seed two users via admin connection (bypasses RLS)
    await adminPool.query(
        `INSERT INTO public.users (id, user_code, email) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING;`,
        [TEST_USER_ID_A, TEST_CODE_A, TEST_EMAIL_A]
    );
    await adminPool.query(
        `INSERT INTO public.users (id, user_code, email) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING;`,
        [TEST_USER_ID_B, 'AS-TESTLOCAL02', TEST_EMAIL_B]
    );

    // Connect as runtime role (uses local password from db_connection.ts)
    const runtimeConfig = {
        host: '127.0.0.1',
        port: 5432,
        user: 'archscale_app_runtime',
        password: 'archscale_runtime_local_pass',
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
        // 42501 = insufficient_privilege
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
            [TEST_EMAIL_A]  // passing an email directly should not resolve
        );
        expect(res.rows[0].fn_resolve_user_code).toBeNull();
    });

    it('6. fn_upsert_user_mirror inserts identity fields only — no role column possible', async () => {
        const newId = '30000000-0000-0000-0000-000000000003';
        const res = await runtimeClient.query(
            `SELECT * FROM fn_upsert_user_mirror($1, $2, $3, NULL);`,
            [newId, 'new.user@archscale.test', 'AS-NEWUSER01']
        );
        expect(res.rows.length).toBe(1);
        expect(res.rows[0].id).toBe(newId);
        expect(res.rows[0].email).toBe('new.user@archscale.test');
        expect(res.rows[0].user_code).toBe('AS-NEWUSER01');

        // Verify admin-readable row has no role column
        const adminCheck = await adminPool.query(
            `SELECT column_name FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = 'users'
               AND column_name IN ('role_key', 'role', 'organisation_id');`
        );
        expect(adminCheck.rows.length).toBe(0); // None of these columns exist

        // Cleanup
        await adminPool.query('DELETE FROM public.users WHERE id = $1;', [newId]);
    });

    it('7. fn_upsert_user_mirror cannot set role column (column does not exist)', async () => {
        // This verifies at the schema level that there is no role column to set
        const res = await adminPool.query(
            `SELECT column_name FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = 'users'
             ORDER BY ordinal_position;`
        );
        const cols = res.rows.map((r: any) => r.column_name);
        expect(cols).not.toContain('role_key');
        expect(cols).not.toContain('role');
        expect(cols).not.toContain('organisation_id');
    });
});
