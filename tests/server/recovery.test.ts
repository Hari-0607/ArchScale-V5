/**
 * Password Recovery & Session Invalidation Integration Tests (A4)
 * Verifies identical responses, timing floor, database-backed rate limiting,
 * and complete session/context revocation upon password reset.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import { AddressInfo } from 'net';
import pg from 'pg';
import { createServer } from '../../src/server/index.js';
import { createIsolatedTestDatabase } from '../setup/db_connection.js';
import { LocalProvider } from '../../src/identity/providers/local.js';

let server: http.Server;
let baseUrl: string;
let adminPool: pg.Pool;
let localIdp: LocalProvider;

const USER_TEST_ID = '70000000-0000-0000-0000-000000000001';
const KNOWN_EMAIL = 'known.user@recovery.local';
const UNKNOWN_EMAIL = 'nobody@recovery.local';

beforeAll(async () => {
    process.env.ALLOW_LOCAL_AUTH = 'true';
    process.env.ARCHSCALE_ALLOW_LOCAL_AUTH = 'true';
    process.env.NODE_ENV = 'test';
    delete process.env.SUPABASE_URL;
    delete process.env.SUPABASE_DB_ADMIN_URL;

    adminPool = await createIsolatedTestDatabase('archscale_test_recovery');
    localIdp = new LocalProvider();

    localIdp.registerTestUser({
        id: USER_TEST_ID,
        email: KNOWN_EMAIL,
        userCode: 'AS-RCV01',
        password: 'initial-password',
        aal: 'aal1'
    });

    await adminPool.query(`INSERT INTO auth.users (id, email) VALUES ($1, $2) ON CONFLICT DO NOTHING;`, [USER_TEST_ID, KNOWN_EMAIL]);
    await adminPool.query(`INSERT INTO public.users (id, user_code, email) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING;`, [USER_TEST_ID, 'AS-RCV01', KNOWN_EMAIL]);

    server = createServer(localIdp, adminPool);
    await new Promise<void>((resolve) => {
        server.listen(0, '127.0.0.1', () => {
            const addr = server.address() as AddressInfo;
            baseUrl = `http://127.0.0.1:${addr.port}`;
            resolve();
        });
    });
});

afterAll(async () => {
    if (server) await new Promise<void>((res) => server.close(() => res()));
    if (adminPool) await adminPool.end();
});

describe('A4 Account Flows & Password Recovery', () => {
    it('1. known and unknown addresses return identical response body and status code (200)', async () => {
        const startKnown = Date.now();
        const resKnown = await fetch(`${baseUrl}/api/session/recovery`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: KNOWN_EMAIL })
        });
        const elapsedKnown = Date.now() - startKnown;

        const startUnknown = Date.now();
        const resUnknown = await fetch(`${baseUrl}/api/session/recovery`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: UNKNOWN_EMAIL })
        });
        const elapsedUnknown = Date.now() - startUnknown;

        expect(resKnown.status).toBe(200);
        expect(resUnknown.status).toBe(200);

        const dataKnown = await resKnown.json();
        const dataUnknown = await resUnknown.json();

        expect(dataKnown).toEqual({ message: 'If the address is registered, a recovery link has been sent' });
        expect(dataUnknown).toEqual({ message: 'If the address is registered, a recovery link has been sent' });

        // Timing floor verification (approx 1000ms floor applied)
        expect(elapsedKnown).toBeGreaterThanOrEqual(900);
        expect(elapsedUnknown).toBeGreaterThanOrEqual(900);
    });

    it('2. rate limiting per IP and address via fn_rate_limit_hit(..., recovery)', async () => {
        const testEmail = 'spam.target@recovery.local';
        // Make repeated recovery requests until rate limit triggered (429)
        let rateLimited = false;
        for (let i = 0; i < 7; i++) {
            const res = await fetch(`${baseUrl}/api/session/recovery`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': '192.168.10.50' },
                body: JSON.stringify({ email: testEmail })
            });
            if (res.status === 429) {
                rateLimited = true;
                const err = await res.json();
                expect(err.error).toBe('AUTH_RATE_LIMIT_EXCEEDED');
                break;
            }
        }
        expect(rateLimited).toBe(true);
    });

    it('3. password reset revokes every session and context of that user (B0.6 item 6)', async () => {
        // Set up organisation, workspace and membership for KNOWN_EMAIL / USER_TEST_ID
        const ORG_ID = '70000000-0000-0000-0000-000000000010';
        await adminPool.query(`
            INSERT INTO public.organisations (id, name, portal, tenant_type_key, status)
            VALUES ($1, 'Recovery Test Org', 'subscriber', 'studio_owner', 'ACTIVE')
            ON CONFLICT DO NOTHING;
        `, [ORG_ID]);

        const wsRes = await adminPool.query(`
            INSERT INTO public.workspaces (organisation_id, name, is_active)
            VALUES ($1, 'Recovery WS', true) RETURNING id;
        `, [ORG_ID]);
        const wsId = wsRes.rows[0].id;

        await adminPool.query(`
            INSERT INTO public.memberships (user_id, organisation_id, role_key, status)
            VALUES ($1, $2, 'leader', 'ACTIVE')
            ON CONFLICT DO NOTHING;
        `, [USER_TEST_ID, ORG_ID]);

        // Sign in with initial password
        const initialLogin = await localIdp.signIn({ email: KNOWN_EMAIL, password: 'initial-password' });
        const oldToken = initialLogin.accessToken;

        const ctxRes = await adminPool.query(`
            SELECT fn_create_access_context($1::uuid, $2, $3::uuid, $4::uuid, 'aal1');
        `, [USER_TEST_ID, initialLogin.principal.sessionId, ORG_ID, wsId]);
        const oldContextId = ctxRes.rows[0].fn_create_access_context;

        // Verify valid access
        const preCheck = await fetch(`${baseUrl}/api/me`, {
            headers: {
                'Authorization': `Bearer ${oldToken}`,
                'X-ArchScale-Context': oldContextId
            }
        });
        expect(preCheck.status).toBe(200);

        // Perform password reset
        const resetRes = await fetch(`${baseUrl}/api/session/reset-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email: KNOWN_EMAIL,
                newPassword: 'brand-new-password-2026'
            })
        });
        expect(resetRes.status).toBe(200);

        // Old token is rejected (session revoked)
        const oldTokenCheck = await fetch(`${baseUrl}/api/me`, {
            headers: {
                'Authorization': `Bearer ${oldToken}`,
                'X-ArchScale-Context': oldContextId
            }
        });
        expect(oldTokenCheck.status).toBe(401);

        // Context is revoked in DB
        const dbCtxCheck = await adminPool.query(`
            SELECT revoked_at FROM public.access_contexts WHERE id = $1::uuid;
        `, [oldContextId]);
        expect(dbCtxCheck.rows[0].revoked_at).not.toBeNull();

        // Old password no longer works
        await expect(localIdp.signIn({ email: KNOWN_EMAIL, password: 'initial-password' })).rejects.toThrow();

        // New password works
        const newLogin = await localIdp.signIn({ email: KNOWN_EMAIL, password: 'brand-new-password-2026' });
        expect(newLogin.accessToken).toBeDefined();
    });
});

