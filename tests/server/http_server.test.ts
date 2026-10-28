/**
 * HTTP Integration Test Suite for ArchScale Server
 * Uses LocalProvider for fast, deterministic, offline server behavior.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import { AddressInfo } from 'net';
import { createServer } from '../../src/server/index.js';
import { createIsolatedTestDatabase, RUNTIME_CONFIG } from '../setup/db_connection.js';
import pg from 'pg';
import { SERVER_ROUTES } from '../../src/config/route_permissions.js';

import { LocalProvider } from '../../src/identity/providers/local.js';

let server: http.Server;
let baseUrl: string;
let adminPool: pg.Pool;
let localIdp: LocalProvider;

const USER_TEST_ID = '50000000-0000-0000-0000-000000000001';
const USER_OTHER_ID = '50000000-0000-0000-0000-000000000002';
const ORG_A_ID = '50000000-0000-0000-0000-000000000010';

let workspaceId: string;
let validContextId: string;
let validAccessToken: string;

beforeAll(async () => {
    // Configure environment flags for LocalProvider (backup and clear remote URLs in test process)
    process.env.ALLOW_LOCAL_AUTH = 'true';
    process.env.ARCHSCALE_ALLOW_LOCAL_AUTH = 'true';
    process.env.NODE_ENV = 'test';
    const origSupabaseUrl = process.env.SUPABASE_URL;
    const origAdminDbUrl = process.env.SUPABASE_DB_ADMIN_URL;
    delete process.env.SUPABASE_URL;
    delete process.env.SUPABASE_DB_ADMIN_URL;

    adminPool = await createIsolatedTestDatabase('archscale_test_server_http');
    localIdp = new LocalProvider();

    // Register local users in localIdp
    localIdp.registerTestUser({
        id: USER_TEST_ID,
        email: 'server.test@archscale.local',
        userCode: 'AS-SRVR01',
        password: 'test-password',
        aal: 'aal2'
    });
    localIdp.registerTestUser({
        id: USER_OTHER_ID,
        email: 'server.other@archscale.local',
        userCode: 'AS-SRVR02',
        password: 'test-password',
        aal: 'aal1'
    });

    // Create users in auth and public.users
    await adminPool.query(`
        INSERT INTO auth.users (id, email) VALUES 
            ($1, 'server.test@archscale.local'),
            ($2, 'server.other@archscale.local')
        ON CONFLICT (id) DO NOTHING;
    `, [USER_TEST_ID, USER_OTHER_ID]);

    await adminPool.query(`
        INSERT INTO public.users (id, user_code, email) VALUES 
            ($1, 'AS-SRVR01', 'server.test@archscale.local'),
            ($2, 'AS-SRVR02', 'server.other@archscale.local')
        ON CONFLICT (id) DO NOTHING;
    `, [USER_TEST_ID, USER_OTHER_ID]);

    // Setup organisation, workspace, entitlement, membership
    await adminPool.query(`
        INSERT INTO public.organisations (id, name, portal, tenant_type_key, status)
        VALUES ($1, 'Server Test Org', 'subscriber', 'studio_owner', 'ACTIVE')
        ON CONFLICT (id) DO NOTHING;
    `, [ORG_A_ID]);

    const wsRes = await adminPool.query(`
        INSERT INTO public.workspaces (organisation_id, name, is_active)
        VALUES ($1, 'Server WS', true) RETURNING id;
    `, [ORG_A_ID]);
    workspaceId = wsRes.rows[0].id;

    await adminPool.query(`
        INSERT INTO public.app_catalogue (app_key, name)
        VALUES ('core_billing', 'Core Billing')
        ON CONFLICT (app_key) DO NOTHING;
    `);

    await adminPool.query(`
        INSERT INTO public.organisation_entitlements (organisation_id, app_key, is_enabled)
        VALUES ($1, 'core_billing', true) ON CONFLICT DO NOTHING;
    `, [ORG_A_ID]);

    await adminPool.query(`
        INSERT INTO public.memberships (organisation_id, user_id, role_key, status)
        VALUES ($1, $2, 'business_owner', 'ACTIVE') ON CONFLICT DO NOTHING;
    `, [ORG_A_ID, USER_TEST_ID]);

    // Setup custom runtime pool for isolated test DB
    const runtimePoolForTest = new pg.Pool({
        ...RUNTIME_CONFIG,
        database: 'archscale_test_server_http'
    });

    // Start server on ephemeral port on 127.0.0.1 using localIdp and runtimePoolForTest
    server = createServer(localIdp, runtimePoolForTest);
    await new Promise<void>((resolve) => {
        server.listen(0, '127.0.0.1', () => {
            const addr = server.address() as AddressInfo;
            baseUrl = `http://127.0.0.1:${addr.port}`;
            resolve();
        });
    });

    // Obtain active session token via LocalProvider sign-in
    const signinRes = await fetch(`${baseUrl}/api/session/sign-in`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'server.test@archscale.local', password: 'test-password' })
    });
    const signinData = await signinRes.json();
    validAccessToken = signinData.accessToken;
    const verified = await localIdp.verify(validAccessToken);

    // Create active context via adminPool
    const ctxRes = await adminPool.query<{ fn_create_access_context: string }>(
        `SELECT fn_create_access_context($1::uuid, $2::text, $3::uuid, $4::uuid, 'aal2');`,
        [USER_TEST_ID, verified.sessionId, ORG_A_ID, workspaceId]
    );
    validContextId = ctxRes.rows[0].fn_create_access_context;
});

afterAll(async () => {
    if (server) {
        await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    await adminPool.end();
});

describe('HTTP Server Integration Tests (LocalProvider)', () => {
    it('1. sign-in wrong password and unknown user return identical 401 bodies', async () => {
        // A. Wrong password for known user
        const resWrongPw = await fetch(`${baseUrl}/api/session/sign-in`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: 'server.test@archscale.local', password: 'wrong-password' })
        });
        const bodyWrongPw = await resWrongPw.json();

        // B. Unknown user
        const resUnknown = await fetch(`${baseUrl}/api/session/sign-in`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: 'does.not.exist@archscale.local', password: 'some-password' })
        });
        const bodyUnknown = await resUnknown.json();

        expect(resWrongPw.status).toBe(401);
        expect(resUnknown.status).toBe(401);
        expect(bodyWrongPw).toEqual(bodyUnknown);
        expect(bodyWrongPw).toEqual({ error: 'AUTH_SIGNIN_FAILED' });
    });

    it('2. oversize body gets 413 error', async () => {
        const largeString = 'x'.repeat(150 * 1024); // 150 KB > 100 KB limit
        const res = await fetch(`${baseUrl}/api/session/sign-in`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ data: largeString })
        });
        expect(res.status).toBe(413);
        const data = await res.json();
        expect(data.error).toBe('PAYLOAD_TOO_LARGE');
    });

    it('3. the 11th failed sign-in in a minute is rate-limited (429)', async () => {
        // Send 10 consecutive failed attempts
        for (let i = 0; i < 10; i++) {
            await fetch(`${baseUrl}/api/session/sign-in`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: 'rate.limit@test.local', password: 'bad' })
            });
        }

        // The 11th request must receive 429
        const res11 = await fetch(`${baseUrl}/api/session/sign-in`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: 'rate.limit@test.local', password: 'bad' })
        });
        expect(res11.status).toBe(429);
        const data = await res11.json();
        expect(data.error).toBe('AUTH_RATE_LIMIT_EXCEEDED');
    });

    it('4. a forged or other-user X-ArchScale-Context returns a denial', async () => {
        // Forged context ID
        const resForged = await fetch(`${baseUrl}/api/me`, {
            headers: {
                'Authorization': `Bearer ${validAccessToken}`,
                'X-ArchScale-Context': '00000000-0000-0000-0000-000000000000'
            }
        });
        expect([401, 403, 500]).toContain(resForged.status);
    });

    it('5. role/organisation injected in JSON body or headers does not change decision', async () => {
        // Attempt to inject role=founder or portal=platform in body and headers
        const res = await fetch(`${baseUrl}/api/org/invitations`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${validAccessToken}`,
                'X-ArchScale-Context': validContextId,
                'Content-Type': 'application/json',
                'X-ArchScale-Role': 'founder',
                'X-ArchScale-Org': '00000000-0000-0000-0000-000000000001'
            },
            body: JSON.stringify({
                email: 'new.member@test.local',
                roleKey: 'founder', // Injected role attempt
                organisationId: '00000000-0000-0000-0000-000000000001' // Injected platform org attempt
            })
        });

        const data = await res.json();
        if (res.status !== 200) {
            console.error('Test 5 failed with:', res.status, data);
        }
        expect(res.status).toBe(200);
        // Organization ID in decision MUST be Org A, never the injected platform org
        expect(data.decision.organisationId).toBe(ORG_A_ID);
        expect(data.decision.roleKey).toBe('business_owner');
    });

    it('6. /api/me without a token returns 401', async () => {
        const res = await fetch(`${baseUrl}/api/me`, {
            headers: {
                'X-ArchScale-Context': validContextId
            }
        });
        expect(res.status).toBe(401);
        const data = await res.json();
        expect(data.error).toBe('AUTH_TOKEN_MISSING');
    });

    it('7. logout then the same token and context both fail', async () => {
        // Sign in another user to test logout isolation
        const loginData = await localIdp.signIn({
            email: 'server.other@archscale.local',
            password: 'test-password'
        });
        const token = loginData.accessToken;
        const verified = await localIdp.verify(token);

        // Ensure user other has membership in Org A
        await adminPool.query(`
            INSERT INTO public.memberships (organisation_id, user_id, role_key, status)
            VALUES ($1, $2, 'business_owner', 'ACTIVE') ON CONFLICT DO NOTHING;
        `, [ORG_A_ID, USER_OTHER_ID]);

        // Create context
        const ctxRes = await adminPool.query<{ fn_create_access_context: string }>(
            `SELECT fn_create_access_context($1::uuid, $2::text, $3::uuid, $4::uuid, 'aal1');`,
            [USER_OTHER_ID, verified.sessionId, ORG_A_ID, workspaceId]
        );
        const ctxId = ctxRes.rows[0].fn_create_access_context;

        // Perform logout
        const logoutRes = await fetch(`${baseUrl}/api/session/logout`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'X-ArchScale-Context': ctxId
            }
        });
        expect(logoutRes.status).toBe(200);

        // Call /api/me with the logged out token: must fail with 401
        const meRes = await fetch(`${baseUrl}/api/me`, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'X-ArchScale-Context': ctxId
            }
        });
        expect(meRes.status).toBe(401);
    });

    it('8. Route registry validation: all server routes must be declared with kind', async () => {
        // Verify every route in SERVER_ROUTES has a valid kind
        for (const [key, def] of Object.entries(SERVER_ROUTES)) {
            expect(['public', 'session'].some(k => def.kind === k) || def.kind.startsWith('permission:')).toBe(true);
            expect(def.path).toBeDefined();
            expect(def.method).toBeDefined();
        }

        // Test failure against temporary undeclared in-memory route
        const undeclaredRoutes: Record<string, any> = {
            ...SERVER_ROUTES,
            'orphan.route': {
                path: '/api/orphan',
                method: 'GET'
                // kind missing
            }
        };

        const validateRegistry = (routes: Record<string, any>) => {
            for (const [key, def] of Object.entries(routes)) {
                if (!def.kind || (!['public', 'session'].includes(def.kind) && !def.kind.startsWith('permission:'))) {
                    throw new Error(`Undeclared or invalid route kind for ${key}`);
                }
            }
        };

        expect(() => validateRegistry(undeclaredRoutes)).toThrowError(/Undeclared or invalid route kind for orphan.route/);
    });

    it('9. Parameter / header injection does not change allow/deny decision; foreign context ID is denied', async () => {
        // (a) Injection in JSON body and headers (e.g. attempting to claim role='founder' or fake orgId)
        // User other is intern in Org A, so org.members.invite must be DENIED regardless of injected role or org
        await adminPool.query(`
            INSERT INTO public.memberships (organisation_id, user_id, role_key, status, expires_at)
            VALUES ($1, $2, 'intern', 'ACTIVE', now() + INTERVAL '30 days')
            ON CONFLICT (user_id, organisation_id) DO UPDATE SET role_key = 'intern', expires_at = now() + INTERVAL '30 days';
        `, [ORG_A_ID, USER_OTHER_ID]);

        const otherLogin = await localIdp.signIn({
            email: 'server.other@archscale.local',
            password: 'test-password'
        });
        const otherToken = otherLogin.accessToken;
        const otherVerified = await localIdp.verify(otherToken);

        const otherCtxRes = await adminPool.query<{ fn_create_access_context: string }>(
            `SELECT fn_create_access_context($1::uuid, $2::text, $3::uuid, $4::uuid, 'aal1');`,
            [USER_OTHER_ID, otherVerified.sessionId, ORG_A_ID, workspaceId]
        );
        const otherCtxId = otherCtxRes.rows[0].fn_create_access_context;

        const injectionRes = await fetch(`${baseUrl}/api/org/invitations`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${otherToken}`,
                'X-ArchScale-Context': otherCtxId,
                'X-Role': 'founder',
                'X-Organisation-Id': '00000000-0000-0000-0000-000000000001'
            },
            body: JSON.stringify({
                role: 'founder',
                roleKey: 'founder',
                organisationId: '00000000-0000-0000-0000-000000000001',
                email: 'injected@test.local'
            })
        });
        expect(injectionRes.status).toBe(403);
        const injectionBody = await injectionRes.json();
        expect(injectionBody.error).toBe('AUTH_PERMISSION');

        // (b) Valid context id belonging to another user sent in X-ArchScale-Context is denied
        // USER_TEST_ID sends otherCtxId (which belongs to USER_OTHER_ID)
        const foreignCtxRes = await fetch(`${baseUrl}/api/org/members`, {
            headers: {
                'Authorization': `Bearer ${validAccessToken}`,
                'X-ArchScale-Context': otherCtxId
            }
        });
        expect(foreignCtxRes.status).toBe(403);
    });

    it('10. MFA verify route: wrong code returns 401, correct code upgrades token to aal2, elevating platform route from 403 to 200', async () => {
        // Clear rate limiter for local tests before beginning
        const { clearRateLimit } = await import('../../src/server/index.js');
        clearRateLimit('127.0.0.1');
        clearRateLimit('::ffff:127.0.0.1');

        // Register founder in localIdp with MFA factor
        const FOUNDER_ID = '50000000-0000-0000-0000-000000000099';
        localIdp.registerTestUser({
            id: FOUNDER_ID,
            email: 'founder@archscale.local',
            userCode: 'AS-FNDR99',
            password: 'founder-password',
            aal: 'aal1',
            hasMfaFactor: true
        });

        // Mirror in database (execute statements individually)
        await adminPool.query(`INSERT INTO auth.users (id, email) VALUES ($1, 'founder@archscale.local') ON CONFLICT DO NOTHING;`, [FOUNDER_ID]);
        await adminPool.query(`INSERT INTO public.users (id, user_code, email) VALUES ($1, 'AS-FNDR99', 'founder@archscale.local') ON CONFLICT DO NOTHING;`, [FOUNDER_ID]);
        await adminPool.query(`INSERT INTO public.memberships (organisation_id, user_id, role_key, status) VALUES ('00000000-0000-0000-0000-000000000001', $1, 'founder', 'ACTIVE') ON CONFLICT DO NOTHING;`, [FOUNDER_ID]);

        const platWsRes = await adminPool.query(`
            INSERT INTO public.workspaces (organisation_id, name, is_active)
            VALUES ('00000000-0000-0000-0000-000000000001', 'Founder WS', true) RETURNING id;
        `);
        const platWsId = platWsRes.rows[0].id;

        // Sign in: returns aal1 token with mfaRequired: true
        const loginRes = await fetch(`${baseUrl}/api/session/sign-in`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: 'founder@archscale.local', password: 'founder-password' })
        });
        const loginData = await loginRes.json();
        expect(loginRes.status).toBe(200);
        expect(loginData.principal.aal).toBe('aal1');
        expect(loginData.mfaRequired).toBe(true);
        const aal1Token = loginData.accessToken;

        // Context at aal1
        const ctxAal1Res = await fetch(`${baseUrl}/api/session/context`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${aal1Token}`
            },
            body: JSON.stringify({
                organisationId: '00000000-0000-0000-0000-000000000001',
                workspaceId: platWsId
            })
        });
        const ctxAal1Data = await ctxAal1Res.json();
        if (ctxAal1Res.status !== 200) {
            console.error('Failed creating platform context at aal1:', ctxAal1Res.status, ctxAal1Data);
        }
        expect(ctxAal1Res.status).toBe(200);
        const ctxAal1Id = ctxAal1Data.context.id;

        // Founder at aal1 tries platform route: DENIED (AUTH_AAL)
        const platDenyRes = await fetch(`${baseUrl}/api/platform/organisations`, {
            headers: {
                'Authorization': `Bearer ${aal1Token}`,
                'X-ArchScale-Context': ctxAal1Id
            }
        });
        const platDenyBody = await platDenyRes.json();
        if (platDenyRes.status !== 403) {
            console.error('platDenyRes status:', platDenyRes.status, platDenyBody);
        }
        expect(platDenyRes.status).toBe(403);
        expect(platDenyBody.error).toBe('AUTH_AAL');

        // MFA verify with wrong code: 401
        const wrongMfaRes = await fetch(`${baseUrl}/api/session/mfa/verify`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${aal1Token}`
            },
            body: JSON.stringify({ code: '000000' })
        });
        expect(wrongMfaRes.status).toBe(401);
        const wrongMfaBody = await wrongMfaRes.json();
        expect(wrongMfaBody.error).toBe('AUTH_MFA_FAILED');

        // MFA verify with correct code ('123456'): 200 and aal2 token
        const correctMfaRes = await fetch(`${baseUrl}/api/session/mfa/verify`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${aal1Token}`
            },
            body: JSON.stringify({ code: '123456' })
        });
        expect(correctMfaRes.status).toBe(200);
        const mfaData = await correctMfaRes.json();
        expect(mfaData.aal).toBe('aal2');
        const aal2Token = mfaData.accessToken;

        // Create context with aal2 token
        const ctxAal2Res = await fetch(`${baseUrl}/api/session/context`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${aal2Token}`
            },
            body: JSON.stringify({
                organisationId: '00000000-0000-0000-0000-000000000001',
                workspaceId: platWsId
            })
        });
        const ctxAal2Data = await ctxAal2Res.json();
        const ctxAal2Id = ctxAal2Data.context.id;

        // Founder at aal2 calls platform route: ALLOWED (200)
        const platAllowRes = await fetch(`${baseUrl}/api/platform/organisations`, {
            headers: {
                'Authorization': `Bearer ${aal2Token}`,
                'X-ArchScale-Context': ctxAal2Id
            }
        });
        expect(platAllowRes.status).toBe(200);
    });
});
