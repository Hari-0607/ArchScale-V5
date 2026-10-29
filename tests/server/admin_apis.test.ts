/**
 * Admin APIs Integration Tests (A5 & A6)
 * Tests Frontstage tenant administration, Backstage platform administration,
 * session lifecycle management, and A6 verification security boundaries.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import { AddressInfo } from 'net';
import pg from 'pg';
import { createServer } from '../../src/server/index.js';
import { createIsolatedTestDatabase } from '../setup/db_connection.js';
import { LocalProvider } from '../../src/identity/providers/local.js';
import { SERVER_ROUTES } from '../../src/config/route_permissions.js';

let server: http.Server;
let baseUrl: string;
let adminPool: pg.Pool;
let localIdp: LocalProvider;

const USER_FOUNDER_ID = '80000000-0000-0000-0000-000000000001';
const USER_OWNER_ID   = '80000000-0000-0000-0000-000000000002';
const USER_MEMBER_ID  = '80000000-0000-0000-0000-000000000003';
const USER_STAFF_ID   = '80000000-0000-0000-0000-000000000004';

const PLATFORM_ORG_ID = '00000000-0000-0000-0000-000000000001';
const SUB_ORG_ID      = '80000000-0000-0000-0000-000000000010';

let workspaceSubId: string;
let workspacePlatId: string;

let founderToken: string;
let founderContextId: string;

let ownerToken: string;
let ownerContextId: string;

let memberToken: string;
let memberContextId: string;
let memberMembershipId: string;

let staffToken: string;
let staffSupportGrantId: string;
let staffSupportContextId: string;

beforeAll(async () => {
    process.env.ALLOW_LOCAL_AUTH = 'true';
    process.env.ARCHSCALE_ALLOW_LOCAL_AUTH = 'true';
    process.env.NODE_ENV = 'test';
    delete process.env.SUPABASE_URL;
    delete process.env.SUPABASE_DB_ADMIN_URL;

    adminPool = await createIsolatedTestDatabase('archscale_test_admin_apis');
    localIdp = new LocalProvider();

    // Register users
    const testUsers = [
        { id: USER_FOUNDER_ID, email: 'founder@platform.local', userCode: 'AS-FND01', aal: 'aal2' as const },
        { id: USER_OWNER_ID, email: 'owner@tenant.local', userCode: 'AS-OWN01', aal: 'aal2' as const },
        { id: USER_MEMBER_ID, email: 'member@tenant.local', userCode: 'AS-MBR01', aal: 'aal1' as const },
        { id: USER_STAFF_ID, email: 'staff@platform.local', userCode: 'AS-STF01', aal: 'aal2' as const }
    ];

    for (const u of testUsers) {
        localIdp.registerTestUser({ ...u, password: 'test-password' });
        await adminPool.query(`INSERT INTO auth.users (id, email) VALUES ($1, $2) ON CONFLICT DO NOTHING;`, [u.id, u.email]);
        await adminPool.query(`INSERT INTO public.users (id, user_code, email) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING;`, [u.id, u.userCode, u.email]);
    }

    // Platform workspace
    const platWs = await adminPool.query(`
        INSERT INTO public.workspaces (organisation_id, name, is_active)
        VALUES ($1, 'Platform Admin WS', true) RETURNING id;
    `, [PLATFORM_ORG_ID]);
    workspacePlatId = platWs.rows[0].id;

    // Subscriber org & workspace
    await adminPool.query(`
        INSERT INTO public.organisations (id, name, portal, tenant_type_key, status, member_min_aal)
        VALUES ($1, 'Tenant Alpha Org', 'subscriber', 'studio_owner', 'ACTIVE', 'aal1')
        ON CONFLICT DO NOTHING;
    `, [SUB_ORG_ID]);

    const subWs = await adminPool.query(`
        INSERT INTO public.workspaces (organisation_id, name, is_active)
        VALUES ($1, 'Tenant Studio WS', true) RETURNING id;
    `, [SUB_ORG_ID]);
    workspaceSubId = subWs.rows[0].id;

    await adminPool.query(`INSERT INTO public.app_catalogue (app_key, name) VALUES ('app_model', 'Model App') ON CONFLICT DO NOTHING;`);
    await adminPool.query(`INSERT INTO public.organisation_entitlements (organisation_id, app_key, is_enabled) VALUES ($1, 'app_model', true) ON CONFLICT DO NOTHING;`, [SUB_ORG_ID]);

    // Memberships
    await adminPool.query(`
        INSERT INTO public.memberships (user_id, organisation_id, role_key, status)
        VALUES ($1, $2, 'founder', 'ACTIVE');
    `, [USER_FOUNDER_ID, PLATFORM_ORG_ID]);

    const mStaff = await adminPool.query(`
        INSERT INTO public.memberships (user_id, organisation_id, role_key, status)
        VALUES ($1, $2, 'client_servicing', 'ACTIVE') RETURNING id;
    `, [USER_STAFF_ID, PLATFORM_ORG_ID]);
    const staffMembershipId = mStaff.rows[0].id;

    await adminPool.query(`
        INSERT INTO public.memberships (user_id, organisation_id, role_key, status, is_primary_owner)
        VALUES ($1, $2, 'business_owner', 'ACTIVE', true);
    `, [USER_OWNER_ID, SUB_ORG_ID]);

    const mMbr = await adminPool.query(`
        INSERT INTO public.memberships (user_id, organisation_id, role_key, status)
        VALUES ($1, $2, 'executive', 'ACTIVE') RETURNING id;
    `, [USER_MEMBER_ID, SUB_ORG_ID]);
    memberMembershipId = mMbr.rows[0].id;

    // Support grant for staff
    const grantRes = await adminPool.query(`
        INSERT INTO public.support_access_grants (staff_membership_id, target_organisation_id, reason, expires_at)
        VALUES ($1, $2, 'Assisting tenant onboard', now() + interval '4 hours') RETURNING id;
    `, [staffMembershipId, SUB_ORG_ID]);
    staffSupportGrantId = grantRes.rows[0].id;

    // Sign in and create contexts
    const founderLogin = await localIdp.signIn({ email: 'founder@platform.local', password: 'test-password' });
    founderToken = founderLogin.accessToken;
    const fCtx = await adminPool.query(`SELECT fn_create_access_context($1::uuid, $2, $3::uuid, $4::uuid, 'aal2');`,
        [USER_FOUNDER_ID, founderLogin.principal.sessionId, PLATFORM_ORG_ID, workspacePlatId]);
    founderContextId = fCtx.rows[0].fn_create_access_context;

    const ownerLogin = await localIdp.signIn({ email: 'owner@tenant.local', password: 'test-password' });
    ownerToken = ownerLogin.accessToken;
    const oCtx = await adminPool.query(`SELECT fn_create_access_context($1::uuid, $2, $3::uuid, $4::uuid, 'aal2');`,
        [USER_OWNER_ID, ownerLogin.principal.sessionId, SUB_ORG_ID, workspaceSubId]);
    ownerContextId = oCtx.rows[0].fn_create_access_context;

    const memberLogin = await localIdp.signIn({ email: 'member@tenant.local', password: 'test-password' });
    memberToken = memberLogin.accessToken;
    const mCtx = await adminPool.query(`SELECT fn_create_access_context($1::uuid, $2, $3::uuid, $4::uuid, 'aal1');`,
        [USER_MEMBER_ID, memberLogin.principal.sessionId, SUB_ORG_ID, workspaceSubId]);
    memberContextId = mCtx.rows[0].fn_create_access_context;

    const staffLogin = await localIdp.signIn({ email: 'staff@platform.local', password: 'test-password' });
    staffToken = staffLogin.accessToken;
    const sCtx = await adminPool.query(`SELECT fn_create_access_context($1::uuid, $2, $3::uuid, $4::uuid, 'aal2', $5::uuid);`,
        [USER_STAFF_ID, staffLogin.principal.sessionId, SUB_ORG_ID, workspaceSubId, staffSupportGrantId]);
    staffSupportContextId = sCtx.rows[0].fn_create_access_context;

    // Start server
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

describe('Frontstage Tenant Administration APIs (A5)', () => {
    it('1. GET /api/org/members returns member list via fn_list_org_members', async () => {
        const res = await fetch(`${baseUrl}/api/org/members`, {
            headers: {
                'Authorization': `Bearer ${ownerToken}`,
                'X-ArchScale-Context': ownerContextId
            }
        });
        expect(res.status).toBe(200);
        const data = await res.json();
        expect(data.data).toBeInstanceOf(Array);
        expect(data.data.length).toBeGreaterThanOrEqual(2);
    });

    it('2. PATCH /api/org/members/:id/role updates member role within level ceiling', async () => {
        const res = await fetch(`${baseUrl}/api/org/members/${memberMembershipId}/role`, {
            method: 'PATCH',
            headers: {
                'Authorization': `Bearer ${ownerToken}`,
                'X-ArchScale-Context': ownerContextId,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ roleKey: 'manager_coordinator' })
        });
        expect(res.status).toBe(200);

        const check = await adminPool.query(`SELECT role_key FROM public.memberships WHERE id = $1;`, [memberMembershipId]);
        expect(check.rows[0].role_key).toBe('manager_coordinator');
    });

    it('3. POST /api/org/members/:id/suspend suspends member and invalidates active context', async () => {
        const res = await fetch(`${baseUrl}/api/org/members/${memberMembershipId}/suspend`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${ownerToken}`,
                'X-ArchScale-Context': ownerContextId,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ reason: 'Temporary suspension' })
        });
        expect(res.status).toBe(200);

        // Member membership is SUSPENDED
        const check = await adminPool.query(`SELECT status FROM public.memberships WHERE id = $1;`, [memberMembershipId]);
        expect(check.rows[0].status).toBe('SUSPENDED');

        // Member cannot access authenticated endpoints with previous context
        const reqAfter = await fetch(`${baseUrl}/api/me`, {
            headers: {
                'Authorization': `Bearer ${memberToken}`,
                'X-ArchScale-Context': memberContextId
            }
        });
        expect([401, 403]).toContain(reqAfter.status);
    });

    it('4. POST /api/org/members/:id/reactivate reactivates member', async () => {
        const res = await fetch(`${baseUrl}/api/org/members/${memberMembershipId}/reactivate`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${ownerToken}`,
                'X-ArchScale-Context': ownerContextId,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ reason: 'Suspension lifted' })
        });
        expect(res.status).toBe(200);

        const check = await adminPool.query(`SELECT status FROM public.memberships WHERE id = $1;`, [memberMembershipId]);
        expect(check.rows[0].status).toBe('ACTIVE');
    });

    it('5. POST /api/org/settings/mfa modifies tenant MFA requirement', async () => {
        const res = await fetch(`${baseUrl}/api/org/settings/mfa`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${ownerToken}`,
                'X-ArchScale-Context': ownerContextId,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ memberMinAal: 'aal2' })
        });
        expect(res.status).toBe(200);

        const check = await adminPool.query(`SELECT member_min_aal FROM public.organisations WHERE id = $1;`, [SUB_ORG_ID]);
        expect(check.rows[0].member_min_aal).toBe('aal2');
    });
});

describe('Backstage Platform Administration APIs (A5)', () => {
    it('6. GET /api/platform/organisations returns platform tenant list', async () => {
        const res = await fetch(`${baseUrl}/api/platform/organisations`, {
            headers: {
                'Authorization': `Bearer ${founderToken}`,
                'X-ArchScale-Context': founderContextId
            }
        });
        expect(res.status).toBe(200);
        const data = await res.json();
        expect(data.data).toBeInstanceOf(Array);
        expect(data.data.length).toBeGreaterThanOrEqual(1);
    });

    it('7. POST /api/platform/organisations creates a new pending subscriber org', async () => {
        const res = await fetch(`${baseUrl}/api/platform/organisations`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${founderToken}`,
                'X-ArchScale-Context': founderContextId,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name: 'Brand New Studio',
                tenantTypeKey: 'studio_owner'
            })
        });
        expect(res.status).toBe(200);
        const data = await res.json();
        expect(data.organisationId).toBeDefined();

        const check = await adminPool.query(`SELECT status FROM public.organisations WHERE id = $1;`, [data.organisationId]);
        expect(check.rows[0].status).toBe('APPLIED');
    });

    it('8. POST /api/platform/support/grants and revoke grant', async () => {
        // Create support grant
        const createRes = await fetch(`${baseUrl}/api/platform/support/grants`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${founderToken}`,
                'X-ArchScale-Context': founderContextId,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                targetOrganisationId: SUB_ORG_ID,
                reason: 'Diagnostic grant',
                hours: 6
            })
        });
        expect(createRes.status).toBe(200);
        const { grantId } = await createRes.json();
        expect(grantId).toBeDefined();

        // Revoke grant
        const revokeRes = await fetch(`${baseUrl}/api/platform/support/grants/${grantId}/revoke`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${founderToken}`,
                'X-ArchScale-Context': founderContextId
            }
        });
        expect(revokeRes.status).toBe(200);

        const check = await adminPool.query(`SELECT revoked_at FROM public.support_access_grants WHERE id = $1;`, [grantId]);
        expect(check.rows[0].revoked_at).not.toBeNull();
    });

    it('9. GET /api/platform/audit reads system audit trail', async () => {
        const res = await fetch(`${baseUrl}/api/platform/audit`, {
            headers: {
                'Authorization': `Bearer ${founderToken}`,
                'X-ArchScale-Context': founderContextId
            }
        });
        expect(res.status).toBe(200);
        const data = await res.json();
        expect(data.auditLogs).toBeInstanceOf(Array);
        expect(data.auditLogs.length).toBeGreaterThan(0);
    });
});

describe('Session Lifecycle Management (A5)', () => {
    it('10. GET /api/me/sessions lists active user sessions', async () => {
        const res = await fetch(`${baseUrl}/api/me/sessions`, {
            headers: { 'Authorization': `Bearer ${ownerToken}` }
        });
        expect(res.status).toBe(200);
        const data = await res.json();
        expect(data.sessions).toBeInstanceOf(Array);
    });

    it('11. DELETE /api/me/sessions revokes all sessions and contexts', async () => {
        const res = await fetch(`${baseUrl}/api/me/sessions`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${ownerToken}` }
        });
        expect(res.status).toBe(200);

        // Previous context is invalidated
        const resAfter = await fetch(`${baseUrl}/api/me`, {
            headers: {
                'Authorization': `Bearer ${ownerToken}`,
                'X-ArchScale-Context': ownerContextId
            }
        });
        expect([401, 403]).toContain(resAfter.status);
    });
});

describe('A6 Verification Tests: Boundaries & Invariants', () => {
    it('12. Tenant admin cannot access Backstage platform routes (403 denial)', async () => {
        // Tenant business owner trying to call GET /api/platform/organisations
        const res = await fetch(`${baseUrl}/api/platform/organisations`, {
            headers: {
                'Authorization': `Bearer ${ownerToken}`,
                'X-ArchScale-Context': ownerContextId
            }
        });
        expect([401, 403]).toContain(res.status);
    });

    it('13. Support context cannot write on any new route (Gate 5 AUTH_SUPPORT_READ_ONLY)', async () => {
        const res = await fetch(`${baseUrl}/api/org/settings/mfa`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${staffToken}`,
                'X-ArchScale-Context': staffSupportContextId,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ memberMinAal: 'aal1' })
        });
        expect(res.status).toBe(403);
        const data = await res.json();
        expect(data.error).toBe('AUTH_SUPPORT_READ_ONLY');
    });

    it('14. Every registered route in SERVER_ROUTES has proper configuration', () => {
        for (const [key, def] of Object.entries(SERVER_ROUTES)) {
            expect(def.path).toBeDefined();
            expect(def.method).toBeDefined();
            expect(['public', 'session', `permission:${key}`].some(k => def.kind.startsWith('permission:') || def.kind === 'public' || def.kind === 'session')).toBe(true);
        }
    });
});
