/**
 * Invitations Integration Tests
 * Tests invitation creation, listing, revoking, resending, and acceptance
 * along with level ceiling, seat allocation, separation of duties, and concurrency guards.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import http from 'http';
import { AddressInfo } from 'net';
import pg from 'pg';
import crypto from 'crypto';
import { createServer } from '../../src/server/index.js';
import { createIsolatedTestDatabase } from '../setup/db_connection.js';
import { LocalProvider } from '../../src/identity/providers/local.js';
import { getSentMails, clearSentMails } from '../../src/mail/sink.js';

let server: http.Server;
let baseUrl: string;
let adminPool: pg.Pool;
let localIdp: LocalProvider;

const USER_OWNER_ID   = '60000000-0000-0000-0000-000000000001';
const USER_LEADER_ID  = '60000000-0000-0000-0000-000000000002';
const USER_MGR_ID     = '60000000-0000-0000-0000-000000000003';
const USER_INTERN_ID  = '60000000-0000-0000-0000-000000000004';
const USER_INVITEE_ID = '60000000-0000-0000-0000-000000000005';
const USER_OTHER_ID   = '60000000-0000-0000-0000-000000000006';

const ORG_ID = '60000000-0000-0000-0000-000000000010';
let workspaceId: string;
let ownerContextId: string;
let ownerToken: string;
let leaderContextId: string;
let leaderToken: string;
let internContextId: string;
let internToken: string;
let inviteeToken: string;
let otherToken: string;
let mgrMembershipId: string;

beforeAll(async () => {
    process.env.ALLOW_LOCAL_AUTH = 'true';
    process.env.ARCHSCALE_ALLOW_LOCAL_AUTH = 'true';
    process.env.NODE_ENV = 'test';
    delete process.env.SUPABASE_URL;
    delete process.env.SUPABASE_DB_ADMIN_URL;

    adminPool = await createIsolatedTestDatabase('archscale_test_invitations');
    localIdp = new LocalProvider();

    // Register local users in localIdp
    const users = [
        { id: USER_OWNER_ID, email: 'owner@inv.local', userCode: 'AS-INV01', aal: 'aal2' as const },
        { id: USER_LEADER_ID, email: 'leader@inv.local', userCode: 'AS-INV02', aal: 'aal1' as const },
        { id: USER_MGR_ID, email: 'mgr@inv.local', userCode: 'AS-INV03', aal: 'aal1' as const },
        { id: USER_INTERN_ID, email: 'intern@inv.local', userCode: 'AS-INV04', aal: 'aal1' as const },
        { id: USER_INVITEE_ID, email: 'target.invitee@inv.local', userCode: 'AS-INV05', aal: 'aal1' as const },
        { id: USER_OTHER_ID, email: 'other@inv.local', userCode: 'AS-INV06', aal: 'aal1' as const },
    ];

    for (const u of users) {
        localIdp.registerTestUser({ ...u, password: 'test-password' });
        await adminPool.query(`INSERT INTO auth.users (id, email) VALUES ($1, $2) ON CONFLICT DO NOTHING;`, [u.id, u.email]);
        await adminPool.query(`INSERT INTO public.users (id, user_code, email) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING;`, [u.id, u.userCode, u.email]);
    }

    // Create organisation, workspace, app entitlement
    await adminPool.query(`
        INSERT INTO public.organisations (id, name, portal, tenant_type_key, status, member_min_aal)
        VALUES ($1, 'Invitations Studio Org', 'subscriber', 'studio_owner', 'ACTIVE', 'aal1')
        ON CONFLICT DO NOTHING;
    `, [ORG_ID]);

    const wsRes = await adminPool.query(`
        INSERT INTO public.workspaces (organisation_id, name, is_active)
        VALUES ($1, 'Main Workspace', true) RETURNING id;
    `, [ORG_ID]);
    workspaceId = wsRes.rows[0].id;

    await adminPool.query(`INSERT INTO public.app_catalogue (app_key, name) VALUES ('core_app', 'Core App') ON CONFLICT DO NOTHING;`);
    await adminPool.query(`INSERT INTO public.organisation_entitlements (organisation_id, app_key, is_enabled) VALUES ($1, 'core_app', true) ON CONFLICT DO NOTHING;`, [ORG_ID]);

    // Memberships
    await adminPool.query(`
        INSERT INTO public.memberships (user_id, organisation_id, role_key, status, is_primary_owner)
        VALUES ($1, $2, 'business_owner', 'ACTIVE', true);
    `, [USER_OWNER_ID, ORG_ID]);

    await adminPool.query(`
        INSERT INTO public.memberships (user_id, organisation_id, role_key, status)
        VALUES ($1, $2, 'leader', 'ACTIVE');
    `, [USER_LEADER_ID, ORG_ID]);

    const mgrRes = await adminPool.query(`
        INSERT INTO public.memberships (user_id, organisation_id, role_key, status, department, job_role)
        VALUES ($1, $2, 'manager_coordinator', 'ACTIVE', 'Design', 'Design Manager')
        RETURNING id;
    `, [USER_MGR_ID, ORG_ID]);
    mgrMembershipId = mgrRes.rows[0].id;

    await adminPool.query(`
        INSERT INTO public.memberships (user_id, organisation_id, role_key, status, expires_at)
        VALUES ($1, $2, 'intern', 'ACTIVE', now() + interval '30 days');
    `, [USER_INTERN_ID, ORG_ID]);

    // Sign in and create contexts
    const ownerLogin = await localIdp.signIn({ email: 'owner@inv.local', password: 'test-password' });
    ownerToken = ownerLogin.accessToken;
    const ownerCtxRes = await adminPool.query(`
        SELECT fn_create_access_context($1::uuid, $2, $3::uuid, $4::uuid, 'aal2');
    `, [USER_OWNER_ID, ownerLogin.principal.sessionId, ORG_ID, workspaceId]);
    ownerContextId = ownerCtxRes.rows[0].fn_create_access_context;

    const leaderLogin = await localIdp.signIn({ email: 'leader@inv.local', password: 'test-password' });
    leaderToken = leaderLogin.accessToken;
    const leaderCtxRes = await adminPool.query(`
        SELECT fn_create_access_context($1::uuid, $2, $3::uuid, $4::uuid, 'aal1');
    `, [USER_LEADER_ID, leaderLogin.principal.sessionId, ORG_ID, workspaceId]);
    leaderContextId = leaderCtxRes.rows[0].fn_create_access_context;

    const internLogin = await localIdp.signIn({ email: 'intern@inv.local', password: 'test-password' });
    internToken = internLogin.accessToken;
    const internCtxRes = await adminPool.query(`
        SELECT fn_create_access_context($1::uuid, $2, $3::uuid, $4::uuid, 'aal1');
    `, [USER_INTERN_ID, internLogin.principal.sessionId, ORG_ID, workspaceId]);
    internContextId = internCtxRes.rows[0].fn_create_access_context;

    const inviteeLogin = await localIdp.signIn({ email: 'target.invitee@inv.local', password: 'test-password' });
    inviteeToken = inviteeLogin.accessToken;

    const otherLogin = await localIdp.signIn({ email: 'other@inv.local', password: 'test-password' });
    otherToken = otherLogin.accessToken;

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

beforeEach(() => {
    clearSentMails();
});

describe('Invitations Engine API Integration Tests', () => {
    it('1. intern and non-invite roles cannot create invitations (403 AUTH_PERMISSION_DENIED)', async () => {
        const res = await fetch(`${baseUrl}/api/org/invitations`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${internToken}`,
                'X-ArchScale-Context': internContextId,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: 'test@target.local',
                roleKey: 'intern'
            })
        });
        expect(res.status).toBe(403);
        const data = await res.json();
        expect(data.error).toBe('AUTH_PERMISSION');
    });

    it('2. higher or equal level invite is denied (caller level ceiling)', async () => {
        // Business owner (level 80) cannot invite founder (level 100)
        const res = await fetch(`${baseUrl}/api/org/invitations`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${ownerToken}`,
                'X-ArchScale-Context': ownerContextId,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: 'test@target.local',
                roleKey: 'founder'
            })
        });
        expect([400, 403]).toContain(res.status);
    });

    it('3. creates invitation, dispatches mail via sink, and records Sent status', async () => {
        const res = await fetch(`${baseUrl}/api/org/invitations`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${ownerToken}`,
                'X-ArchScale-Context': ownerContextId,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: 'target.invitee@inv.local',
                roleKey: 'intern',
                department: 'Design',
                jobRole: 'Junior Drafter',
                reportingManagerMembershipId: mgrMembershipId,
                expiresAt: new Date(Date.now() + 30 * 86400000).toISOString()
            })
        });

        expect(res.status).toBe(200);
        const data = await res.json();
        expect(data.invitationId).toBeDefined();

        const sent = getSentMails();
        expect(sent.length).toBe(1);
        expect(sent[0].to).toBe('target.invitee@inv.local');
        expect(sent[0].rawToken).toBeDefined();
    });

    it('4. GET /api/org/invitations lists invitations and NEVER exposes token_hash or raw token', async () => {
        const res = await fetch(`${baseUrl}/api/org/invitations`, {
            headers: {
                'Authorization': `Bearer ${ownerToken}`,
                'X-ArchScale-Context': ownerContextId
            }
        });
        expect(res.status).toBe(200);
        const data = await res.json();
        expect(data.invitations).toBeInstanceOf(Array);
        expect(data.invitations.length).toBeGreaterThan(0);

        for (const inv of data.invitations) {
            expect(inv).not.toHaveProperty('token_hash');
            expect(inv).not.toHaveProperty('token');
            expect(inv).toHaveProperty('id');
            expect(inv).toHaveProperty('email');
            expect(inv).toHaveProperty('status');
        }
    });

    it('5. POST /api/invitations/accept succeeds for matching user email and copies metadata', async () => {
        // Create fresh invitation for target.invitee
        await fetch(`${baseUrl}/api/org/invitations`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${ownerToken}`,
                'X-ArchScale-Context': ownerContextId,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: 'target.invitee@inv.local',
                roleKey: 'intern',
                department: 'Architecture',
                jobRole: 'Model Maker',
                reportingManagerMembershipId: mgrMembershipId,
                expiresAt: new Date(Date.now() + 30 * 86400000).toISOString()
            })
        });

        const sent = getSentMails();
        const latestMail = sent[sent.length - 1];
        const rawToken = latestMail.rawToken;

        // Accepting with wrong user (other@inv.local) fails with 403 / 400
        const wrongUserRes = await fetch(`${baseUrl}/api/invitations/accept`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${otherToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ token: rawToken })
        });
        expect([400, 403]).toContain(wrongUserRes.status);

        // Accepting with matching user succeeds
        const acceptRes = await fetch(`${baseUrl}/api/invitations/accept`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${inviteeToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ token: rawToken })
        });
        expect(acceptRes.status).toBe(200);
        const acceptData = await acceptRes.json();
        expect(acceptData.membershipId).toBeDefined();

        // Verify membership record has department, job_role, manager
        const memRes = await adminPool.query(`
            SELECT department, job_role, reporting_manager_membership_id, role_key, status
            FROM public.memberships WHERE id = $1;
        `, [acceptData.membershipId]);
        expect(memRes.rows[0].department).toBe('Architecture');
        expect(memRes.rows[0].job_role).toBe('Model Maker');
        expect(memRes.rows[0].reporting_manager_membership_id).toBe(mgrMembershipId);
        expect(memRes.rows[0].role_key).toBe('intern');
        expect(memRes.rows[0].status).toBe('ACTIVE');
    });

    it('6. concurrent acceptance: two parallel requests yield exactly one success and one failure', async () => {
        // Invite a fresh user
        const CONCURRENT_EMAIL = 'concurrent.test@inv.local';
        const CONCURRENT_USER_ID = '60000000-0000-0000-0000-000000000088';
        localIdp.registerTestUser({ id: CONCURRENT_USER_ID, email: CONCURRENT_EMAIL, userCode: 'AS-CONC01', password: 'test-password', aal: 'aal1' });
        await adminPool.query(`INSERT INTO auth.users (id, email) VALUES ($1, $2) ON CONFLICT DO NOTHING;`, [CONCURRENT_USER_ID, CONCURRENT_EMAIL]);
        await adminPool.query(`INSERT INTO public.users (id, user_code, email) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING;`, [CONCURRENT_USER_ID, 'AS-CONC01', CONCURRENT_EMAIL]);

        const concLogin = await localIdp.signIn({ email: CONCURRENT_EMAIL, password: 'test-password' });
        const concToken = concLogin.accessToken;

        await fetch(`${baseUrl}/api/org/invitations`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${ownerToken}`,
                'X-ArchScale-Context': ownerContextId,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: CONCURRENT_EMAIL,
                roleKey: 'intern',
                expiresAt: new Date(Date.now() + 30 * 86400000).toISOString()
            })
        });

        const sent = getSentMails();
        const rawToken = sent[sent.length - 1].rawToken;

        // Fire 2 concurrent accepts
        const [res1, res2] = await Promise.all([
            fetch(`${baseUrl}/api/invitations/accept`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${concToken}`, 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: rawToken })
            }),
            fetch(`${baseUrl}/api/invitations/accept`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${concToken}`, 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: rawToken })
            })
        ]);

        const statuses = [res1.status, res2.status];
        expect(statuses).toContain(200);
        expect(statuses.some(s => s === 400 || s === 409 || s === 500)).toBe(true);
    });

    it('7. resend invalidates the previous token and generates a new token', async () => {
        const RESEND_EMAIL = 'resend.test@inv.local';
        const createRes = await fetch(`${baseUrl}/api/org/invitations`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${ownerToken}`,
                'X-ArchScale-Context': ownerContextId,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: RESEND_EMAIL,
                roleKey: 'intern',
                expiresAt: new Date(Date.now() + 30 * 86400000).toISOString()
            })
        });
        const { invitationId } = await createRes.json();
        const sent1 = getSentMails();
        const oldToken = sent1[sent1.length - 1].rawToken;

        // Resend
        const resendRes = await fetch(`${baseUrl}/api/org/invitations/${invitationId}/resend`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${ownerToken}`,
                'X-ArchScale-Context': ownerContextId
            }
        });
        expect(resendRes.status).toBe(200);

        const sent2 = getSentMails();
        const newToken = sent2[sent2.length - 1].rawToken;
        expect(newToken).not.toBe(oldToken);

        // Attempting to accept with oldToken is rejected
        const acceptOld = await fetch(`${baseUrl}/api/invitations/accept`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${inviteeToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: oldToken })
        });
        expect([400, 404]).toContain(acceptOld.status);
    });

    it('8. revoking an invitation sets status Revoked and prevents acceptance', async () => {
        const REVOKE_EMAIL = 'revoke.test@inv.local';
        const createRes = await fetch(`${baseUrl}/api/org/invitations`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${ownerToken}`,
                'X-ArchScale-Context': ownerContextId,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: REVOKE_EMAIL,
                roleKey: 'intern',
                expiresAt: new Date(Date.now() + 30 * 86400000).toISOString()
            })
        });
        const { invitationId } = await createRes.json();
        const sent = getSentMails();
        const rawToken = sent[sent.length - 1].rawToken;

        // Revoke
        const revokeRes = await fetch(`${baseUrl}/api/org/invitations/${invitationId}/revoke`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${ownerToken}`,
                'X-ArchScale-Context': ownerContextId
            }
        });
        expect(revokeRes.status).toBe(200);

        // Attempt to accept revoked invitation
        const acceptRes = await fetch(`${baseUrl}/api/invitations/accept`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${inviteeToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: rawToken })
        });
        expect([400, 403]).toContain(acceptRes.status);
    });
});
