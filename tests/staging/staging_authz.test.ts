/**
 * Comprehensive Staging Verification Suite
 * Exercises real Supabase authentication, TOTP verification, and context authorization.
 * Runs against real Staging project only when ARCHSCALE_STAGING_TESTS=true.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'fs';
import path from 'path';
import http from 'http';
import { AddressInfo } from 'net';
import { fileURLToPath } from 'url';
import { createServer } from '../../src/server/index.js';
import { SupabaseProvider } from '../../src/identity/providers/supabase.js';
import { runtimePool } from '../../src/db/index.js';
import { generateTotpCode } from '../../src/utils/totp.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const isStagingEnabled = process.env.ARCHSCALE_STAGING_TESTS === 'true';

describe.runIf(isStagingEnabled)('Staging Authorization & MFA Integration Tests', () => {
    let server: http.Server;
    let baseUrl: string;
    let testUsers: Record<string, any>;
    let provider: SupabaseProvider;

    beforeAll(async () => {
        const testUsersPath = path.join(__dirname, '../../.local/test-users.json');
        if (!fs.existsSync(testUsersPath)) {
            throw new Error('.local/test-users.json not found! Run scripts/seed_staging_users.ts --confirm-staging first.');
        }
        testUsers = JSON.parse(fs.readFileSync(testUsersPath, 'utf-8'));

        provider = new SupabaseProvider();
        server = createServer(provider, runtimePool);

        await new Promise<void>((resolve) => {
            server.listen(0, '127.0.0.1', () => {
                const addr = server.address() as AddressInfo;
                baseUrl = `http://127.0.0.1:${addr.port}`;
                resolve();
            });
        });
    });

    afterAll(async () => {
        if (server) {
            await new Promise<void>((resolve) => server.close(() => resolve()));
        }
        await runtimePool.end().catch(() => {});
    });

    it('1. business_owner: at aal1 denied on invite, at aal2 allowed', async () => {
        const user = testUsers.business_owner;
        // Step A: Sign in
        const signinRes = await fetch(`${baseUrl}/api/session/sign-in`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: user.email, password: user.password })
        });
        const signinData = await signinRes.json();
        expect(signinRes.status).toBe(200);
        expect(signinData.mfaRequired).toBe(true);
        expect(signinData.principal.aal).toBe('aal1');
        const aal1Token = signinData.accessToken;

        // Context at aal1
        const ctxAal1Res = await fetch(`${baseUrl}/api/session/context`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${aal1Token}`
            },
            body: JSON.stringify({
                organisationId: user.orgId,
                workspaceId: user.workspaceId
            })
        });
        const ctxAal1Data = await ctxAal1Res.json();
        expect(ctxAal1Res.status).toBe(200);
        const ctxAal1Id = ctxAal1Data.context.contextId;

        // Invite at aal1: DENIED (AUTH_AAL)
        const inviteDeny = await fetch(`${baseUrl}/api/org/invitations`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${aal1Token}`,
                'X-ArchScale-Context': ctxAal1Id
            },
            body: JSON.stringify({ email: 'invitee@test.local' })
        });
        expect(inviteDeny.status).toBe(403);
        const inviteDenyBody = await inviteDeny.json();
        expect(inviteDenyBody.error).toBe('AUTH_AAL');

        // Step B: MFA verify to upgrade to aal2
        const totpCode = generateTotpCode(user.totpSecret);
        const mfaRes = await fetch(`${baseUrl}/api/session/mfa/verify`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${aal1Token}`
            },
            body: JSON.stringify({ code: totpCode })
        });
        expect(mfaRes.status).toBe(200);
        const mfaData = await mfaRes.json();
        expect(mfaData.aal).toBe('aal2');
        const aal2Token = mfaData.accessToken;

        // Create context at aal2
        const ctxAal2Res = await fetch(`${baseUrl}/api/session/context`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${aal2Token}`
            },
            body: JSON.stringify({
                organisationId: user.orgId,
                workspaceId: user.workspaceId
            })
        });
        const ctxAal2Data = await ctxAal2Res.json();
        expect(ctxAal2Res.status).toBe(200);
        const ctxAal2Id = ctxAal2Data.context.contextId;

        // Invite at aal2: ALLOWED (200)
        const inviteAllow = await fetch(`${baseUrl}/api/org/invitations`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${aal2Token}`,
                'X-ArchScale-Context': ctxAal2Id
            },
            body: JSON.stringify({ email: 'invitee@test.local' })
        });
        expect(inviteAllow.status).toBe(200);
    });

    it('2. founder: at aal1 denied on platform route, at aal2 allowed', async () => {
        const user = testUsers.founder;
        const signinRes = await fetch(`${baseUrl}/api/session/sign-in`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: user.email, password: user.password })
        });
        const signinData = await signinRes.json();
        expect(signinRes.status).toBe(200);
        const aal1Token = signinData.accessToken;

        // Create aal1 context
        const ctxAal1Res = await fetch(`${baseUrl}/api/session/context`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${aal1Token}`
            },
            body: JSON.stringify({
                organisationId: user.orgId,
                workspaceId: user.workspaceId
            })
        });
        const ctxAal1Data = await ctxAal1Res.json();
        const ctxAal1Id = ctxAal1Data.context.contextId;

        // Platform read at aal1: DENIED (AUTH_AAL)
        const platDeny = await fetch(`${baseUrl}/api/platform/organisations`, {
            headers: {
                'Authorization': `Bearer ${aal1Token}`,
                'X-ArchScale-Context': ctxAal1Id
            }
        });
        expect(platDeny.status).toBe(403);
        const platDenyBody = await platDeny.json();
        expect(platDenyBody.error).toBe('AUTH_AAL');

        // MFA verify
        const totpCode = generateTotpCode(user.totpSecret);
        const mfaRes = await fetch(`${baseUrl}/api/session/mfa/verify`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${aal1Token}`
            },
            body: JSON.stringify({ code: totpCode })
        });
        expect(mfaRes.status).toBe(200);
        const mfaData = await mfaRes.json();
        const aal2Token = mfaData.accessToken;

        // Create aal2 context
        const ctxAal2Res = await fetch(`${baseUrl}/api/session/context`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${aal2Token}`
            },
            body: JSON.stringify({
                organisationId: user.orgId,
                workspaceId: user.workspaceId
            })
        });
        const ctxAal2Data = await ctxAal2Res.json();
        const ctxAal2Id = ctxAal2Data.context.contextId;

        // Platform read at aal2: ALLOWED (200)
        const platAllow = await fetch(`${baseUrl}/api/platform/organisations`, {
            headers: {
                'Authorization': `Bearer ${aal2Token}`,
                'X-ArchScale-Context': ctxAal2Id
            }
        });
        expect(platAllow.status).toBe(200);
    });

    it('3. intern: allowed to read me, denied on invite', async () => {
        const user = testUsers.intern;
        const signinRes = await fetch(`${baseUrl}/api/session/sign-in`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: user.email, password: user.password })
        });
        const signinData = await signinRes.json();
        expect(signinRes.status).toBe(200);
        const token = signinData.accessToken;

        const ctxRes = await fetch(`${baseUrl}/api/session/context`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                organisationId: user.orgId,
                workspaceId: user.workspaceId
            })
        });
        const ctxData = await ctxRes.json();
        const ctxId = ctxData.context.contextId;

        // /api/me: ALLOWED (200)
        const meRes = await fetch(`${baseUrl}/api/me`, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'X-ArchScale-Context': ctxId
            }
        });
        expect(meRes.status).toBe(200);

        // Invite: DENIED (AUTH_PERMISSION)
        const inviteRes = await fetch(`${baseUrl}/api/org/invitations`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
                'X-ArchScale-Context': ctxId
            },
            body: JSON.stringify({ email: 'intern.invitee@test.local' })
        });
        expect(inviteRes.status).toBe(403);
        const inviteBody = await inviteRes.json();
        expect(inviteBody.error).toBe('AUTH_PERMISSION');
    });

    it('4. no-membership user: lists empty memberships, cannot create context', async () => {
        const user = testUsers.no_membership;
        const signinRes = await fetch(`${baseUrl}/api/session/sign-in`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: user.email, password: user.password })
        });
        const signinData = await signinRes.json();
        expect(signinRes.status).toBe(200);
        const token = signinData.accessToken;

        // List memberships: empty
        const memRes = await fetch(`${baseUrl}/api/session/memberships`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const memData = await memRes.json();
        expect(memData.memberships.length).toBe(0);

        // Context creation: rejected (400)
        const ctxRes = await fetch(`${baseUrl}/api/session/context`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                organisationId: '00000000-0000-0000-0000-000000000001',
                workspaceId: '00000000-0000-0000-0000-000000000001'
            })
        });
        expect(ctxRes.status).toBe(400);
    });

    it('5. logout: makes both token and context fail immediately', async () => {
        const user = testUsers.leader;
        const signinRes = await fetch(`${baseUrl}/api/session/sign-in`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: user.email, password: user.password })
        });
        const signinData = await signinRes.json();
        const token = signinData.accessToken;

        const ctxRes = await fetch(`${baseUrl}/api/session/context`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                organisationId: user.orgId,
                workspaceId: user.workspaceId
            })
        });
        const ctxData = await ctxRes.json();
        const ctxId = ctxData.context.contextId;

        // Logout
        const logoutRes = await fetch(`${baseUrl}/api/session/logout`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'X-ArchScale-Context': ctxId
            }
        });
        expect(logoutRes.status).toBe(200);

        // Token call fails: 401
        const afterTokenCall = await fetch(`${baseUrl}/api/me`, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'X-ArchScale-Context': ctxId
            }
        });
        expect(afterTokenCall.status).toBe(401);
    });
});
