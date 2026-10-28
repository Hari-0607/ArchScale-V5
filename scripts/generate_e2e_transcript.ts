import fs from 'fs';
import path from 'path';
import http from 'http';
import { AddressInfo } from 'net';
import { fileURLToPath } from 'url';
import { createServer } from '../src/server/index.js';
import { SupabaseProvider } from '../src/identity/providers/supabase.js';
import { runtimePool } from '../src/db/index.js';
import { generateTotpCode } from '../src/utils/totp.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function redact(data: any): any {
    if (!data) return data;
    if (typeof data === 'string') {
        if (data.startsWith('eyJ') || data.length > 50) return '[REDACTED_TOKEN]';
        // Redact UUIDs representing contexts
        if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(data)) {
            return '[REDACTED_CONTEXT_ID]';
        }
        return data;
    }
    if (Array.isArray(data)) return data.map(redact);
    if (typeof data === 'object') {
        const out: any = {};
        for (const [k, v] of Object.entries(data)) {
            if (k === 'accessToken' || k === 'refreshToken') {
                out[k] = '[REDACTED_TOKEN]';
            } else if (k === 'contextId' || k === 'id' && typeof v === 'string' && /^[0-9a-f-]{36}$/i.test(v)) {
                out[k] = '[REDACTED_ID]';
            } else {
                out[k] = redact(v);
            }
        }
        return out;
    }
    return data;
}

async function main() {
    const testUsersPath = path.join(__dirname, '../.local/test-users.json');
    if (!fs.existsSync(testUsersPath)) {
        console.error('Missing .local/test-users.json');
        process.exit(1);
    }
    const testUsers = JSON.parse(fs.readFileSync(testUsersPath, 'utf-8'));
    const user = testUsers.business_owner;

    const provider = new SupabaseProvider();
    const server = createServer(provider, runtimePool);

    await new Promise<void>((resolve) => {
        server.listen(0, '127.0.0.1', () => resolve());
    });
    const addr = server.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${addr.port}`;

    console.log('=== START E2E RUNBOOK HTTP TRANSCRIPT (STAGING) ===\n');

    // 1. Sign In
    console.log('>>> 1. POST /api/session/sign-in');
    const signinReq = { email: user.email, password: '[REDACTED_PASSWORD]' };
    console.log('Request Body:', JSON.stringify(signinReq, null, 2));

    const signinRes = await fetch(`${baseUrl}/api/session/sign-in`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: user.email, password: user.password })
    });
    const signinData = await signinRes.json();
    console.log(`Response HTTP ${signinRes.status}:`, JSON.stringify(redact(signinData), null, 2), '\n');
    const aal1Token = signinData.accessToken;

    // 2. MFA Verify
    console.log('>>> 2. POST /api/session/mfa/verify');
    const totpCode = generateTotpCode(user.totpSecret);
    console.log('Request Headers: Authorization: Bearer [REDACTED_TOKEN]');
    console.log('Request Body:', JSON.stringify({ code: '[REDACTED_6DIGIT_CODE]' }, null, 2));

    const mfaRes = await fetch(`${baseUrl}/api/session/mfa/verify`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${aal1Token}`
        },
        body: JSON.stringify({ code: totpCode })
    });
    const mfaData = await mfaRes.json();
    console.log(`Response HTTP ${mfaRes.status}:`, JSON.stringify(redact(mfaData), null, 2), '\n');
    const aal2Token = mfaData.accessToken;

    // 3. Memberships
    console.log('>>> 3. GET /api/session/memberships');
    console.log('Request Headers: Authorization: Bearer [REDACTED_TOKEN]');
    const memRes = await fetch(`${baseUrl}/api/session/memberships`, {
        headers: { 'Authorization': `Bearer ${aal2Token}` }
    });
    const memData = await memRes.json();
    console.log(`Response HTTP ${memRes.status}:`, JSON.stringify(redact(memData), null, 2), '\n');

    const orgId = memData.memberships[0].organisation_id;

    // 4. Workspaces
    console.log(`>>> 4. GET /api/session/workspaces?organisationId=[REDACTED_ORG_ID]`);
    console.log('Request Headers: Authorization: Bearer [REDACTED_TOKEN]');
    const wsRes = await fetch(`${baseUrl}/api/session/workspaces?organisationId=${orgId}`, {
        headers: { 'Authorization': `Bearer ${aal2Token}` }
    });
    const wsData = await wsRes.json();
    console.log(`Response HTTP ${wsRes.status}:`, JSON.stringify(redact(wsData), null, 2), '\n');

    const wsId = wsData.workspaces[0].workspace_id;

    // 5. Context
    console.log('>>> 5. POST /api/session/context');
    console.log('Request Headers: Authorization: Bearer [REDACTED_TOKEN]');
    console.log('Request Body:', JSON.stringify({ organisationId: '[REDACTED_ORG_ID]', workspaceId: '[REDACTED_WS_ID]' }, null, 2));
    const ctxRes = await fetch(`${baseUrl}/api/session/context`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${aal2Token}`
        },
        body: JSON.stringify({ organisationId: orgId, workspaceId: wsId })
    });
    const ctxData = await ctxRes.json();
    console.log(`Response HTTP ${ctxRes.status}:`, JSON.stringify(redact(ctxData), null, 2), '\n');
    const ctxId = ctxData.context.contextId;

    // 6. /api/me
    console.log('>>> 6. GET /api/me');
    console.log('Request Headers: Authorization: Bearer [REDACTED_TOKEN], X-ArchScale-Context: [REDACTED_CONTEXT_ID]');
    const meRes = await fetch(`${baseUrl}/api/me`, {
        headers: {
            'Authorization': `Bearer ${aal2Token}`,
            'X-ArchScale-Context': ctxId
        }
    });
    const meData = await meRes.json();
    console.log(`Response HTTP ${meRes.status}:`, JSON.stringify(redact(meData), null, 2), '\n');

    // 7. Route Mutation
    console.log('>>> 7. POST /api/org/invitations (Allowed at AAL2)');
    console.log('Request Headers: Authorization: Bearer [REDACTED_TOKEN], X-ArchScale-Context: [REDACTED_CONTEXT_ID]');
    console.log('Request Body:', JSON.stringify({ email: 'newmember@studio.test', roleKey: 'leader' }, null, 2));
    const invRes = await fetch(`${baseUrl}/api/org/invitations`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${aal2Token}`,
            'X-ArchScale-Context': ctxId
        },
        body: JSON.stringify({ email: 'newmember@studio.test', roleKey: 'leader' })
    });
    const invData = await invRes.json();
    console.log(`Response HTTP ${invRes.status}:`, JSON.stringify(redact(invData), null, 2), '\n');

    // 8. Renew Context
    console.log('>>> 8. POST /api/session/context/renew');
    console.log('Request Headers: Authorization: Bearer [REDACTED_TOKEN], X-ArchScale-Context: [REDACTED_CONTEXT_ID]');
    const renewRes = await fetch(`${baseUrl}/api/session/context/renew`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${aal2Token}`,
            'X-ArchScale-Context': ctxId
        },
        body: JSON.stringify({})
    });
    const renewData = await renewRes.json();
    console.log(`Response HTTP ${renewRes.status}:`, JSON.stringify(redact(renewData), null, 2), '\n');

    // 9. Logout
    console.log('>>> 9. POST /api/session/logout');
    console.log('Request Headers: Authorization: Bearer [REDACTED_TOKEN], X-ArchScale-Context: [REDACTED_CONTEXT_ID]');
    const logoutRes = await fetch(`${baseUrl}/api/session/logout`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${aal2Token}`,
            'X-ArchScale-Context': ctxId
        }
    });
    const logoutData = await logoutRes.json();
    console.log(`Response HTTP ${logoutRes.status}:`, JSON.stringify(redact(logoutData), null, 2), '\n');

    // 10. Post-logout rejection check
    console.log('>>> 10. GET /api/me (After logout)');
    const postLogoutRes = await fetch(`${baseUrl}/api/me`, {
        headers: {
            'Authorization': `Bearer ${aal2Token}`,
            'X-ArchScale-Context': ctxId
        }
    });
    const postLogoutData = await postLogoutRes.json();
    console.log(`Response HTTP ${postLogoutRes.status}:`, JSON.stringify(redact(postLogoutData), null, 2), '\n');

    console.log('=== END OF E2E RUNBOOK HTTP TRANSCRIPT ===');

    server.close();
    await runtimePool.end().catch(() => {});
}

main();
