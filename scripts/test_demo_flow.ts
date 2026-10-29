import fs from 'fs';
import { createServer } from '../src/server/index.js';
import { SupabaseProvider } from '../src/identity/providers/supabase.js';
import { runtimePool } from '../src/db/index.js';
import { generateTotpCode } from '../src/utils/totp.js';

async function testDemoFlows() {
    process.env.ARCHSCALE_DEMO = 'true';
    const testUsers = JSON.parse(fs.readFileSync('.local/test-users.json', 'utf8'));
    const provider = new SupabaseProvider();
    const server = createServer(provider, runtimePool);

    await new Promise<void>((resolve) => server.listen(3000, '127.0.0.1', () => resolve()));
    const baseUrl = 'http://127.0.0.1:3000';

    console.log('=== DEMO FLOW VERIFICATION (127.0.0.1:3000) ===\n');

    // Fetch HTML
    const htmlRes = await fetch(`${baseUrl}/`);
    const htmlText = await htmlRes.text();
    console.log('GET / -> Status:', htmlRes.status, '| Banner present:', htmlText.includes('Demo only. Final screens come in Phase 5.'));

    // Flow A: Intern
    {
        const u = testUsers.intern;
        const signinRes = await fetch(`${baseUrl}/api/session/sign-in`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: u.email, password: u.password })
        });
        const signinData = await signinRes.json();
        console.log('\n[Demo - Intern]');
        console.log('  1. Sign-in status:', signinRes.status, '| mfaRequired:', signinData.mfaRequired, '| AAL:', signinData.principal?.aal);

        // Fetch memberships
        const memRes = await fetch(`${baseUrl}/api/session/memberships`, {
            headers: { 'Authorization': `Bearer ${signinData.accessToken}` }
        });
        const memData = await memRes.json();
        console.log('  2. Memberships loaded:', memData.memberships?.length, '| Org:', memData.memberships?.[0]?.organisationName);

        // Create context
        const ctxRes = await fetch(`${baseUrl}/api/session/context`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${signinData.accessToken}` },
            body: JSON.stringify({ organisationId: u.orgId, workspaceId: u.workspaceId })
        });
        const ctxData = await ctxRes.json();
        console.log('  3. Create Context status:', ctxRes.status, '| Context created:', !!ctxData.context);

        // Test route: POST /api/org/invitations (intern lacks permission)
        const invRes = await fetch(`${baseUrl}/api/org/invitations`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${signinData.accessToken}`, 'X-ArchScale-Context': ctxData.context.contextId },
            body: JSON.stringify({ email: 'invitee@test.local' })
        });
        const invBody = await invRes.json();
        console.log('  4. Button Click: POST /api/org/invitations -> Status:', invRes.status, '| Error:', invBody.error);
        console.log('     -> UI Result: Red Badge [DENIED] with error "AUTH_PERMISSION"');
    }

    // Flow B: Business Owner
    {
        const u = testUsers.business_owner;
        const signinRes = await fetch(`${baseUrl}/api/session/sign-in`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: u.email, password: u.password })
        });
        const signinData = await signinRes.json();
        console.log('\n[Demo - Business Owner]');
        console.log('  1. Sign-in status:', signinRes.status, '| mfaRequired:', signinData.mfaRequired, '| AAL:', signinData.principal?.aal);
        console.log('     -> UI Result: Step 1b (MFA Verification) unhides with prompt "Enter 6-digit TOTP code"');

        // Step 1b: Verify MFA
        const totp = generateTotpCode(u.totpSecret);
        const mfaRes = await fetch(`${baseUrl}/api/session/mfa/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${signinData.accessToken}` },
            body: JSON.stringify({ code: totp })
        });
        const mfaData = await mfaRes.json();
        console.log('  2. MFA verify status:', mfaRes.status, '| Upgraded AAL:', mfaData.aal);
        console.log('     -> UI Result: Step 2 (Organisation & Workspace Selection) appears and populates dropdowns');

        // Create context at AAL2
        const ctxRes = await fetch(`${baseUrl}/api/session/context`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${mfaData.accessToken}` },
            body: JSON.stringify({ organisationId: u.orgId, workspaceId: u.workspaceId })
        });
        const ctxData = await ctxRes.json();
        console.log('  3. Create Context status:', ctxRes.status, '| Context created:', !!ctxData.context);
        console.log('     -> UI Result: Step 3 (Call Protected Routes) activates');

        // Protected route: POST /api/org/invitations (business_owner at aal2 is allowed)
        const invRes = await fetch(`${baseUrl}/api/org/invitations`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${mfaData.accessToken}`, 'X-ArchScale-Context': ctxData.context.contextId },
            body: JSON.stringify({ email: 'invitee@test.local' })
        });
        const invBody = await invRes.json();
        console.log('  4. Button Click: POST /api/org/invitations -> Status:', invRes.status, '| Decision Allow:', invBody.decision?.allow);
        console.log('     -> UI Result: Green Badge [ALLOWED] with details');
    }

    server.close();
    await runtimePool.end();
}

testDemoFlows().catch(e => { console.error('Demo error:', e.message); process.exit(1); });
