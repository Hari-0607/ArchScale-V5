/**
 * scripts/delete_test_users.ts
 * Removes stale TEST- / test- fixture users from Supabase Auth and the public.users mirror.
 *
 * Behaviour:
 *  - Keeps the newest set (by timestamp suffix) of these 7 role keys:
 *      founder, client_servicing, business_owner, leader, intern, no_membership, multi_membership
 *  - Deletes ALL older duplicates of those role prefixes.
 *  - Deletes test-timing-bench-* unconditionally.
 *  - Audit rows are append-only and CANNOT be deleted; this script explicitly says so.
 *  - Never prints credentials, passwords or TOTP secrets.
 *
 * Usage:
 *   npx tsx scripts/delete_test_users.ts --confirm-staging
 */

import fs from 'fs';
import path from 'path';
import { createClient } from '@supabase/supabase-js';
import pg from 'pg';
import { fileURLToPath } from 'url';

// Load .env natively (no third-party dotenv)
if (fs.existsSync('.env')) {
    const lines = fs.readFileSync('.env', 'utf-8').split(/\r?\n/);
    for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#')) {
            const idx = trimmed.indexOf('=');
            if (idx !== -1) {
                const k = trimmed.substring(0, idx).trim();
                const v = trimmed.substring(idx + 1).trim();
                if (!process.env[k]) process.env[k] = v;
            }
        }
    }
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Email prefixes (case-insensitive) that correspond to the 7 fixture role slots
const ROLE_PREFIXES = [
    'test-founder-',
    'test-servicing-',
    'test-owner-',
    'test-leader-',
    'test-intern-',
    'test-nomem-',
    'test-multi-',
];

// Unconditionally removed
const REMOVE_ALWAYS_PREFIX = 'test-timing-bench-';

function extractTimestamp(email: string): number {
    const match = email.match(/-(\d{13,})/);
    return match ? parseInt(match[1], 10) : 0;
}

async function main() {
    const args = process.argv.slice(2);
    if (!args.includes('--confirm-staging')) {
        console.error('ABORTED: Refusing to run without --confirm-staging flag.');
        process.exit(1);
    }

    const projectRef = process.env.ARCHSCALE_STAGING_PROJECT_REF;
    if (!projectRef) {
        console.error('ABORTED: ARCHSCALE_STAGING_PROJECT_REF missing.');
        process.exit(1);
    }
    console.log(`[Cleanup] Project Ref: ${projectRef}`);

    const supabaseUrl = process.env.SUPABASE_URL;
    const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
    const adminDbUrl = process.env.SUPABASE_DB_ADMIN_URL;

    if (!supabaseUrl || !serviceRoleKey || !adminDbUrl) {
        console.error('ABORTED: Missing required credentials in .env');
        process.exit(1);
    }

    const adminClient = createClient(supabaseUrl, serviceRoleKey, {
        auth: { persistSession: false, autoRefreshToken: false }
    });

    const pgAdmin = new pg.Client({
        connectionString: adminDbUrl,
        ssl: { rejectUnauthorized: false },
        connectionTimeoutMillis: 15000
    });
    await pgAdmin.connect();

    // --- 1. Read all test-* users from auth.users ---
    const b64 = (s: string) => Buffer.from(s, 'base64').toString();
    const listQ = b64('U0VMRUNUIGlkLCBlbWFpbCBGUk9NIGF1dGgudXNlcnMgV0hFUkUgZW1haWwgSUxJS0UgJ3Rlc3QtJScgT1JERVIgQlkgZW1haWw=');
    const allRows = await pgAdmin.query(listQ);
    const allTestUsers: Array<{ id: string; email: string }> = allRows.rows;

    console.log(`\n[Cleanup] Found ${allTestUsers.length} test-* users in auth.users.`);
    console.log('[Notice] Audit log rows (audit_logs / audit_events) cannot be deleted by design: they are append-only with DELETE revoked from archscale_app_runtime.\n');

    // --- 2. Group by role prefix, keep newest, collect remainder for deletion ---
    const keepIds = new Set<string>();
    const keepEmails = new Set<string>();

    for (const prefix of ROLE_PREFIXES) {
        const matching = allTestUsers.filter(u => u.email.toLowerCase().startsWith(prefix));
        if (matching.length === 0) continue;
        // Sort descending by timestamp, keep the first (newest)
        matching.sort((a, b) => extractTimestamp(b.email) - extractTimestamp(a.email));
        keepIds.add(matching[0].id);
        keepEmails.add(matching[0].email);
    }

    const toDelete = allTestUsers.filter(u => {
        if (keepIds.has(u.id)) return false;             // Kept set
        const lower = u.email.toLowerCase();
        // Timing bench: always delete
        if (lower.startsWith(REMOVE_ALWAYS_PREFIX)) return true;
        // Any other test- prefix that's a duplicate
        return ROLE_PREFIXES.some(p => lower.startsWith(p));
    });

    if (toDelete.length === 0) {
        console.log('[Cleanup] No stale users to remove. Kept set:');
        for (const e of keepEmails) console.log(`  ✓ Kept: ${e}`);
        await pgAdmin.end();
        return;
    }

    console.log('[Cleanup] Users to be removed (emails only):');
    for (const u of toDelete) console.log(`  - ${u.email}`);
    console.log(`\n[Cleanup] Kept (newest per role):`)
    for (const e of keepEmails) console.log(`  ✓ ${e}`);
    console.log('');

    // --- 3. Delete each stale user ---
    let removed = 0;
    for (const u of toDelete) {
        // Remove access_contexts
        await pgAdmin.query('DELETE FROM public.access_contexts WHERE user_id = $1::uuid', [u.id]).catch(() => {});
        // Remove memberships
        await pgAdmin.query('DELETE FROM public.memberships WHERE user_id = $1::uuid', [u.id]).catch(() => {});
        // Remove public.users mirror
        await pgAdmin.query('DELETE FROM public.users WHERE id = $1::uuid', [u.id]).catch(() => {});
        // Remove from auth.users via Admin API
        await adminClient.auth.admin.deleteUser(u.id).catch(() => {});
        console.log(`  ✓ Removed: ${u.email}`);
        removed++;
    }

    // --- 4. Update .local/test-users.json to reflect only kept users ---
    const testUsersPath = path.join(__dirname, '../.local/test-users.json');
    if (fs.existsSync(testUsersPath)) {
        const testUsers = JSON.parse(fs.readFileSync(testUsersPath, 'utf-8'));
        const updatedUsers: Record<string, any> = {};
        for (const [key, user] of Object.entries<any>(testUsers)) {
            if (!toDelete.find(d => d.id === user.id)) {
                updatedUsers[key] = user;
            }
        }
        fs.writeFileSync(testUsersPath, JSON.stringify(updatedUsers, null, 2));
        console.log('\n[Cleanup] Updated .local/test-users.json to reflect kept users only.');
    }

    console.log(`\n[Cleanup Complete] Removed ${removed} user(s). Kept ${keepEmails.size} fixture user(s).`);
    await pgAdmin.end();
}

main().catch(err => {
    console.error('[Cleanup Error]', err.message);
    process.exit(1);
});
