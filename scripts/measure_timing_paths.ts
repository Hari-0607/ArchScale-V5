import { createClient } from '@supabase/supabase-js';
import { config } from '../src/config/env.js';
import { SupabaseProvider } from '../src/identity/providers/supabase.js';
import pg from 'pg';
import crypto from 'crypto';

const RUNS = 20;
const PAUSE_MS = 600; // pause between calls to avoid HTTP 429 rate limits

function median(arr: number[]): number {
    const sorted = [...arr].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 === 0
        ? (sorted[mid - 1] + sorted[mid]) / 2
        : sorted[mid];
}

function p95(arr: number[]): number {
    const sorted = [...arr].sort((a, b) => a - b);
    const idx = Math.ceil(sorted.length * 0.95) - 1;
    return sorted[Math.min(idx, sorted.length - 1)];
}

function min(arr: number[]): number {
    return Math.min(...arr);
}

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

async function main() {
    if (config.env !== 'staging') throw new Error('Requires staging env');

    const provider = new SupabaseProvider();
    const adminSupabase = createClient(config.supabaseUrl, config.supabaseServiceRoleKey, {
        auth: { persistSession: false, autoRefreshToken: false }
    });

    const TEST_EMAIL = `TEST-timing-bench-${Date.now()}@archscale.test`;
    const TEST_PASSWORD = crypto.randomBytes(24).toString('base64url') + 'Aa1!';
    const TEST_USER_CODE = `AS-BENCH-${Date.now().toString().slice(-4)}`;

    // Create real user in Supabase Auth
    const { data, error } = await adminSupabase.auth.admin.createUser({
        email: TEST_EMAIL,
        password: TEST_PASSWORD,
        email_confirm: true
    });
    if (error || !data.user) throw new Error(`User creation failed: ${error?.message}`);
    const userId = data.user.id;

    // Seed mirror in staging DB
    const adminDb = new pg.Client({ connectionString: config.supabaseDbAdminUrl, ssl: { rejectUnauthorized: false } });
    await adminDb.connect();
    try {
        await adminDb.query(`SELECT fn_upsert_user_mirror($1, $2, $3, NULL);`, [userId, TEST_EMAIL, TEST_USER_CODE]);
    } catch {
        await adminDb.query(`INSERT INTO public.users (id, email, user_code) VALUES ($1, $2, $3);`, [userId, TEST_EMAIL, TEST_USER_CODE]);
    }
    await adminDb.end();

    console.log('================================================================');
    console.log(`Measuring ${RUNS} runs per failure path against Staging Supabase Auth`);
    console.log(`Pause between calls: ${PAUSE_MS}ms`);
    console.log('================================================================\n');

    let count429 = 0;
    const timingsA: number[] = [];
    const timingsB: number[] = [];
    const timingsC: number[] = [];

    try {
        // Path A: Unknown email
        console.log('Running Path A (unknown email)...');
        for (let i = 0; i < RUNS; i++) {
            const t0 = Date.now();
            try {
                await provider.signIn({ email: `TEST-unk-bench-${i}@archscale.test`, password: 'WrongPass123!' });
            } catch (err: any) {
                if (err.status === 429 || (err.message && err.message.includes('429'))) count429++;
            }
            timingsA.push(Date.now() - t0);
            await sleep(PAUSE_MS);
        }

        // Path B: Unresolved AS-... code
        console.log('Running Path B (unresolved AS- code)...');
        for (let i = 0; i < RUNS; i++) {
            const t0 = Date.now();
            try {
                await provider.signIn({ userCode: `AS-DOESNOTEXIST-${i}`, password: 'WrongPass123!' });
            } catch (err: any) {
                if (err.status === 429 || (err.message && err.message.includes('429'))) count429++;
            }
            timingsB.push(Date.now() - t0);
            await sleep(PAUSE_MS);
        }

        // Path C: Wrong password for real registered user
        console.log('Running Path C (wrong password for real user)...');
        for (let i = 0; i < RUNS; i++) {
            const t0 = Date.now();
            try {
                await provider.signIn({ email: TEST_EMAIL, password: 'CompletelyWrongPassword999!' });
            } catch (err: any) {
                if (err.status === 429 || (err.message && err.message.includes('429'))) count429++;
            }
            timingsC.push(Date.now() - t0);
            await sleep(PAUSE_MS);
        }

        console.log('\n--- Timing Measurement Results ---');
        console.log(`HTTP 429 count: ${count429}`);
        console.log(`Path A (unknown email):    min=${min(timingsA)}ms, median=${median(timingsA)}ms, p95=${p95(timingsA)}ms`);
        console.log(`Path B (unresolved code):  min=${min(timingsB)}ms, median=${median(timingsB)}ms, p95=${p95(timingsB)}ms`);
        console.log(`Path C (wrong password):   min=${min(timingsC)}ms, median=${median(timingsC)}ms, p95=${p95(timingsC)}ms`);

        const slowestP95 = Math.max(p95(timingsA), p95(timingsB), p95(timingsC));
        console.log(`\nSlowest p95 across all paths: ${slowestP95}ms`);
        const suggestedFloor = Math.ceil(slowestP95 / 50) * 50 + 50; // rounded up + 50ms buffer
        console.log(`Suggested fixed floor (above slowest p95): ${suggestedFloor}ms`);

    } finally {
        // Cleanup test user
        await adminSupabase.auth.admin.deleteUser(userId).catch(() => {});
        const cleanupDb = new pg.Client({ connectionString: config.supabaseDbAdminUrl, ssl: { rejectUnauthorized: false } });
        await cleanupDb.connect().catch(() => {});
        await cleanupDb.query('DELETE FROM public.users WHERE id = $1;', [userId]).catch(() => {});
        await cleanupDb.end().catch(() => {});
    }
}

main().catch(err => {
    let msg = err.message || '';
    console.error('Fatal measurement error:', msg);
    process.exit(1);
});
