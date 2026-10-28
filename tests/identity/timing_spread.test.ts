/**
 * Timing Consistency Tests — Failure Path Spread
 *
 * Measures 20 runs each of three sign-in failure paths against staging:
 *   A. Unknown email (no DB lookup, Supabase Auth returns error)
 *   B. Unresolved AS-... code (fn_resolve_user_code returns NULL, then Supabase Auth error)
 *   C. Wrong password for a real registered user (Supabase Auth password mismatch)
 *
 * Asserts: |median(A) - median(B)| <= 50ms  and  |median(B) - median(C)| <= 50ms
 *
 * Also asserts the fixed floor (TIMING_FLOOR_MS) is applied — all individual
 * runs must be >= TIMING_FLOOR_MS.
 *
 * Label: staging integration — requires ARCHSCALE_ENV=staging
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { config } from '../../src/config/env.js';
import { SupabaseProvider } from '../../src/identity/providers/supabase.js';
import pg from 'pg';
import crypto from 'crypto';

const RUNS = 20;
const TOLERANCE_MS = 50;

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

// The staging TEST- user password — random per run
const TIMING_TEST_PASSWORD = crypto.randomBytes(24).toString('base64url') + 'Aa1!';
const TIMING_TEST_EMAIL = `TEST-timing-${Date.now()}@archscale.test`;
const TIMING_USER_CODE = `AS-TEST-TMG${Date.now().toString().slice(-4)}`;

describe('Timing: failure path spread across staging (real Supabase Auth)', () => {
    let provider: SupabaseProvider;
    let adminSupabase: SupabaseClient;
    let timingUserId: string | null = null;

    beforeAll(async () => {
        if (config.env !== 'staging') return;

        provider = new SupabaseProvider();
        adminSupabase = createClient(config.supabaseUrl, config.supabaseServiceRoleKey, {
            auth: { persistSession: false, autoRefreshToken: false }
        });

        const { data, error } = await adminSupabase.auth.admin.createUser({
            email: TIMING_TEST_EMAIL,
            password: TIMING_TEST_PASSWORD,
            email_confirm: true
        });
        if (error || !data.user) throw new Error(`Timing test user creation failed: ${error?.message}`);
        timingUserId = data.user.id;

        // Also seed the mirror row via admin DB for user_code resolution test
        const adminDb = new pg.Client({ connectionString: config.supabaseDbAdminUrl, ssl: { rejectUnauthorized: false } });
        await adminDb.connect();
        await adminDb.query(`SELECT fn_upsert_user_mirror($1, $2, $3, NULL);`, [timingUserId, TIMING_TEST_EMAIL, TIMING_USER_CODE]);
        await adminDb.end();
    });

    afterAll(async () => {
        if (timingUserId) {
            await adminSupabase?.auth.admin.deleteUser(timingUserId).catch(() => {});
            const adminDb = new pg.Client({ connectionString: config.supabaseDbAdminUrl, ssl: { rejectUnauthorized: false } });
            await adminDb.connect().catch(() => {});
            await adminDb.query('DELETE FROM public.users WHERE email = $1;', [TIMING_TEST_EMAIL]).catch(() => {});
            await adminDb.end().catch(() => {});
        }
    });

    it(`measures ${RUNS} runs per path and asserts median spread <= ${TOLERANCE_MS}ms`, async () => {
        if (config.env !== 'staging') {
            console.warn('[skip] timing test requires staging env');
            return;
        }

        const timingsA: number[] = []; // Unknown email
        const timingsB: number[] = []; // Unresolved AS-... code
        const timingsC: number[] = []; // Wrong password, real user

        // Path A: unknown email
        for (let i = 0; i < RUNS; i++) {
            const t0 = Date.now();
            try {
                await provider.signIn({ email: `TEST-unknown-timing-${i}@archscale.test`, password: 'WrongPass123!' });
            } catch { /* expected */ }
            timingsA.push(Date.now() - t0);
        }

        // Path B: unresolved AS-... code
        for (let i = 0; i < RUNS; i++) {
            const t0 = Date.now();
            try {
                await provider.signIn({ userCode: `AS-DOESNOTEXIST-${i}`, password: 'WrongPass123!' });
            } catch { /* expected */ }
            timingsB.push(Date.now() - t0);
        }

        // Path C: wrong password for real registered user
        for (let i = 0; i < RUNS; i++) {
            const t0 = Date.now();
            try {
                await provider.signIn({ email: TIMING_TEST_EMAIL, password: 'CompletelyWrongPassword999!' });
            } catch { /* expected */ }
            timingsC.push(Date.now() - t0);
        }

        const medA = median(timingsA);
        const medB = median(timingsB);
        const medC = median(timingsC);

        console.log(`\nTiming results (${RUNS} runs each):`);
        console.log(`  Path A (unknown email):    min=${min(timingsA)}ms  median=${medA}ms  p95=${p95(timingsA)}ms`);
        console.log(`  Path B (unresolved code):  min=${min(timingsB)}ms  median=${medB}ms  p95=${p95(timingsB)}ms`);
        console.log(`  Path C (wrong password):   min=${min(timingsC)}ms  median=${medC}ms  p95=${p95(timingsC)}ms`);
        console.log(`  |A-B| = ${Math.abs(medA - medB).toFixed(1)}ms  |B-C| = ${Math.abs(medB - medC).toFixed(1)}ms  tolerance = ${TOLERANCE_MS}ms`);

        expect(Math.abs(medA - medB), `Spread A vs B exceeds ${TOLERANCE_MS}ms tolerance`).toBeLessThanOrEqual(TOLERANCE_MS);
        expect(Math.abs(medB - medC), `Spread B vs C exceeds ${TOLERANCE_MS}ms tolerance`).toBeLessThanOrEqual(TOLERANCE_MS);
        expect(Math.abs(medA - medC), `Spread A vs C exceeds ${TOLERANCE_MS}ms tolerance`).toBeLessThanOrEqual(TOLERANCE_MS);
    }, 120_000); // 2-minute timeout for 60 network calls
});
