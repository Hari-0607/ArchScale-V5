/**
 * SupabaseProvider Staging Integration Suite
 *
 * Hygiene rules enforced here:
 *   - Test email and user_code carry TEST- prefix for easy identification
 *   - Password is generated randomly in-memory at startup — never stored, never printed
 *   - A sweep at beforeAll and afterAll removes any leftover TEST-* rows
 *   - Tests 1-8 require ARCHSCALE_ENV=staging and real Supabase credentials
 *   - "local pre-check" tests (marked below) run in local_identity.test.ts
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { config } from '../../src/config/env.js';
import { SupabaseProvider } from '../../src/identity/providers/supabase.js';
import { AuthenticationError } from '../../src/user/user_mirror.js';
import pg from 'pg';
import crypto from 'crypto';

// ---------------------------------------------------------------------------
// Random password — generated in-memory at module load; never stored or printed
// ---------------------------------------------------------------------------
const TEST_RUN_PASSWORD = crypto.randomBytes(24).toString('base64url') + 'Aa1!';

// TEST- prefixed identifiers for easy sweep identification
const TEST_EMAIL = `TEST-staging-${Date.now()}@archscale.test`;
const TEST_USER_CODE = `AS-TEST-${Date.now().toString().slice(-6)}`;

describe('SupabaseProvider Staging Integration Suite (Real Supabase Auth)', () => {
    let provider: SupabaseProvider;
    let adminSupabase: SupabaseClient;
    let adminDbClient: pg.Client;
    let testUserId: string | null = null;

    // -------------------------------------------------------------------------
    // Sweep: remove leftover TEST- rows from previous failed runs
    // -------------------------------------------------------------------------
    async function sweepTestUsers() {
        if (!adminSupabase || !adminDbClient) return;
        try {
            // Sweep Supabase Auth: list users and delete those with TEST- email
            const { data } = await adminSupabase.auth.admin.listUsers({ perPage: 200 });
            if (data?.users) {
                for (const u of data.users) {
                    if (u.email?.startsWith('TEST-') || u.email?.startsWith('test_identity_')) {
                        await adminSupabase.auth.admin.deleteUser(u.id).catch(() => {});
                    }
                }
            }
        } catch { /* sweep errors are non-fatal */ }

        try {
            // Sweep public.users: delete TEST- prefixed rows (admin has DELETE)
            await adminDbClient.query(
                `DELETE FROM public.users WHERE email LIKE 'TEST-%' OR email LIKE 'test_identity_%';`
            );
        } catch { /* sweep errors are non-fatal */ }
    }

    beforeAll(async () => {
        if (config.env !== 'staging' || process.env.ARCHSCALE_STAGING_TESTS !== 'true') {
            console.warn('[skip] Supabase staging integration tests: Requires ARCHSCALE_ENV=staging and ARCHSCALE_STAGING_TESTS=true.');
            return;
        }

        provider = new SupabaseProvider();
        adminSupabase = createClient(config.supabaseUrl, config.supabaseServiceRoleKey, {
            auth: { persistSession: false, autoRefreshToken: false }
        });

        adminDbClient = new pg.Client({
            connectionString: config.supabaseDbAdminUrl,
            ssl: { rejectUnauthorized: false }
        });
        await adminDbClient.connect();

        // Sweep before this run
        await sweepTestUsers();

        // Create isolated test user in Supabase Auth via Admin API
        const { data, error } = await adminSupabase.auth.admin.createUser({
            email: TEST_EMAIL,
            password: TEST_RUN_PASSWORD,
            email_confirm: true,
            user_metadata: { user_code: TEST_USER_CODE }
        });

        if (error || !data.user) {
            throw new Error(`Failed to create staging test user: ${error?.message}`);
        }
        testUserId = data.user.id;

        // Pre-seed mirror row in public.users via admin connection
        await adminDbClient.query(
            `INSERT INTO public.users (id, email, user_code) VALUES ($1, $2, $3)
             ON CONFLICT (id) DO UPDATE SET user_code = EXCLUDED.user_code;`,
            [testUserId, TEST_EMAIL, TEST_USER_CODE]
        );
    });

    afterAll(async () => {
        if (testUserId) {
            await adminSupabase?.auth.admin.deleteUser(testUserId).catch(() => {});
            await adminDbClient?.query('DELETE FROM public.users WHERE id = $1;', [testUserId]).catch(() => {});
        }
        // Final sweep
        await sweepTestUsers();
        await adminDbClient?.end().catch(() => {});
    });

    it('1. sign-in success: authenticates against real Supabase GoTrue and syncs mirror', async () => {
        if (config.env !== 'staging') return;
        const session = await provider.signIn({
            email: TEST_EMAIL,
            password: TEST_RUN_PASSWORD
        });

        expect(session).toBeDefined();
        expect(session.accessToken).toBeTruthy();
        expect(session.refreshToken).toBeTruthy();
        expect(session.principal.id).toBe(testUserId);
        expect(session.principal.email).toBe(TEST_EMAIL.toLowerCase());
        expect(session.principal.aal).toBe('aal1');

        const verified = await provider.verify(session.accessToken);
        expect(verified.id).toBe(testUserId);
        expect(verified.email).toBe(TEST_EMAIL.toLowerCase());
        expect(verified.audience).toBe('authenticated');
    });

    it('2. wrong password: fails against real Supabase and returns generic error', async () => {
        if (config.env !== 'staging') return;
        await expect(
            provider.signIn({ email: TEST_EMAIL, password: 'CompletelyWrongPassword999!' })
        ).rejects.toThrowError(AuthenticationError);

        try {
            await provider.signIn({ email: TEST_EMAIL, password: 'CompletelyWrongPassword999!' });
        } catch (err: any) {
            expect(err.code).toBe('AUTH_INVALID_CREDENTIALS');
            expect(err.message).toBe('Invalid login credentials');
        }
    });

    it('3. unknown user: returns identical generic error on non-existent email', async () => {
        if (config.env !== 'staging') return;
        try {
            await provider.signIn({
                email: 'TEST-completely-nonexistent-999@archscale.test',
                password: 'AnyPassword123!'
            });
        } catch (err: any) {
            expect(err.code).toBe('AUTH_INVALID_CREDENTIALS');
            expect(err.message).toBe('Invalid login credentials');
        }
    });

    it('4. user_code alias: resolves TEST- code to email and authenticates', async () => {
        if (config.env !== 'staging') return;
        const session = await provider.signIn({
            userCode: TEST_USER_CODE,
            password: TEST_RUN_PASSWORD
        });
        expect(session.principal.id).toBe(testUserId);
        expect(session.principal.email).toBe(TEST_EMAIL.toLowerCase());
    });

    it('5. expired token: verify rejects token with exp in the past [local pre-check in local_identity.test.ts]', async () => {
        if (config.env !== 'staging') return;
        const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
        const payload = Buffer.from(
            JSON.stringify({
                sub: testUserId,
                email: TEST_EMAIL,
                session_id: 'dummy_sess',
                iss: `${config.supabaseUrl}/auth/v1`,
                aud: 'authenticated',
                exp: Math.floor(Date.now() / 1000) - 3600
            })
        ).toString('base64url');
        const dummyToken = `${header}.${payload}.dummy_signature`;
        await expect(provider.verify(dummyToken)).rejects.toThrowError(AuthenticationError);
    });

    it('6. tampered token: verify rejects modified payload against Supabase Auth service', async () => {
        if (config.env !== 'staging') return;
        const session = await provider.signIn({ email: TEST_EMAIL, password: TEST_RUN_PASSWORD });
        const parts = session.accessToken.split('.');
        const tamperedPayload = Buffer.from(
            JSON.stringify({
                sub: '00000000-0000-0000-0000-000000000001',
                email: 'hacker@archscale.test',
                iss: `${config.supabaseUrl}/auth/v1`,
                aud: 'authenticated',
                exp: Math.floor(Date.now() / 1000) + 3600
            })
        ).toString('base64url');
        const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;
        await expect(provider.verify(tamperedToken)).rejects.toThrowError(AuthenticationError);
    });

    it('6b. one-character tamper: token with a single character changed in the MIDDLE of the signature fails', async () => {
        if (config.env !== 'staging') return;
        const session = await provider.signIn({ email: TEST_EMAIL, password: TEST_RUN_PASSWORD });
        const parts = session.accessToken.split('.');
        const sig = parts[2];

        // Change the character at the midpoint of the signature segment
        const mid = Math.floor(sig.length / 2);
        const originalChar = sig[mid];
        // Pick a different base64url character
        const replacement = originalChar === 'A' ? 'B' : 'A';
        const tamperedSig = sig.substring(0, mid) + replacement + sig.substring(mid + 1);

        const tamperedToken = `${parts[0]}.${parts[1]}.${tamperedSig}`;
        await expect(provider.verify(tamperedToken)).rejects.toThrowError(AuthenticationError);
    });

    it('7. revoked session: session revoked via Supabase Admin API fails verification', async () => {
        if (config.env !== 'staging') return;
        const session = await provider.signIn({ email: TEST_EMAIL, password: TEST_RUN_PASSWORD });
        const beforeRevoke = await provider.verify(session.accessToken);
        expect(beforeRevoke.id).toBe(testUserId);

        await provider.revokeSession(session.accessToken);
        await expect(provider.verify(session.accessToken)).rejects.toThrowError(AuthenticationError);
    });

    it('8. issuer/audience mismatch: verify rejects token with incorrect claims', async () => {
        if (config.env !== 'staging') return;
        const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
        const wrongIssPayload = Buffer.from(
            JSON.stringify({
                sub: testUserId,
                email: TEST_EMAIL,
                iss: 'https://foreign-service.example.com/auth/v1',
                aud: 'authenticated',
                exp: Math.floor(Date.now() / 1000) + 3600
            })
        ).toString('base64url');
        const wrongIssToken = `${header}.${wrongIssPayload}.sig`;
        await expect(provider.verify(wrongIssToken)).rejects.toThrowError(AuthenticationError);
    });
});
