import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { config } from '../../src/config/env.js';
import { SupabaseProvider } from '../../src/identity/providers/supabase.js';
import { runtimePool } from '../../src/db/index.js';
import { AuthenticationError } from '../../src/user/user_mirror.js';

describe('SupabaseProvider Staging Integration Suite (Real Supabase Auth)', () => {
    let provider: SupabaseProvider;
    let adminSupabase: SupabaseClient;
    let testUserId: string | null = null;

    const testEmail = `test_identity_${Date.now()}@archscale.test`;
    const testPassword = 'ArchScaleSecureTestPass123!';
    const testUserCode = `AS-TINT${Date.now().toString().slice(-4)}`;

    beforeAll(async () => {
        if (config.env !== 'staging') {
            console.warn('Skipping Supabase staging integration tests: ARCHSCALE_ENV is not staging.');
            return;
        }

        provider = new SupabaseProvider();
        adminSupabase = createClient(config.supabaseUrl, config.supabaseServiceRoleKey, {
            auth: { persistSession: false, autoRefreshToken: false }
        });

        // Create isolated test user in Supabase Auth via Admin API
        const { data, error } = await adminSupabase.auth.admin.createUser({
            email: testEmail,
            password: testPassword,
            email_confirm: true,
            user_metadata: { user_code: testUserCode }
        });

        if (error || !data.user) {
            throw new Error(`Failed to create staging test user: ${error?.message}`);
        }
        testUserId = data.user.id;

        // Pre-seed mirror user_code in public.users so alias resolution can be tested
        const client = await runtimePool.connect();
        try {
            await client.query(
                `INSERT INTO users (id, user_code, email)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (email) DO UPDATE SET user_code = $2;`,
                [testUserId, testUserCode, testEmail]
            );
        } finally {
            client.release();
        }
    });

    afterAll(async () => {
        if (testUserId) {
            // Clean up Supabase Auth user via admin API
            await adminSupabase.auth.admin.deleteUser(testUserId).catch(() => {});

            // Clean up public.users test row using admin connection (runtime role has no DELETE privilege)
            const pg = await import('pg');
            const adminClient = new pg.default.Client({
                connectionString: config.supabaseDbAdminUrl,
                ssl: { rejectUnauthorized: false }
            });
            try {
                await adminClient.connect();
                await adminClient.query('DELETE FROM users WHERE id = $1;', [testUserId]);
            } catch {
                // Ignore cleanup errors
            } finally {
                await adminClient.end().catch(() => {});
            }
        }
    });

    it('1. sign-in success: authenticates against real Supabase GoTrue and syncs mirror', async () => {
        const session = await provider.signIn({
            email: testEmail,
            password: testPassword
        });

        expect(session).toBeDefined();
        expect(session.accessToken).toBeTruthy();
        expect(session.refreshToken).toBeTruthy();
        expect(session.principal.id).toBe(testUserId);
        expect(session.principal.email).toBe(testEmail);
        expect(session.principal.aal).toBe('aal1');

        // Live verification through Supabase Auth
        const verified = await provider.verify(session.accessToken);
        expect(verified.id).toBe(testUserId);
        expect(verified.email).toBe(testEmail);
        expect(verified.audience).toBe('authenticated');
    });

    it('2. wrong password: fails against real Supabase and returns generic error', async () => {
        await expect(
            provider.signIn({
                email: testEmail,
                password: 'CompletelyWrongPassword999!'
            })
        ).rejects.toThrowError(AuthenticationError);

        try {
            await provider.signIn({
                email: testEmail,
                password: 'CompletelyWrongPassword999!'
            });
        } catch (err: any) {
            expect(err.code).toBe('AUTH_INVALID_CREDENTIALS');
            expect(err.message).toBe('Invalid login credentials');
        }
    });

    it('3. unknown user: returns identical generic error on non-existent email', async () => {
        try {
            await provider.signIn({
                email: 'completely_nonexistent_user_999@archscale.test',
                password: 'AnyPassword123!'
            });
        } catch (err: any) {
            expect(err.code).toBe('AUTH_INVALID_CREDENTIALS');
            expect(err.message).toBe('Invalid login credentials');
        }
    });

    it('4. user_code alias: resolves AS-... code to email and authenticates successfully', async () => {
        const session = await provider.signIn({
            userCode: testUserCode,
            password: testPassword
        });

        expect(session.principal.id).toBe(testUserId);
        expect(session.principal.email).toBe(testEmail);
    });

    it('5. expired token: verify rejects token with exp in the past', async () => {
        // Construct expired token payload signed with dummy header
        const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
        const payload = Buffer.from(
            JSON.stringify({
                sub: testUserId,
                email: testEmail,
                session_id: 'dummy_sess',
                iss: `${config.supabaseUrl}/auth/v1`,
                aud: 'authenticated',
                exp: Math.floor(Date.now() / 1000) - 3600 // 1 hour ago
            })
        ).toString('base64url');
        const dummyToken = `${header}.${payload}.dummy_signature`;

        await expect(provider.verify(dummyToken)).rejects.toThrowError(AuthenticationError);
    });

    it('6. tampered token: verify rejects modified payload against Supabase Auth service', async () => {
        const session = await provider.signIn({
            email: testEmail,
            password: testPassword
        });

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

    it('7. revoked session: session is revoked via Supabase Admin API and fails verification', async () => {
        const session = await provider.signIn({
            email: testEmail,
            password: testPassword
        });

        // Verified before revocation
        const beforeRevoke = await provider.verify(session.accessToken);
        expect(beforeRevoke.id).toBe(testUserId);

        // Revoke session via Supabase provider API
        await provider.revokeSession(session.accessToken);

        // Verification or refresh after sign-out should fail
        await expect(provider.verify(session.accessToken)).rejects.toThrowError(AuthenticationError);
    });

    it('8. issuer/audience mismatch: verify rejects token with incorrect claims', async () => {
        const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
        const wrongIssPayload = Buffer.from(
            JSON.stringify({
                sub: testUserId,
                email: testEmail,
                iss: 'https://foreign-service.example.com/auth/v1',
                aud: 'authenticated',
                exp: Math.floor(Date.now() / 1000) + 3600
            })
        ).toString('base64url');
        const wrongIssToken = `${header}.${wrongIssPayload}.sig`;

        await expect(provider.verify(wrongIssToken)).rejects.toThrowError(AuthenticationError);
    });
});
