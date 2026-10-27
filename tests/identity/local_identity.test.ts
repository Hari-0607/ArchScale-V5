import { describe, it, expect, beforeEach } from 'vitest';
import { LocalProvider } from '../../src/identity/providers/local.js';
import { AuthenticationError } from '../../src/user/user_mirror.js';

describe('LocalProvider Identity Unit Tests (LocalProvider & Invariants)', () => {
    let provider: LocalProvider;

    beforeEach(() => {
        process.env.NODE_ENV = 'test';
        process.env.ALLOW_LOCAL_AUTH = 'true';
        delete process.env.SUPABASE_URL;
        delete process.env.SUPABASE_DB_ADMIN_URL;

        provider = new LocalProvider();
        provider.registerTestUser({
            email: 'founder@archscale.test',
            userCode: 'AS-FNDR',
            password: 'CorrectPassword123!',
            aal: 'aal2'
        });
        provider.registerTestUser({
            email: 'member@archscale.test',
            userCode: 'AS-MEMB',
            password: 'MemberPass123!',
            aal: 'aal1'
        });
    });

    it('1. sign-in success: authenticates with valid email and returns valid session', async () => {
        const session = await provider.signIn({
            email: 'founder@archscale.test',
            password: 'CorrectPassword123!'
        });

        expect(session).toBeDefined();
        expect(session.accessToken).toBeTruthy();
        expect(session.refreshToken).toBeTruthy();
        expect(session.tokenType).toBe('bearer');
        expect(session.principal.email).toBe('founder@archscale.test');
        expect(session.principal.aal).toBe('aal2');

        // Verify the issued token
        const verified = await provider.verify(session.accessToken);
        expect(verified.id).toBe(session.principal.id);
        expect(verified.email).toBe('founder@archscale.test');
    });

    it('2. wrong password: fails with generic AUTH_INVALID_CREDENTIALS', async () => {
        await expect(
            provider.signIn({
                email: 'founder@archscale.test',
                password: 'WrongPassword999!'
            })
        ).rejects.toThrowError(AuthenticationError);

        try {
            await provider.signIn({
                email: 'founder@archscale.test',
                password: 'WrongPassword999!'
            });
        } catch (err: any) {
            expect(err.code).toBe('AUTH_INVALID_CREDENTIALS');
            expect(err.message).toBe('Invalid login credentials');
        }
    });

    it('3. unknown user: fails with identical generic AUTH_INVALID_CREDENTIALS', async () => {
        try {
            await provider.signIn({
                email: 'nonexistent@archscale.test',
                password: 'AnyPassword123!'
            });
        } catch (err: any) {
            expect(err.code).toBe('AUTH_INVALID_CREDENTIALS');
            expect(err.message).toBe('Invalid login credentials');
        }
    });

    it('4. user_code alias: authenticates via AS-... user_code instead of email', async () => {
        const session = await provider.signIn({
            userCode: 'AS-FNDR',
            password: 'CorrectPassword123!'
        });

        expect(session.principal.email).toBe('founder@archscale.test');

        const memberSession = await provider.signIn({
            userCode: 'AS-MEMB',
            password: 'MemberPass123!'
        });
        expect(memberSession.principal.email).toBe('member@archscale.test');
    });

    it('5. expired token: verify rejects token with exp in the past', async () => {
        const expiredToken = provider.generateTokenWithCustomClaims({
            email: 'founder@archscale.test',
            expiresAt: Math.floor(Date.now() / 1000) - 120 // Expired 2 minutes ago
        });

        await expect(provider.verify(expiredToken)).rejects.toThrowError(
            expect.objectContaining({ code: 'AUTH_TOKEN_EXPIRED' })
        );
    });

    it('6. tampered token: verify rejects modified token payload or signature', async () => {
        const session = await provider.signIn({
            email: 'founder@archscale.test',
            password: 'CorrectPassword123!'
        });

        const parts = session.accessToken.split('.');
        // Modify payload slightly
        const tamperedPayload = Buffer.from(
            JSON.stringify({ sub: 'forged_sub', email: 'hacker@archscale.test' })
        ).toString('base64url');
        const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

        await expect(provider.verify(tamperedToken)).rejects.toThrowError(
            expect.objectContaining({ code: 'AUTH_TOKEN_TAMPERED' })
        );
    });

    it('7. revoked session: verify rejects token after session revocation', async () => {
        const session = await provider.signIn({
            email: 'founder@archscale.test',
            password: 'CorrectPassword123!'
        });

        // Token is valid initially
        const beforeRevoke = await provider.verify(session.accessToken);
        expect(beforeRevoke.sessionId).toBe(session.principal.sessionId);

        // Revoke the session
        await provider.revokeSession(session.principal.sessionId);

        // Token must now be rejected
        await expect(provider.verify(session.accessToken)).rejects.toThrowError(
            expect.objectContaining({ code: 'AUTH_SESSION_REVOKED' })
        );
    });

    it('8. issuer and audience mismatch: verify rejects tokens with foreign iss/aud', async () => {
        const wrongIssuerToken = provider.generateTokenWithCustomClaims({
            issuer: 'https://rogue-auth.example.com/auth/v1'
        });

        await expect(provider.verify(wrongIssuerToken)).rejects.toThrowError(
            expect.objectContaining({ code: 'AUTH_TOKEN_ISSUER_MISMATCH' })
        );

        const wrongAudienceToken = provider.generateTokenWithCustomClaims({
            audience: 'unauthenticated'
        });

        await expect(provider.verify(wrongAudienceToken)).rejects.toThrowError(
            expect.objectContaining({ code: 'AUTH_TOKEN_AUDIENCE_MISMATCH' })
        );
    });

    it('9. security guardrails: LocalProvider strictly refuses initialization if staging credentials exist', () => {
        process.env.SUPABASE_URL = 'https://avntrnedrhysiqdkmdwc.supabase.co';
        expect(() => new LocalProvider()).toThrow(/SECURITY VIOLATION/);

        delete process.env.SUPABASE_URL;
        process.env.NODE_ENV = 'production';
        expect(() => new LocalProvider()).toThrow(/NODE_ENV=test/);
    });
});
