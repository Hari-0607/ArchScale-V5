import crypto from 'crypto';
import {
    AalLevel,
    AuthSession,
    IdentityProvider,
    MfaChallenge,
    MfaStatus,
    MfaVerificationResult,
    SignInCredentials,
    VerifiedPrincipal
} from '../types.js';
import { AuthenticationError, syncUserMirror } from '../../user/user_mirror.js';

interface LocalUser {
    id: string;
    email: string;
    userCode: string;
    passwordHash: string;
    aal: AalLevel;
    totpSecret?: string;
    factors: Array<{
        id: string;
        friendlyName?: string;
        factorType: 'totp';
        status: 'verified' | 'unverified';
    }>;
}

interface LocalSession {
    sessionId: string;
    userId: string;
    accessToken: string;
    refreshToken: string;
    expiresAt: number;
    isRevoked: boolean;
    aal: AalLevel;
}

export class LocalProvider implements IdentityProvider {
    private users: Map<string, LocalUser> = new Map();
    private sessions: Map<string, LocalSession> = new Map();
    private challenges: Map<string, { factorId: string; expiresAt: number; code: string }> = new Map();
    private secretKey = crypto.randomBytes(32);

    constructor() {
        // Strict guardrails: LocalProvider refuses to start in non-test or staging environments
        if (process.env.NODE_ENV !== 'test') {
            throw new Error('SECURITY VIOLATION: LocalProvider can only be initialized when NODE_ENV=test.');
        }

        if (process.env.ALLOW_LOCAL_AUTH !== 'true') {
            throw new Error('SECURITY VIOLATION: LocalProvider requires explicit ALLOW_LOCAL_AUTH=true flag.');
        }

        const supabaseUrl = process.env.SUPABASE_URL || '';
        const adminDbUrl = process.env.SUPABASE_DB_ADMIN_URL || '';

        if (
            supabaseUrl.includes('supabase.co') ||
            adminDbUrl.includes('pooler.supabase.com') ||
            adminDbUrl.includes('supabase.co')
        ) {
            throw new Error(
                'SECURITY VIOLATION: LocalProvider refused to start because remote Staging credentials or URLs are present.'
            );
        }
    }

    /**
     * Test helper to register an in-memory user for local testing.
     */
    registerTestUser(user: {
        id?: string;
        email: string;
        userCode: string;
        password: string;
        aal?: AalLevel;
        totpSecret?: string;
        hasMfaFactor?: boolean;
    }): LocalUser {
        const id = user.id || crypto.randomUUID();
        const hash = this.hashPassword(user.password);
        const hasFactor = user.hasMfaFactor ?? (user.aal === 'aal2');
        const localUser: LocalUser = {
            id,
            email: user.email.toLowerCase(),
            userCode: user.userCode,
            passwordHash: hash,
            aal: user.aal || 'aal1',
            totpSecret: user.totpSecret,
            factors: hasFactor ? [{
                id: `factor_${crypto.randomBytes(4).toString('hex')}`,
                friendlyName: 'Authenticator App',
                factorType: 'totp',
                status: 'verified'
            }] : []
        };
        this.users.set(localUser.email, localUser);
        this.users.set(localUser.userCode.toLowerCase(), localUser);
        return localUser;
    }

    async signIn(credentials: SignInCredentials): Promise<AuthSession> {
        const startTime = Date.now();
        const identifier = (credentials.email || credentials.userCode || '').toLowerCase().trim();

        const user = this.users.get(identifier);
        const hash = user ? user.passwordHash : this.hashPassword('dummy_password_timing');
        const isValid = user && this.verifyPassword(credentials.password, hash);

        if (!user || !isValid) {
            await this.equalizeTiming(startTime);
            throw new AuthenticationError('Invalid login credentials', 'AUTH_INVALID_CREDENTIALS');
        }

        const sessionId = `sess_${crypto.randomUUID()}`;
        const expiresIn = 3600;
        const expiresAt = Math.floor(Date.now() / 1000) + expiresIn;

        const principal: VerifiedPrincipal = {
            id: user.id,
            email: user.email,
            sessionId,
            aal: user.aal,
            issuer: 'http://localhost:54321/auth/v1',
            audience: 'authenticated',
            expiresAt
        };

        const accessToken = this.signToken(principal);
        const refreshToken = `ref_${crypto.randomBytes(24).toString('hex')}`;

        this.sessions.set(sessionId, {
            sessionId,
            userId: user.id,
            accessToken,
            refreshToken,
            expiresAt,
            isRevoked: false,
            aal: user.aal
        });

        // Mirror user identity in database if DB pool is connected
        try {
            await syncUserMirror(principal);
        } catch {
            // In unit tests without DB, mirror sync can be skipped
        }

        return {
            accessToken,
            refreshToken,
            tokenType: 'bearer',
            expiresIn,
            principal
        };
    }

    async verify(token: string): Promise<VerifiedPrincipal> {
        if (!token) {
            throw new AuthenticationError('Missing access token', 'AUTH_TOKEN_MISSING');
        }

        const principal = this.verifyTokenSignature(token);
        const session = this.sessions.get(principal.sessionId);

        if (!session || session.isRevoked) {
            throw new AuthenticationError('Session revoked or not found', 'AUTH_SESSION_REVOKED');
        }

        const nowSec = Math.floor(Date.now() / 1000);
        if (principal.expiresAt <= nowSec) {
            throw new AuthenticationError('Token expired', 'AUTH_TOKEN_EXPIRED');
        }

        if (principal.audience !== 'authenticated') {
            throw new AuthenticationError('Invalid token audience', 'AUTH_TOKEN_AUDIENCE_MISMATCH');
        }

        if (principal.issuer !== 'http://localhost:54321/auth/v1') {
            throw new AuthenticationError('Invalid token issuer', 'AUTH_TOKEN_ISSUER_MISMATCH');
        }

        return principal;
    }

    async refresh(refreshToken: string): Promise<AuthSession> {
        let foundSession: LocalSession | undefined;
        for (const s of this.sessions.values()) {
            if (s.refreshToken === refreshToken && !s.isRevoked) {
                foundSession = s;
                break;
            }
        }

        if (!foundSession) {
            throw new AuthenticationError('Invalid refresh token', 'AUTH_REFRESH_FAILED');
        }

        const user = Array.from(this.users.values()).find(u => u.id === foundSession!.userId);
        if (!user) {
            throw new AuthenticationError('User not found', 'AUTH_USER_NOT_FOUND');
        }

        const expiresIn = 3600;
        const expiresAt = Math.floor(Date.now() / 1000) + expiresIn;
        const principal: VerifiedPrincipal = {
            id: user.id,
            email: user.email,
            sessionId: foundSession.sessionId,
            aal: foundSession.aal,
            issuer: 'http://localhost:54321/auth/v1',
            audience: 'authenticated',
            expiresAt
        };

        const newAccessToken = this.signToken(principal);
        const newRefreshToken = `ref_${crypto.randomBytes(24).toString('hex')}`;

        foundSession.accessToken = newAccessToken;
        foundSession.refreshToken = newRefreshToken;
        foundSession.expiresAt = expiresAt;

        return {
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
            tokenType: 'bearer',
            expiresIn,
            principal
        };
    }

    async revokeSession(sessionId: string): Promise<void> {
        const session = this.sessions.get(sessionId);
        if (session) {
            session.isRevoked = true;
        }
    }

    async revokeAllForUser(userId: string): Promise<void> {
        for (const s of this.sessions.values()) {
            if (s.userId === userId) {
                s.isRevoked = true;
            }
        }
    }

    async requestPasswordReset(_email: string): Promise<void> {
        // Recovery request accepted silently
        return;
    }

    async confirmPasswordReset(emailOrToken: string, newPassword: string): Promise<{ userId: string }> {
        const user = Array.from(this.users.values()).find(u => u.email === emailOrToken || u.id === emailOrToken);
        if (!user) {
            throw new AuthenticationError('User not found for password reset', 'USER_NOT_FOUND');
        }
        user.passwordHash = await this.hashPassword(newPassword);
        await this.revokeAllForUser(user.id);
        return { userId: user.id };
    }

    async getMfaStatus(userId: string): Promise<MfaStatus> {
        const user = Array.from(this.users.values()).find(u => u.id === userId);
        if (!user) {
            throw new AuthenticationError('User not found for MFA', 'MFA_USER_NOT_FOUND');
        }

        return {
            factors: user.factors,
            currentLevel: user.aal,
            nextLevel: user.aal === 'aal2' ? 'aal2' : 'aal2'
        };
    }

    async challengeMfa(factorId: string): Promise<MfaChallenge> {
        const challengeId = `ch_${crypto.randomBytes(8).toString('hex')}`;
        const expiresAt = Math.floor(Date.now() / 1000) + 300;
        // In local provider, deterministic code for testing is '123456'
        this.challenges.set(challengeId, { factorId, expiresAt, code: '123456' });

        return {
            id: challengeId,
            expiresAt
        };
    }

    async verifyMfa(factorId: string, challengeId: string, code: string, currentSessionId?: string, currentUserId?: string, currentEmail?: string): Promise<MfaVerificationResult> {
        const ch = this.challenges.get(challengeId);
        if (!ch || ch.factorId !== factorId || Date.now() / 1000 > ch.expiresAt) {
            throw new AuthenticationError('Invalid or expired MFA challenge', 'MFA_CHALLENGE_INVALID');
        }

        if (ch.code !== code) {
            throw new AuthenticationError('Invalid MFA verification code', 'MFA_INVALID_CODE');
        }

        this.challenges.delete(challengeId);

        // Keep the same session ID (sid claim) as verified on staging
        const sid = currentSessionId || `sess_elevated_${challengeId}`;
        const uid = currentUserId || `usr_elevated_${factorId}`;
        const email = currentEmail || 'elevated@archscale.local';

        const elevatedPrincipal: VerifiedPrincipal = {
            id: uid,
            email: email,
            sessionId: sid,
            aal: 'aal2',
            issuer: 'http://localhost:54321/auth/v1',
            audience: 'authenticated',
            expiresAt: Math.floor(Date.now() / 1000) + 3600
        };

        const session = this.sessions.get(sid);
        if (session) {
            session.aal = 'aal2';
        }

        const accessToken = this.signToken(elevatedPrincipal);
        const refreshToken = `ref_${crypto.randomBytes(24).toString('hex')}`;

        return {
            accessToken,
            refreshToken,
            aal: 'aal2'
        };
    }

    // Helper to generate a token with custom claims (used to test invalid issuer, audience, expired, etc.)
    generateTokenWithCustomClaims(claims: Partial<VerifiedPrincipal>): string {
        const full: VerifiedPrincipal = {
            id: claims.id || crypto.randomUUID(),
            email: claims.email || 'test@archscale.local',
            sessionId: claims.sessionId || `sess_${crypto.randomUUID()}`,
            aal: claims.aal || 'aal1',
            issuer: claims.issuer || 'http://localhost:54321/auth/v1',
            audience: claims.audience || 'authenticated',
            expiresAt: claims.expiresAt !== undefined ? claims.expiresAt : Math.floor(Date.now() / 1000) + 3600
        };

        // If not already in session map, record it
        if (!this.sessions.has(full.sessionId)) {
            this.sessions.set(full.sessionId, {
                sessionId: full.sessionId,
                userId: full.id,
                accessToken: '',
                refreshToken: 'dummy_ref',
                expiresAt: full.expiresAt,
                isRevoked: false,
                aal: full.aal
            });
        }

        return this.signToken(full);
    }

    private signToken(principal: VerifiedPrincipal): string {
        const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
        const payload = Buffer.from(JSON.stringify({
            sub: principal.id,
            email: principal.email,
            session_id: principal.sessionId,
            aal: principal.aal,
            iss: principal.issuer,
            aud: principal.audience,
            exp: principal.expiresAt
        })).toString('base64url');

        const signature = crypto
            .createHmac('sha256', this.secretKey)
            .update(`${header}.${payload}`)
            .digest('base64url');

        return `${header}.${payload}.${signature}`;
    }

    private verifyTokenSignature(token: string): VerifiedPrincipal {
        const parts = token.split('.');
        if (parts.length !== 3) {
            throw new AuthenticationError('Malformed token structure', 'AUTH_TOKEN_MALFORMED');
        }

        const [header, payload, signature] = parts;
        const expectedSig = crypto
            .createHmac('sha256', this.secretKey)
            .update(`${header}.${payload}`)
            .digest('base64url');

        if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
            throw new AuthenticationError('Cryptographic signature verification failed', 'AUTH_TOKEN_TAMPERED');
        }

        const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf-8'));
        return {
            id: parsed.sub,
            email: parsed.email,
            sessionId: parsed.session_id,
            aal: parsed.aal,
            issuer: parsed.iss,
            audience: parsed.aud,
            expiresAt: parsed.exp
        };
    }

    private hashPassword(password: string): string {
        const salt = crypto.randomBytes(16).toString('hex');
        const hash = crypto.scryptSync(password, salt, 32).toString('hex');
        return `${salt}:${hash}`;
    }

    private verifyPassword(password: string, combinedHash: string): boolean {
        const [salt, key] = combinedHash.split(':');
        if (!salt || !key) return false;
        const testHash = crypto.scryptSync(password, salt, 32).toString('hex');
        return crypto.timingSafeEqual(Buffer.from(key), Buffer.from(testHash));
    }

    private async equalizeTiming(startTime: number, minMs = 50): Promise<void> {
        const elapsed = Date.now() - startTime;
        if (elapsed < minMs) {
            await new Promise(resolve => setTimeout(resolve, minMs - elapsed));
        }
    }
}
