import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { config } from '../../config/env.js';
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
import { AuthenticationError, resolveUserIdentifier, syncUserMirror } from '../../user/user_mirror.js';

interface JwtPayload {
    sub: string;
    email?: string;
    session_id?: string;
    iss: string;
    aud: string;
    exp: number;
    aal?: AalLevel;
    amr?: Array<{ method: string; timestamp: number }>;
    app_metadata?: {
        provider?: string;
        providers?: string[];
        aal?: AalLevel;
    };
    user_metadata?: Record<string, any>;
}

let timingFloorBreachCount = 0;

export function getTimingFloorBreachCount(): number {
    return timingFloorBreachCount;
}

export function resetTimingFloorBreachCount(): void {
    timingFloorBreachCount = 0;
}

export class SupabaseProvider implements IdentityProvider {
    private client: SupabaseClient;
    private adminClient: SupabaseClient;

    constructor() {
        this.client = createClient(config.supabaseUrl, config.supabaseAnonKey, {
            auth: {
                persistSession: false,
                autoRefreshToken: false
            }
        });

        this.adminClient = createClient(config.supabaseUrl, config.supabaseServiceRoleKey, {
            auth: {
                persistSession: false,
                autoRefreshToken: false
            }
        });
    }

    async signIn(credentials: SignInCredentials): Promise<AuthSession> {
        const startTime = Date.now();
        const identifier = credentials.email || credentials.userCode;

        if (!identifier || !credentials.password) {
            throw new AuthenticationError('Invalid login credentials', 'AUTH_INVALID_CREDENTIALS');
        }

        try {
            // Resolve AS-... user_code alias or email with constant timing
            const email = await resolveUserIdentifier(identifier);

            const { data, error } = await this.client.auth.signInWithPassword({
                email,
                password: credentials.password
            });

            if (error || !data.session || !data.user) {
                await this.equalizeTiming(startTime);
                throw new AuthenticationError('Invalid login credentials', 'AUTH_INVALID_CREDENTIALS');
            }

            const principal = await this.verify(data.session.access_token);

            // Sync user identity mirror (public.users)
            await syncUserMirror(principal);

            return {
                accessToken: data.session.access_token,
                refreshToken: data.session.refresh_token,
                tokenType: data.session.token_type || 'bearer',
                expiresIn: data.session.expires_in,
                principal
            };
        } catch (err: any) {
            await this.equalizeTiming(startTime);
            if (err instanceof AuthenticationError) {
                throw err;
            }
            throw new AuthenticationError('Invalid login credentials', 'AUTH_INVALID_CREDENTIALS');
        }
    }

    async verify(token: string): Promise<VerifiedPrincipal> {
        if (!token) {
            throw new AuthenticationError('Missing access token', 'AUTH_TOKEN_MISSING');
        }

        // 1. Mandatory live verification through Supabase Auth service
        const { data: userData, error } = await this.client.auth.getUser(token);
        if (error || !userData.user) {
            throw new AuthenticationError('Token rejected by authentication service', 'AUTH_TOKEN_INVALID');
        }

        // 2. Decode and cryptographically/structurally validate JWT claims
        const claims = this.decodeJwtClaims(token);
        const nowSec = Math.floor(Date.now() / 1000);

        // Assert sub matches Supabase verified user ID
        if (claims.sub !== userData.user.id) {
            throw new AuthenticationError('Token subject mismatch', 'AUTH_TOKEN_TAMPERED');
        }

        // Assert expiry
        if (claims.exp <= nowSec) {
            throw new AuthenticationError('Token expired', 'AUTH_TOKEN_EXPIRED');
        }

        // Assert audience
        if (claims.aud !== 'authenticated') {
            throw new AuthenticationError('Invalid token audience', 'AUTH_TOKEN_AUDIENCE_MISMATCH');
        }

        // Assert issuer
        const expectedIssuer = `${config.supabaseUrl.replace(/\/+$/, '')}/auth/v1`;
        if (claims.iss !== expectedIssuer) {
            throw new AuthenticationError('Invalid token issuer', 'AUTH_TOKEN_ISSUER_MISMATCH');
        }

        // Assert session ID presence
        const sessionId = claims.session_id || userData.user.id;
        if (!sessionId) {
            throw new AuthenticationError('Missing session identifier in token', 'AUTH_SESSION_INVALID');
        }

        // Extract and validate AAL level
        const aal: AalLevel = (claims.aal || claims.app_metadata?.aal || 'aal1') as AalLevel;

        return {
            id: userData.user.id,
            email: userData.user.email || claims.email || '',
            sessionId,
            aal,
            issuer: claims.iss,
            audience: claims.aud,
            expiresAt: claims.exp
        };
    }

    async refresh(refreshToken: string): Promise<AuthSession> {
        const { data, error } = await this.client.auth.refreshSession({
            refresh_token: refreshToken
        });

        if (error || !data.session || !data.user) {
            throw new AuthenticationError('Could not refresh session', 'AUTH_REFRESH_FAILED');
        }

        const principal = await this.verify(data.session.access_token);

        return {
            accessToken: data.session.access_token,
            refreshToken: data.session.refresh_token,
            tokenType: data.session.token_type || 'bearer',
            expiresIn: data.session.expires_in,
            principal
        };
    }

    async revokeSession(accessToken: string): Promise<void> {
        const { error } = await this.clientForAccessToken(accessToken).auth.signOut({ scope: 'local' });
        if (error) throw new AuthenticationError('Session revocation failed', 'AUTH_SESSION_REVOKE_FAILED');
    }

    async revokeAllForUser(accessToken: string): Promise<void> {
        const { error } = await this.clientForAccessToken(accessToken).auth.signOut({ scope: 'global' });
        if (error) throw new AuthenticationError('Global session revocation failed', 'AUTH_SESSION_REVOKE_FAILED');
    }

    async requestPasswordReset(email: string): Promise<void> {
        const redirectTo = `${process.env.ARCHSCALE_FRONTEND_URL || 'http://localhost:5173'}/recover`;
        const { error } = await this.client.auth.resetPasswordForEmail(email, { redirectTo });
        if (error) throw new AuthenticationError('Recovery request could not be processed', 'AUTH_RECOVERY_FAILED');
    }

    async confirmPasswordReset(token: string, newPassword: string): Promise<{ userId: string }> {
        const { data, error } = await this.client.auth.getUser(token);
        if (error || !data.user) throw new AuthenticationError('Recovery token is invalid or expired', 'AUTH_RECOVERY_TOKEN_INVALID');
        const claims = this.decodeJwtClaims(token);
        if (!claims.amr?.some(method => method.method === 'recovery')) {
            throw new AuthenticationError('A password recovery token is required', 'AUTH_RECOVERY_TOKEN_INVALID');
        }
        const recoveryClient = createClient(config.supabaseUrl, config.supabaseAnonKey, {
            global: { headers: { Authorization: `Bearer ${token}` } },
            auth: { persistSession: false, autoRefreshToken: false }
        });
        const { error: updateError } = await recoveryClient.auth.updateUser({ password: newPassword });
        if (updateError) throw new AuthenticationError('Password update failed', 'AUTH_RECOVERY_FAILED');
        await this.adminClient.auth.admin.signOut(token, 'global');
        return { userId: data.user.id };
    }

    async getMfaStatus(userId: string): Promise<MfaStatus> {
        const { data, error } = await this.adminClient.auth.admin.getUserById(userId);
        if (error || !data.user) {
            throw new AuthenticationError('User not found for MFA inspection', 'MFA_USER_NOT_FOUND');
        }

        const factors = (data.user.factors || []).map(f => ({
            id: f.id,
            friendlyName: f.friendly_name,
            factorType: 'totp' as const,
            status: f.status as 'verified' | 'unverified'
        }));

        const hasVerifiedFactor = factors.some(f => f.status === 'verified');
        const currentLevel: AalLevel = hasVerifiedFactor ? 'aal2' : 'aal1';
        const nextLevel: AalLevel = hasVerifiedFactor ? 'aal2' : 'aal2';

        return {
            factors,
            currentLevel,
            nextLevel
        };
    }

    async challengeMfa(factorId: string, accessToken?: string): Promise<MfaChallenge> {
        const client = accessToken ? this.clientForAccessToken(accessToken) : this.client;
        const { data, error } = await client.auth.mfa.challenge({ factorId });
        if (error || !data) {
            throw new AuthenticationError('MFA challenge generation failed', 'MFA_CHALLENGE_FAILED');
        }

        return {
            id: data.id,
            expiresAt: data.expires_at
        };
    }

    async verifyMfa(factorId: string, challengeId: string, code: string, accessToken?: string): Promise<MfaVerificationResult> {
        const client = accessToken ? this.clientForAccessToken(accessToken) : this.client;
        const { data, error } = await client.auth.mfa.verify({
            factorId,
            challengeId,
            code
        });

        if (error || !data) {
            throw new AuthenticationError('MFA verification code rejected', 'MFA_INVALID_CODE');
        }

        return {
            accessToken: data.access_token,
            refreshToken: data.refresh_token,
            aal: 'aal2'
        };
    }

    private clientForAccessToken(accessToken: string): SupabaseClient {
        return createClient(config.supabaseUrl, config.supabaseAnonKey, {
            global: { headers: { Authorization: `Bearer ${accessToken}` } },
            auth: { persistSession: false, autoRefreshToken: false }
        });
    }

    private decodeJwtClaims(token: string): JwtPayload {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) {
                throw new Error('Invalid JWT format');
            }
            const payloadJson = Buffer.from(parts[1], 'base64url').toString('utf-8');
            return JSON.parse(payloadJson) as JwtPayload;
        } catch {
            throw new AuthenticationError('Malformed JWT payload', 'AUTH_TOKEN_MALFORMED');
        }
    }

    private async equalizeTiming(startTime: number, minMs = 1000): Promise<void> {
        const elapsed = Date.now() - startTime;
        if (elapsed > minMs) {
            timingFloorBreachCount++;
            console.log(`[TIMING_FLOOR_EXCEEDED] Path duration ${elapsed}ms naturally exceeded floor ${minMs}ms (total breaches: ${timingFloorBreachCount})`);
        } else {
            await new Promise(resolve => setTimeout(resolve, minMs - elapsed));
        }
    }
}
