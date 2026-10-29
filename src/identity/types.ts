export type AalLevel = 'aal1' | 'aal2' | 'aal3';

export interface VerifiedPrincipal {
    id: string; // Supabase auth.users.id
    email: string;
    sessionId: string;
    aal: AalLevel;
    issuer: string;
    audience: string;
    expiresAt: number; // Unix timestamp (seconds)
}

export interface AuthSession {
    accessToken: string;
    refreshToken: string;
    tokenType: string;
    expiresIn: number;
    principal: VerifiedPrincipal;
}

export interface SignInCredentials {
    email?: string;
    userCode?: string;
    password: string;
}

export interface MfaStatus {
    factors: Array<{
        id: string;
        friendlyName?: string;
        factorType: 'totp';
        status: 'verified' | 'unverified';
    }>;
    currentLevel: AalLevel;
    nextLevel: AalLevel;
}

export interface MfaChallenge {
    id: string;
    expiresAt: number;
}

export interface MfaVerificationResult {
    accessToken: string;
    refreshToken: string;
    aal: AalLevel;
}

export interface IdentityProvider {
    /**
     * Authenticates credentials (via email or user_code alias).
     * Returns an active authenticated session.
     */
    signIn(credentials: SignInCredentials): Promise<AuthSession>;

    /**
     * Cryptographically and statefully validates an access token.
     * Must verify through provider API and assert sub, sessionId, issuer, audience, expiry, and AAL.
     * Never trusts JWT decoding alone.
     */
    verify(token: string): Promise<VerifiedPrincipal>;

    /**
     * Refreshes an expired access token using a valid refresh token.
     */
    refresh(refreshToken: string): Promise<AuthSession>;

    /**
     * Revokes a single user session by ID.
     */
    revokeSession(sessionId: string): Promise<void>;

    /**
     * Revokes all active sessions for a user across all devices.
     */
    revokeAllForUser(userId: string): Promise<void>;

    /**
     * Password recovery contract (Phase 4 deferred implementation).
     */
    requestPasswordReset(email: string): Promise<void>;
    confirmPasswordReset(token: string, newPassword: string): Promise<{ userId: string } | void>;

    /**
     * Multi-factor authentication (MFA) status and verification.
     */
    getMfaStatus(userId: string): Promise<MfaStatus>;
    challengeMfa(factorId: string): Promise<MfaChallenge>;
    verifyMfa(factorId: string, challengeId: string, code: string): Promise<MfaVerificationResult>;
}
