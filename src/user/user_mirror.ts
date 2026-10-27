import crypto from 'crypto';
import pg from 'pg';
import { runtimePool } from '../db/index.js';
import { VerifiedPrincipal } from '../identity/types.js';

export interface UserRecord {
    id: string;
    userCode: string;
    email: string;
    phone?: string;
    createdAt: Date;
    updatedAt: Date;
}

export class AuthenticationError extends Error {
    constructor(
        message = 'Invalid login credentials',
        public readonly code = 'AUTH_INVALID_CREDENTIALS',
        public readonly status = 401
    ) {
        super(message);
        this.name = 'AuthenticationError';
    }
}

/**
 * Normalizes identifier input.
 * Accepts an AS-... user_code alias or an email.
 */
export async function resolveUserIdentifier(identifier: string): Promise<string> {
    const trimmed = identifier.trim();

    // Direct email pattern
    if (trimmed.includes('@')) {
        return trimmed.toLowerCase();
    }

    // User code alias pattern (e.g. AS-FNDR, AS-1001, USR-01)
    const client = await runtimePool.connect();
    try {
        const res = await client.query<{ email: string }>(
            'SELECT email FROM users WHERE LOWER(user_code) = LOWER($1) LIMIT 1;',
            [trimmed]
        );
        if (res.rows.length > 0) {
            return res.rows[0].email.toLowerCase();
        }
    } finally {
        client.release();
    }

    // Unresolved alias: Return dummy email to prevent timing/enumeration attacks
    // Downstream signIn will fail with identical timing and generic error
    return `unresolved_${crypto.randomBytes(8).toString('hex')}@archscale.internal`;
}

/**
 * Creates or synchronizes the public.users mirror record on verified login.
 * Never writes to auth.* schema.
 */
export async function syncUserMirror(
    principal: VerifiedPrincipal,
    customUserCode?: string
): Promise<UserRecord> {
    const client = await runtimePool.connect();
    try {
        await client.query('BEGIN;');

        // Check if user already exists by ID or email
        const existing = await client.query<UserRecord>(
            'SELECT id, user_code as "userCode", email, phone, created_at as "createdAt", updated_at as "updatedAt" FROM users WHERE id = $1 OR email = $2 LIMIT 1;',
            [principal.id, principal.email.toLowerCase()]
        );

        if (existing.rows.length > 0) {
            await client.query('COMMIT;');
            return existing.rows[0];
        }

        // Generate canonical user_code if not provided (AS-XXXXXX format)
        const code = customUserCode || `AS-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;

        const inserted = await client.query<UserRecord>(
            `INSERT INTO users (id, user_code, email)
             VALUES ($1, $2, $3)
             ON CONFLICT (email) DO UPDATE
             SET updated_at = now()
             RETURNING id, user_code as "userCode", email, phone, created_at as "createdAt", updated_at as "updatedAt";`,
            [principal.id, code, principal.email.toLowerCase()]
        );

        await client.query('COMMIT;');
        return inserted.rows[0];
    } catch (err) {
        await client.query('ROLLBACK;').catch(() => {});
        throw err;
    } finally {
        client.release();
    }
}
