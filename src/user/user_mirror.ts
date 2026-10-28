import crypto from 'crypto';
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
 * Resolves an AS-... user_code alias to a sign-in email via
 * fn_resolve_user_code (SECURITY DEFINER, search_path = public, pg_temp).
 *
 * The function returns NULL for unknown codes; this function returns a random
 * dummy email so all failure paths take the same code path downstream.
 *
 * Direct raw SELECT on public.users is intentionally absent here.
 */
export async function resolveUserIdentifier(identifier: string): Promise<string> {
    const trimmed = identifier.trim();

    // Direct email — no DB lookup required
    if (trimmed.includes('@')) {
        return trimmed.toLowerCase();
    }

    // AS-... user code: call the SECURITY DEFINER resolver
    const client = await runtimePool.connect();
    try {
        const res = await client.query<{ fn_resolve_user_code: string | null }>(
            'SELECT fn_resolve_user_code($1);',
            [trimmed]
        );
        const email = res.rows[0]?.fn_resolve_user_code ?? null;
        if (email) {
            return email.toLowerCase();
        }
    } finally {
        client.release();
    }

    // Unresolved: return a deterministic-looking dummy so callers see the same
    // code path and timing pad as the wrong-password case.
    return `unresolved_${crypto.randomBytes(8).toString('hex')}@archscale.internal`;
}

/**
 * Creates or synchronises the public.users mirror record on verified login
 * via fn_upsert_user_mirror (SECURITY DEFINER, search_path = public, pg_temp).
 *
 * Only writes id, user_code, email, phone — never roles or tenant data.
 * The INSERT/UPDATE is scoped to the verified principal's own id.
 */
export async function syncUserMirror(
    principal: VerifiedPrincipal,
    customUserCode?: string
): Promise<UserRecord> {
    const client = await runtimePool.connect();
    try {
        const res = await client.query<{
            id: string;
            user_code: string;
            email: string;
            created_at: Date;
            updated_at: Date;
        }>(
            `SELECT * FROM fn_upsert_user_mirror($1, $2, $3, NULL);`,
            [
                principal.id,
                principal.email.toLowerCase(),
                customUserCode ?? null
            ]
        );

        if (res.rows.length === 0) {
            throw new Error(`fn_upsert_user_mirror returned no row for id=${principal.id}`);
        }

        const row = res.rows[0];
        return {
            id: row.id,
            userCode: row.user_code,
            email: row.email,
            createdAt: row.created_at,
            updatedAt: row.updated_at
        };
    } finally {
        client.release();
    }
}
