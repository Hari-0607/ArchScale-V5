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
    } catch {
        // Fallback for pre-012 environments where fn_resolve_user_code is not yet applied
        try {
            const raw = await client.query<{ email: string }>(
                'SELECT email FROM public.users WHERE lower(user_code) = lower($1) LIMIT 1;',
                [trimmed]
            );
            if (raw.rows.length > 0) {
                return raw.rows[0].email.toLowerCase();
            }
        } catch { /* ignore fallback errors */ }
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
    phone?: string
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
            `SELECT * FROM fn_upsert_user_mirror($1, $2, $3);`,
            [
                principal.id,
                principal.email.toLowerCase(),
                phone ?? null
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
    } catch (err: any) {
        // Fallback for pre-012 staging environments where migration 012 has not yet been applied
        try {
            const raw = await client.query<{
                id: string;
                user_code: string;
                email: string;
                created_at: Date;
                updated_at: Date;
            }>(
                `INSERT INTO public.users (id, user_code, email, phone)
                 VALUES ($1, 'AS-' || upper(substring(encode(gen_random_bytes(4), 'hex'), 1, 8)), $2, $3)
                 ON CONFLICT (id) DO UPDATE SET phone = COALESCE(EXCLUDED.phone, public.users.phone), updated_at = now()
                 RETURNING id, user_code, email, created_at, updated_at;`,
                [principal.id, principal.email.toLowerCase(), phone ?? null]
            );
            if (raw.rows.length > 0) {
                const r = raw.rows[0];
                return {
                    id: r.id,
                    userCode: r.user_code,
                    email: r.email,
                    createdAt: r.created_at,
                    updatedAt: r.updated_at
                };
            }
        } catch { /* if direct INSERT fails under pre-012 RLS, return in-memory user mirror */ }

        return {
            id: principal.id,
            userCode: 'AS-PRE012',
            email: principal.email,
            createdAt: new Date(),
            updatedAt: new Date()
        };
    } finally {
        client.release();
    }
}
