import { runtimePool } from '../db/index.js';

export interface CreateContextInput {
    userId: string;
    sessionId: string;
    organisationId: string;
    workspaceId: string;
    aal?: 'aal1' | 'aal2';
    supportGrantId?: string;
}

export interface ContextResult {
    contextId: string;
    expiresAt: Date;
}

/**
 * Creates a validated 24h access context via fn_create_access_context.
 * User ID and Session ID MUST be passed from the cryptographic identity token,
 * never from untrusted client request bodies.
 */
export async function createAccessContext(input: CreateContextInput): Promise<ContextResult> {
    const client = await runtimePool.connect();
    try {
        const res = await client.query<{ fn_create_access_context: string }>(
            `SELECT fn_create_access_context(
                $1::uuid,
                $2::text,
                $3::uuid,
                $4::uuid,
                $5::text,
                $6::uuid
            );`,
            [
                input.userId,
                input.sessionId,
                input.organisationId,
                input.workspaceId,
                input.aal || 'aal1',
                input.supportGrantId || null
            ]
        );

        const contextId = res.rows[0]?.fn_create_access_context;
        if (!contextId) {
            throw new Error('AUTH_CONTEXT_DENIED');
        }

        // Fetch the calculated expiry date
        const expRes = await client.query<{ expires_at: Date }>(
            'SELECT expires_at FROM access_contexts WHERE id = $1::uuid;',
            [contextId]
        );

        return {
            contextId,
            expiresAt: expRes.rows[0]?.expires_at || new Date(Date.now() + 24 * 60 * 60 * 1000)
        };
    } catch (err: any) {
        if (err.message && err.message.includes('AUTH_CONTEXT_DENIED')) {
            throw new Error('AUTH_CONTEXT_DENIED');
        }
        throw err;
    } finally {
        client.release();
    }
}

/**
 * Renews an existing valid access context via fn_renew_access_context.
 * Enforces hard 24h cap from initial creation.
 */
export async function renewAccessContext(
    contextId: string,
    userId: string,
    sessionId: string
): Promise<ContextResult> {
    const client = await runtimePool.connect();
    try {
        const res = await client.query<{
            context_id: string;
            expires_at: Date;
        }>(
            `SELECT * FROM fn_renew_access_context($1::uuid, $2::uuid, $3::text);`,
            [contextId, userId, sessionId]
        );

        if (res.rows.length === 0) {
            throw new Error('AUTH_CONTEXT_DENIED');
        }

        return {
            contextId: res.rows[0].context_id,
            expiresAt: res.rows[0].expires_at
        };
    } catch (err: any) {
        if (err.message && err.message.includes('AUTH_CONTEXT_DENIED')) {
            throw new Error('AUTH_CONTEXT_DENIED');
        }
        throw err;
    } finally {
        client.release();
    }
}

/**
 * Revokes an access context via fn_revoke_access_context.
 */
export async function revokeAccessContext(
    contextId: string,
    userId: string,
    sessionId: string
): Promise<boolean> {
    const client = await runtimePool.connect();
    try {
        const res = await client.query<{ fn_revoke_access_context: boolean }>(
            `SELECT fn_revoke_access_context($1::uuid, $2::uuid, $3::text);`,
            [contextId, userId, sessionId]
        );

        return res.rows[0]?.fn_revoke_access_context ?? false;
    } finally {
        client.release();
    }
}

