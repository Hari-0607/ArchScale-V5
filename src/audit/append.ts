import { PoolClient } from 'pg';
import { runtimePool } from '../db/index.js';

export interface AuditAppendInput {
    action: string;
    targetEntity: string;
    targetId: string;
    diff?: Record<string, any>;
    userId?: string;
}

/**
 * Appends an entry to the append-only audit trail via fn_audit_append.
 * When a transaction context is active, actor and org are derived from the database row.
 * When no context is active, only allowlisted actions are accepted.
 */
export async function appendAuditLog(
    input: AuditAppendInput,
    client?: PoolClient
): Promise<string> {
    const c = client || (await runtimePool.connect());
    try {
        const diffJson = input.diff ? JSON.stringify(input.diff) : null;
        const res = await c.query<{ fn_audit_append: string }>(
            `SELECT fn_audit_append($1::text, $2::text, $3::text, $4::jsonb, $5::uuid);`,
            [
                input.action,
                input.targetEntity,
                input.targetId,
                diffJson,
                input.userId || null
            ]
        );

        return res.rows[0]?.fn_audit_append;
    } finally {
        if (!client) {
            c.release();
        }
    }
}

