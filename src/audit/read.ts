import { runtimePool } from '../db/index.js';

export interface AuditRecord {
    id: string;
    actorUserId: string | null;
    actorMembershipId: string | null;
    organisationId: string | null;
    action: string;
    targetEntity: string;
    targetId: string;
    diff: any;
    createdAt: Date;
}

/**
 * Reads organisation audit logs via fn_read_audit_logs.
 * Must be executed within a valid application context with org.audit.read or platform.audit.read.
 */
export async function readAuditLogs(limit = 50, offset = 0): Promise<AuditRecord[]> {
    const client = await runtimePool.connect();
    try {
        const res = await client.query<{
            id: string;
            actor_user_id: string | null;
            actor_membership_id: string | null;
            organisation_id: string | null;
            action: string;
            target_entity: string;
            target_id: string;
            diff: any;
            created_at: Date;
        }>(
            'SELECT * FROM fn_read_audit_logs($1::int, $2::int);',
            [limit, offset]
        );

        return res.rows.map(r => ({
            id: r.id,
            actorUserId: r.actor_user_id,
            actorMembershipId: r.actor_membership_id,
            organisationId: r.organisation_id,
            action: r.action,
            targetEntity: r.target_entity,
            targetId: r.target_id,
            diff: r.diff,
            createdAt: r.created_at
        }));
    } finally {
        client.release();
    }
}
