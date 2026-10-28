import { PoolClient } from 'pg';
import { VerifiedPrincipal } from '../identity/types.js';
import { ReasonCode, Decision } from './reasons.js';
import { ROUTE_PERMISSIONS } from './route_map.js';
import { appendAuditLog } from '../audit/append.js';

export interface ResourceFacts {
    workspaceId?: string;
    isMutation?: boolean;
}

export interface ContextQueryRow {
    context_id: string;
    user_id: string;
    session_id: string;
    organisation_id: string;
    organisation_name: string;
    org_status: string;
    portal: 'platform' | 'subscriber';
    tenant_type_key: string | null;
    workspace_id: string;
    workspace_name: string;
    workspace_is_active: boolean;
    membership_id: string;
    membership_status: string;
    membership_expires_at: Date | null;
    role_key: string;
    support_grant_id: string | null;
    grant_expires_at: Date | null;
    grant_revoked_at: Date | null;
    aal: 'aal1' | 'aal2';
    expires_at: Date;
    revoked_at: Date | null;
    is_valid: boolean;
}

/**
 * Gate-based authorization decision engine.
 *
 * Runs Gates 0 through 8:
 *  0. Context validity & session match
 *  1. Organisation active
 *  2. Membership active & unexpired
 *  3. Workspace active & belongs to org
 *  4. Portal match
 *  5. Support grant rules (staff required, read-only mutation block)
 *  6. Tenant type allowed for role
 *  7. Organisation entitlement enabled (subscriber only)
 *  8. Role has required permission & AAL check
 */
export async function decide(
    client: PoolClient,
    principal: VerifiedPrincipal,
    contextId: string,
    routeKey: string,
    resourceFacts?: ResourceFacts
): Promise<Decision> {
    const routeDef = ROUTE_PERMISSIONS[routeKey];
    if (!routeDef) {
        throw new Error(`Unknown route key: ${routeKey}`);
    }

    // Load context facts and run DB-level validation check
    const query = `
        SELECT 
            ac.id AS context_id,
            ac.user_id,
            ac.session_id,
            ac.organisation_id,
            o.name AS organisation_name,
            o.status AS org_status,
            o.portal,
            o.tenant_type_key,
            ac.workspace_id,
            w.name AS workspace_name,
            w.is_active AS workspace_is_active,
            ac.membership_id,
            m.status AS membership_status,
            m.expires_at AS membership_expires_at,
            m.role_key,
            m.role_key,
            ac.support_grant_id,
            sag.expires_at AS grant_expires_at,
            sag.revoked_at AS grant_revoked_at,
            ac.aal_level AS aal,
            ac.expires_at,
            ac.revoked_at,
            public.is_context_valid(ac.id) AS is_valid
        FROM public.access_contexts ac
        JOIN public.organisations o ON o.id = ac.organisation_id
        JOIN public.workspaces w ON w.id = ac.workspace_id AND w.organisation_id = ac.organisation_id
        JOIN public.memberships m ON m.id = ac.membership_id
        LEFT JOIN public.support_access_grants sag ON sag.id = ac.support_grant_id
        WHERE ac.id = $1::uuid;
    `;

    const res = await client.query<ContextQueryRow>(query, [contextId]);
    const row = res.rows[0];

    async function deny(gateFailed: number, reasonCode: ReasonCode, auditReason: string): Promise<Decision> {
        try {
            await appendAuditLog(
                {
                    action: 'AUTH_CONTEXT_DENIED',
                    targetEntity: 'access_contexts',
                    targetId: contextId,
                    userId: principal.id,
                    diff: {
                        gateFailed,
                        reasonCode,
                        auditReason,
                        routeKey
                    }
                },
                client
            );
        } catch {
            // Audit append should not prevent returning decision
        }
        return {
            allow: false,
            gateFailed,
            reasonCode,
            auditReason
        };
    }

    // Gate 0: Context exists, matches principal/session, not expired/revoked, and is_context_valid is true
    if (!row) {
        return deny(0, 'AUTH_CONTEXT_INVALID', 'Access context not found');
    }

    if (row.user_id !== principal.id || row.session_id !== principal.sessionId) {
        return deny(0, 'AUTH_CONTEXT_MISMATCH', 'Context user or session mismatch with verified principal');
    }

    const now = new Date();
    if (row.revoked_at || row.expires_at <= now) {
        // If revocation was triggered by org suspension, report AUTH_ORG_INACTIVE (Gate 1)
        if (row.org_status !== 'ACTIVE') {
            return deny(1, 'AUTH_ORG_INACTIVE', `Organisation status is ${row.org_status}`);
        }
        return deny(0, 'AUTH_CONTEXT_INVALID', 'Access context expired or revoked');
    }

    // Gate 1: Organisation active
    if (row.org_status !== 'ACTIVE') {
        return deny(1, 'AUTH_ORG_INACTIVE', `Organisation status is ${row.org_status}`);
    }

    // Gate 2: Membership active & unexpired
    if (row.membership_status !== 'ACTIVE') {
        return deny(2, 'AUTH_MEMBERSHIP', `Membership status is ${row.membership_status}`);
    }
    if (row.membership_expires_at && row.membership_expires_at <= now) {
        return deny(2, 'AUTH_MEMBERSHIP', 'Membership has expired');
    }

    // Gate 3: Workspace active
    if (!row.workspace_is_active) {
        return deny(3, 'AUTH_WORKSPACE', 'Workspace is inactive');
    }
    if (resourceFacts?.workspaceId && resourceFacts.workspaceId !== row.workspace_id) {
        return deny(3, 'AUTH_WORKSPACE', 'Resource workspace mismatch');
    }

    // Gate 4: Portal match
    if (routeDef.portal !== row.portal) {
        return deny(4, 'AUTH_PORTAL', `Route portal ${routeDef.portal} does not match organisation portal ${row.portal}`);
    }

    // Gate 5: Support grant checks
    if (row.support_grant_id) {
        // Must be unexpired and unrevoked
        if (
            (row.grant_expires_at && row.grant_expires_at <= now) ||
            row.grant_revoked_at !== null
        ) {
            return deny(5, 'AUTH_SUPPORT_GRANT', 'Support access grant is expired or revoked');
        }

        // Support contexts are strictly read-only
        const isMutation = resourceFacts?.isMutation ?? routeDef.isMutation ?? false;
        if (isMutation) {
            return deny(5, 'AUTH_SUPPORT_READ_ONLY', 'Support context cannot perform mutation operations');
        }
    }

    // Gate 6: Role is permitted for organisation's tenant type
    // Support contexts represent platform staff entering a subscriber tenant under a grant, so they are exempt from subscriber role_tenant_types mapping
    if (row.tenant_type_key && !row.support_grant_id) {
        const tenantTypeCheck = await client.query(
            `SELECT 1 FROM public.role_tenant_types WHERE role_key = $1 AND tenant_type_key = $2;`,
            [row.role_key, row.tenant_type_key]
        );
        if (tenantTypeCheck.rowCount === 0) {
            return deny(6, 'AUTH_TENANT_TYPE', `Role ${row.role_key} is not permitted for tenant type ${row.tenant_type_key}`);
        }
    }

    // Gate 7: Subscriber organisation entitlement
    if (row.portal === 'subscriber') {
        const appKey = routeDef.appKey;
        if (appKey) {
            const entCheck = await client.query(
                `SELECT 1 FROM public.organisation_entitlements 
                 WHERE organisation_id = $1::uuid AND app_key = $2 AND is_enabled = true;`,
                [row.organisation_id, appKey]
            );
            if (entCheck.rowCount === 0) {
                return deny(7, 'AUTH_ENTITLEMENT', `Organisation lacks active entitlement for app ${appKey}`);
            }
        } else {
            // General subscriber check: must have at least one active entitlement
            const generalEntCheck = await client.query(
                `SELECT 1 FROM public.organisation_entitlements 
                 WHERE organisation_id = $1::uuid AND is_enabled = true LIMIT 1;`,
                [row.organisation_id]
            );
            if (generalEntCheck.rowCount === 0) {
                return deny(7, 'AUTH_ENTITLEMENT', 'Organisation has no active entitlements');
            }
        }
    }

    // Gate 8: Role has permission & AAL
    // First, check role holds the required permission
    const permCheck = await client.query(
        `SELECT 1 FROM public.role_permissions WHERE role_key = $1 AND permission_key = $2;`,
        [row.role_key, routeDef.permission]
    );
    if (permCheck.rowCount === 0) {
        return deny(8, 'AUTH_PERMISSION', `Role ${row.role_key} does not hold permission ${routeDef.permission}`);
    }

    // Second, verify context AAL meets both role's min_aal and permission's min_aal
    const aalQuery = `
        SELECT 
            r.min_aal AS role_min_aal,
            p.min_aal AS perm_min_aal
        FROM public.roles r
        CROSS JOIN public.permissions p
        WHERE r.key = $1 AND p.key = $2;
    `;
    const aalRes = await client.query<{ role_min_aal: 'aal1' | 'aal2'; perm_min_aal: 'aal1' | 'aal2' }>(
        aalQuery,
        [row.role_key, routeDef.permission]
    );

    if (aalRes.rowCount && aalRes.rowCount > 0) {
        const { role_min_aal, perm_min_aal } = aalRes.rows[0];
        // Note per Backlog Item 8: business_owner MFA is deferred for local demo
        const effectiveRoleMinAal = row.role_key === 'business_owner' ? 'aal1' : role_min_aal;
        const requiredAal = (effectiveRoleMinAal === 'aal2' || perm_min_aal === 'aal2') ? 'aal2' : 'aal1';
        if (requiredAal === 'aal2' && row.aal !== 'aal2') {
            return deny(8, 'AUTH_AAL', `Operation requires AAL2 (role requires ${role_min_aal}, permission requires ${perm_min_aal}, current is ${row.aal})`);
        }
    }

    // Final sanity check: DB is_context_valid must pass
    if (!row.is_valid) {
        return deny(0, 'AUTH_CONTEXT_INVALID', 'Database is_context_valid returned false');
    }

    return {
        allow: true,
        contextId: row.context_id,
        userId: row.user_id,
        organisationId: row.organisation_id,
        organisationName: row.organisation_name,
        workspaceId: row.workspace_id,
        workspaceName: row.workspace_name,
        membershipId: row.membership_id,
        roleKey: row.role_key,
        portal: row.portal,
        tenantTypeKey: row.tenant_type_key,
        aal: row.aal,
        expiresAt: row.expires_at
    };
}
