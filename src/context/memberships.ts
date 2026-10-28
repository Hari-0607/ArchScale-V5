import { runtimePool } from '../db/index.js';

export interface PrincipalMembership {
    membershipId: string;
    organisationId: string;
    organisationName: string;
    roleKey: string;
    portal: 'platform' | 'subscriber';
    tenantTypeKey: string | null;
}

export interface OrgWorkspace {
    workspaceId: string;
    workspaceName: string;
    isDefault: boolean;
    isActive: boolean;
}

/**
 * Pre-context listing of active organisations and memberships for a verified principal.
 * Invokes fn_list_principal_memberships (SECURITY DEFINER, minimal columns).
 */
export async function listPrincipalMemberships(userId: string, pool: any = runtimePool): Promise<PrincipalMembership[]> {
    if (!userId) return [];

    const client = await pool.connect();
    try {
        const res = await client.query<{
            membership_id: string;
            organisation_id: string;
            organisation_name: string;
            role_key: string;
            portal: 'platform' | 'subscriber';
            tenant_type_key: string | null;
        }>(
            'SELECT * FROM fn_list_principal_memberships($1::uuid);',
            [userId]
        );

        return res.rows.map(r => ({
            membershipId: r.membership_id,
            organisationId: r.organisation_id,
            organisationName: r.organisation_name,
            roleKey: r.role_key,
            portal: r.portal,
            tenantTypeKey: r.tenant_type_key
        }));
    } finally {
        client.release();
    }
}

/**
 * Pre-context listing of active workspaces for a chosen organisation.
 * Invokes fn_list_org_workspaces_for_principal (SECURITY DEFINER, minimal columns).
 */
export async function listOrgWorkspaces(
    userId: string,
    organisationId: string,
    pool: any = runtimePool
): Promise<OrgWorkspace[]> {
    if (!userId || !organisationId) return [];

    const client = await pool.connect();
    try {
        const res = await client.query<{
            workspace_id: string;
            workspace_name: string;
            is_default: boolean;
            is_active: boolean;
        }>(
            'SELECT * FROM fn_list_org_workspaces_for_principal($1::uuid, $2::uuid);',
            [userId, organisationId]
        );

        return res.rows.map(r => ({
            workspaceId: r.workspace_id,
            workspaceName: r.workspace_name,
            isDefault: r.is_default,
            isActive: r.is_active
        }));
    } finally {
        client.release();
    }
}

