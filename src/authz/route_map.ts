export interface RoutePermission {
    permission: string;
    portal: 'platform' | 'subscriber';
    appKey?: string;
    deniedRoleKeys?: string[];
    isMutation?: boolean;
}

export const ROUTE_PERMISSIONS: Record<string, RoutePermission> = {
    'platform.organisations.read': {
        permission: 'platform.orgs.read',
        portal: 'platform'
    },
    'org.members.read': {
        permission: 'org.members.read',
        portal: 'subscriber'
    },
    'org.members.invite': {
        permission: 'org.members.invite',
        portal: 'subscriber',
        deniedRoleKeys: ['intern', 'executive'],
        isMutation: true
    },
    'org.audit.read': {
        permission: 'org.audit.read',
        portal: 'subscriber'
    }
};
