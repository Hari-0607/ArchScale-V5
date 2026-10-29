/**
 * Route declarations and permission bindings for ArchScale HTTP Server.
 * All registered endpoints (public, session, and permission-gated) are enumerated here.
 */

export type RouteKind = 'public' | 'session' | `permission:${string}`;

export interface ServerRouteDef {
    path: string;
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
    kind: RouteKind;
    portal?: 'platform' | 'subscriber';
    appKey?: string;
    isMutation?: boolean;
}

export const SERVER_ROUTES: Record<string, ServerRouteDef> = {
    // 1. Public endpoints
    'public.demo': {
        path: '/demo',
        method: 'GET',
        kind: 'public'
    },
    'public.signin': {
        path: '/api/session/sign-in',
        method: 'POST',
        kind: 'public'
    },
    'public.recovery': {
        path: '/api/session/recovery',
        method: 'POST',
        kind: 'public'
    },

    // 2. Pre-context session endpoints (require verified identity token)
    'session.mfa.verify': {
        path: '/api/session/mfa/verify',
        method: 'POST',
        kind: 'session'
    },
    'session.memberships': {
        path: '/api/session/memberships',
        method: 'GET',
        kind: 'session'
    },
    'session.workspaces': {
        path: '/api/session/workspaces',
        method: 'GET',
        kind: 'session'
    },
    'session.context': {
        path: '/api/session/context',
        method: 'POST',
        kind: 'session'
    },
    'session.context.renew': {
        path: '/api/session/context/renew',
        method: 'POST',
        kind: 'session'
    },
    'session.logout': {
        path: '/api/session/logout',
        method: 'POST',
        kind: 'session'
    },
    'session.invitations.accept': {
        path: '/api/invitations/accept',
        method: 'POST',
        kind: 'session'
    },
    'session.me.sessions.list': {
        path: '/api/me/sessions',
        method: 'GET',
        kind: 'session'
    },
    'session.me.sessions.delete_one': {
        path: '/api/me/sessions/:id',
        method: 'DELETE',
        kind: 'session'
    },
    'session.me.sessions.delete_all': {
        path: '/api/me/sessions',
        method: 'DELETE',
        kind: 'session'
    },

    // 3. Authenticated context endpoints (require valid X-ArchScale-Context)
    'context.me': {
        path: '/api/me',
        method: 'GET',
        kind: 'session' // Needs valid context only, no specific route permission
    },
    'platform.organisations.read': {
        path: '/api/platform/organisations',
        method: 'GET',
        kind: 'permission:platform.organisations.read',
        portal: 'platform'
    },
    'platform.organisations.get_one': {
        path: '/api/platform/organisations/:id',
        method: 'GET',
        kind: 'permission:platform.organisations.read',
        portal: 'platform'
    },
    'platform.organisations.create': {
        path: '/api/platform/organisations',
        method: 'POST',
        kind: 'permission:platform.organisations.manage',
        portal: 'platform',
        isMutation: true
    },
    'platform.organisations.approve': {
        path: '/api/platform/organisations/:id/approve',
        method: 'POST',
        kind: 'permission:platform.organisations.manage',
        portal: 'platform',
        isMutation: true
    },
    'platform.organisations.suspend': {
        path: '/api/platform/organisations/:id/suspend',
        method: 'POST',
        kind: 'permission:platform.organisations.manage',
        portal: 'platform',
        isMutation: true
    },
    'platform.organisations.invite_admin': {
        path: '/api/platform/organisations/:id/invite-admin',
        method: 'POST',
        kind: 'permission:platform.organisations.manage',
        portal: 'platform',
        isMutation: true
    },
    'platform.support.grants.create': {
        path: '/api/platform/support/grants',
        method: 'POST',
        kind: 'permission:platform.support.manage',
        portal: 'platform',
        isMutation: true
    },
    'platform.support.grants.revoke': {
        path: '/api/platform/support/grants/:id/revoke',
        method: 'POST',
        kind: 'permission:platform.support.manage',
        portal: 'platform',
        isMutation: true
    },
    'platform.audit.read': {
        path: '/api/platform/audit',
        method: 'GET',
        kind: 'permission:platform.audit.read',
        portal: 'platform'
    },
    'org.members.read': {
        path: '/api/org/members',
        method: 'GET',
        kind: 'permission:org.members.read',
        portal: 'subscriber'
    },
    'org.members.role.update': {
        path: '/api/org/members/:id/role',
        method: 'PATCH',
        kind: 'permission:org.members.manage',
        portal: 'subscriber',
        isMutation: true
    },
    'org.members.suspend': {
        path: '/api/org/members/:id/suspend',
        method: 'POST',
        kind: 'permission:org.members.manage',
        portal: 'subscriber',
        isMutation: true
    },
    'org.members.reactivate': {
        path: '/api/org/members/:id/reactivate',
        method: 'POST',
        kind: 'permission:org.members.manage',
        portal: 'subscriber',
        isMutation: true
    },
    'org.members.profile.update': {
        path: '/api/org/members/:id/profile',
        method: 'PATCH',
        kind: 'permission:org.members.manage',
        portal: 'subscriber',
        isMutation: true
    },
    'org.settings.mfa': {
        path: '/api/org/settings/mfa',
        method: 'POST',
        kind: 'permission:org.settings.manage',
        portal: 'subscriber',
        isMutation: true
    },
    'org.invitations.list': {
        path: '/api/org/invitations',
        method: 'GET',
        kind: 'permission:org.members.invite',
        portal: 'subscriber'
    },
    'org.members.invite': {
        path: '/api/org/invitations',
        method: 'POST',
        kind: 'permission:org.members.invite',
        portal: 'subscriber',
        isMutation: true
    },
    'org.invitations.revoke': {
        path: '/api/org/invitations/:id/revoke',
        method: 'POST',
        kind: 'permission:org.members.invite',
        portal: 'subscriber',
        isMutation: true
    },
    'org.invitations.resend': {
        path: '/api/org/invitations/:id/resend',
        method: 'POST',
        kind: 'permission:org.members.invite',
        portal: 'subscriber',
        isMutation: true
    },
    'org.audit.read': {
        path: '/api/org/audit',
        method: 'GET',
        kind: 'permission:org.audit.read',
        portal: 'subscriber'
    }
};

/**
 * Legacy permission-only map used by decide()
 */
export interface RoutePermission {
    permission: string;
    portal: 'platform' | 'subscriber';
    appKey?: string;
    isMutation?: boolean;
}

export const ROUTE_PERMISSIONS: Record<string, RoutePermission> = {
    'platform.organisations.read': {
        permission: 'platform.organisations.read',
        portal: 'platform'
    },
    'platform.organisations.manage': {
        permission: 'platform.organisations.manage',
        portal: 'platform',
        isMutation: true
    },
    'platform.support.manage': {
        permission: 'platform.support.manage',
        portal: 'platform',
        isMutation: true
    },
    'platform.support.read': {
        permission: 'platform.support.read',
        portal: 'platform'
    },
    'platform.audit.read': {
        permission: 'platform.audit.read',
        portal: 'platform'
    },
    'org.members.read': {
        permission: 'org.members.read',
        portal: 'subscriber'
    },
    'org.members.manage': {
        permission: 'org.members.manage',
        portal: 'subscriber',
        isMutation: true
    },
    'org.settings.manage': {
        permission: 'org.settings.manage',
        portal: 'subscriber',
        isMutation: true
    },
    'org.members.invite': {
        permission: 'org.members.invite',
        portal: 'subscriber',
        isMutation: true
    },
    'org.audit.read': {
        permission: 'org.audit.read',
        portal: 'subscriber'
    }
};

