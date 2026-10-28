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
    'org.members.read': {
        path: '/api/org/members',
        method: 'GET',
        kind: 'permission:org.members.read',
        portal: 'subscriber'
    },
    'org.members.invite': {
        path: '/api/org/invitations',
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
    'org.members.read': {
        permission: 'org.members.read',
        portal: 'subscriber'
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

