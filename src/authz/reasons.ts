export type ReasonCode =
    | 'AUTH_CONTEXT_MISMATCH'
    | 'AUTH_CONTEXT_INVALID'
    | 'AUTH_ORG_INACTIVE'
    | 'AUTH_MEMBERSHIP'
    | 'AUTH_WORKSPACE'
    | 'AUTH_PORTAL'
    | 'AUTH_SUPPORT_GRANT'
    | 'AUTH_SUPPORT_READ_ONLY'
    | 'AUTH_TENANT_TYPE'
    | 'AUTH_ENTITLEMENT'
    | 'AUTH_PERMISSION'
    | 'AUTH_AAL';

export interface DecisionAllow {
    allow: true;
    contextId: string;
    userId: string;
    organisationId: string;
    organisationName: string;
    workspaceId: string;
    workspaceName: string;
    membershipId: string;
    roleKey: string;
    portal: 'platform' | 'subscriber';
    tenantTypeKey: string | null;
    aal: 'aal1' | 'aal2';
    expiresAt: Date;
}

export interface DecisionDeny {
    allow: false;
    reasonCode: ReasonCode;
    auditReason: string;
    gateFailed: number;
}

export type Decision = DecisionAllow | DecisionDeny;
