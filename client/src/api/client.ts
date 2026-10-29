import { XAuthClient, ApiResult } from '../../../sdk/src/index.js';

// Access tokens stay in memory. The same SDK contract can be consumed by the
// independent Tasks and Attendance apps without copying authentication logic.
let _token: string | null = null;
let _contextId: string | null = null;
let _demoPersona: { role: string; dept: string; memberId: string; title: string } | null = null;
const xauth = new XAuthClient({
  baseURL: import.meta.env.VITE_API_URL || '',
  onUnauthorized: () => window.dispatchEvent(new Event('xauth:unauthorized')),
});

export function setToken(t: string | null): void { _token = t; xauth.setAccessToken(t); }
export function setRefreshToken(t: string | null): void { xauth.setRefreshToken(t); }
export function setContextId(c: string | null): void { _contextId = c; xauth.setContext(c); }
// Display-only test persona metadata. It is never sent to the API or used for authorization.
export function setDemoPersona(p: typeof _demoPersona): void { _demoPersona = p; }
export function getToken(): string | null { return _token; }
export function getContextId(): string | null { return _contextId; }

export async function api<T = unknown>(
  path: string,
  method = 'GET',
  body?: unknown,
  overrideToken?: string
): Promise<ApiResult<T>> {
  return xauth.request<T>(path, method, body, overrideToken);
}

// ── Auth ──────────────────────────────────────────────────────────────────────
export const signIn = (email: string, password: string) =>
  api('/api/session/sign-in', 'POST', { email, password });

export const signInByCode = (userCode: string, password: string) =>
  api('/api/session/sign-in', 'POST', { userCode, password });

export const quickLogin = (key: string) =>
  api('/api/demo/quick-login', 'POST', { key });

export const verifyMfa = (code: string, overrideToken?: string) =>
  api('/api/session/mfa/verify', 'POST', { code }, overrideToken);

export const recovery = (email: string) =>
  api('/api/session/recovery', 'POST', { email });

export const resetPassword = (token: string, newPassword: string) =>
  api('/api/session/reset-password', 'POST', { token, newPassword });

export const acceptInvitation = (token: string, password?: string) =>
  api('/api/invitations/accept', 'POST', { token, password });

export const logout = (contextId?: string) =>
  api('/api/session/logout', 'POST', { contextId });

// ── Session hierarchy ─────────────────────────────────────────────────────────
export const getMemberships = () =>
  api<{ memberships: any[] }>('/api/session/memberships');

export const getWorkspaces = (organisationId: string) =>
  api<{ workspaces: any[] }>(`/api/session/workspaces?organisationId=${encodeURIComponent(organisationId)}`);

export const createContext = (organisationId: string, workspaceId: string) =>
  api('/api/session/context', 'POST', { organisationId, workspaceId });

export const renewContext = (contextId: string) =>
  api('/api/session/context/renew', 'POST', { contextId });

// ── Me ────────────────────────────────────────────────────────────────────────
export const getMe = () => api('/api/me');
export const getMeSessions = () => api('/api/me/sessions');
export const deleteMeSession = (id: string) => api(`/api/me/sessions/${id}`, 'DELETE');
export const deleteAllMeSessions = () => api('/api/me/sessions', 'DELETE');

// ── Org: Members ──────────────────────────────────────────────────────────────
export const getMembers = () => api<{ data: any[] }>('/api/org/members');
export const updateMemberRole = (id: string, roleKey: string) =>
  api(`/api/org/members/${id}/role`, 'PATCH', { roleKey });
export const updateMemberProfile = (id: string, payload: unknown) =>
  api(`/api/org/members/${id}/profile`, 'PATCH', payload);
export const suspendMember = (id: string) =>
  api(`/api/org/members/${id}/suspend`, 'POST');
export const reactivateMember = (id: string) =>
  api(`/api/org/members/${id}/reactivate`, 'POST');

// ── Org: Invitations ─────────────────────────────────────────────────────────
export const getInvitations = () => api('/api/org/invitations');
export const sendInvitation = (payload: unknown) =>
  api('/api/org/invitations', 'POST', payload);
export const revokeInvitation = (id: string) =>
  api(`/api/org/invitations/${id}/revoke`, 'POST');
export const resendInvitation = (id: string) =>
  api(`/api/org/invitations/${id}/resend`, 'POST');

// ── Org: Settings ────────────────────────────────────────────────────────────
export const setOrgMfa = (required: boolean) =>
  api('/api/org/settings/mfa', 'POST', { required });
export const getSupportGrants = () => api('/api/org/support-grants');

// ── Platform (Backstage) ──────────────────────────────────────────────────────
export const getPlatformOrgs = () =>
  api<{ organisations: any[] }>('/api/platform/organisations');
export const getPlatformOrg = (id: string) =>
  api(`/api/platform/organisations/${id}`);
export const registerOrg = (name: string, adminEmail: string) =>
  api('/api/platform/organisations', 'POST', { name, adminEmail });
export const suspendOrg = (id: string) =>
  api(`/api/platform/organisations/${id}/suspend`, 'POST');
export const approveOrg = (id: string) =>
  api(`/api/platform/organisations/${id}/approve`, 'POST');
export const inviteOrgAdmin = (id: string, email: string) =>
  api(`/api/platform/organisations/${id}/invite-admin`, 'POST', { email });

export const createSupportGrant = (payload: unknown) =>
  api('/api/platform/support/grants', 'POST', payload);
export const revokeSupportGrant = (id: string) =>
  api(`/api/platform/support/grants/${id}/revoke`, 'POST');

export const getPlatformAudit = (params?: Record<string, string>) => {
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  return api(`/api/platform/audit${qs}`);
};

// ── Tasks ─────────────────────────────────────────────────────────────────────
export const getTasks = () => api<{ tasks: any[] }>('/api/tasks');
export const createTask = (payload: unknown) => api('/api/tasks', 'POST', payload);
export const updateTask = (id: string, payload: unknown) =>
  api(`/api/tasks/${id}`, 'PATCH', payload);
export const approveTask = (id: string, approvalStatus: string) =>
  api(`/api/tasks/${id}/approve`, 'POST', { approvalStatus });

// ── Attendance ────────────────────────────────────────────────────────────────
export const getAttendance = () => api<{ records: any[] }>('/api/attendance');
export const updateAttendance = (id: string, payload: unknown) =>
  api(`/api/attendance/${id}`, 'PATCH', payload);
export const commentAttendance = (id: string, comment: string) =>
  api(`/api/attendance/${id}/comment`, 'POST', { comment });
