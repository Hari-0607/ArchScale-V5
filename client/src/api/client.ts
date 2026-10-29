import { AccessContext, AttendanceItem, Membership, TaskItem, TeamMember, TenantItem, UserSession, Workspace } from '../types';

let currentSession: UserSession | null = null;
let currentContext: AccessContext | null = null;

export function setApiSession(session: UserSession | null) {
  currentSession = session;
}

export function setApiContext(context: AccessContext | null) {
  currentContext = context;
}

export function getApiSession() {
  return currentSession;
}

export function getApiContext() {
  return currentContext;
}

function getHeaders(isJson = true, overrideToken?: string): Record<string, string> {
  const headers: Record<string, string> = {};
  if (isJson) headers['Content-Type'] = 'application/json';
  const token = overrideToken || currentSession?.accessToken;
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  if (currentContext?.contextId) {
    headers['X-ArchScale-Context'] = currentContext.contextId;
  }
  return headers;
}

export async function apiRequest<T = any>(
  path: string,
  method = 'GET',
  body?: any,
  overrideToken?: string
): Promise<{ ok: boolean; status: number; data?: T; error?: string }> {
  try {
    const res = await fetch(path, {
      method,
      headers: getHeaders(body !== undefined, overrideToken),
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      return { ok: false, status: res.status, error: data.error || data.message || `HTTP ${res.status}` };
    }
    return { ok: true, status: res.status, data };
  } catch (err: any) {
    return { ok: false, status: 0, error: err.message || 'Network error' };
  }
}

// Auth APIs
export async function signInApi(identifier: string, password: string) {
  const isUserCode = identifier.toUpperCase().startsWith('AS-');
  return apiRequest('/api/session/sign-in', 'POST', {
    password,
    ...(isUserCode ? { userCode: identifier } : { email: identifier }),
  });
}

export async function quickLoginApi(roleKey: string) {
  return apiRequest('/api/demo/quick-login', 'POST', { key: roleKey });
}

export async function verifyMfaApi(code: string, bypass = false, token?: string) {
  return apiRequest('/api/session/mfa/verify', 'POST', { code, bypass }, token);
}

export async function logoutApi() {
  return apiRequest('/api/session/logout', 'POST', {
    contextId: currentContext?.contextId,
  });
}

// Context & Hierarchy
export async function getMembershipsApi(): Promise<{ ok: boolean; memberships?: Membership[]; error?: string }> {
  const res = await apiRequest<{ memberships: Membership[] }>('/api/session/memberships', 'GET');
  return { ok: res.ok, memberships: res.data?.memberships, error: res.error };
}

export async function getWorkspacesApi(organisationId: string): Promise<{ ok: boolean; workspaces?: Workspace[]; error?: string }> {
  const res = await apiRequest<{ workspaces: Workspace[] }>(`/api/session/workspaces?organisationId=${encodeURIComponent(organisationId)}`, 'GET');
  return { ok: res.ok, workspaces: res.data?.workspaces, error: res.error };
}

export async function createContextApi(organisationId: string, workspaceId: string) {
  return apiRequest('/api/session/context', 'POST', { organisationId, workspaceId });
}

export async function renewContextApi(contextId: string) {
  return apiRequest('/api/session/context/renew', 'POST', { contextId });
}

// Team Members
export async function getMembersApi(): Promise<{ ok: boolean; members?: TeamMember[]; error?: string }> {
  const res = await apiRequest<{ data: TeamMember[] }>('/api/org/members', 'GET');
  return { ok: res.ok, members: res.data?.data, error: res.error };
}

export async function updateMemberRoleApi(memberId: string, roleKey: string) {
  return apiRequest(`/api/org/members/${memberId}/role`, 'PATCH', { roleKey });
}

// Invitations
export async function getInvitationsApi() {
  return apiRequest('/api/org/invitations', 'GET');
}

export async function sendInvitationApi(payload: {
  email: string;
  roleKey: string;
  department: string;
  jobRole: string;
  invitationExpiresAt?: string;
  membershipExpiresAt?: string;
}) {
  return apiRequest('/api/org/invitations', 'POST', payload);
}

export async function revokeInvitationApi(invitationId: string) {
  return apiRequest(`/api/org/invitations/${invitationId}/revoke`, 'POST');
}

// Backstage Platform APIs
export async function getPlatformTenantsApi(): Promise<{ ok: boolean; tenants?: TenantItem[]; error?: string }> {
  const res = await apiRequest<{ organisations: TenantItem[] }>('/api/platform/organisations', 'GET');
  return { ok: res.ok, tenants: res.data?.organisations, error: res.error };
}

export async function registerTenantApi(name: string, adminEmail: string) {
  return apiRequest('/api/platform/organisations', 'POST', { name, adminEmail });
}

export async function suspendTenantApi(tenantId: string) {
  return apiRequest(`/api/platform/organisations/${tenantId}/suspend`, 'POST');
}

export async function approveTenantApi(tenantId: string) {
  return apiRequest(`/api/platform/organisations/${tenantId}/approve`, 'POST');
}

// Tasks Application APIs
export async function getTasksApi(): Promise<{ ok: boolean; tasks?: TaskItem[]; error?: string }> {
  const res = await apiRequest<{ tasks: TaskItem[] }>('/api/tasks', 'GET');
  return { ok: res.ok, tasks: res.data?.tasks, error: res.error };
}

export async function createTaskApi(task: Partial<TaskItem>) {
  return apiRequest('/api/tasks', 'POST', task);
}

export async function updateTaskStatusApi(taskId: string, status: string) {
  return apiRequest(`/api/tasks/${taskId}`, 'PATCH', { status });
}

export async function reviewTaskApi(taskId: string, approvalStatus: 'Approved' | 'Rejected') {
  return apiRequest(`/api/tasks/${taskId}/approve`, 'POST', { approvalStatus });
}

// Attendance Application APIs
export async function getAttendanceApi(): Promise<{ ok: boolean; records?: AttendanceItem[]; error?: string }> {
  const res = await apiRequest<{ records: AttendanceItem[] }>('/api/attendance', 'GET');
  return { ok: res.ok, records: res.data?.records, error: res.error };
}

export async function updateAttendanceApi(id: string, payload: { status: string; checkInTime?: string; checkOutTime?: string }) {
  return apiRequest(`/api/attendance/${id}`, 'PATCH', payload);
}

export async function addAttendanceCommentApi(id: string, comment: string) {
  return apiRequest(`/api/attendance/${id}/comment`, 'POST', { comment });
}

