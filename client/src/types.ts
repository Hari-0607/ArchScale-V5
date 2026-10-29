export type AalLevel = 'aal1' | 'aal2';

export interface VerifiedPrincipal {
  id: string;
  email: string;
  sessionId?: string;
  aal: AalLevel;
  role?: string;
}

export interface UserSession {
  accessToken: string;
  refreshToken?: string;
  principal: VerifiedPrincipal;
  mfaRequired?: boolean;
}

export interface AccessContext {
  contextId: string;
  organisationId: string;
  organisationName?: string;
  workspaceId: string;
  workspaceName?: string;
  aal: AalLevel;
  expiresAt: string;
}

export interface Membership {
  membershipId: string;
  organisationId: string;
  organisationName: string;
  roleKey: string;
  portal: string;
  tenantTypeKey: string;
}

export interface Workspace {
  workspaceId: string;
  workspaceName: string;
  isDefault: boolean;
  isActive: boolean;
}

export interface TeamMember {
  id: string;
  userId: string;
  name: string;
  email: string;
  department: string;
  jobRole: string;
  reportingManagerId?: string;
  reportingManagerName?: string;
  roleKey: string;
  status: 'ACTIVE' | 'SUSPENDED';
}

export interface TaskItem {
  id: string;
  workId: string;
  title: string;
  description: string;
  assignedToId: string;
  assignedToName: string;
  department: string;
  reviewerId: string;
  reviewerName: string;
  startDate: string;
  dueDateTime: string;
  priority: 'Low' | 'Normal' | 'High' | 'Urgent';
  status: 'To Do' | 'In Progress' | 'In Review' | 'Completed';
  approvalStatus: 'Not Required' | 'Pending' | 'Approved' | 'Rejected';
  createdById: string;
  approvedById?: string;
}

export interface AttendanceItem {
  id: string;
  attendanceId: string;
  memberId: string;
  memberName: string;
  department: string;
  date: string;
  checkInTime: string;
  checkOutTime: string;
  status: 'Present' | 'Absent' | 'Half Day' | 'Leave' | 'Holiday' | 'Work From Home';
  remarks?: string;
  hrComments?: Array<{
    id: string;
    author: string;
    text: string;
    timestamp: string;
  }>;
  createdBy: string;
  lastUpdatedBy: string;
}

export interface TenantItem {
  id: string;
  name: string;
  status: 'ACTIVE' | 'SUSPENDED' | 'PENDING';
  tier: string;
  createdAt: string;
  adminEmail: string;
}
