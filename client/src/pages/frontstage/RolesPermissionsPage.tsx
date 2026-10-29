import React, { useState } from 'react';
import { PageHeader } from '../../components/PageHeader';
import { Badge } from '../../components/Badge';
import { FormField, SelectInput } from '../../components/FormField';
import { useSession } from '../../hooks/useSession';

interface PersonaDef {
  id: string;
  name: string;
  email: string;
  role: string;
  dept: string;
  jobRole: string;
  reportsTo: string;
  taskVisibility: string;
  canCreateTask: boolean;
  canApproveTask: boolean;
  attendanceAccess: 'Full Edit' | 'Comment Only' | 'Denied' | 'Audited View';
  canManageTeam: boolean;
  canInvite: boolean;
}

const TEAM_PERSONAS: PersonaDef[] = [
  {
    id: 'mem-admin',
    name: 'Tenant Admin',
    email: 'admin@studio.archscale',
    role: 'business_owner',
    dept: 'Management',
    jobRole: 'Studio Owner',
    reportsTo: 'Platform Super Admin',
    taskVisibility: 'All tenant tasks (Full visibility)',
    canCreateTask: true,
    canApproveTask: true,
    attendanceAccess: 'Denied',
    canManageTeam: true,
    canInvite: true,
  },
  {
    id: 'mem-dm1',
    name: 'Design Manager 1',
    email: 'dm1@studio.archscale',
    role: 'leader',
    dept: 'Design',
    jobRole: 'Lead Architect',
    reportsTo: 'Tenant Admin',
    taskVisibility: 'Cross-team Design: all 3 design teams (Section 09)',
    canCreateTask: true,
    canApproveTask: true,
    attendanceAccess: 'Denied',
    canManageTeam: false,
    canInvite: false,
  },
  {
    id: 'mem-jd1',
    name: 'Junior Designer 1',
    email: 'jd1@studio.archscale',
    role: 'intern',
    dept: 'Design',
    jobRole: 'Junior Architect',
    reportsTo: 'Design Manager 1',
    taskVisibility: 'Own assigned tasks only (Section 08)',
    canCreateTask: false,
    canApproveTask: false,
    attendanceAccess: 'Denied',
    canManageTeam: false,
    canInvite: false,
  },
  {
    id: 'mem-dm2',
    name: 'Design Manager 2',
    email: 'dm2@studio.archscale',
    role: 'leader',
    dept: 'Design',
    jobRole: 'MEP Design Lead',
    reportsTo: 'Tenant Admin',
    taskVisibility: 'Cross-team Design: all 3 design teams (Section 09)',
    canCreateTask: true,
    canApproveTask: true,
    attendanceAccess: 'Denied',
    canManageTeam: false,
    canInvite: false,
  },
  {
    id: 'mem-jd2',
    name: 'Junior Designer 2',
    email: 'jd2@studio.archscale',
    role: 'intern',
    dept: 'Design',
    jobRole: 'CAD Technician',
    reportsTo: 'Design Manager 2',
    taskVisibility: 'Own assigned tasks only (Section 08)',
    canCreateTask: false,
    canApproveTask: false,
    attendanceAccess: 'Denied',
    canManageTeam: false,
    canInvite: false,
  },
  {
    id: 'mem-dm3',
    name: 'Design Manager 3',
    email: 'dm3@studio.archscale',
    role: 'leader',
    dept: 'Design',
    jobRole: 'Landscape Design Lead',
    reportsTo: 'Tenant Admin',
    taskVisibility: 'Cross-team Design: all 3 design teams (Section 09)',
    canCreateTask: true,
    canApproveTask: true,
    attendanceAccess: 'Denied',
    canManageTeam: false,
    canInvite: false,
  },
  {
    id: 'mem-jd3',
    name: 'Junior Designer 3',
    email: 'jd3@studio.archscale',
    role: 'intern',
    dept: 'Design',
    jobRole: '3D Visualizer',
    reportsTo: 'Design Manager 3',
    taskVisibility: 'Own assigned tasks only (Section 08)',
    canCreateTask: false,
    canApproveTask: false,
    attendanceAccess: 'Denied',
    canManageTeam: false,
    canInvite: false,
  },
  {
    id: 'mem-acc-m',
    name: 'Accounts Manager',
    email: 'accm@studio.archscale',
    role: 'manager_coordinator',
    dept: 'Accounts',
    jobRole: 'Finance Controller',
    reportsTo: 'Tenant Admin',
    taskVisibility: 'Accounts department tasks only (Section 08)',
    canCreateTask: true,
    canApproveTask: true,
    attendanceAccess: 'Denied',
    canManageTeam: false,
    canInvite: false,
  },
  {
    id: 'mem-acc-j',
    name: 'Junior Accountant',
    email: 'accj@studio.archscale',
    role: 'intern',
    dept: 'Accounts',
    jobRole: 'Billing Specialist',
    reportsTo: 'Accounts Manager',
    taskVisibility: 'Own assigned tasks only (Section 08)',
    canCreateTask: false,
    canApproveTask: false,
    attendanceAccess: 'Denied',
    canManageTeam: false,
    canInvite: false,
  },
  {
    id: 'mem-hr-m',
    name: 'HR Manager',
    email: 'hrm@studio.archscale',
    role: 'manager_coordinator',
    dept: 'HR',
    jobRole: 'People & Culture Lead',
    reportsTo: 'Tenant Admin',
    taskVisibility: 'HR department tasks only (Section 08)',
    canCreateTask: true,
    canApproveTask: true,
    attendanceAccess: 'Full Edit',
    canManageTeam: false,
    canInvite: false,
  },
  {
    id: 'mem-hr-j',
    name: 'Junior HR',
    email: 'hrj@studio.archscale',
    role: 'intern',
    dept: 'HR',
    jobRole: 'HR Coordinator',
    reportsTo: 'HR Manager',
    taskVisibility: 'Own assigned tasks only (Section 08)',
    canCreateTask: false,
    canApproveTask: false,
    attendanceAccess: 'Comment Only',
    canManageTeam: false,
    canInvite: false,
  },
];

export const RolesPermissionsPage: React.FC = () => {
  const { session } = useSession();
  const [selectedMemberId, setSelectedMemberId] = useState('mem-admin');
  const [crossTeamActive, setCrossTeamActive] = useState(true);
  const [attendanceEnforced, setAttendanceEnforced] = useState(true);

  const selected = TEAM_PERSONAS.find(p => p.id === selectedMemberId) ?? TEAM_PERSONAS[0];
  const activeRole = session?.demoPersona?.role ?? session?.principal.role;
  const isTenantAdmin = activeRole === 'business_owner' || activeRole === 'founder';

  return (
    <div className="page-body">
      <PageHeader
        title="Roles & Permissions"
        subtitle="Reusable RBAC Controller & Access Policy Configuration (Assignment Section 12 & 13)"
      />

      {/* Policy Status Overview Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 'var(--sp-4)', marginBottom: 'var(--sp-6)' }}>
        <div style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)', padding: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <span style={{ fontSize: 'var(--font-size-xs)', fontWeight: 700, textTransform: 'uppercase', color: 'var(--color-text-subtle)' }}>
              Section 09 Policy
            </span>
            <Badge variant="success">ACTIVE</Badge>
          </div>
          <div style={{ fontWeight: 600, fontSize: 'var(--font-size-body)', marginBottom: 4 }}>
            Design Manager Cross-Team Read
          </div>
          <p style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-muted)', margin: 0, lineHeight: 1.4 }}>
            Design Managers 1, 2, and 3 view all Design tasks across teams. Cross-team reassignment and peer editing remain strictly prohibited.
          </p>
        </div>

        <div style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)', padding: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <span style={{ fontSize: 'var(--font-size-xs)', fontWeight: 700, textTransform: 'uppercase', color: 'var(--color-text-subtle)' }}>
              Section 11 Policy
            </span>
            <Badge variant="warning">RESTRICTED</Badge>
          </div>
          <div style={{ fontWeight: 600, fontSize: 'var(--font-size-body)', marginBottom: 4 }}>
            Sensitive Attendance Isolation
          </div>
          <p style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-muted)', margin: 0, lineHeight: 1.4 }}>
            Tenant Admin and peer departments are denied access by default. HR Manager can edit; Junior HR is restricted to commenting only.
          </p>
        </div>

        <div style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)', padding: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <span style={{ fontSize: 'var(--font-size-xs)', fontWeight: 700, textTransform: 'uppercase', color: 'var(--color-text-subtle)' }}>
              Section 08 & 14 Policy
            </span>
            <Badge variant="info">ENFORCED</Badge>
          </div>
          <div style={{ fontWeight: 600, fontSize: 'var(--font-size-body)', marginBottom: 4 }}>
            Record Ownership & Approvals
          </div>
          <p style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-muted)', margin: 0, lineHeight: 1.4 }}>
            Task creator is evaluated independently from assignee. Juniors cannot approve work. Changing assignee retains creator audit trail.
          </p>
        </div>
      </div>

      {/* Section 13: Interactive Effective Permissions Inspector */}
      <div style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)', padding: 20, marginBottom: 'var(--sp-6)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12, marginBottom: 16 }}>
          <div>
            <h2 style={{ fontSize: 'var(--font-size-h2)', fontWeight: 700, margin: '0 0 4px 0' }}>
              Preview Effective Permissions
            </h2>
            <p style={{ fontSize: 'var(--font-size-sm)', color: 'var(--color-text-muted)', margin: 0 }}>
              Select any of the 11 team members to preview their active privileges and policy constraints
            </p>
          </div>
          <div style={{ width: 280 }}>
            <FormField label="Select Team Member">
              <SelectInput
                value={selectedMemberId}
                onChange={e => setSelectedMemberId(e.target.value)}
              >
                {TEAM_PERSONAS.map(p => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.jobRole} · {p.dept})
                  </option>
                ))}
              </SelectInput>
            </FormField>
          </div>
        </div>

        {/* Selected Member Profile Card */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, padding: 14, background: 'var(--color-surface-2)', borderRadius: 'var(--radius)', marginBottom: 20 }}>
          <div>
            <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-muted)' }}>Department</div>
            <div style={{ fontWeight: 600, fontSize: 'var(--font-size-body)' }}>{selected.dept}</div>
          </div>
          <div>
            <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-muted)' }}>Job Role</div>
            <div style={{ fontWeight: 600, fontSize: 'var(--font-size-body)' }}>{selected.jobRole}</div>
          </div>
          <div>
            <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-muted)' }}>Reports To</div>
            <div style={{ fontWeight: 600, fontSize: 'var(--font-size-body)' }}>{selected.reportsTo}</div>
          </div>
          <div>
            <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-muted)' }}>RBAC System Role</div>
            <div><Badge variant="info">{selected.role}</Badge></div>
          </div>
        </div>

        {/* Allowed vs Denied Actions Breakdown */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-4)' }}>
          {/* Allowed */}
          <div style={{ border: '1px solid var(--color-border)', borderRadius: 'var(--radius)', padding: 14 }}>
            <div style={{ fontSize: 'var(--font-size-sm)', fontWeight: 700, color: 'var(--color-success)', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 6 }}>
              <span>✓</span> Allowed Capabilities
            </div>
            <ul style={{ margin: 0, paddingLeft: 18, fontSize: 'var(--font-size-sm)', color: 'var(--color-text)', display: 'flex', flexDirection: 'column', gap: 6 }}>
              <li><strong>Tasks Visibility:</strong> {selected.taskVisibility}</li>
              <li><strong>Task Status Update:</strong> Permitted on assigned tasks</li>
              {selected.canCreateTask && <li><strong>Task Creation:</strong> Authorized to create new tasks in {selected.dept}</li>}
              {selected.canApproveTask && <li><strong>Task Approval Authority:</strong> Authorized to approve/reject tasks</li>}
              {selected.attendanceAccess === 'Full Edit' && <li><strong>Attendance Management:</strong> Full access to view, update statuses/hours, and comment</li>}
              {selected.attendanceAccess === 'Comment Only' && <li><strong>Attendance Access:</strong> Can view all records and append authenticated comments</li>}
              {selected.canManageTeam && <li><strong>Team & Member Admin:</strong> Authorized to assign roles and manage memberships</li>}
              {selected.canInvite && <li><strong>Tenant Invitations:</strong> Authorized to send and revoke workspace invitations</li>}
            </ul>
          </div>

          {/* Denied */}
          <div style={{ border: '1px solid var(--color-border)', borderRadius: 'var(--radius)', padding: 14 }}>
            <div style={{ fontSize: 'var(--font-size-sm)', fontWeight: 700, color: 'var(--color-error)', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 6 }}>
              <span>✗</span> Restricted / Denied Actions
            </div>
            <ul style={{ margin: 0, paddingLeft: 18, fontSize: 'var(--font-size-sm)', color: 'var(--color-text-muted)', display: 'flex', flexDirection: 'column', gap: 6 }}>
              <li><strong>Platform Backstage:</strong> Access denied (Super Admin only)</li>
              {selected.attendanceAccess === 'Denied' && (
                <li><strong>Attendance Module:</strong> Denied by Section 11 Restricted Access Policy</li>
              )}
              {selected.attendanceAccess === 'Comment Only' && (
                <li><strong>Attendance Mutations:</strong> Cannot modify check-in/out times or attendance statuses</li>
              )}
              {!selected.canCreateTask && (
                <li><strong>Task Creation:</strong> Restricted per Section 08 (Juniors cannot create tasks)</li>
              )}
              {!selected.canApproveTask && (
                <li><strong>Task Approval:</strong> Restricted per Section 08 & 14 (Only Managers/Admins approve)</li>
              )}
              {!selected.canManageTeam && (
                <li><strong>Role Elevation / Member Management:</strong> Denied (Restricted to Tenant Admin)</li>
              )}
              {!selected.canInvite && (
                <li><strong>Send Invitations:</strong> Denied (Restricted to Tenant Admin)</li>
              )}
              {selected.dept === 'Design' && selected.role === 'intern' && (
                <li><strong>Peer Tasks:</strong> Cannot view peer junior designers' tasks (isolated per §09)</li>
              )}
            </ul>
          </div>
        </div>
      </div>

      {/* Comprehensive Permission Matrix (Section 11 & 13) */}
      <div style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)', padding: 20 }}>
        <h2 style={{ fontSize: 'var(--font-size-h2)', fontWeight: 700, margin: '0 0 4px 0' }}>
          Foundation Permission Matrix
        </h2>
        <p style={{ fontSize: 'var(--font-size-sm)', color: 'var(--color-text-muted)', marginBottom: 16 }}>
          Comparative capability map across the 4 tenant RBAC roles and Platform Super Admin
        </p>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--font-size-sm)' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid var(--color-border)', textAlign: 'left' }}>
                <th style={{ padding: '8px 12px' }}>Capability / Resource</th>
                <th style={{ padding: '8px 12px' }}>Super Admin</th>
                <th style={{ padding: '8px 12px' }}>Tenant Admin</th>
                <th style={{ padding: '8px 12px' }}>Team Leader (Design)</th>
                <th style={{ padding: '8px 12px' }}>Manager (Accounts/HR)</th>
                <th style={{ padding: '8px 12px' }}>Junior / Member</th>
              </tr>
            </thead>
            <tbody>
              <tr style={{ borderBottom: '1px solid var(--color-border)' }}>
                <td style={{ padding: '8px 12px', fontWeight: 600 }}>Backstage (Platform Tenants)</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-success)' }}>Full Access</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-error)' }}>Denied</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-error)' }}>Denied</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-error)' }}>Denied</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-error)' }}>Denied</td>
              </tr>
              <tr style={{ borderBottom: '1px solid var(--color-border)' }}>
                <td style={{ padding: '8px 12px', fontWeight: 600 }}>Team Members Management</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-success)' }}>Full (All Tenants)</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-success)' }}>Full (Tenant)</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-text-muted)' }}>Directory Only</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-text-muted)' }}>Directory Only</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-text-muted)' }}>Directory Only</td>
              </tr>
              <tr style={{ borderBottom: '1px solid var(--color-border)' }}>
                <td style={{ padding: '8px 12px', fontWeight: 600 }}>Tenant Invitations</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-success)' }}>Tenant Admins</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-success)' }}>Tenant Members</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-error)' }}>Denied</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-error)' }}>Denied</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-error)' }}>Denied</td>
              </tr>
              <tr style={{ borderBottom: '1px solid var(--color-border)' }}>
                <td style={{ padding: '8px 12px', fontWeight: 600 }}>Tasks: Visibility Scope</td>
                <td style={{ padding: '8px 12px' }}>Audited / All</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-success)' }}>All Tenant Tasks</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-accent)' }}>All Design Teams (§09)</td>
                <td style={{ padding: '8px 12px' }}>Department Tasks</td>
                <td style={{ padding: '8px 12px' }}>Assigned Only</td>
              </tr>
              <tr style={{ borderBottom: '1px solid var(--color-border)' }}>
                <td style={{ padding: '8px 12px', fontWeight: 600 }}>Tasks: Create & Approve</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-success)' }}>Yes</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-success)' }}>Yes</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-success)' }}>Yes (Dept/Direct)</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-success)' }}>Yes (Dept/Direct)</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-error)' }}>Denied</td>
              </tr>
              <tr style={{ borderBottom: '1px solid var(--color-border)' }}>
                <td style={{ padding: '8px 12px', fontWeight: 600 }}>Attendance: View Records</td>
                <td style={{ padding: '8px 12px' }}>Audited Only</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-error)' }}>Denied (§11)</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-error)' }}>Denied (§11)</td>
                <td style={{ padding: '8px 12px' }}>HR Only (Others Denied)</td>
                <td style={{ padding: '8px 12px' }}>HR Only (Others Denied)</td>
              </tr>
              <tr>
                <td style={{ padding: '8px 12px', fontWeight: 600 }}>Attendance: Edit Records</td>
                <td style={{ padding: '8px 12px' }}>Audited Only</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-error)' }}>Denied (§11)</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-error)' }}>Denied (§11)</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-success)' }}>HR Manager: Yes</td>
                <td style={{ padding: '8px 12px', color: 'var(--color-warning)' }}>Junior HR: Comment Only</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

