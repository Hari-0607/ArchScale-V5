import React, { useEffect, useState } from 'react';
import { createContextApi, getInvitationsApi, getMembershipsApi, getWorkspacesApi, renewContextApi, revokeInvitationApi, sendInvitationApi, setApiContext } from '../api/client';
import { DataTable, Column } from '../components/DataTable';
import { Drawer } from '../components/Drawer';
import { StatusBadge } from '../components/StatusBadge';
import { AccessContext, Membership, Workspace } from '../types';
import { AttendanceApp } from './AttendanceApp';
import { TasksApp } from './TasksApp';
import { TeamView } from './TeamView';

interface FrontstageViewProps {
  context: AccessContext | null;
  onContextChange: (ctx: AccessContext | null) => void;
}

export const FrontstageView: React.FC<FrontstageViewProps> = ({ context, onContextChange }) => {
  const [activeTab, setActiveTab] = useState<'context' | 'team' | 'tasks' | 'attendance' | 'invitations' | 'rbac'>('context');

  // Context Management State
  const [memberships, setMemberships] = useState<Membership[]>([]);
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [selectedOrgId, setSelectedOrgId] = useState('');
  const [selectedWsId, setSelectedWsId] = useState('');
  const [loadingContext, setLoadingContext] = useState(false);
  const [contextError, setContextError] = useState<string | null>(null);

  // Invitations State
  const [invitations, setInvitations] = useState<any[]>([]);
  const [isInviteOpen, setIsInviteOpen] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('leader');
  const [inviteDept, setInviteDept] = useState('Design');
  const [inviteJobRole, setInviteJobRole] = useState('Architect');

  const loadHierarchy = async () => {
    const memRes = await getMembershipsApi();
    if (memRes.ok && memRes.memberships && memRes.memberships.length > 0) {
      setMemberships(memRes.memberships);
      const firstOrgId = memRes.memberships[0].organisationId;
      setSelectedOrgId(firstOrgId);

      const wsRes = await getWorkspacesApi(firstOrgId);
      if (wsRes.ok && wsRes.workspaces) {
        setWorkspaces(wsRes.workspaces);
        if (wsRes.workspaces.length > 0) {
          setSelectedWsId(wsRes.workspaces[0].workspaceId);
        }
      }
    }
  };

  useEffect(() => {
    loadHierarchy();
  }, []);

  const handleOrgChange = async (orgId: string) => {
    setSelectedOrgId(orgId);
    const wsRes = await getWorkspacesApi(orgId);
    if (wsRes.ok && wsRes.workspaces) {
      setWorkspaces(wsRes.workspaces);
      if (wsRes.workspaces.length > 0) {
        setSelectedWsId(wsRes.workspaces[0].workspaceId);
      }
    }
  };

  const handleActivateContext = async () => {
    if (!selectedOrgId || !selectedWsId) return;
    setLoadingContext(true);
    setContextError(null);
    const res = await createContextApi(selectedOrgId, selectedWsId);
    setLoadingContext(false);

    if (!res.ok) {
      setContextError(res.error || 'Failed to activate access context');
      return;
    }

    const orgMatch = memberships.find((m) => m.organisationId === selectedOrgId);
    const wsMatch = workspaces.find((w) => w.workspaceId === selectedWsId);

    const newContext: AccessContext = {
      contextId: res.data.context.contextId || res.data.context.id,
      organisationId: selectedOrgId,
      organisationName: orgMatch?.organisationName || 'Studio Architecture',
      workspaceId: selectedWsId,
      workspaceName: wsMatch?.workspaceName || 'Main Workspace',
      aal: res.data.context.aal || 'aal2',
      expiresAt: res.data.context.expiresAt || res.data.context.expires_at,
    };

    setApiContext(newContext);
    onContextChange(newContext);
  };

  const handleRenewContext = async () => {
    if (!context) return;
    const res = await renewContextApi(context.contextId);
    if (res.ok) {
      alert('Context renewed successfully!');
    } else {
      alert('Renewal failed: ' + res.error);
    }
  };

  const handleRevokeContext = () => {
    setApiContext(null);
    onContextChange(null);
  };

  // Invitations Logic
  const loadInvitations = async () => {
    if (!context) return;
    const res = await getInvitationsApi();
    if (res.ok) {
      setInvitations(res.data?.invitations || []);
    }
  };

  useEffect(() => {
    if (activeTab === 'invitations') {
      loadInvitations();
    }
  }, [activeTab, context]);

  const handleSendInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inviteEmail) return;

    const res = await sendInvitationApi({
      email: inviteEmail,
      roleKey: inviteRole,
      department: inviteDept,
      jobRole: inviteJobRole,
    });

    if (res.ok) {
      setIsInviteOpen(false);
      setInviteEmail('');
      loadInvitations();
      alert('Invitation sent successfully!');
    } else {
      alert('Invitation failed: ' + (res.error || 'Denied'));
    }
  };

  const handleRevokeInvite = async (invId: string) => {
    if (!confirm('Revoke this invitation?')) return;
    const res = await revokeInvitationApi(invId);
    if (res.ok) {
      loadInvitations();
    }
  };

  const inviteColumns: Column<any>[] = [
    { header: 'Email', accessor: 'email', render: (i) => <strong>{i.email}</strong> },
    { header: 'Target Role', accessor: 'target_role_key', render: (i) => <StatusBadge status={i.target_role_key} /> },
    { header: 'Status', accessor: 'status', render: (i) => <StatusBadge status={i.status} /> },
    {
      header: 'Expires At',
      render: (i) => (
        <span style={{ fontSize: '12px', color: '#94a3b8' }}>
          {new Date(i.invitation_expires_at || i.expires_at).toLocaleDateString()}
        </span>
      ),
    },
    {
      header: 'Actions',
      render: (i) =>
        i.status === 'Pending' || i.status === 'Sent' ? (
          <button
            onClick={() => handleRevokeInvite(i.id)}
            style={{
              background: '#dc2626',
              color: 'white',
              border: 'none',
              padding: '4px 8px',
              borderRadius: '4px',
              fontSize: '11px',
              cursor: 'pointer',
            }}
          >
            Revoke
          </button>
        ) : (
          <span style={{ color: '#64748b', fontSize: '12px' }}>—</span>
        ),
    },
  ];

  return (
    <div style={{ maxWidth: '1280px', margin: '0 auto', padding: '24px' }}>
      {/* Frontstage Sub-Navigation */}
      <div
        style={{
          display: 'flex',
          gap: '8px',
          borderBottom: '1px solid #2d3748',
          paddingBottom: '12px',
          marginBottom: '24px',
          overflowX: 'auto',
        }}
      >
        <button
          onClick={() => setActiveTab('context')}
          style={{
            background: activeTab === 'context' ? '#2563eb' : '#1e293b',
            color: activeTab === 'context' ? '#ffffff' : '#94a3b8',
            border: 'none',
            padding: '8px 16px',
            borderRadius: '6px',
            fontSize: '13px',
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          🏢 Tenant Context
        </button>

        <button
          onClick={() => setActiveTab('team')}
          style={{
            background: activeTab === 'team' ? '#2563eb' : '#1e293b',
            color: activeTab === 'team' ? '#ffffff' : '#94a3b8',
            border: 'none',
            padding: '8px 16px',
            borderRadius: '6px',
            fontSize: '13px',
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          👥 Team Roster (11 Members)
        </button>

        <button
          onClick={() => setActiveTab('tasks')}
          style={{
            background: activeTab === 'tasks' ? '#2563eb' : '#1e293b',
            color: activeTab === 'tasks' ? '#ffffff' : '#94a3b8',
            border: 'none',
            padding: '8px 16px',
            borderRadius: '6px',
            fontSize: '13px',
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          📋 Tasks (App A)
        </button>

        <button
          onClick={() => setActiveTab('attendance')}
          style={{
            background: activeTab === 'attendance' ? '#2563eb' : '#1e293b',
            color: activeTab === 'attendance' ? '#ffffff' : '#94a3b8',
            border: 'none',
            padding: '8px 16px',
            borderRadius: '6px',
            fontSize: '13px',
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          ⏱️ Attendance (App B)
        </button>

        <button
          onClick={() => setActiveTab('invitations')}
          style={{
            background: activeTab === 'invitations' ? '#2563eb' : '#1e293b',
            color: activeTab === 'invitations' ? '#ffffff' : '#94a3b8',
            border: 'none',
            padding: '8px 16px',
            borderRadius: '6px',
            fontSize: '13px',
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          ✉️ Invitations
        </button>

        <button
          onClick={() => setActiveTab('rbac')}
          style={{
            background: activeTab === 'rbac' ? '#2563eb' : '#1e293b',
            color: activeTab === 'rbac' ? '#ffffff' : '#94a3b8',
            border: 'none',
            padding: '8px 16px',
            borderRadius: '6px',
            fontSize: '13px',
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          🛡️ RBAC Permissions Matrix
        </button>
      </div>

      {/* Tab: Tenant Context */}
      {activeTab === 'context' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
          <div style={{ background: '#111827', border: '1px solid #2d3748', borderRadius: '10px', padding: '24px' }}>
            <h3 style={{ fontSize: '16px', fontWeight: 700, margin: '0 0 16px 0', color: '#f8fafc' }}>
              Activate 24-Hour Scope Context
            </h3>

            {contextError && (
              <div style={{ background: 'rgba(239, 68, 68, 0.15)', color: '#fca5a5', padding: '10px', borderRadius: '6px', marginBottom: '14px', fontSize: '13px' }}>
                {contextError}
              </div>
            )}

            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '13px', color: '#cbd5e1', marginBottom: '6px', fontWeight: 600 }}>
                Organisation (Membership)
              </label>
              <select
                value={selectedOrgId}
                onChange={(e) => handleOrgChange(e.target.value)}
                style={{
                  width: '100%',
                  background: '#0d1322',
                  border: '1px solid #2d3748',
                  color: '#f8fafc',
                  padding: '10px',
                  borderRadius: '6px',
                  fontSize: '13px',
                }}
              >
                {memberships.map((m) => (
                  <option key={m.organisationId} value={m.organisationId}>
                    {m.organisationName} ({m.roleKey})
                  </option>
                ))}
              </select>
            </div>

            <div style={{ marginBottom: '20px' }}>
              <label style={{ display: 'block', fontSize: '13px', color: '#cbd5e1', marginBottom: '6px', fontWeight: 600 }}>
                Workspace
              </label>
              <select
                value={selectedWsId}
                onChange={(e) => setSelectedWsId(e.target.value)}
                style={{
                  width: '100%',
                  background: '#0d1322',
                  border: '1px solid #2d3748',
                  color: '#f8fafc',
                  padding: '10px',
                  borderRadius: '6px',
                  fontSize: '13px',
                }}
              >
                {workspaces.map((w) => (
                  <option key={w.workspaceId} value={w.workspaceId}>
                    {w.workspaceName}
                  </option>
                ))}
              </select>
            </div>

            <button
              onClick={handleActivateContext}
              disabled={loadingContext}
              style={{
                width: '100%',
                background: '#2563eb',
                color: 'white',
                border: 'none',
                padding: '12px',
                borderRadius: '6px',
                fontSize: '14px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              {loadingContext ? 'Initializing Context...' : 'Activate 24-Hour Context'}
            </button>
          </div>

          <div style={{ background: '#111827', border: '1px solid #2d3748', borderRadius: '10px', padding: '24px' }}>
            <h3 style={{ fontSize: '16px', fontWeight: 700, margin: '0 0 16px 0', color: '#f8fafc' }}>
              Active Context Inspector
            </h3>

            {context ? (
              <div>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px', marginBottom: '20px' }}>
                  <tbody>
                    <tr style={{ borderBottom: '1px solid #2d3748' }}>
                      <td style={{ padding: '8px 0', color: '#94a3b8' }}>Context ID:</td>
                      <td style={{ padding: '8px 0', fontFamily: 'monospace', color: '#93c5fd' }}>{context.contextId}</td>
                    </tr>
                    <tr style={{ borderBottom: '1px solid #2d3748' }}>
                      <td style={{ padding: '8px 0', color: '#94a3b8' }}>Organisation:</td>
                      <td style={{ padding: '8px 0', fontWeight: 600 }}>{context.organisationName}</td>
                    </tr>
                    <tr style={{ borderBottom: '1px solid #2d3748' }}>
                      <td style={{ padding: '8px 0', color: '#94a3b8' }}>Assurance Level:</td>
                      <td style={{ padding: '8px 0' }}><StatusBadge status={context.aal.toUpperCase()} /></td>
                    </tr>
                    <tr style={{ borderBottom: '1px solid #2d3748' }}>
                      <td style={{ padding: '8px 0', color: '#94a3b8' }}>Expires At:</td>
                      <td style={{ padding: '8px 0' }}>{new Date(context.expiresAt).toLocaleString()}</td>
                    </tr>
                  </tbody>
                </table>

                <div style={{ display: 'flex', gap: '10px' }}>
                  <button
                    onClick={handleRenewContext}
                    style={{
                      background: '#334155',
                      color: '#f8fafc',
                      border: 'none',
                      padding: '8px 14px',
                      borderRadius: '6px',
                      fontSize: '12px',
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    Renew (24h Hard Cap)
                  </button>
                  <button
                    onClick={handleRevokeContext}
                    style={{
                      background: '#dc2626',
                      color: 'white',
                      border: 'none',
                      padding: '8px 14px',
                      borderRadius: '6px',
                      fontSize: '12px',
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    Revoke Context
                  </button>
                </div>
              </div>
            ) : (
              <p style={{ color: '#64748b', fontSize: '14px' }}>
                No active context. Select an organisation and workspace on the left to activate.
              </p>
            )}
          </div>
        </div>
      )}

      {/* Tab: Team Roster */}
      {activeTab === 'team' && <TeamView />}

      {/* Tab: Tasks Application */}
      {activeTab === 'tasks' && <TasksApp />}

      {/* Tab: Attendance Application */}
      {activeTab === 'attendance' && <AttendanceApp />}

      {/* Tab: Invitations */}
      {activeTab === 'invitations' && (
        <div style={{ background: '#111827', border: '1px solid #2d3748', borderRadius: '10px', padding: '24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
            <div>
              <h3 style={{ fontSize: '18px', fontWeight: 700, margin: '0 0 4px 0', color: '#f8fafc' }}>
                Tenant Invitations Manager
              </h3>
              <p style={{ color: '#94a3b8', fontSize: '13px', margin: 0 }}>
                Issue invitations strictly to subordinate roles with automated link expiry and membership duration.
              </p>
            </div>
            <button
              onClick={() => setIsInviteOpen(true)}
              style={{
                background: '#2563eb',
                color: 'white',
                border: 'none',
                padding: '8px 16px',
                borderRadius: '6px',
                fontSize: '13px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              + Send Invitation
            </button>
          </div>

          <DataTable columns={inviteColumns} data={invitations} searchKey="email" searchPlaceholder="Search invitations..." />

          {/* Send Invite Drawer */}
          <Drawer
            isOpen={isInviteOpen}
            onClose={() => setIsInviteOpen(false)}
            title="Issue Team Invitation"
            subtitle="Invites a new member to your tenant workspace."
            footer={
              <>
                <button
                  onClick={() => setIsInviteOpen(false)}
                  style={{
                    background: '#334155',
                    color: '#f8fafc',
                    border: 'none',
                    padding: '8px 14px',
                    borderRadius: '6px',
                    fontSize: '13px',
                    cursor: 'pointer',
                  }}
                >
                  Cancel
                </button>
                <button
                  onClick={handleSendInvite}
                  style={{
                    background: '#2563eb',
                    color: 'white',
                    border: 'none',
                    padding: '8px 16px',
                    borderRadius: '6px',
                    fontSize: '13px',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  Send Invite
                </button>
              </>
            }
          >
            <form onSubmit={handleSendInvite}>
              <div style={{ marginBottom: '14px' }}>
                <label style={{ display: 'block', fontSize: '13px', color: '#cbd5e1', marginBottom: '6px', fontWeight: 600 }}>
                  Invitee Email Address
                </label>
                <input
                  type="email"
                  placeholder="colleague@architects.example"
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  style={{
                    width: '100%',
                    background: '#0d1322',
                    border: '1px solid #2d3748',
                    color: '#f8fafc',
                    padding: '10px 12px',
                    borderRadius: '6px',
                    fontSize: '13px',
                    boxSizing: 'border-box',
                  }}
                />
              </div>

              <div style={{ marginBottom: '14px' }}>
                <label style={{ display: 'block', fontSize: '13px', color: '#cbd5e1', marginBottom: '6px', fontWeight: 600 }}>
                  Assigned Subordinate Role
                </label>
                <select
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value)}
                  style={{
                    width: '100%',
                    background: '#0d1322',
                    border: '1px solid #2d3748',
                    color: '#f8fafc',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    fontSize: '13px',
                  }}
                >
                  <option value="leader">leader (Team Lead)</option>
                  <option value="manager_coordinator">manager_coordinator</option>
                  <option value="senior_architect">senior_architect</option>
                  <option value="architect">architect</option>
                  <option value="intern">intern (Expiry Required)</option>
                  <option value="collaborator">collaborator (Expiry Required)</option>
                  <option value="guest">guest (Expiry Required)</option>
                </select>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '14px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '13px', color: '#cbd5e1', marginBottom: '6px', fontWeight: 600 }}>
                    Department
                  </label>
                  <input
                    type="text"
                    value={inviteDept}
                    onChange={(e) => setInviteDept(e.target.value)}
                    style={{
                      width: '100%',
                      background: '#0d1322',
                      border: '1px solid #2d3748',
                      color: '#f8fafc',
                      padding: '8px 12px',
                      borderRadius: '6px',
                      fontSize: '13px',
                      boxSizing: 'border-box',
                    }}
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '13px', color: '#cbd5e1', marginBottom: '6px', fontWeight: 600 }}>
                    Job Role Title
                  </label>
                  <input
                    type="text"
                    value={inviteJobRole}
                    onChange={(e) => setInviteJobRole(e.target.value)}
                    style={{
                      width: '100%',
                      background: '#0d1322',
                      border: '1px solid #2d3748',
                      color: '#f8fafc',
                      padding: '8px 12px',
                      borderRadius: '6px',
                      fontSize: '13px',
                      boxSizing: 'border-box',
                    }}
                  />
                </div>
              </div>
            </form>
          </Drawer>
        </div>
      )}

      {/* Tab: RBAC Matrix */}
      {activeTab === 'rbac' && (
        <div style={{ background: '#111827', border: '1px solid #2d3748', borderRadius: '10px', padding: '24px' }}>
          <h3 style={{ fontSize: '18px', fontWeight: 700, margin: '0 0 8px 0', color: '#f8fafc' }}>
            🛡️ Centralized RBAC Controller & Matrix (Sections 11 & 12)
          </h3>
          <p style={{ color: '#94a3b8', fontSize: '13px', marginBottom: '20px' }}>
            Multi-dimensional evaluation: Platform vs Tenant, Department, Reporting Relationships, and Explicit Exceptions.
          </p>

          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
            <thead>
              <tr style={{ background: '#161f30', borderBottom: '1px solid #2d3748' }}>
                <th style={{ padding: '10px 14px', color: '#94a3b8' }}>User Role / Category</th>
                <th style={{ padding: '10px 14px', color: '#94a3b8' }}>Tasks Scope</th>
                <th style={{ padding: '10px 14px', color: '#94a3b8' }}>Attendance View</th>
                <th style={{ padding: '10px 14px', color: '#94a3b8' }}>Attendance Edit</th>
                <th style={{ padding: '10px 14px', color: '#94a3b8' }}>Attendance Comment</th>
              </tr>
            </thead>
            <tbody>
              <tr style={{ borderBottom: '1px solid #1e293b' }}>
                <td style={{ padding: '10px 14px' }}><strong>Platform Super Admin</strong></td>
                <td style={{ padding: '10px 14px' }}>Audited (Platform grants)</td>
                <td style={{ padding: '10px 14px' }}><StatusBadge status="Audited" variant="purple" /></td>
                <td style={{ padding: '10px 14px' }}><StatusBadge status="Explicit Only" variant="warning" /></td>
                <td style={{ padding: '10px 14px' }}><StatusBadge status="Authorized" variant="purple" /></td>
              </tr>
              <tr style={{ borderBottom: '1px solid #1e293b' }}>
                <td style={{ padding: '10px 14px' }}><strong>Tenant Admin (Owner)</strong></td>
                <td style={{ padding: '10px 14px' }}>All Tenant Tasks</td>
                <td style={{ padding: '10px 14px' }}><StatusBadge status="NO (Blocked)" variant="danger" /></td>
                <td style={{ padding: '10px 14px' }}><StatusBadge status="NO" variant="danger" /></td>
                <td style={{ padding: '10px 14px' }}><StatusBadge status="NO" variant="danger" /></td>
              </tr>
              <tr style={{ borderBottom: '1px solid #1e293b' }}>
                <td style={{ padding: '10px 14px' }}><strong>Design Managers (1, 2, 3)</strong></td>
                <td style={{ padding: '10px 14px' }}><StatusBadge status="All 3 Design Teams" variant="blue" /></td>
                <td style={{ padding: '10px 14px' }}><StatusBadge status="NO" variant="danger" /></td>
                <td style={{ padding: '10px 14px' }}><StatusBadge status="NO" variant="danger" /></td>
                <td style={{ padding: '10px 14px' }}><StatusBadge status="NO" variant="danger" /></td>
              </tr>
              <tr style={{ borderBottom: '1px solid #1e293b' }}>
                <td style={{ padding: '10px 14px' }}><strong>Junior Designers</strong></td>
                <td style={{ padding: '10px 14px' }}>Own Assigned Tasks Only</td>
                <td style={{ padding: '10px 14px' }}><StatusBadge status="NO" variant="danger" /></td>
                <td style={{ padding: '10px 14px' }}><StatusBadge status="NO" variant="danger" /></td>
                <td style={{ padding: '10px 14px' }}><StatusBadge status="NO" variant="danger" /></td>
              </tr>
              <tr style={{ borderBottom: '1px solid #1e293b' }}>
                <td style={{ padding: '10px 14px' }}><strong>HR Manager</strong></td>
                <td style={{ padding: '10px 14px' }}>HR Team Tasks</td>
                <td style={{ padding: '10px 14px' }}><StatusBadge status="All Records" variant="success" /></td>
                <td style={{ padding: '10px 14px' }}><StatusBadge status="YES" variant="success" /></td>
                <td style={{ padding: '10px 14px' }}><StatusBadge status="YES" variant="success" /></td>
              </tr>
              <tr style={{ borderBottom: '1px solid #1e293b' }}>
                <td style={{ padding: '10px 14px' }}><strong>Junior HR</strong></td>
                <td style={{ padding: '10px 14px' }}>Assigned HR Tasks</td>
                <td style={{ padding: '10px 14px' }}><StatusBadge status="All Records" variant="success" /></td>
                <td style={{ padding: '10px 14px' }}><StatusBadge status="NO" variant="danger" /></td>
                <td style={{ padding: '10px 14px' }}><StatusBadge status="YES (Append)" variant="warning" /></td>
              </tr>
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
