import React, { useEffect, useState } from 'react';
import { getMembersApi, updateMemberRoleApi } from '../api/client';
import { DataTable, Column } from '../components/DataTable';
import { StatusBadge } from '../components/StatusBadge';
import { TeamMember } from '../types';

export const TeamView: React.FC = () => {
  const [members, setMembers] = useState<TeamMember[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadMembers = async () => {
    setLoading(true);
    setError(null);
    const res = await getMembersApi();
    setLoading(false);

    if (!res.ok) {
      setError(res.error || 'Failed to load team members. Ensure your context has org.members.read permission.');
      return;
    }

    setMembers(res.members || []);
  };

  useEffect(() => {
    loadMembers();
  }, []);

  const handleChangeRole = async (memberId: string) => {
    const newRole = prompt('Enter new role key (e.g. leader, manager_coordinator, senior_architect, architect, intern):');
    if (!newRole) return;
    const res = await updateMemberRoleApi(memberId, newRole.trim());
    if (res.ok) {
      loadMembers();
    } else {
      alert('Role modification failed: ' + (res.error || 'Permission denied'));
    }
  };

  const columns: Column<TeamMember>[] = [
    {
      header: 'Member Name / User ID',
      accessor: 'name',
      render: (m) => (
        <div>
          <strong style={{ color: '#f8fafc' }}>{m.name || m.email || 'Team Member'}</strong>
          <div style={{ fontFamily: 'monospace', fontSize: '11px', color: '#94a3b8' }}>
            {m.userId || m.id?.substring(0, 8)}
          </div>
        </div>
      ),
    },
    {
      header: 'Department',
      accessor: 'department',
      render: (m) => <span>{m.department || 'General'}</span>,
    },
    {
      header: 'Job Role',
      accessor: 'jobRole',
      render: (m) => <span>{m.jobRole || 'Member'}</span>,
    },
    {
      header: 'Role Key',
      accessor: 'roleKey',
      render: (m) => <StatusBadge status={m.roleKey} />,
    },
    {
      header: 'Reporting Manager',
      render: (m) => (
        <span style={{ fontSize: '12px', color: m.reportingManagerName ? '#cbd5e1' : '#64748b' }}>
          {m.reportingManagerName || (m.reportingManagerId ? `ID: ${m.reportingManagerId.substring(0, 8)}...` : 'None / Root')}
        </span>
      ),
    },
    {
      header: 'Status',
      accessor: 'status',
      render: (m) => <StatusBadge status={m.status || 'ACTIVE'} />,
    },
    {
      header: 'Actions',
      render: (m) => (
        <button
          onClick={() => handleChangeRole(m.id)}
          style={{
            background: '#1e293b',
            color: '#93c5fd',
            border: '1px solid #334155',
            padding: '4px 10px',
            borderRadius: '4px',
            fontSize: '11px',
            cursor: 'pointer',
          }}
        >
          Change Role
        </button>
      ),
    },
  ];

  return (
    <div style={{ background: '#111827', border: '1px solid #2d3748', borderRadius: '10px', padding: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h2 style={{ fontSize: '18px', fontWeight: 700, color: '#f8fafc', margin: '0 0 4px 0' }}>
            👥 11-Member Test Team Roster
          </h2>
          <p style={{ color: '#94a3b8', fontSize: '13px', margin: 0 }}>
            Structured reporting lines across Design (3 pairs), Accounts (1 pair), HR (1 pair), and Tenant Admin.
          </p>
        </div>

        <button
          onClick={loadMembers}
          style={{
            background: '#2563eb',
            color: 'white',
            border: 'none',
            padding: '6px 14px',
            borderRadius: '6px',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          🔄 Refresh Roster
        </button>
      </div>

      {error ? (
        <div
          style={{
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            color: '#fca5a5',
            padding: '14px',
            borderRadius: '6px',
            fontSize: '13px',
          }}
        >
          <strong>Access Denied:</strong> {error}
        </div>
      ) : (
        <DataTable
          columns={columns}
          data={members}
          loading={loading}
          searchKey="name"
          searchPlaceholder="Search members or roles..."
        />
      )}
    </div>
  );
};
