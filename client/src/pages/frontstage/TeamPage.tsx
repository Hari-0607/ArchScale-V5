import React, { useEffect, useState, useCallback } from 'react';
import { getMembers, suspendMember, reactivateMember, updateMemberRole } from '../../api/client';
import { DataTable, Column } from '../../components/DataTable';
import { PageHeader } from '../../components/PageHeader';
import { Badge, statusVariant } from '../../components/Badge';
import { Button } from '../../components/Button';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { Drawer } from '../../components/Drawer';
import { FormField, SelectInput } from '../../components/FormField';
import { useToast } from '../../hooks/useToast';
import { ToastList } from '../../components/Toast';
import { useSession } from '../../hooks/useSession';

/* eslint-disable @typescript-eslint/no-explicit-any */

const ROLES = [
  { value: 'business_owner',      label: 'Tenant Admin' },
  { value: 'leader',              label: 'Team Leader' },
  { value: 'manager_coordinator', label: 'Manager / Coordinator' },
  { value: 'intern',              label: 'Member / Intern' },
];

export const TeamPage: React.FC = () => {
  const { session } = useSession();
  const { toasts, addToast, removeToast } = useToast();
  const [members, setMembers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Derive role
  const activeRole = session?.demoPersona?.role ?? session?.principal.role;
  const canManageMembers = activeRole === 'business_owner' || activeRole === 'founder';

  // Role drawer
  const [roleDrawer, setRoleDrawer] = useState<any | null>(null);
  const [newRole, setNewRole] = useState('');
  const [saving, setSaving] = useState(false);

  // Confirm dialog
  const [confirm, setConfirm] = useState<{ id: string; name: string; action: 'suspend' | 'reactivate' } | null>(null);
  const [confirming, setConfirming] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const res = await getMembers();
    setLoading(false);
    if (!res.ok) { setError(res.message); return; }
    setMembers(res.data?.data ?? []);
  }, []);

  useEffect(() => { load(); }, [load]);

  const openRoleDrawer = (member: any) => {
    setRoleDrawer(member);
    setNewRole(member.roleKey || member.role_key || 'intern');
  };

  const handleRoleSave = async () => {
    if (!roleDrawer || !newRole) return;
    setSaving(true);
    const res = await updateMemberRole(roleDrawer.id, newRole);
    setSaving(false);
    if (!res.ok) { addToast('error', res.message); return; }
    addToast('success', `Role updated for ${roleDrawer.name}`);
    setRoleDrawer(null);
    load();
  };

  const handleStatusAction = async () => {
    if (!confirm) return;
    setConfirming(true);
    const res = confirm.action === 'suspend'
      ? await suspendMember(confirm.id)
      : await reactivateMember(confirm.id);
    setConfirming(false);
    setConfirm(null);
    if (!res.ok) { addToast('error', res.message); return; }
    addToast('success', `Member ${confirm.action === 'suspend' ? 'suspended' : 'reactivated'}`);
    load();
  };

  const columns: Column<any>[] = [
    { key: 'name', label: 'Name', sortable: true, width: 170 },
    { key: 'email', label: 'Email', sortable: true, width: 210 },
    { key: 'department', label: 'Department', sortable: true, width: 110 },
    { key: 'jobRole', label: 'Job Role', width: 160 },
    {
      key: 'reportingManager',
      label: 'Reports To',
      width: 150,
      render: row => {
        const mgrId = row.reportingManagerId || row.reporting_manager_membership_id;
        const mgr = members.find(m => m.id === mgrId);
        const text = mgr?.name || (row.roleKey === 'business_owner' || row.role_key === 'business_owner' ? 'Super Admin' : 'Tenant Admin');
        return <span style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-muted)' }}>{text}</span>;
      }
    },
    {
      key: 'roleKey',
      label: 'System Role',
      width: 150,
      render: row => {
        const key = row.roleKey || row.role_key || 'intern';
        const label = ROLES.find(r => r.value === key)?.label ?? key;
        const variant = key === 'business_owner' ? 'warning' : key === 'leader' ? 'accent' : key === 'manager_coordinator' ? 'info' : 'neutral';
        return <Badge variant={variant as any}>{label}</Badge>;
      }
    },
    {
      key: 'status',
      label: 'Status',
      width: 90,
      render: row => <Badge variant={statusVariant(row.status)}>{row.status}</Badge>
    },
  ];

  return (
    <div className="page-body">
      <ToastList toasts={toasts} onRemove={removeToast} />
      <PageHeader
        title="Team Members"
        subtitle={canManageMembers
          ? "Manage your organisation's 11-member team, assign roles and configure access (Section 06 & 07)"
          : "Organisation Team Directory — Read-only view per Section 08 permission rules"
        }
      />

      {!canManageMembers && (
        <div style={{ padding: '10px 14px', background: 'var(--color-surface-2)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius)', marginBottom: 'var(--sp-4)', fontSize: 'var(--font-size-sm)', color: 'var(--color-text-muted)' }}>
          🔒 <strong>Directory View:</strong> Role assignment and account suspension are restricted to Tenant Administrators per Assignment Section 06.
        </div>
      )}

      <DataTable
        columns={columns}
        data={members}
        loading={loading}
        error={error ?? undefined}
        onRetry={load}
        searchKeys={['name', 'email', 'department', 'jobRole']}
        emptyTitle="No members"
        emptySubtitle="Your team will appear here once added"
        rowActions={canManageMembers ? (row => (
          <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
            <Button variant="secondary" size="sm" onClick={() => openRoleDrawer(row)}>Edit Role</Button>
            {row.status === 'ACTIVE'
              ? <Button variant="danger" size="sm" onClick={() => setConfirm({ id: row.id, name: row.name, action: 'suspend' })}>Suspend</Button>
              : <Button variant="secondary" size="sm" onClick={() => setConfirm({ id: row.id, name: row.name, action: 'reactivate' })}>Reactivate</Button>
            }
          </div>
        )) : undefined}
      />

      {/* Role edit drawer - only accessible to Tenant Admin */}
      <Drawer
        open={!!roleDrawer}
        title={`Edit Role — ${roleDrawer?.name}`}
        onClose={() => setRoleDrawer(null)}
        onSave={handleRoleSave}
        saving={saving}
        saveLabel="Update Role"
      >
        {roleDrawer && (
          <>
            <div style={{ marginBottom: 'var(--sp-4)', padding: '10px 12px', background: 'var(--color-surface-2)', borderRadius: 'var(--radius)', fontSize: 'var(--font-size-sm)' }}>
              <div style={{ fontWeight: 600, marginBottom: 2 }}>{roleDrawer.name}</div>
              <div style={{ color: 'var(--color-text-muted)' }}>{roleDrawer.email}</div>
              <div style={{ color: 'var(--color-text-subtle)', fontSize: 'var(--font-size-xs)', marginTop: 4 }}>
                Department: {roleDrawer.department} · Job Role: {roleDrawer.jobRole}
              </div>
            </div>
            <FormField label="System Role" required>
              <SelectInput value={newRole} onChange={e => setNewRole(e.target.value)}>
                {ROLES.map(r => (
                  <option key={r.value} value={r.value}>{r.label}</option>
                ))}
              </SelectInput>
            </FormField>
          </>
        )}
      </Drawer>

      {/* Confirm suspend/reactivate */}
      <ConfirmDialog
        open={!!confirm}
        title={confirm?.action === 'suspend' ? 'Suspend Member' : 'Reactivate Member'}
        message={confirm?.action === 'suspend'
          ? `Suspend ${confirm?.name}? They will lose access immediately.`
          : `Reactivate ${confirm?.name}? They will regain access.`
        }
        confirmLabel={confirm?.action === 'suspend' ? 'Suspend' : 'Reactivate'}
        loading={confirming}
        onConfirm={handleStatusAction}
        onCancel={() => setConfirm(null)}
      />
    </div>
  );
};
