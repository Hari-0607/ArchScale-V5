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

/* eslint-disable @typescript-eslint/no-explicit-any */

const ROLES = [
  { value: 'business_owner',      label: 'Tenant Admin' },
  { value: 'leader',              label: 'Team Leader' },
  { value: 'manager_coordinator', label: 'Manager / Coordinator' },
  { value: 'intern',              label: 'Member / Intern' },
];

export const TeamPage: React.FC = () => {
  const { toasts, addToast, removeToast } = useToast();
  const [members, setMembers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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
    setNewRole(member.roleKey ?? '');
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
    { key: 'name', label: 'Name', sortable: true, width: 180 },
    { key: 'email', label: 'Email', sortable: true, width: 220 },
    { key: 'department', label: 'Department', sortable: true, width: 120 },
    { key: 'jobRole', label: 'Job Role', width: 160 },
    { key: 'roleKey', label: 'System Role', width: 160, render: row => (
      <Badge variant="info">{ROLES.find(r => r.value === row.roleKey)?.label ?? row.roleKey}</Badge>
    )},
    { key: 'status', label: 'Status', width: 90, render: row => (
      <Badge variant={statusVariant(row.status)}>{row.status}</Badge>
    )},
  ];

  return (
    <div className="page-body">
      <ToastList toasts={toasts} onRemove={removeToast} />
      <PageHeader
        title="Team Members"
        subtitle="Manage your organisation's members, roles and access"
      />

      <DataTable
        columns={columns}
        data={members}
        loading={loading}
        error={error ?? undefined}
        onRetry={load}
        searchKeys={['name', 'email', 'department', 'jobRole']}
        emptyTitle="No members"
        emptySubtitle="Your team will appear here once added"
        rowActions={row => (
          <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
            <Button variant="secondary" size="sm" onClick={() => openRoleDrawer(row)}>Edit Role</Button>
            {row.status === 'ACTIVE'
              ? <Button variant="danger" size="sm" onClick={() => setConfirm({ id: row.id, name: row.name, action: 'suspend' })}>Suspend</Button>
              : <Button variant="secondary" size="sm" onClick={() => setConfirm({ id: row.id, name: row.name, action: 'reactivate' })}>Reactivate</Button>
            }
          </div>
        )}
      />

      {/* Role edit drawer */}
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

