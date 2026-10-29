import React, { useEffect, useState, useCallback } from 'react';
import { getInvitations, sendInvitation, revokeInvitation, resendInvitation } from '../../api/client';
import { DataTable, Column } from '../../components/DataTable';
import { PageHeader } from '../../components/PageHeader';
import { Badge, statusVariant } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Drawer } from '../../components/Drawer';
import { FormField, TextInput, SelectInput } from '../../components/FormField';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { useToast } from '../../hooks/useToast';
import { ToastList } from '../../components/Toast';
import { useForm } from '../../hooks/useForm';

/* eslint-disable @typescript-eslint/no-explicit-any */

const ROLES = [
  { value: 'leader',              label: 'Team Leader' },
  { value: 'manager_coordinator', label: 'Manager / Coordinator' },
  { value: 'intern',              label: 'Member / Intern' },
];

const DEPTS = ['Design', 'Accounts', 'HR', 'Management', 'Engineering', 'Operations', 'Other'];

interface InviteForm {
  email: string;
  roleKey: string;
  department: string;
  jobRole: string;
  invitationExpiresAt: string;
  membershipExpiresAt: string;
}

const INITIAL: InviteForm = {
  email: '',
  roleKey: 'intern',
  department: 'Design',
  jobRole: '',
  invitationExpiresAt: '',
  membershipExpiresAt: '',
};

export const InvitationsPage: React.FC = () => {
  const { toasts, addToast, removeToast } = useToast();
  const [invitations, setInvitations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [drawerOpen, setDrawerOpen] = useState(false);
  const { values, errors, set, validate, reset, submitting, setSubmitting, dirty } = useForm<InviteForm>(
    INITIAL,
    {
      email: v => (!v || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(v))) ? 'Valid email required' : null,
      jobRole: v => (!v || String(v).trim().length < 2) ? 'Job role required' : null,
    }
  );

  const [confirm, setConfirm] = useState<{ id: string; action: 'revoke' } | null>(null);
  const [confirming, setConfirming] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const res = await getInvitations();
    setLoading(false);
    if (!res.ok) { setError(res.message); return; }
    setInvitations((res.data as any)?.invitations ?? []);
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleSend = async () => {
    if (!validate()) return;
    setSubmitting(true);
    const payload: any = {
      email: values.email.trim(),
      roleKey: values.roleKey,
      department: values.department,
      jobRole: values.jobRole.trim(),
    };
    if (values.invitationExpiresAt) payload.invitationExpiresAt = values.invitationExpiresAt;
    if (values.membershipExpiresAt) payload.membershipExpiresAt = values.membershipExpiresAt;

    const res = await sendInvitation(payload);
    setSubmitting(false);
    if (!res.ok) { addToast('error', res.message); return; }
    addToast('success', `Invitation sent to ${values.email}`);
    reset();
    setDrawerOpen(false);
    load();
  };

  const handleRevoke = async () => {
    if (!confirm) return;
    setConfirming(true);
    const res = await revokeInvitation(confirm.id);
    setConfirming(false);
    setConfirm(null);
    if (!res.ok) { addToast('error', res.message); return; }
    addToast('success', 'Invitation revoked');
    load();
  };

  const handleResend = async (id: string) => {
    const res = await resendInvitation(id);
    if (!res.ok) { addToast('error', res.message); return; }
    addToast('success', 'Invitation resent');
  };

  const columns: Column<any>[] = [
    { key: 'email', label: 'Email', sortable: true, width: 220 },
    { key: 'roleKey', label: 'Role', width: 140, render: row => <Badge variant="info">{row.roleKey}</Badge> },
    { key: 'department', label: 'Department', width: 120 },
    { key: 'status', label: 'Status', width: 100, render: row => <Badge variant={statusVariant(row.status)}>{row.status}</Badge> },
    { key: 'invitationExpiresAt', label: 'Expires', width: 140, render: row =>
        row.invitationExpiresAt ? new Date(row.invitationExpiresAt).toLocaleDateString() : '—'
    },
    { key: 'createdAt', label: 'Sent', width: 140, render: row =>
        row.createdAt ? new Date(row.createdAt).toLocaleDateString() : '—'
    },
  ];

  return (
    <div className="page-body">
      <ToastList toasts={toasts} onRemove={removeToast} />
      <PageHeader
        title="Invitations"
        subtitle="Send and manage team invitations"
        actions={
          <Button onClick={() => { reset(); setDrawerOpen(true); }}>Send Invitation</Button>
        }
      />

      <DataTable
        columns={columns}
        data={invitations}
        loading={loading}
        error={error ?? undefined}
        onRetry={load}
        searchKeys={['email', 'roleKey', 'department']}
        emptyTitle="No invitations"
        emptySubtitle="Send your first invitation to get started"
        emptyAction={<Button onClick={() => setDrawerOpen(true)}>Send Invitation</Button>}
        rowActions={row => (
          <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
            {row.status === 'sent' || row.status === 'pending' ? (
              <>
                <Button variant="secondary" size="sm" onClick={() => handleResend(row.id)}>Resend</Button>
                <Button variant="danger" size="sm" onClick={() => setConfirm({ id: row.id, action: 'revoke' })}>Revoke</Button>
              </>
            ) : null}
          </div>
        )}
      />

      {/* Send invitation drawer */}
      <Drawer
        open={drawerOpen}
        title="Send Invitation"
        onClose={() => { reset(); setDrawerOpen(false); }}
        onSave={handleSend}
        saving={submitting}
        saveLabel="Send Invitation"
        dirty={dirty}
      >
        <FormField label="Email Address" required error={errors.email}>
          <TextInput
            type="email"
            placeholder="name@example.com"
            value={values.email}
            onChange={e => set('email', e.target.value)}
            hasError={!!errors.email}
            autoFocus
          />
        </FormField>
        <FormField label="Role" required>
          <SelectInput value={values.roleKey} onChange={e => set('roleKey', e.target.value)}>
            {ROLES.map(r => <option key={r.value} value={r.value}>{r.label}</option>)}
          </SelectInput>
        </FormField>
        <FormField label="Department" required>
          <SelectInput value={values.department} onChange={e => set('department', e.target.value)}>
            {DEPTS.map(d => <option key={d} value={d}>{d}</option>)}
          </SelectInput>
        </FormField>
        <FormField label="Job Role / Title" required error={errors.jobRole}>
          <TextInput
            placeholder="e.g. Lead Architect"
            value={values.jobRole}
            onChange={e => set('jobRole', e.target.value)}
            hasError={!!errors.jobRole}
          />
        </FormField>
        <FormField label="Invitation Expires" hint="Leave blank for 7-day default (max 30 days)">
          <TextInput
            type="datetime-local"
            value={values.invitationExpiresAt}
            onChange={e => set('invitationExpiresAt', e.target.value)}
          />
        </FormField>
        <FormField label="Membership Expires" hint="Required for intern, collaborator, guest roles">
          <TextInput
            type="datetime-local"
            value={values.membershipExpiresAt}
            onChange={e => set('membershipExpiresAt', e.target.value)}
          />
        </FormField>
      </Drawer>

      <ConfirmDialog
        open={!!confirm}
        title="Revoke Invitation"
        message="This invitation will be invalidated immediately. The recipient will not be able to use it."
        confirmLabel="Revoke"
        loading={confirming}
        onConfirm={handleRevoke}
        onCancel={() => setConfirm(null)}
      />
    </div>
  );
};

