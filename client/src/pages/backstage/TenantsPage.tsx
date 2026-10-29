import React, { useEffect, useState, useCallback } from 'react';
import { getPlatformOrgs, approveOrg, suspendOrg, registerOrg } from '../../api/client';
import { DataTable, Column } from '../../components/DataTable';
import { PageHeader } from '../../components/PageHeader';
import { Badge, statusVariant } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Drawer } from '../../components/Drawer';
import { FormField, TextInput } from '../../components/FormField';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { useToast } from '../../hooks/useToast';
import { ToastList } from '../../components/Toast';
import { useForm } from '../../hooks/useForm';

/* eslint-disable @typescript-eslint/no-explicit-any */

interface RegisterForm {
  name: string;
  adminEmail: string;
}

const INITIAL: RegisterForm = { name: '', adminEmail: '' };

export const TenantsPage: React.FC = () => {
  const { toasts, addToast, removeToast } = useToast();
  const [orgs, setOrgs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [confirm, setConfirm] = useState<{ id: string; name: string; action: 'approve' | 'suspend' } | null>(null);
  const [confirming, setConfirming] = useState(false);

  const { values, errors, set, validate, reset, submitting, setSubmitting, dirty } = useForm<RegisterForm>(
    INITIAL,
    {
      name: v => (!v || String(v).trim().length < 2) ? 'Organisation name required' : null,
      adminEmail: v => (!v || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(v))) ? 'Valid admin email required' : null,
    }
  );

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const res = await getPlatformOrgs();
    setLoading(false);
    if (!res.ok) { setError(res.message); return; }
    setOrgs(res.data?.organisations ?? []);
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleRegister = async () => {
    if (!validate()) return;
    setSubmitting(true);
    const res = await registerOrg(values.name.trim(), values.adminEmail.trim());
    setSubmitting(false);
    if (!res.ok) { addToast('error', res.message); return; }
    addToast('success', `Organisation "${values.name}" registered`);
    reset();
    setDrawerOpen(false);
    load();
  };

  const handleAction = async () => {
    if (!confirm) return;
    setConfirming(true);
    const res = confirm.action === 'approve' ? await approveOrg(confirm.id) : await suspendOrg(confirm.id);
    setConfirming(false);
    setConfirm(null);
    if (!res.ok) { addToast('error', res.message); return; }
    addToast('success', `Organisation ${confirm.action === 'approve' ? 'approved' : 'suspended'}`);
    load();
  };

  const columns: Column<any>[] = [
    { key: 'name', label: 'Name', sortable: true, width: 200 },
    { key: 'status', label: 'Status', width: 100, render: row => <Badge variant={statusVariant(row.status)}>{row.status}</Badge> },
    { key: 'tier', label: 'Tier', width: 80 },
    { key: 'adminEmail', label: 'Admin Email', width: 220 },
    { key: 'createdAt', label: 'Created', width: 130, sortable: true, render: row =>
        row.createdAt ? new Date(row.createdAt).toLocaleDateString() : '—'
    },
  ];

  return (
    <div className="page-body">
      <ToastList toasts={toasts} onRemove={removeToast} />
      <PageHeader
        title="Tenants"
        subtitle="Platform-wide organisation management"
        actions={<Button onClick={() => { reset(); setDrawerOpen(true); }}>Register Tenant</Button>}
      />

      <DataTable
        columns={columns}
        data={orgs}
        loading={loading}
        error={error ?? undefined}
        onRetry={load}
        searchKeys={['name', 'adminEmail', 'status']}
        emptyTitle="No organisations"
        emptySubtitle="Register the first tenant to get started"
        rowActions={row => (
          <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
            {row.status === 'PENDING' && (
              <Button variant="secondary" size="sm" onClick={() => setConfirm({ id: row.id, name: row.name, action: 'approve' })}>Approve</Button>
            )}
            {row.status === 'ACTIVE' && (
              <Button variant="danger" size="sm" onClick={() => setConfirm({ id: row.id, name: row.name, action: 'suspend' })}>Suspend</Button>
            )}
          </div>
        )}
      />

      <Drawer
        open={drawerOpen}
        title="Register New Tenant"
        onClose={() => { reset(); setDrawerOpen(false); }}
        onSave={handleRegister}
        saving={submitting}
        saveLabel="Register"
        dirty={dirty}
      >
        <FormField label="Organisation Name" required error={errors.name}>
          <TextInput
            placeholder="Acme Architecture Studio"
            value={values.name}
            onChange={e => set('name', e.target.value)}
            hasError={!!errors.name}
            autoFocus
          />
        </FormField>
        <FormField label="Admin Email" required error={errors.adminEmail} hint="An invitation will be sent to this address">
          <TextInput
            type="email"
            placeholder="admin@example.com"
            value={values.adminEmail}
            onChange={e => set('adminEmail', e.target.value)}
            hasError={!!errors.adminEmail}
          />
        </FormField>
      </Drawer>

      <ConfirmDialog
        open={!!confirm}
        title={confirm?.action === 'approve' ? 'Approve Organisation' : 'Suspend Organisation'}
        message={confirm?.action === 'approve'
          ? `Approve "${confirm?.name}"? They will become an active tenant.`
          : `Suspend "${confirm?.name}"? All members will lose access immediately.`
        }
        confirmLabel={confirm?.action === 'approve' ? 'Approve' : 'Suspend'}
        loading={confirming}
        onConfirm={handleAction}
        onCancel={() => setConfirm(null)}
      />
    </div>
  );
};

