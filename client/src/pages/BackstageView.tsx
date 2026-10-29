import React, { useEffect, useState } from 'react';
import { approveTenantApi, getPlatformTenantsApi, registerTenantApi, suspendTenantApi } from '../api/client';
import { DataTable, Column } from '../components/DataTable';
import { Drawer } from '../components/Drawer';
import { StatusBadge } from '../components/StatusBadge';
import { TenantItem } from '../types';

export const BackstageView: React.FC = () => {
  const [tenants, setTenants] = useState<TenantItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Register Tenant Drawer
  const [isRegisterOpen, setIsRegisterOpen] = useState(false);
  const [tenantName, setTenantName] = useState('');
  const [adminEmail, setAdminEmail] = useState('');
  const [actionLoading, setActionLoading] = useState(false);

  const loadTenants = async () => {
    setLoading(true);
    setError(null);
    const res = await getPlatformTenantsApi();
    setLoading(false);

    if (!res.ok) {
      setError(res.error || 'Failed to load platform tenants. Ensure you have platform.organisations.read permission.');
      return;
    }

    setTenants(res.tenants || []);
  };

  useEffect(() => {
    loadTenants();
  }, []);

  const handleRegisterTenant = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!tenantName || !adminEmail) return;

    setActionLoading(true);
    const res = await registerTenantApi(tenantName, adminEmail);
    setActionLoading(false);

    if (res.ok) {
      setIsRegisterOpen(false);
      setTenantName('');
      setAdminEmail('');
      loadTenants();
    } else {
      alert('Failed to register tenant: ' + (res.error || 'Permission denied'));
    }
  };

  const handleSuspend = async (tenantId: string) => {
    if (!confirm('Suspend this tenant organization?')) return;
    const res = await suspendTenantApi(tenantId);
    if (res.ok) {
      loadTenants();
    } else {
      alert('Action failed: ' + res.error);
    }
  };

  const handleApprove = async (tenantId: string) => {
    const res = await approveTenantApi(tenantId);
    if (res.ok) {
      loadTenants();
    } else {
      alert('Action failed: ' + res.error);
    }
  };

  const columns: Column<TenantItem>[] = [
    {
      header: 'Tenant Name',
      accessor: 'name',
      render: (t) => <strong>{t.name}</strong>,
    },
    {
      header: 'Tenant ID',
      accessor: 'id',
      render: (t) => <span style={{ fontFamily: 'monospace', fontSize: '11px', color: '#94a3b8' }}>{t.id}</span>,
    },
    {
      header: 'Admin Email',
      accessor: 'adminEmail',
      render: (t) => <span>{t.adminEmail || 'admin@tenant.local'}</span>,
    },
    {
      header: 'Status',
      accessor: 'status',
      render: (t) => <StatusBadge status={t.status} />,
    },
    {
      header: 'Actions',
      render: (t) => (
        <div style={{ display: 'flex', gap: '8px' }}>
          {t.status === 'ACTIVE' ? (
            <button
              onClick={() => handleSuspend(t.id)}
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
              Suspend
            </button>
          ) : (
            <button
              onClick={() => handleApprove(t.id)}
              style={{
                background: '#059669',
                color: 'white',
                border: 'none',
                padding: '4px 8px',
                borderRadius: '4px',
                fontSize: '11px',
                cursor: 'pointer',
              }}
            >
              Approve
            </button>
          )}
        </div>
      ),
    },
  ];

  return (
    <div style={{ padding: '24px', maxWidth: '1280px', margin: '0 auto' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div>
          <h1 style={{ fontSize: '22px', fontWeight: 800, color: '#f8fafc', margin: '0 0 6px 0' }}>
            🛡️ Platform Backstage Super Admin
          </h1>
          <p style={{ color: '#94a3b8', fontSize: '13px', margin: 0 }}>
            Global platform governance: manage tenants, invite tenant admins, and enforce multi-tenant isolation.
          </p>
        </div>

        <button
          onClick={() => setIsRegisterOpen(true)}
          style={{
            background: '#8b5cf6',
            color: 'white',
            border: 'none',
            padding: '8px 16px',
            borderRadius: '6px',
            fontSize: '13px',
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          + Register New Tenant
        </button>
      </div>

      {error ? (
        <div
          style={{
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            color: '#fca5a5',
            padding: '16px',
            borderRadius: '8px',
            fontSize: '14px',
          }}
        >
          <strong>Security Gate Refusal (403):</strong> {error}
          <div style={{ marginTop: '8px', fontSize: '12px', color: '#cbd5e1' }}>
            Tenant administrators cannot access Backstage platform administration. Sign in as <strong>founder</strong> to manage tenants.
          </div>
        </div>
      ) : (
        <div style={{ background: '#111827', border: '1px solid #2d3748', borderRadius: '10px', padding: '20px' }}>
          <DataTable
            columns={columns}
            data={tenants}
            loading={loading}
            searchKey="name"
            searchPlaceholder="Search tenants..."
            actions={
              <button
                onClick={loadTenants}
                style={{
                  background: '#1e293b',
                  color: '#94a3b8',
                  border: '1px solid #334155',
                  padding: '6px 12px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  cursor: 'pointer',
                }}
              >
                🔄 Refresh
              </button>
            }
          />
        </div>
      )}

      {/* Register Tenant Drawer */}
      <Drawer
        isOpen={isRegisterOpen}
        onClose={() => setIsRegisterOpen(false)}
        title="Register New Tenant"
        subtitle="Creates a new isolated organization and invites a tenant administrator."
        footer={
          <>
            <button
              onClick={() => setIsRegisterOpen(false)}
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
              onClick={handleRegisterTenant}
              disabled={actionLoading}
              style={{
                background: '#8b5cf6',
                color: 'white',
                border: 'none',
                padding: '8px 16px',
                borderRadius: '6px',
                fontSize: '13px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              {actionLoading ? 'Creating...' : 'Create Tenant'}
            </button>
          </>
        }
      >
        <form onSubmit={handleRegisterTenant}>
          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', fontSize: '13px', color: '#cbd5e1', marginBottom: '6px', fontWeight: 600 }}>
              Tenant / Organization Name
            </label>
            <input
              type="text"
              placeholder="e.g. Apex Architects Studio"
              value={tenantName}
              onChange={(e) => setTenantName(e.target.value)}
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
          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', fontSize: '13px', color: '#cbd5e1', marginBottom: '6px', fontWeight: 600 }}>
              Tenant Administrator Email
            </label>
            <input
              type="email"
              placeholder="admin@apexarchitects.example"
              value={adminEmail}
              onChange={(e) => setAdminEmail(e.target.value)}
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
        </form>
      </Drawer>
    </div>
  );
};

