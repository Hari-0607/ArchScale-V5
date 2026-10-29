import React, { useState, useEffect } from 'react';
import { getMemberships, getWorkspaces, createContext, setContextId } from '../../api/client';
import type { ContextData } from '../../hooks/useSession';
import { Button } from '../../components/Button';
import { Alert } from '../../components/Alert';
import { Spinner } from '../../components/Spinner';
import { Badge, statusVariant } from '../../components/Badge';

/* eslint-disable @typescript-eslint/no-explicit-any */

interface OrgPickerProps {
  onContextCreated: (ctx: ContextData) => void;
  onLogout: () => void;
}

export const OrgWorkspacePicker: React.FC<OrgPickerProps> = ({ onContextCreated, onLogout }) => {
  const [memberships, setMemberships] = useState<any[]>([]);
  const [workspaces, setWorkspaces] = useState<any[]>([]);
  const [selectedOrgId, setSelectedOrgId] = useState<string | null>(null);
  const [selectedWsId, setSelectedWsId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [wsLoading, setWsLoading] = useState(false);
  const [activating, setActivating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      setLoading(true);
      const res = await getMemberships();
      setLoading(false);
      if (!res.ok) { setError(res.message); return; }
      setMemberships(res.data?.memberships ?? []);
    })();
  }, []);

  const handleSelectOrg = async (orgId: string) => {
    setSelectedOrgId(orgId);
    setSelectedWsId(null);
    setWorkspaces([]);
    setError(null);
    setWsLoading(true);
    const res = await getWorkspaces(orgId);
    setWsLoading(false);
    if (!res.ok) { setError(res.message); return; }
    setWorkspaces(res.data?.workspaces ?? []);
  };

  const handleActivate = async () => {
    if (!selectedOrgId || !selectedWsId) return;
    setActivating(true);
    setError(null);
    const res = await createContext(selectedOrgId, selectedWsId);
    setActivating(false);
    if (!res.ok) { setError(res.message); return; }

    const data = (res.data as any)?.context ?? res.data;
    const mem = memberships.find(m => m.organisationId === selectedOrgId);
    const ws = workspaces.find(w => w.workspaceId === selectedWsId);

    const ctx: ContextData = {
      contextId: data.contextId ?? data.id,
      organisationId: selectedOrgId,
      organisationName: mem?.organisationName ?? data.organisationName,
      workspaceId: selectedWsId,
      workspaceName: ws?.workspaceName ?? data.workspaceName,
      aal: data.aal ?? 'aal1',
      expiresAt: data.expiresAt ?? '',
      roleKey: mem?.roleKey,
      membershipId: data.membership_id ?? mem?.membershipId,
      department: data.department ?? mem?.department,
      jobRole: data.job_role ?? mem?.jobRole,
    };
    setContextId(ctx.contextId);
    onContextCreated(ctx);
  };

  if (loading) {
    return (
      <div style={SHELL}>
        <div style={CARD}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'var(--color-text-muted)' }}>
            <Spinner />
            <span>Loading your organisations…</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={SHELL}>
      <div style={{ ...CARD, maxWidth: 540 }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
          <div>
            <h1 style={{ fontSize: 'var(--font-size-h1)', fontWeight: 700, color: 'var(--color-text)' }}>Select Workspace</h1>
            <p style={{ fontSize: 'var(--font-size-sm)', color: 'var(--color-text-muted)', marginTop: 4 }}>
              Choose an organisation and workspace to continue
            </p>
          </div>
          <button onClick={onLogout} style={{ background: 'none', border: 'none', color: 'var(--color-text-muted)', cursor: 'pointer', fontSize: 'var(--font-size-sm)' }}>
            Sign out
          </button>
        </div>

        {error && <Alert kind="error">{error}</Alert>}

        {memberships.length === 0 ? (
          <div style={{ padding: '32px 0', textAlign: 'center', color: 'var(--color-text-muted)' }}>
            <p>You have no organisation memberships.</p>
          </div>
        ) : (
          <>
            {/* Step 1: Select organisation */}
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 'var(--font-size-xs)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--color-text-subtle)', marginBottom: 8 }}>
                Organisation
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {memberships.map(m => (
                  <button
                    key={m.membershipId}
                    onClick={() => handleSelectOrg(m.organisationId)}
                    style={{
                      padding: '10px 14px',
                      background: selectedOrgId === m.organisationId ? 'var(--color-accent-light)' : 'var(--color-surface)',
                      border: `1px solid ${selectedOrgId === m.organisationId ? 'var(--color-accent)' : 'var(--color-border)'}`,
                      borderRadius: 'var(--radius)',
                      cursor: 'pointer',
                      textAlign: 'left',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: 10,
                      transition: 'border-color var(--transition), background var(--transition)',
                    }}
                  >
                    <div>
                      <div style={{ fontSize: 'var(--font-size-body)', fontWeight: 600, color: 'var(--color-text)' }}>
                        {m.organisationName}
                      </div>
                      <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-muted)', marginTop: 2 }}>
                        {m.roleKey}
                      </div>
                    </div>
                    <Badge variant={statusVariant(m.status ?? 'active')}>{m.status ?? 'Active'}</Badge>
                  </button>
                ))}
              </div>
            </div>

            {/* Step 2: Select workspace */}
            {selectedOrgId && (
              <div style={{ marginBottom: 20 }}>
                <div style={{ fontSize: 'var(--font-size-xs)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--color-text-subtle)', marginBottom: 8 }}>
                  Workspace
                </div>
                {wsLoading ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--color-text-muted)', padding: 8 }}>
                    <Spinner size={14} />
                    <span style={{ fontSize: 'var(--font-size-sm)' }}>Loading workspaces…</span>
                  </div>
                ) : workspaces.length === 0 ? (
                  <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--color-text-muted)', padding: 8 }}>
                    No workspaces available.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {workspaces.map(w => (
                      <button
                        key={w.workspaceId}
                        onClick={() => setSelectedWsId(w.workspaceId)}
                        style={{
                          padding: '9px 14px',
                          background: selectedWsId === w.workspaceId ? 'var(--color-accent-light)' : 'var(--color-surface)',
                          border: `1px solid ${selectedWsId === w.workspaceId ? 'var(--color-accent)' : 'var(--color-border)'}`,
                          borderRadius: 'var(--radius)',
                          cursor: 'pointer',
                          textAlign: 'left',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          gap: 10,
                          transition: 'border-color var(--transition), background var(--transition)',
                        }}
                      >
                        <span style={{ fontSize: 'var(--font-size-body)', color: 'var(--color-text)' }}>
                          {w.workspaceName}
                          {w.isDefault && <span style={{ marginLeft: 6, fontSize: 'var(--font-size-xs)', color: 'var(--color-text-muted)' }}>(default)</span>}
                        </span>
                        {selectedWsId === w.workspaceId && <span style={{ color: 'var(--color-accent)', fontWeight: 700, fontSize: 14 }}>✓</span>}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}

            <Button
              onClick={handleActivate}
              loading={activating}
              disabled={!selectedOrgId || !selectedWsId}
              style={{ width: '100%' }}
            >
              Enter Workspace
            </Button>
          </>
        )}
      </div>
    </div>
  );
};

const SHELL: React.CSSProperties = {
  minHeight: '100vh',
  background: 'var(--color-bg)',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  padding: 24,
};

const CARD: React.CSSProperties = {
  background: 'var(--color-surface)',
  border: '1px solid var(--color-border)',
  borderRadius: 'var(--radius-lg)',
  padding: 32,
  width: '100%',
  boxShadow: 'var(--shadow-sm)',
};

