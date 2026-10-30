import React, { useState } from 'react';
import {
  quickLogin, signIn, signInByCode, verifyMfa,
  setToken, setRefreshToken, setContextId, setDemoPersona,
} from '../../api/client';
import type { SessionData } from '../../hooks/useSession';
import { Button } from '../../components/Button';
import { Alert } from '../../components/Alert';
import { FormField, TextInput } from '../../components/FormField';
import { Spinner } from '../../components/Spinner';

interface LoginProps {
  onSuccess: (session: SessionData) => void;
}

interface Persona {
  key: string;
  name: string;
  role: string;
  dept: string;
  jobRole: string;
  badge: string;
  badgeColor: string;
  aal: 'AAL1' | 'AAL2';
  desc: string;
}

const PERSONAS: Persona[] = [
  { key: 'owner',   name: 'Organisation Owner', role: 'business_owner', dept: 'Management', jobRole: 'Studio Owner', badge: 'OWNER', badgeColor: '#8b5cf6', aal: 'AAL1', desc: 'Manage the local demo organisation and its team.' },
  { key: 'lead',    name: 'Design Lead',        role: 'leader',         dept: 'Design',     jobRole: 'Lead Architect', badge: 'LEAD', badgeColor: 'var(--color-accent)', aal: 'AAL1', desc: 'Organisation member with the design lead role.' },
  { key: 'member',  name: 'Organisation Member',role: 'intern',         dept: 'Design',     jobRole: 'Junior Architect', badge: 'MEMBER', badgeColor: 'var(--color-success)', aal: 'AAL1', desc: 'Standard organisation team member.' },
  { key: 'partner', name: 'External Partner',   role: 'collaborator',   dept: 'External',   jobRole: 'Partner Architect', badge: 'PARTNER', badgeColor: 'var(--color-warning)', aal: 'AAL1', desc: 'External collaborator in the demo organisation.' },
];

const DEPT_ORDER = ['Management', 'Design', 'External'];

function groupByDept(personas: Persona[]) {
  const groups: Record<string, Persona[]> = {};
  for (const p of personas) {
    if (!groups[p.dept]) groups[p.dept] = [];
    groups[p.dept].push(p);
  }
  return DEPT_ORDER.map(d => ({ dept: d, items: groups[d] ?? [] })).filter(g => g.items.length);
}

export const LoginPage: React.FC<LoginProps> = ({ onSuccess }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // MFA step
  const [mfaSession, setMfaSession] = useState<{ token: string; email: string } | null>(null);
  const [totpCode, setTotpCode] = useState('');

  // Manual login
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [activeTab, setActiveTab] = useState<'quick' | 'manual'>('manual');

  const finaliseSession = (data: { accessToken: string; refreshToken?: string; principal: { id: string; email: string; aal: 'aal1'|'aal2'; role?: string; department?: string; jobRole?: string; personaKey?: string; memberId?: string; sessionId?: string }; mfaRequired?: boolean; demoPersona?: { key: string; role: string; dept: string; title: string; memberId: string } }) => {
    // Guard: accessToken must be present or we cannot proceed
    if (!data.accessToken) {
      setError('Sign in failed: no access token returned. Please try again.');
      return;
    }
    const session: SessionData = {
      accessToken: data.accessToken,
      refreshToken: data.refreshToken,
      principal: data.principal,
      mfaRequired: data.mfaRequired,
      demoPersona: data.demoPersona,
    };
    // Store demo persona for RBAC header forwarding
    if (data.demoPersona) {
      setDemoPersona({ role: data.demoPersona.role, dept: data.demoPersona.dept, memberId: data.demoPersona.memberId, title: data.demoPersona.title });
    }
    // Always put the token in memory first — verifyMfa will use it via overrideToken
    setToken(data.accessToken);
    setRefreshToken(data.refreshToken ?? null);
    // If MFA is required and not yet at aal2, show MFA screen
    if (data.mfaRequired && data.principal.aal !== 'aal2') {
      setMfaSession({ token: data.accessToken, email: data.principal.email });
    } else {
      setContextId(null);
      onSuccess(session);
    }
  };

  const handleQuickLogin = async (key: string) => {
    setLoading(true);
    setError(null);
    const res = await quickLogin(key);
    setLoading(false);
    if (!res.ok) { setError(res.message); return; }
    finaliseSession(res.data as typeof res.data & { accessToken: string; principal: { id: string; email: string; aal: 'aal1'|'aal2'; role?: string } });
  };

  const handleManualLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!identifier.trim() || !password) { setError('Please enter your email/user code and password.'); return; }
    setLoading(true);
    setError(null);

    const isCode = identifier.trim().toUpperCase().startsWith('AS-');
    const res = isCode
      ? await signInByCode(identifier.trim(), password)
      : await signIn(identifier.trim(), password);
    setLoading(false);

    if (!res.ok) {
      // Always use a generic message for credential failures (security)
      setError('Sign in failed. Please check your credentials and try again.');
      return;
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    finaliseSession(res.data as any);
  };

  const handleMfaVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!totpCode.trim()) { setError('Please enter your 6-digit code.'); return; }
    if (!mfaSession) return;
    setLoading(true);
    setError(null);
    const res = await verifyMfa(totpCode.trim(), mfaSession.token);
    setLoading(false);
    if (!res.ok) {
      setError('Invalid code. Please check your authenticator app and try again.');
      return;
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = res.data as any;
    const session: SessionData = {
      accessToken: data.accessToken ?? mfaSession.token,
      refreshToken: data.refreshToken,
      principal: { ...data.principal, aal: 'aal2' as const },
    };
    setToken(session.accessToken);
    setRefreshToken(session.refreshToken ?? null);
    setContextId(null);
    onSuccess(session);
  };

  // ── MFA step ──────────────────────────────────────────────────────────────
  if (mfaSession) {
    return (
      <div style={SHELL}>
        <div style={CARD}>
          <div style={LOGO_MARK}>AS</div>
          <h1 style={H1}>Two-Factor Authentication</h1>
          <p style={SUB}>Enter the 6-digit code from your authenticator app for <strong>{mfaSession.email}</strong></p>
          {error && <Alert kind="error">{error}</Alert>}
          <form onSubmit={handleMfaVerify}>
            <FormField label="Authenticator Code" required>
              <TextInput
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                placeholder="000000"
                value={totpCode}
                onChange={e => { setTotpCode(e.target.value); setError(null); }}
                style={{ fontSize: 24, letterSpacing: 6, textAlign: 'center' }}
                autoFocus
              />
            </FormField>
            <Button type="submit" loading={loading} style={{ width: '100%', marginTop: 4 }}>
              Verify Code
            </Button>
            <button
              type="button"
              onClick={() => { setMfaSession(null); setTotpCode(''); setError(null); }}
              style={{ display: 'block', width: '100%', marginTop: 12, background: 'none', border: 'none', color: 'var(--color-text-muted)', fontSize: 'var(--font-size-sm)', cursor: 'pointer', textAlign: 'center' }}
            >
              ← Back to sign in
            </button>
          </form>
        </div>
      </div>
    );
  }

  // ── Main login ────────────────────────────────────────────────────────────
  const groups = groupByDept(PERSONAS);

  return (
    <div style={{ minHeight: '100vh', background: 'var(--color-bg)', overflowY: 'auto' }}>
      {/* Header */}
      <div style={{ background: 'var(--color-surface)', borderBottom: '1px solid var(--color-border)', padding: '16px 32px', display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={LOGO_MARK}>AS</div>
        <div>
          <div style={{ fontSize: 'var(--font-size-h2)', fontWeight: 700, color: 'var(--color-text)' }}>ArchScale</div>
          <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-muted)' }}>Organisation Authentication Platform</div>
        </div>
      </div>

      <div style={{ maxWidth: 900, margin: '0 auto', padding: '32px 24px' }}>
        {/* Tabs */}
        <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--color-border)', marginBottom: 28 }}>
          {((import.meta.env.DEV || ['localhost', '127.0.0.1', '::1'].includes(window.location.hostname.replace(/^\[|\]$/g, ''))) ? (['manual', 'quick'] as const) : (['manual'] as const)).map(tab => (
            <button
              key={tab}
              onClick={() => { setActiveTab(tab); setError(null); }}
              style={{
                padding: '9px 18px',
                fontSize: 'var(--font-size-body)',
                fontWeight: activeTab === tab ? 600 : 400,
                color: activeTab === tab ? 'var(--color-accent)' : 'var(--color-text-muted)',
                background: 'none',
                border: 'none',
                borderBottom: activeTab === tab ? '2px solid var(--color-accent)' : '2px solid transparent',
                cursor: 'pointer',
              }}
            >
              {tab === 'quick' ? 'Quick Login (Development)' : 'Sign In with Credentials'}
            </button>
          ))}
        </div>

        {error && <Alert kind="error" style={{ marginBottom: 20 }}>{error}</Alert>}

        {/* Loading overlay */}
        {loading && (
          <div style={{ textAlign: 'center', padding: '20px 0', color: 'var(--color-text-muted)', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10 }}>
            <Spinner size={16} />
            <span>Signing in…</span>
          </div>
        )}

        {/* Quick login tab */}
        {activeTab === 'quick' && !loading && (
          <div>
            <div style={{ padding: '10px 14px', background: 'var(--color-warning-bg)', borderRadius: 'var(--radius)', border: '1px solid var(--color-warning)', marginBottom: 24, fontSize: 'var(--font-size-sm)', color: 'var(--color-warning)' }}>
              Development mode: use the local demo account for a quick UI preview. Server access still follows that account’s actual organization membership.
            </div>
            {groups.map(({ dept, items }) => (
              <div key={dept} style={{ marginBottom: 24 }}>
                <div style={{ fontSize: 'var(--font-size-xs)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.6px', color: 'var(--color-text-subtle)', marginBottom: 10 }}>
                  {dept}
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 10 }}>
                  {items.map(p => (
                    <button
                      key={p.key}
                      onClick={() => handleQuickLogin(p.key)}
                      disabled={loading}
                      style={{
                        background: 'var(--color-surface)',
                        border: '1px solid var(--color-border)',
                        borderRadius: 'var(--radius-md)',
                        padding: '12px 14px',
                        cursor: 'pointer',
                        textAlign: 'left',
                        transition: 'border-color var(--transition), box-shadow var(--transition)',
                      }}
                      onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--color-accent)'; (e.currentTarget as HTMLButtonElement).style.boxShadow = '0 0 0 3px var(--color-accent-light)'; }}
                      onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--color-border)'; (e.currentTarget as HTMLButtonElement).style.boxShadow = 'none'; }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                        <span style={{ fontSize: 'var(--font-size-body)', fontWeight: 600, color: 'var(--color-text)' }}>{p.name}</span>
                        <div style={{ display: 'flex', gap: 4 }}>
                          <span style={{ fontSize: 'var(--font-size-xs)', color: p.badgeColor, fontWeight: 700 }}>{p.badge}</span>
                          <span style={{ fontSize: 'var(--font-size-xs)', color: p.aal === 'AAL2' ? 'var(--color-warning)' : 'var(--color-text-subtle)', fontWeight: 600 }}>{p.aal}</span>
                        </div>
                      </div>
                      <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-muted)', marginBottom: 2 }}>{p.jobRole}</div>
                      <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-subtle)', lineHeight: 1.4 }}>{p.desc}</div>
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Manual login tab */}
        {activeTab === 'manual' && !loading && (
          <div style={{ maxWidth: 420 }}>
            <form onSubmit={handleManualLogin}>
              <FormField label="Email or User Code" required>
                <TextInput
                  type="text"
                  placeholder="user@example.com or AS-XXXXXXXX"
                  value={identifier}
                  onChange={e => { setIdentifier(e.target.value); setError(null); }}
                  autoFocus
                  autoComplete="username"
                />
              </FormField>
              <FormField label="Password" required>
                <TextInput
                  type="password"
                  placeholder="Password"
                  value={password}
                  onChange={e => { setPassword(e.target.value); setError(null); }}
                  autoComplete="current-password"
                />
              </FormField>
              <Button type="submit" loading={loading} style={{ width: '100%' }}>
                Sign In
              </Button>
              <div style={{ marginTop: 14, fontSize: 'var(--font-size-sm)' }}>
                <a href="/forgot-password">Forgot password?</a>
              </div>
            </form>
          </div>
        )}
      </div>
    </div>
  );
};

// Shared styles
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
  maxWidth: 400,
  boxShadow: 'var(--shadow-sm)',
};

const LOGO_MARK: React.CSSProperties = {
  width: 40,
  height: 40,
  borderRadius: 10,
  background: 'var(--color-accent)',
  color: '#fff',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  fontSize: 14,
  fontWeight: 700,
  marginBottom: 20,
};

const H1: React.CSSProperties = {
  fontSize: 'var(--font-size-h1)',
  fontWeight: 700,
  marginBottom: 8,
  color: 'var(--color-text)',
};

const SUB: React.CSSProperties = {
  fontSize: 'var(--font-size-body)',
  color: 'var(--color-text-muted)',
  marginBottom: 24,
  lineHeight: 1.5,
};

