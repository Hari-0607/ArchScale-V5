import React, { useState } from 'react';
import { quickLoginApi, setApiSession, signInApi, verifyMfaApi } from '../api/client';
import { UserSession } from '../types';

interface LoginViewProps {
  onLoginSuccess: (session: UserSession) => void;
}

interface PersonaConfig {
  key: string;
  name: string;
  role: string;
  department: string;
  jobRole: string;
  reportsTo: string;
  badge: string;
  badgeColor: string;
  description: string;
}

const personas: PersonaConfig[] = [
  // Platform Super Admin
  { key: 'founder', name: 'Platform Founder', role: 'founder', department: 'Platform', jobRole: 'Platform Super Admin', reportsTo: 'None (Root)', badge: 'BACKSTAGE AAL2', badgeColor: '#d97706', description: 'Global Platform Super Admin. Accesses Backstage to manage tenants.' },

  // 1. Tenant Admin
  { key: 'tenant_admin', name: 'Tenant Admin', role: 'business_owner', department: 'Management', jobRole: 'Studio Owner', reportsTo: 'Founder (Backstage)', badge: 'OWNER AAL2', badgeColor: '#8b5cf6', description: 'Studio Architecture Owner. Full tenant management, team configuration, settings.' },

  // Design Department (3 Pairs)
  { key: 'design_manager_1', name: 'Design Manager 1', role: 'leader', department: 'Design', jobRole: 'Lead Architect', reportsTo: 'Tenant Admin', badge: 'LEADER AAL1', badgeColor: '#2563eb', description: 'Design Team 1 Lead. Cross-team visibility exception across all 3 design teams.' },
  { key: 'junior_designer_1', name: 'Junior Designer 1', role: 'intern', department: 'Design', jobRole: 'Junior Architect', reportsTo: 'Design Manager 1', badge: 'INTERN AAL1', badgeColor: '#0d9488', description: 'Design Team 1 Junior. Restricted to own tasks; cannot view peer tasks.' },

  { key: 'design_manager_2', name: 'Design Manager 2', role: 'leader', department: 'Design', jobRole: 'MEP Design Lead', reportsTo: 'Tenant Admin', badge: 'LEADER AAL1', badgeColor: '#2563eb', description: 'Design Team 2 Lead. Cross-team visibility exception across all 3 design teams.' },
  { key: 'junior_designer_2', name: 'Junior Designer 2', role: 'intern', department: 'Design', jobRole: 'CAD Technician', reportsTo: 'Design Manager 2', badge: 'INTERN AAL1', badgeColor: '#0d9488', description: 'Design Team 2 Junior. Restricted to own tasks; cannot view peer tasks.' },

  { key: 'design_manager_3', name: 'Design Manager 3', role: 'leader', department: 'Design', jobRole: 'Landscape Design Lead', reportsTo: 'Tenant Admin', badge: 'LEADER AAL1', badgeColor: '#2563eb', description: 'Design Team 3 Lead. Cross-team visibility exception across all 3 design teams.' },
  { key: 'junior_designer_3', name: 'Junior Designer 3', role: 'intern', department: 'Design', jobRole: '3D Visualizer', reportsTo: 'Design Manager 3', badge: 'INTERN AAL1', badgeColor: '#0d9488', description: 'Design Team 3 Junior. Restricted to own tasks; cannot view peer tasks.' },

  // Accounts Department (1 Pair)
  { key: 'accounts_manager', name: 'Accounts Manager', role: 'manager_coordinator', department: 'Accounts', jobRole: 'Finance Controller', reportsTo: 'Tenant Admin', badge: 'MANAGER AAL1', badgeColor: '#059669', description: 'Accounts Team Lead. Manages billing, reconciliations, and vendor tasks.' },
  { key: 'junior_accountant', name: 'Junior Accountant', role: 'intern', department: 'Accounts', jobRole: 'Billing Specialist', reportsTo: 'Accounts Manager', badge: 'INTERN AAL1', badgeColor: '#0d9488', description: 'Accounts Junior. Restricted to assigned invoices and vouchers.' },

  // HR Department (1 Pair)
  { key: 'hr_manager', name: 'HR Manager', role: 'manager_coordinator', department: 'HR', jobRole: 'People & Culture Lead', reportsTo: 'Tenant Admin', badge: 'MANAGER AAL1', badgeColor: '#ec4899', description: 'HR Team Lead. Full access to view and edit Attendance records.' },
  { key: 'junior_hr', name: 'Junior HR', role: 'intern', department: 'HR', jobRole: 'HR Coordinator', reportsTo: 'HR Manager', badge: 'INTERN AAL1', badgeColor: '#0d9488', description: 'HR Junior. Can view Attendance and append comments (editing is restricted).' },
];

export const LoginView: React.FC<LoginViewProps> = ({ onLoginSuccess }) => {
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // MFA Challenge State
  const [tempSession, setTempSession] = useState<UserSession | null>(null);
  const [totpCode, setTotpCode] = useState('');

  const handleManualLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!identifier || !password) {
      setError('Please provide email/user-code and password.');
      return;
    }

    setLoading(true);
    setError(null);
    const res = await signInApi(identifier, password);
    setLoading(false);

    if (!res.ok) {
      setError(res.error || 'Login failed');
      return;
    }

    const session: UserSession = res.data;
    setApiSession(session);

    if (session.mfaRequired && session.principal.aal !== 'aal2') {
      setTempSession(session);
    } else {
      onLoginSuccess(session);
    }
  };

  const handleQuickLogin = async (roleKey: string) => {
    setLoading(true);
    setError(null);
    const res = await quickLoginApi(roleKey);
    setLoading(false);

    if (!res.ok) {
      setError(res.error || `Failed to sign in as ${roleKey}`);
      return;
    }

    const session: UserSession = res.data;
    setApiSession(session);

    if (session.mfaRequired && session.principal.aal !== 'aal2') {
      setTempSession(session);
    } else {
      onLoginSuccess(session);
    }
  };

  const handleMfaVerify = async (isBypass = false) => {
    setLoading(true);
    setError(null);
    const code = isBypass ? '123456' : totpCode.trim() || '123456';
    const token = tempSession?.accessToken;
    const res = await verifyMfaApi(code, isBypass, token);
    setLoading(false);

    if (!res.ok) {
      setError(res.error || 'MFA Verification failed');
      return;
    }

    if (tempSession) {
      const elevatedSession: UserSession = {
        ...tempSession,
        accessToken: res.data.accessToken || tempSession.accessToken,
        principal: {
          ...tempSession.principal,
          aal: 'aal2',
        },
      };
      setApiSession(elevatedSession);
      setTempSession(null);
      onLoginSuccess(elevatedSession);
    }
  };

  return (
    <div style={{ maxWidth: '1100px', margin: '30px auto', padding: '0 20px' }}>
      <div style={{ textAlign: 'center', marginBottom: '28px' }}>
        <h1 style={{ fontSize: '26px', fontWeight: 800, color: '#f8fafc', marginBottom: '6px' }}>
          XAuth Authentication & RBAC Foundation
        </h1>
        <p style={{ color: '#94a3b8', fontSize: '14px' }}>
          Test all 11 organization roles + Platform Founder with pre-configured personas and reporting lines.
        </p>
      </div>

      {error && (
        <div
          style={{
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            color: '#fca5a5',
            padding: '12px 16px',
            borderRadius: '6px',
            fontSize: '13px',
            marginBottom: '20px',
          }}
        >
          {error}
        </div>
      )}

      {/* MFA Verification Screen */}
      {tempSession ? (
        <div
          style={{
            background: '#111827',
            border: '1px solid #8b5cf6',
            borderRadius: '10px',
            padding: '28px',
            boxShadow: '0 8px 24px rgba(0, 0, 0, 0.4)',
            maxWidth: '600px',
            margin: '0 auto 30px auto',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <span style={{ fontSize: '20px' }}>🔐</span>
            <h2 style={{ fontSize: '18px', fontWeight: 700, margin: 0 }}>Two-Factor Authentication Required</h2>
          </div>
          <p style={{ color: '#94a3b8', fontSize: '13px', marginBottom: '20px' }}>
            Authenticated as <strong>{tempSession.principal.email}</strong>. This account requires AAL2 verification.
          </p>

          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', fontSize: '13px', color: '#cbd5e1', marginBottom: '6px', fontWeight: 600 }}>
              6-Digit Authenticator Code (or test code 123456)
            </label>
            <input
              type="text"
              maxLength={6}
              placeholder="123456"
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value)}
              style={{
                width: '100%',
                background: '#0d1322',
                border: '1px solid #334155',
                color: '#f8fafc',
                padding: '10px 14px',
                borderRadius: '6px',
                fontSize: '16px',
                letterSpacing: '4px',
                outline: 'none',
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
            <button
              onClick={() => handleMfaVerify(false)}
              disabled={loading}
              style={{
                background: '#2563eb',
                color: 'white',
                border: 'none',
                padding: '10px 20px',
                borderRadius: '6px',
                fontSize: '14px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              Verify TOTP Code
            </button>
            <button
              onClick={() => handleMfaVerify(true)}
              disabled={loading}
              style={{
                background: '#059669',
                color: 'white',
                border: 'none',
                padding: '10px 20px',
                borderRadius: '6px',
                fontSize: '14px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              ⚡ Instant Bypass (Elevate to AAL2)
            </button>
          </div>
        </div>
      ) : (
        <>
          {/* Section 07: 11-Member Persona Switcher */}
          <div
            style={{
              background: '#111827',
              border: '1px solid #2d3748',
              borderRadius: '10px',
              padding: '24px',
              marginBottom: '24px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px' }}>
              <div>
                <h3 style={{ fontSize: '16px', color: '#f8fafc', fontWeight: 700, margin: '0 0 4px 0' }}>
                  👥 11-Member Team & Platform Switcher (Section 07)
                </h3>
                <p style={{ fontSize: '13px', color: '#94a3b8', margin: 0 }}>
                  Select any persona to log in instantly and test their exact permissions and reporting visibility.
                </p>
              </div>
            </div>

            {/* Department Sections */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              
              {/* 1. Platform Governance & Tenant Admin */}
              <div>
                <div style={{ fontSize: '12px', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', marginBottom: '10px', letterSpacing: '0.5px' }}>
                  Platform Governance & Tenant Administration
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px' }}>
                  {personas.filter(p => p.key === 'founder' || p.key === 'tenant_admin').map((p) => (
                    <div
                      key={p.key}
                      onClick={() => handleQuickLogin(p.key)}
                      style={{
                        background: '#161f30',
                        border: `1px solid ${p.badgeColor}`,
                        borderRadius: '8px',
                        padding: '14px',
                        cursor: 'pointer',
                        transition: 'transform 0.15s',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                        <strong style={{ fontSize: '14px', color: '#f8fafc' }}>{p.name}</strong>
                        <span style={{ fontSize: '10px', background: 'rgba(255, 255, 255, 0.1)', color: p.badgeColor, padding: '2px 6px', borderRadius: '4px', fontWeight: 700 }}>
                          {p.badge}
                        </span>
                      </div>
                      <div style={{ fontSize: '12px', color: '#cbd5e1', marginBottom: '4px' }}>
                        {p.jobRole} ({p.department})
                      </div>
                      <p style={{ fontSize: '11px', color: '#94a3b8', margin: 0 }}>
                        {p.description}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* 2. Design Department (3 Teams) */}
              <div>
                <div style={{ fontSize: '12px', fontWeight: 700, color: '#60a5fa', textTransform: 'uppercase', marginBottom: '10px', letterSpacing: '0.5px' }}>
                  📐 Design Department (3 Manager & Junior Pairs — Cross-Team Read Exception)
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '12px' }}>
                  {personas.filter(p => p.department === 'Design').map((p) => (
                    <div
                      key={p.key}
                      onClick={() => handleQuickLogin(p.key)}
                      style={{
                        background: '#161f30',
                        border: '1px solid #2d3748',
                        borderRadius: '8px',
                        padding: '12px',
                        cursor: 'pointer',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                        <strong style={{ fontSize: '13px', color: '#f8fafc' }}>{p.name}</strong>
                        <span style={{ fontSize: '10px', color: p.badgeColor, fontWeight: 700 }}>
                          {p.role.toUpperCase()}
                        </span>
                      </div>
                      <div style={{ fontSize: '11px', color: '#94a3b8', marginBottom: '2px' }}>
                        {p.jobRole} • Reports to: <strong>{p.reportsTo}</strong>
                      </div>
                      <p style={{ fontSize: '11px', color: '#64748b', margin: 0 }}>
                        {p.description}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* 3. Accounts Department */}
              <div>
                <div style={{ fontSize: '12px', fontWeight: 700, color: '#34d399', textTransform: 'uppercase', marginBottom: '10px', letterSpacing: '0.5px' }}>
                  💰 Accounts Department (1 Manager & Junior Pair)
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '12px' }}>
                  {personas.filter(p => p.department === 'Accounts').map((p) => (
                    <div
                      key={p.key}
                      onClick={() => handleQuickLogin(p.key)}
                      style={{
                        background: '#161f30',
                        border: '1px solid #2d3748',
                        borderRadius: '8px',
                        padding: '12px',
                        cursor: 'pointer',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                        <strong style={{ fontSize: '13px', color: '#f8fafc' }}>{p.name}</strong>
                        <span style={{ fontSize: '10px', color: p.badgeColor, fontWeight: 700 }}>
                          {p.role.toUpperCase()}
                        </span>
                      </div>
                      <div style={{ fontSize: '11px', color: '#94a3b8', marginBottom: '2px' }}>
                        {p.jobRole} • Reports to: <strong>{p.reportsTo}</strong>
                      </div>
                      <p style={{ fontSize: '11px', color: '#64748b', margin: 0 }}>
                        {p.description}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* 4. HR Department */}
              <div>
                <div style={{ fontSize: '12px', fontWeight: 700, color: '#f472b6', textTransform: 'uppercase', marginBottom: '10px', letterSpacing: '0.5px' }}>
                  👥 HR Department (1 Manager & Junior Pair — Exclusive Attendance Access)
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '12px' }}>
                  {personas.filter(p => p.department === 'HR').map((p) => (
                    <div
                      key={p.key}
                      onClick={() => handleQuickLogin(p.key)}
                      style={{
                        background: '#161f30',
                        border: '1px solid #2d3748',
                        borderRadius: '8px',
                        padding: '12px',
                        cursor: 'pointer',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                        <strong style={{ fontSize: '13px', color: '#f8fafc' }}>{p.name}</strong>
                        <span style={{ fontSize: '10px', color: p.badgeColor, fontWeight: 700 }}>
                          {p.role.toUpperCase()}
                        </span>
                      </div>
                      <div style={{ fontSize: '11px', color: '#94a3b8', marginBottom: '2px' }}>
                        {p.jobRole} • Reports to: <strong>{p.reportsTo}</strong>
                      </div>
                      <p style={{ fontSize: '11px', color: '#64748b', margin: 0 }}>
                        {p.description}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

            </div>
          </div>

          {/* Manual Credentials Sign In */}
          <div
            style={{
              background: '#111827',
              border: '1px solid #2d3748',
              borderRadius: '10px',
              padding: '24px',
            }}
          >
            <h3 style={{ fontSize: '15px', color: '#cbd5e1', fontWeight: 700, margin: '0 0 16px 0' }}>
              Manual Credentials Login
            </h3>
            <form onSubmit={handleManualLogin}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px', marginBottom: '16px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '13px', color: '#94a3b8', marginBottom: '6px', fontWeight: 600 }}>
                    Email or User Code (AS-...)
                  </label>
                  <input
                    type="text"
                    placeholder="user@archscale.test"
                    value={identifier}
                    onChange={(e) => setIdentifier(e.target.value)}
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
                <div>
                  <label style={{ display: 'block', fontSize: '13px', color: '#94a3b8', marginBottom: '6px', fontWeight: 600 }}>
                    Password
                  </label>
                  <input
                    type="password"
                    placeholder="Password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
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
              </div>

              <button
                type="submit"
                disabled={loading}
                style={{
                  background: '#2563eb',
                  color: 'white',
                  border: 'none',
                  padding: '10px 20px',
                  borderRadius: '6px',
                  fontSize: '14px',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                {loading ? 'Authenticating...' : 'Sign In with Credentials'}
              </button>
            </form>
          </div>
        </>
      )}
    </div>
  );
};
