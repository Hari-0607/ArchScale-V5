import React, { useState } from 'react';
import { quickLoginApi, signInApi, verifyMfaApi } from '../api/client';
import { UserSession } from '../types';

interface LoginViewProps {
  onLoginSuccess: (session: UserSession) => void;
}

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
    const res = await verifyMfaApi(code, isBypass);
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
      setTempSession(null);
      onLoginSuccess(elevatedSession);
    }
  };

  return (
    <div style={{ maxWidth: '800px', margin: '40px auto', padding: '0 20px' }}>
      <div style={{ textAlign: 'center', marginBottom: '32px' }}>
        <h1 style={{ fontSize: '26px', fontWeight: 800, color: '#f8fafc', marginBottom: '8px' }}>
          XAuth Authentication & RBAC Foundation
        </h1>
        <p style={{ color: '#94a3b8', fontSize: '14px' }}>
          Test platform roles, tenant administration, and department permissions using pre-configured test personas.
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
              6-Digit Authenticator Code
            </label>
            <input
              type="text"
              maxLength={6}
              placeholder="e.g. 123456"
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
          {/* Persona Switcher Card */}
          <div
            style={{
              background: '#111827',
              border: '1px solid #2d3748',
              borderRadius: '10px',
              padding: '24px',
              marginBottom: '24px',
            }}
          >
            <h3 style={{ fontSize: '15px', color: '#cbd5e1', fontWeight: 700, margin: '0 0 16px 0' }}>
              One-Click Persona Switcher
            </h3>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px' }}>
              <div
                onClick={() => handleQuickLogin('business_owner')}
                style={{
                  background: '#17233a',
                  border: '1px solid #8b5cf6',
                  borderRadius: '8px',
                  padding: '14px',
                  cursor: 'pointer',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <strong style={{ fontSize: '14px', color: '#f8fafc' }}>Tenant Admin</strong>
                  <span style={{ fontSize: '10px', background: 'rgba(139, 92, 246, 0.2)', color: '#c084fc', padding: '2px 6px', borderRadius: '4px', fontWeight: 700 }}>
                    AAL2
                  </span>
                </div>
                <p style={{ fontSize: '12px', color: '#94a3b8', margin: 0 }}>
                  Business Owner of Studio Architecture. Full tenant admin & member control.
                </p>
              </div>

              <div
                onClick={() => handleQuickLogin('leader')}
                style={{
                  background: '#17233a',
                  border: '1px solid #3b82f6',
                  borderRadius: '8px',
                  padding: '14px',
                  cursor: 'pointer',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <strong style={{ fontSize: '14px', color: '#f8fafc' }}>Design Manager</strong>
                  <span style={{ fontSize: '10px', background: 'rgba(59, 130, 246, 0.2)', color: '#93c5fd', padding: '2px 6px', borderRadius: '4px', fontWeight: 700 }}>
                    LEADER
                  </span>
                </div>
                <p style={{ fontSize: '12px', color: '#94a3b8', margin: 0 }}>
                  Manager role. Has cross-team visibility exception across design managers.
                </p>
              </div>

              <div
                onClick={() => handleQuickLogin('intern')}
                style={{
                  background: '#17233a',
                  border: '1px solid #0d9488',
                  borderRadius: '8px',
                  padding: '14px',
                  cursor: 'pointer',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <strong style={{ fontSize: '14px', color: '#f8fafc' }}>Junior Designer</strong>
                  <span style={{ fontSize: '10px', background: 'rgba(13, 148, 136, 0.2)', color: '#5eead4', padding: '2px 6px', borderRadius: '4px', fontWeight: 700 }}>
                    INTERN
                  </span>
                </div>
                <p style={{ fontSize: '12px', color: '#94a3b8', margin: 0 }}>
                  Junior role. Restricted to assigned tasks; cannot view peer tasks.
                </p>
              </div>

              <div
                onClick={() => handleQuickLogin('founder')}
                style={{
                  background: '#17233a',
                  border: '1px solid #d97706',
                  borderRadius: '8px',
                  padding: '14px',
                  cursor: 'pointer',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <strong style={{ fontSize: '14px', color: '#f8fafc' }}>Platform Founder</strong>
                  <span style={{ fontSize: '10px', background: 'rgba(217, 119, 6, 0.2)', color: '#fcd34d', padding: '2px 6px', borderRadius: '4px', fontWeight: 700 }}>
                    BACKSTAGE
                  </span>
                </div>
                <p style={{ fontSize: '12px', color: '#94a3b8', margin: 0 }}>
                  Platform Super Admin with access to Backstage cross-tenant management.
                </p>
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
                {loading ? 'Authenticating...' : 'Sign In'}
              </button>
            </form>
          </div>
        </>
      )}
    </div>
  );
};

