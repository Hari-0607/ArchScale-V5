import React from 'react';
import { AccessContext, UserSession } from '../types';
import { StatusBadge } from './StatusBadge';

interface HeaderProps {
  session: UserSession | null;
  context: AccessContext | null;
  mode: 'backstage' | 'frontstage';
  onModeChange: (mode: 'backstage' | 'frontstage') => void;
  onLogout: () => void;
  onOpenLogin: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  session,
  context,
  mode,
  onModeChange,
  onLogout,
  onOpenLogin,
}) => {
  return (
    <header
      style={{
        backgroundColor: '#111827',
        borderBottom: '1px solid #2d3748',
        padding: '12px 24px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        position: 'sticky',
        top: 0,
        zIndex: 100,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontWeight: 800, fontSize: '18px', color: '#60a5fa', letterSpacing: '0.5px' }}>
            ⚡ XAUTH
          </span>
          <span
            style={{
              fontSize: '11px',
              padding: '2px 8px',
              borderRadius: '9999px',
              background: 'rgba(59, 130, 246, 0.15)',
              color: '#93c5fd',
              border: '1px solid rgba(59, 130, 246, 0.3)',
              fontWeight: 700,
            }}
          >
            v4.0 Foundation
          </span>
        </div>

        {/* Backstage vs Frontstage Interface Toggle */}
        <div
          style={{
            display: 'flex',
            backgroundColor: '#0b0f19',
            border: '1px solid #2d3748',
            borderRadius: '6px',
            padding: '2px',
          }}
        >
          <button
            onClick={() => onModeChange('frontstage')}
            style={{
              background: mode === 'frontstage' ? '#2563eb' : 'transparent',
              color: mode === 'frontstage' ? '#ffffff' : '#94a3b8',
              border: 'none',
              padding: '6px 14px',
              fontSize: '12px',
              fontWeight: 600,
              borderRadius: '4px',
              cursor: 'pointer',
              transition: 'all 0.15s',
            }}
          >
            🏢 Frontstage (Tenants)
          </button>
          <button
            onClick={() => onModeChange('backstage')}
            style={{
              background: mode === 'backstage' ? '#8b5cf6' : 'transparent',
              color: mode === 'backstage' ? '#ffffff' : '#94a3b8',
              border: 'none',
              padding: '6px 14px',
              fontSize: '12px',
              fontWeight: 600,
              borderRadius: '4px',
              cursor: 'pointer',
              transition: 'all 0.15s',
            }}
          >
            🛡️ Backstage (Platform Admin)
          </button>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        {context ? (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              background: 'rgba(139, 92, 246, 0.1)',
              border: '1px solid rgba(139, 92, 246, 0.3)',
              padding: '4px 10px',
              borderRadius: '6px',
              fontSize: '12px',
              color: '#c084fc',
            }}
          >
            <span style={{ fontWeight: 600 }}>Tenant Context:</span>
            <span>{context.organisationName || 'Studio Architecture'}</span>
          </div>
        ) : null}

        {session ? (
          <>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '13px', color: '#cbd5e1', fontWeight: 500 }}>
                {session.principal.email}
              </span>
              <StatusBadge status={session.principal.aal.toUpperCase()} />
              {session.principal.role && <StatusBadge status={session.principal.role} variant="purple" />}
            </div>
            <button
              onClick={onLogout}
              style={{
                background: '#334155',
                color: '#f8fafc',
                border: 'none',
                padding: '6px 12px',
                borderRadius: '6px',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              Sign Out
            </button>
          </>
        ) : (
          <button
            onClick={onOpenLogin}
            style={{
              background: '#2563eb',
              color: '#ffffff',
              border: 'none',
              padding: '6px 16px',
              borderRadius: '6px',
              fontSize: '13px',
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Sign In / Switch Persona
          </button>
        )}
      </div>
    </header>
  );
};

