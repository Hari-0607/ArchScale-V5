import React, { useState, useRef, useEffect } from 'react';
import type { SessionData, ContextData } from '../hooks/useSession';

interface TopBarProps {
  session: SessionData | null;
  context: ContextData | null;
  onLogout: () => void;
  onSwitchContext: () => void;
}

export const TopBar: React.FC<TopBarProps> = ({ session, context, onLogout, onSwitchContext }) => {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!menuOpen) return;
    const h = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, [menuOpen]);

  const initial = session?.principal.email?.[0]?.toUpperCase() ?? '?';

  return (
    <header style={{
      height: 'var(--topbar-height)',
      background: 'var(--color-surface)',
      borderBottom: '1px solid var(--color-border)',
      display: 'flex',
      alignItems: 'center',
      padding: '0 var(--sp-6)',
      gap: 'var(--sp-4)',
      position: 'sticky',
      top: 0,
      zIndex: 100,
      flexShrink: 0,
    }}>
      {/* Org / workspace breadcrumb */}
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 8, overflow: 'hidden', minWidth: 0 }}>
        {context ? (
          <>
            <span style={{ fontSize: 'var(--font-size-body)', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--color-text)' }}>
              {context.organisationName ?? 'Organisation'}
            </span>
            <span style={{ color: 'var(--color-text-subtle)', flexShrink: 0 }}>/</span>
            <span style={{ fontSize: 'var(--font-size-sm)', color: 'var(--color-text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {context.workspaceName ?? 'Workspace'}
            </span>
            {context.roleKey && (
              <span style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-subtle)', flexShrink: 0, padding: '2px 6px', background: 'var(--color-surface-2)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--color-border)' }}>
                {context.roleKey}
              </span>
            )}
            <button
              onClick={onSwitchContext}
              style={{ background: 'none', border: '1px solid var(--color-border)', borderRadius: 'var(--radius)', padding: '3px 8px', fontSize: 'var(--font-size-xs)', cursor: 'pointer', color: 'var(--color-text-muted)', flexShrink: 0 }}
            >
              Switch
            </button>
          </>
        ) : (
          <span style={{ fontSize: 'var(--font-size-sm)', color: 'var(--color-text-muted)' }}>
            No workspace selected
          </span>
        )}
      </div>

      {/* User menu */}
      {session && (
        <div ref={menuRef} style={{ position: 'relative', flexShrink: 0 }}>
          <button
            onClick={() => setMenuOpen(o => !o)}
            aria-expanded={menuOpen}
            aria-haspopup="true"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              background: 'none',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius-md)',
              padding: '4px 10px',
              cursor: 'pointer',
              fontSize: 'var(--font-size-sm)',
              color: 'var(--color-text)',
            }}
          >
            <span style={{
              width: 24, height: 24,
              borderRadius: '50%',
              background: 'var(--color-accent)',
              color: '#fff',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 'var(--font-size-xs)',
              fontWeight: 700,
              flexShrink: 0,
            }}>
              {initial}
            </span>
            <span style={{ maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {session.principal.email}
            </span>
            <span style={{ opacity: 0.5, fontSize: 10 }}>▾</span>
          </button>

          {menuOpen && (
            <div
              style={{
                position: 'absolute',
                top: 'calc(100% + 4px)',
                right: 0,
                background: 'var(--color-surface)',
                border: '1px solid var(--color-border)',
                borderRadius: 'var(--radius-md)',
                boxShadow: 'var(--shadow-md)',
                minWidth: 200,
                zIndex: 200,
              }}
              onClick={() => setMenuOpen(false)}
            >
              <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--color-border)' }}>
                <div style={{ fontSize: 'var(--font-size-sm)', fontWeight: 600, color: 'var(--color-text)', marginBottom: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {session.principal.email}
                </div>
                <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-muted)' }}>
                  AAL: {session.principal.aal?.toUpperCase()}
                </div>
              </div>
              <button
                onClick={onLogout}
                style={{
                  width: '100%',
                  padding: '9px 14px',
                  background: 'none',
                  border: 'none',
                  textAlign: 'left',
                  fontSize: 'var(--font-size-body)',
                  color: 'var(--color-error)',
                  cursor: 'pointer',
                }}
              >
                Sign out
              </button>
            </div>
          )}
        </div>
      )}
    </header>
  );
};
