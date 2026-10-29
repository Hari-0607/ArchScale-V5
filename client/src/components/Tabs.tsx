import React from 'react';

interface Tab {
  key: string;
  label: string;
  badge?: number;
}

interface TabsProps {
  tabs: Tab[];
  active: string;
  onChange: (key: string) => void;
}

export const Tabs: React.FC<TabsProps> = ({ tabs, active, onChange }) => (
  <div style={{
    display: 'flex',
    borderBottom: '1px solid var(--color-border)',
    marginBottom: 'var(--sp-6)',
    gap: 0,
    overflowX: 'auto',
  }}>
    {tabs.map(t => (
      <button
        key={t.key}
        onClick={() => onChange(t.key)}
        style={{
          padding: '9px 16px',
          fontSize: 'var(--font-size-body)',
          fontWeight: active === t.key ? 600 : 400,
          color: active === t.key ? 'var(--color-accent)' : 'var(--color-text-muted)',
          background: 'none',
          border: 'none',
          borderBottom: active === t.key ? '2px solid var(--color-accent)' : '2px solid transparent',
          cursor: 'pointer',
          whiteSpace: 'nowrap',
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          transition: 'color var(--transition)',
        }}
      >
        {t.label}
        {t.badge !== undefined && t.badge > 0 && (
          <span style={{ background: 'var(--color-accent)', color: '#fff', borderRadius: 10, fontSize: 'var(--font-size-xs)', padding: '1px 6px', lineHeight: '16px' }}>
            {t.badge}
          </span>
        )}
      </button>
    ))}
  </div>
);

