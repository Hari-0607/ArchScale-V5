import React from 'react';

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
}

export const PageHeader: React.FC<PageHeaderProps> = ({ title, subtitle, actions }) => (
  <div style={{
    display: 'flex',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
    marginBottom: 'var(--sp-6)',
    gap: 'var(--sp-4)',
    flexWrap: 'wrap',
  }}>
    <div>
      <h1 style={{ fontSize: 'var(--font-size-h1)', fontWeight: 700, color: 'var(--color-text)', lineHeight: 1.2 }}>
        {title}
      </h1>
      {subtitle && (
        <p style={{ fontSize: 'var(--font-size-body)', color: 'var(--color-text-muted)', marginTop: 4 }}>
          {subtitle}
        </p>
      )}
    </div>
    {actions && <div style={{ flexShrink: 0, display: 'flex', gap: 'var(--sp-2)', alignItems: 'center' }}>{actions}</div>}
  </div>
);

