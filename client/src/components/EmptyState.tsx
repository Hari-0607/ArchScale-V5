import React from 'react';
import { Button } from './Button';

interface EmptyStateProps {
  title: string;
  subtitle?: string;
  action?: React.ReactNode;
  icon?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({ title, subtitle, action, icon = '—' }) => (
  <div style={{
    textAlign: 'center',
    padding: '56px 24px',
    color: 'var(--color-text-muted)',
  }}>
    <div style={{ fontSize: 36, marginBottom: 16, opacity: 0.3, userSelect: 'none' }}>{icon}</div>
    <div style={{
      fontWeight: 600,
      fontSize: 'var(--font-size-md)',
      color: 'var(--color-text)',
      marginBottom: 6,
    }}>
      {title}
    </div>
    {subtitle && (
      <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--color-text-muted)', marginBottom: 20 }}>
        {subtitle}
      </div>
    )}
    {action}
  </div>
);

// Re-export for convenience
export { Button };
