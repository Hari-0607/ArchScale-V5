import React from 'react';

export type BadgeVariant = 'success' | 'warning' | 'error' | 'info' | 'neutral';

const COLORS: Record<BadgeVariant, React.CSSProperties> = {
  success: { background: 'var(--color-success-bg)', color: 'var(--color-success)' },
  warning: { background: 'var(--color-warning-bg)', color: 'var(--color-warning)' },
  error:   { background: 'var(--color-error-bg)',   color: 'var(--color-error)' },
  info:    { background: 'var(--color-accent-light)', color: 'var(--color-accent)' },
  neutral: { background: 'var(--color-surface-2)',  color: 'var(--color-text-muted)' },
};

interface BadgeProps {
  variant?: BadgeVariant;
  children: React.ReactNode;
}

export const Badge: React.FC<BadgeProps> = ({ variant = 'neutral', children }) => (
  <span style={{
    ...COLORS[variant],
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: 20,
    fontSize: 'var(--font-size-xs)',
    fontWeight: 600,
    lineHeight: '18px',
    letterSpacing: '0.3px',
    whiteSpace: 'nowrap',
  }}>
    {children}
  </span>
);

/** Map a status string to a badge variant */
export function statusVariant(status: string): BadgeVariant {
  const s = (status ?? '').toLowerCase();
  if (['active', 'approved', 'present', 'completed', 'sent', 'success'].includes(s)) return 'success';
  if (['pending', 'in review', 'leave', 'half day', 'work from home', 'in progress'].includes(s)) return 'warning';
  if (['suspended', 'rejected', 'expired', 'revoked', 'absent', 'error'].includes(s)) return 'error';
  if (['info', 'aal2', 'platform'].includes(s)) return 'info';
  return 'neutral';
}

