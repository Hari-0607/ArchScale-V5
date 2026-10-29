import React from 'react';

type AlertKind = 'error' | 'warning' | 'info' | 'success';

const STYLES: Record<AlertKind, React.CSSProperties> = {
  error:   { background: 'var(--color-error-bg)',   color: 'var(--color-error)',   border: '1px solid var(--color-error)' },
  warning: { background: 'var(--color-warning-bg)', color: 'var(--color-warning)', border: '1px solid var(--color-warning)' },
  info:    { background: 'var(--color-accent-light)',color: 'var(--color-accent)',  border: '1px solid var(--color-accent)' },
  success: { background: 'var(--color-success-bg)', color: 'var(--color-success)', border: '1px solid var(--color-success)' },
};

interface AlertProps {
  kind?: AlertKind;
  children: React.ReactNode;
  style?: React.CSSProperties;
}

export const Alert: React.FC<AlertProps> = ({ kind = 'error', children, style }) => (
  <div
    role="alert"
    style={{
      ...STYLES[kind],
      borderRadius: 'var(--radius)',
      padding: '10px 14px',
      fontSize: 'var(--font-size-body)',
      marginBottom: 'var(--sp-4)',
      lineHeight: 1.5,
      ...style,
    }}
  >
    {children}
  </div>
);

