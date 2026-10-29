import React from 'react';
import type { Toast } from '../hooks/useToast';

const COLORS: Record<string, React.CSSProperties> = {
  success: { background: 'var(--color-success)', color: '#fff' },
  error:   { background: 'var(--color-error)',   color: '#fff' },
  info:    { background: 'var(--color-accent)',  color: '#fff' },
};

interface ToastListProps {
  toasts: Toast[];
  onRemove: (id: string) => void;
}

export const ToastList: React.FC<ToastListProps> = ({ toasts, onRemove }) => (
  <div
    aria-live="polite"
    aria-atomic="false"
    style={{
      position: 'fixed',
      bottom: 24,
      right: 24,
      display: 'flex',
      flexDirection: 'column',
      gap: 8,
      zIndex: 9999,
      maxWidth: 380,
    }}
  >
    {toasts.map(t => (
      <div
        key={t.id}
        role="status"
        style={{
          ...COLORS[t.kind],
          borderRadius: 'var(--radius-md)',
          padding: '10px 14px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: 12,
          boxShadow: 'var(--shadow-md)',
          fontSize: 'var(--font-size-body)',
          minWidth: 260,
        }}
      >
        <span>{t.message}</span>
        <button
          onClick={() => onRemove(t.id)}
          aria-label="Dismiss"
          style={{
            background: 'none',
            border: 'none',
            color: 'rgba(255,255,255,0.8)',
            cursor: 'pointer',
            fontSize: 14,
            padding: '0 2px',
            flexShrink: 0,
            lineHeight: 1,
          }}
        >
          ✕
        </button>
      </div>
    ))}
  </div>
);

