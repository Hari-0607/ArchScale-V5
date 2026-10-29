import React from 'react';

interface StatusBadgeProps {
  status: string;
  variant?: 'default' | 'success' | 'warning' | 'danger' | 'purple' | 'blue';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, variant }) => {
  let computedVariant = variant;

  if (!computedVariant) {
    const s = status.toLowerCase();
    if (s.includes('active') || s.includes('aal2') || s.includes('approved') || s.includes('completed') || s.includes('present')) {
      computedVariant = 'success';
    } else if (s.includes('pending') || s.includes('review') || s.includes('aal1') || s.includes('half')) {
      computedVariant = 'warning';
    } else if (s.includes('suspend') || s.includes('rejected') || s.includes('absent') || s.includes('leave') || s.includes('danger')) {
      computedVariant = 'danger';
    } else if (s.includes('owner') || s.includes('founder') || s.includes('admin')) {
      computedVariant = 'purple';
    } else {
      computedVariant = 'blue';
    }
  }

  const styles: Record<string, { bg: string; color: string; border: string }> = {
    success: { bg: 'rgba(16, 185, 129, 0.15)', color: '#34d399', border: 'rgba(16, 185, 129, 0.4)' },
    warning: { bg: 'rgba(245, 158, 11, 0.15)', color: '#fbbf24', border: 'rgba(245, 158, 11, 0.4)' },
    danger: { bg: 'rgba(239, 68, 68, 0.15)', color: '#f87171', border: 'rgba(239, 68, 68, 0.4)' },
    purple: { bg: 'rgba(139, 92, 246, 0.15)', color: '#c084fc', border: 'rgba(139, 92, 246, 0.4)' },
    blue: { bg: 'rgba(59, 130, 246, 0.15)', color: '#93c5fd', border: 'rgba(59, 130, 246, 0.4)' },
    default: { bg: '#1e293b', color: '#94a3b8', border: '#334155' },
  };

  const style = styles[computedVariant] || styles.default;

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '2px 8px',
        borderRadius: '4px',
        fontSize: '11px',
        fontWeight: 700,
        textTransform: 'uppercase',
        letterSpacing: '0.5px',
        backgroundColor: style.bg,
        color: style.color,
        border: `1px solid ${style.border}`,
        whiteSpace: 'nowrap',
      }}
    >
      {status}
    </span>
  );
};
