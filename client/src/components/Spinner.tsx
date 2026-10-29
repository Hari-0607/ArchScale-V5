import React from 'react';

export const Spinner: React.FC<{ size?: number; color?: string }> = ({ size = 18, color }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    style={{ animation: 'spin 0.75s linear infinite', display: 'block' }}
    aria-label="Loading"
  >
    <circle cx="12" cy="12" r="10" stroke="var(--color-border)" strokeWidth="3" />
    <path
      d="M12 2a10 10 0 0 1 10 10"
      stroke={color ?? 'var(--color-accent)'}
      strokeWidth="3"
      strokeLinecap="round"
    />
  </svg>
);

