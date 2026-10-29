import React from 'react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost';
  size?: 'sm' | 'md';
  loading?: boolean;
}

const VARIANTS: Record<string, React.CSSProperties> = {
  primary: { background: 'var(--color-accent)', color: '#fff', borderColor: 'var(--color-accent)' },
  secondary: { background: 'var(--color-surface)', color: 'var(--color-text)', borderColor: 'var(--color-border)' },
  danger: { background: 'var(--color-error)', color: '#fff', borderColor: 'var(--color-error)' },
  ghost: { background: 'transparent', color: 'var(--color-text-muted)', borderColor: 'transparent' },
};

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = 'primary', size = 'md', loading, children, disabled, style, ...rest }, ref) => {
    const base: React.CSSProperties = {
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center',
      gap: 6,
      height: size === 'sm' ? 26 : 'var(--btn-height)',
      padding: size === 'sm' ? '0 10px' : '0 14px',
      borderRadius: 'var(--radius)',
      border: '1px solid transparent',
      fontWeight: 500,
      fontSize: size === 'sm' ? 'var(--font-size-sm)' : 'var(--font-size-body)',
      cursor: disabled || loading ? 'not-allowed' : 'pointer',
      opacity: disabled || loading ? 0.6 : 1,
      transition: 'background var(--transition), border-color var(--transition), opacity var(--transition)',
      whiteSpace: 'nowrap',
      lineHeight: 1,
      ...VARIANTS[variant],
      ...style,
    };
    return (
      <button ref={ref} {...rest} disabled={disabled || loading} style={base}>
        {loading ? <span style={{ fontSize: 16 }}>⋯</span> : children}
      </button>
    );
  }
);
Button.displayName = 'Button';
