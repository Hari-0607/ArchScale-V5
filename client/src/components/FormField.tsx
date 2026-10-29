import React from 'react';

interface FieldProps {
  label: string;
  hint?: string;
  error?: string;
  required?: boolean;
  children: React.ReactElement;
}

export const inputStyle: React.CSSProperties = {
  width: '100%',
  height: 'var(--input-height)',
  padding: '0 10px',
  border: '1px solid var(--color-border)',
  borderRadius: 'var(--radius)',
  background: 'var(--color-surface)',
  color: 'var(--color-text)',
  fontSize: 'var(--font-size-body)',
  outline: 'none',
  transition: 'border-color var(--transition)',
  boxSizing: 'border-box' as const,
};

export const FormField: React.FC<FieldProps> = ({ label, hint, error, required, children }) => (
  <div style={{ marginBottom: 'var(--sp-4)' }}>
    <label style={{
      display: 'block',
      fontSize: 'var(--font-size-xs)',
      fontWeight: 700,
      color: 'var(--color-text-muted)',
      marginBottom: 'var(--sp-1)',
      textTransform: 'uppercase',
      letterSpacing: '0.5px',
    }}>
      {label}
      {required && <span style={{ color: 'var(--color-error)', marginLeft: 3 }}>*</span>}
    </label>
    {hint && (
      <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-subtle)', marginBottom: 4 }}>
        {hint}
      </div>
    )}
    {children}
    {error && (
      <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-error)', marginTop: 3 }}>
        {error}
      </div>
    )}
  </div>
);

export const TextInput = React.forwardRef<
  HTMLInputElement,
  React.InputHTMLAttributes<HTMLInputElement> & { hasError?: boolean }
>(({ hasError, style, ...props }, ref) => (
  <input
    ref={ref}
    {...props}
    style={{
      ...inputStyle,
      ...(hasError ? { borderColor: 'var(--color-error)' } : {}),
      ...style,
    }}
    onFocus={e => { e.currentTarget.style.borderColor = 'var(--color-accent)'; props.onFocus?.(e); }}
    onBlur={e => { e.currentTarget.style.borderColor = hasError ? 'var(--color-error)' : 'var(--color-border)'; props.onBlur?.(e); }}
  />
));
TextInput.displayName = 'TextInput';

export const SelectInput = React.forwardRef<
  HTMLSelectElement,
  React.SelectHTMLAttributes<HTMLSelectElement> & { hasError?: boolean }
>(({ hasError, style, ...props }, ref) => (
  <select
    ref={ref}
    {...props}
    style={{
      ...inputStyle,
      cursor: 'pointer',
      ...(hasError ? { borderColor: 'var(--color-error)' } : {}),
      ...style,
    }}
    onFocus={e => { e.currentTarget.style.borderColor = 'var(--color-accent)'; props.onFocus?.(e); }}
    onBlur={e => { e.currentTarget.style.borderColor = hasError ? 'var(--color-error)' : 'var(--color-border)'; props.onBlur?.(e); }}
  />
));
SelectInput.displayName = 'SelectInput';

export const TextareaInput = React.forwardRef<
  HTMLTextAreaElement,
  React.TextareaHTMLAttributes<HTMLTextAreaElement> & { hasError?: boolean }
>(({ hasError, style, ...props }, ref) => (
  <textarea
    ref={ref}
    {...props}
    style={{
      ...inputStyle,
      height: 'auto',
      padding: '8px 10px',
      resize: 'vertical',
      minHeight: 72,
      ...(hasError ? { borderColor: 'var(--color-error)' } : {}),
      ...style,
    }}
    onFocus={e => { e.currentTarget.style.borderColor = 'var(--color-accent)'; props.onFocus?.(e); }}
    onBlur={e => { e.currentTarget.style.borderColor = hasError ? 'var(--color-error)' : 'var(--color-border)'; props.onBlur?.(e); }}
  />
));
TextareaInput.displayName = 'TextareaInput';

