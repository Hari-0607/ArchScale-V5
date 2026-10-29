import React, { useEffect, useRef } from 'react';
import { Button } from './Button';

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  loading?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  open, title, message, confirmLabel = 'Confirm', loading, onConfirm, onCancel
}) => {
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (open) cancelRef.current?.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') onCancel(); };
    document.addEventListener('keydown', h);
    return () => document.removeEventListener('keydown', h);
  }, [open, onCancel]);

  if (!open) return null;

  return (
    <div
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 9000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
      onClick={onCancel}
    >
      <div
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="dialog-title"
        style={{
          background: 'var(--color-surface)',
          borderRadius: 'var(--radius-lg)',
          padding: 'var(--sp-6)',
          width: 420,
          maxWidth: '90vw',
          boxShadow: 'var(--shadow-md)',
        }}
        onClick={e => e.stopPropagation()}
      >
        <h3 id="dialog-title" style={{ fontSize: 'var(--font-size-h3)', fontWeight: 600, marginBottom: 'var(--sp-3)', color: 'var(--color-text)' }}>
          {title}
        </h3>
        <p style={{ fontSize: 'var(--font-size-body)', color: 'var(--color-text-muted)', marginBottom: 'var(--sp-6)', lineHeight: 1.6 }}>
          {message}
        </p>
        <div style={{ display: 'flex', gap: 'var(--sp-2)', justifyContent: 'flex-end' }}>
          <Button ref={cancelRef} variant="secondary" onClick={onCancel} disabled={loading}>
            Cancel
          </Button>
          <Button variant="danger" onClick={onConfirm} loading={loading}>
            {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
};
