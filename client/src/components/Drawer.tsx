import React, { useEffect, useRef } from 'react';
import { Button } from './Button';

interface DrawerProps {
  open: boolean;
  title: string;
  onClose: () => void;
  onSave?: () => void;
  saveLabel?: string;
  saving?: boolean;
  dirty?: boolean;
  children: React.ReactNode;
  width?: number;
}

const FOCUSABLE =
  'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

export const Drawer: React.FC<DrawerProps> = ({
  open, title, onClose, onSave, saveLabel = 'Save', saving, dirty, children, width = 480
}) => {
  const panelRef = useRef<HTMLDivElement>(null);

  const handleClose = () => {
    if (dirty && !confirm('You have unsaved changes. Discard them?')) return;
    onClose();
  };

  useEffect(() => {
    if (!open) return;
    const h = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (dirty && !confirm('You have unsaved changes. Discard them?')) return;
        onClose();
      }
    };
    document.addEventListener('keydown', h);
    return () => document.removeEventListener('keydown', h);
  }, [open, dirty, onClose]);

  useEffect(() => {
    if (!open || !panelRef.current) return;
    const panel = panelRef.current;
    const getFocusable = () => Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE));
    getFocusable()[0]?.focus();
    const trap = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return;
      const els = getFocusable();
      if (!els.length) return;
      const idx = els.indexOf(document.activeElement as HTMLElement);
      if (e.shiftKey) {
        if (idx <= 0) { e.preventDefault(); els[els.length - 1].focus(); }
      } else {
        if (idx === els.length - 1) { e.preventDefault(); els[0].focus(); }
      }
    };
    document.addEventListener('keydown', trap);
    return () => document.removeEventListener('keydown', trap);
  }, [open]);

  useEffect(() => {
    if (open) document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = ''; };
  }, [open]);

  if (!open) return null;

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 8000 }}>
      <div style={{ position: 'absolute', inset: 0, background: 'rgba(0,0,0,0.4)' }} onClick={handleClose} />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        style={{
          position: 'absolute', top: 0, right: 0, bottom: 0,
          width, maxWidth: '92vw',
          background: 'var(--color-surface)',
          boxShadow: 'var(--shadow-drawer)',
          display: 'flex', flexDirection: 'column',
          animation: 'slideIn 0.2s ease',
        }}
      >
        <div style={{ padding: 'var(--sp-4) var(--sp-6)', borderBottom: '1px solid var(--color-border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
          <h2 style={{ fontSize: 'var(--font-size-h2)', fontWeight: 600 }}>{title}</h2>
          <Button variant="ghost" size="sm" onClick={handleClose} aria-label="Close">✕</Button>
        </div>
        <div style={{ flex: 1, overflow: 'auto', padding: 'var(--sp-6)' }}>{children}</div>
        {onSave && (
          <div style={{ padding: 'var(--sp-4) var(--sp-6)', borderTop: '1px solid var(--color-border)', display: 'flex', gap: 'var(--sp-2)', justifyContent: 'flex-end', flexShrink: 0 }}>
            <Button variant="secondary" onClick={handleClose} disabled={saving}>Cancel</Button>
            <Button variant="primary" onClick={onSave} loading={saving}>{saveLabel}</Button>
          </div>
        )}
      </div>
    </div>
  );
};
