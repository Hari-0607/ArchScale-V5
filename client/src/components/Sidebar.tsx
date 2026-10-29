import React from 'react';

export interface NavItem {
  key: string;
  label: string;
  icon?: string;
  hidden?: boolean;
}

interface SidebarProps {
  items: NavItem[];
  active: string;
  onChange: (key: string) => void;
  title?: string;
  subtitle?: string;
  collapsed?: boolean;
  onCollapse?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  items, active, onChange, title, subtitle, collapsed, onCollapse
}) => (
  <nav
    style={{
      width: collapsed ? 48 : 'var(--sidebar-width)',
      minWidth: collapsed ? 48 : 'var(--sidebar-width)',
      background: 'var(--color-sidebar-bg)',
      display: 'flex',
      flexDirection: 'column',
      height: '100%',
      flexShrink: 0,
      transition: 'width var(--transition), min-width var(--transition)',
      overflow: 'hidden',
      borderRight: '1px solid rgba(255,255,255,0.06)',
    }}
  >
    {/* Brand / org header */}
    <div style={{
      padding: collapsed ? '14px 0' : '0 16px',
      height: 'var(--topbar-height)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: collapsed ? 'center' : 'space-between',
      borderBottom: '1px solid rgba(255,255,255,0.08)',
      flexShrink: 0,
      gap: 8,
    }}>
      {!collapsed && (
        <div style={{ overflow: 'hidden', flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 'var(--font-size-body)', fontWeight: 700, color: '#fff', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {title ?? 'ArchScale'}
          </div>
          {subtitle && (
            <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-sidebar-text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', opacity: 0.7 }}>
              {subtitle}
            </div>
          )}
        </div>
      )}
      {onCollapse && (
        <button
          onClick={onCollapse}
          style={{ background: 'none', border: 'none', color: 'var(--color-sidebar-text)', cursor: 'pointer', fontSize: 14, padding: '4px', flexShrink: 0, opacity: 0.6, lineHeight: 1 }}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? '»' : '«'}
        </button>
      )}
    </div>

    {/* Nav items */}
    <div style={{ flex: 1, padding: '6px 0', overflowY: 'auto' }}>
      {items.filter(i => !i.hidden).map(item => {
        const isActive = active === item.key;
        return (
          <button
            key={item.key}
            onClick={() => onChange(item.key)}
            title={collapsed ? item.label : undefined}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              width: '100%',
              padding: collapsed ? '0 12px' : '0 16px',
              height: 38,
              background: isActive ? 'var(--color-sidebar-active-bg)' : 'transparent',
              border: 'none',
              borderLeft: isActive ? '3px solid var(--color-sidebar-active)' : '3px solid transparent',
              color: isActive ? '#fff' : 'var(--color-sidebar-text)',
              fontSize: 'var(--font-size-body)',
              fontWeight: isActive ? 600 : 400,
              cursor: 'pointer',
              textAlign: 'left',
              transition: 'background var(--transition)',
              justifyContent: collapsed ? 'center' : 'flex-start',
            }}
            onMouseEnter={e => { if (!isActive) (e.currentTarget as HTMLButtonElement).style.background = 'var(--color-sidebar-hover)'; }}
            onMouseLeave={e => { if (!isActive) (e.currentTarget as HTMLButtonElement).style.background = 'transparent'; }}
          >
            {item.icon && <span style={{ flexShrink: 0, fontSize: 14, opacity: isActive ? 1 : 0.7 }}>{item.icon}</span>}
            {!collapsed && (
              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {item.label}
              </span>
            )}
          </button>
        );
      })}
    </div>
  </nav>
);
