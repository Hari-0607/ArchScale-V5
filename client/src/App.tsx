import React, { useState } from 'react';
import './styles/global.css';

import { setToken, setContextId, logout } from './api/client';
import { SessionContext, SessionData, ContextData } from './hooks/useSession';
import { useToast } from './hooks/useToast';
import { ToastList } from './components/Toast';
import { Sidebar, NavItem } from './components/Sidebar';
import { TopBar } from './components/TopBar';

import { LoginPage } from './pages/auth/LoginPage';
import { OrgWorkspacePicker } from './pages/auth/OrgWorkspacePicker';
import { TeamPage } from './pages/frontstage/TeamPage';
import { TasksPage } from './pages/frontstage/TasksPage';
import { AttendancePage } from './pages/frontstage/AttendancePage';
import { InvitationsPage } from './pages/frontstage/InvitationsPage';
import { TenantsPage } from './pages/backstage/TenantsPage';

// ── Frontstage nav items ───────────────────────────────────────────────────
const FRONTSTAGE_NAV: NavItem[] = [
  { key: 'team',        label: 'Team',         icon: '👥' },
  { key: 'tasks',       label: 'Tasks',        icon: '✓' },
  { key: 'attendance',  label: 'Attendance',   icon: '📅' },
  { key: 'invitations', label: 'Invitations',  icon: '✉' },
];

// ── Backstage nav items ────────────────────────────────────────────────────
const BACKSTAGE_NAV: NavItem[] = [
  { key: 'tenants',  label: 'Tenants',      icon: '🏢' },
  { key: 'audit',    label: 'Audit Log',    icon: '🔍' },
  { key: 'support',  label: 'Support',      icon: '🛡' },
];

// Roles considered backstage (platform super admin)
const BACKSTAGE_ROLES = new Set(['founder', 'platform_admin']);

export const App: React.FC = () => {
  const { toasts, addToast, removeToast } = useToast();
  const [session, setSession] = useState<SessionData | null>(null);
  const [context, setContext] = useState<ContextData | null>(null);
  const [activeNav, setActiveNav] = useState('team');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [pickingContext, setPickingContext] = useState(false);

  const isBackstage = !!(
    session &&
    (BACKSTAGE_ROLES.has(session.principal.role ?? '') ||
      session.principal.email?.includes('founder'))
  );

  const handleLoginSuccess = (sess: SessionData) => {
    setSession(sess);
    setToken(sess.accessToken);
    const isBS = BACKSTAGE_ROLES.has(sess.principal.role ?? '') || sess.principal.email?.includes('founder');
    if (isBS) {
      setActiveNav('tenants');
    } else {
      setPickingContext(true);
      setActiveNav('team');
    }
  };

  const handleContextCreated = (ctx: ContextData) => {
    setContext(ctx);
    setContextId(ctx.contextId);
    setPickingContext(false);
    setActiveNav('team');
  };

  const handleLogout = async () => {
    try { await logout(context?.contextId); } catch { /* ignore */ }
    setSession(null);
    setContext(null);
    setPickingContext(false);
    setActiveNav('team');
    setToken(null);
    setContextId(null);
  };

  const handleSwitchContext = () => {
    setPickingContext(true);
  };

  const renderPage = () => {
    if (isBackstage) {
      switch (activeNav) {
        case 'tenants': return <TenantsPage />;
        case 'audit':   return <BackstageAuditPlaceholder />;
        case 'support': return <BackstageSupportPlaceholder />;
        default:        return <TenantsPage />;
      }
    }
    switch (activeNav) {
      case 'team':        return <TeamPage />;
      case 'tasks':       return <TasksPage />;
      case 'attendance':  return <AttendancePage />;
      case 'invitations': return <InvitationsPage />;
      default:            return <TeamPage />;
    }
  };

  // ── Not logged in ──────────────────────────────────────────────────────────
  if (!session) {
    return (
      <SessionContext.Provider value={{ session, context, setSession, setContext }}>
        <ToastList toasts={toasts} onRemove={removeToast} />
        <LoginPage onSuccess={handleLoginSuccess} />
      </SessionContext.Provider>
    );
  }

  // ── Picking context (org/workspace) ───────────────────────────────────────
  if (pickingContext && !isBackstage) {
    return (
      <SessionContext.Provider value={{ session, context, setSession, setContext }}>
        <ToastList toasts={toasts} onRemove={removeToast} />
        <OrgWorkspacePicker
          onContextCreated={handleContextCreated}
          onLogout={handleLogout}
        />
      </SessionContext.Provider>
    );
  }

  // ── Main app shell ─────────────────────────────────────────────────────────
  const navItems = isBackstage ? BACKSTAGE_NAV : FRONTSTAGE_NAV;

  return (
    <SessionContext.Provider value={{ session, context, setSession, setContext }}>
      <ToastList toasts={toasts} onRemove={removeToast} />
      <div className="app-shell">
        <Sidebar
          items={navItems}
          active={activeNav}
          onChange={setActiveNav}
          title={isBackstage ? 'ArchScale Platform' : (context?.organisationName ?? 'ArchScale')}
          subtitle={isBackstage ? 'Backstage' : (context?.workspaceName ?? undefined)}
          collapsed={sidebarCollapsed}
          onCollapse={() => setSidebarCollapsed(c => !c)}
        />
        <div className="app-content">
          <TopBar
            session={session}
            context={context}
            onLogout={handleLogout}
            onSwitchContext={handleSwitchContext}
          />
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {renderPage()}
          </div>
        </div>
      </div>
    </SessionContext.Provider>
  );
};

// ── Simple placeholder pages for unimplemented backstage sections ──────────
const BackstageAuditPlaceholder: React.FC = () => (
  <div className="page-body">
    <div style={{ padding: '48px 0', textAlign: 'center', color: 'var(--color-text-muted)' }}>
      <div style={{ fontSize: 32, marginBottom: 12, opacity: 0.3 }}>🔍</div>
      <div style={{ fontWeight: 600, color: 'var(--color-text)', marginBottom: 6 }}>Audit Log</div>
      <div style={{ fontSize: 'var(--font-size-sm)' }}>Platform audit log viewer — coming soon</div>
    </div>
  </div>
);

const BackstageSupportPlaceholder: React.FC = () => (
  <div className="page-body">
    <div style={{ padding: '48px 0', textAlign: 'center', color: 'var(--color-text-muted)' }}>
      <div style={{ fontSize: 32, marginBottom: 12, opacity: 0.3 }}>🛡</div>
      <div style={{ fontWeight: 600, color: 'var(--color-text)', marginBottom: 6 }}>Support Access</div>
      <div style={{ fontSize: 'var(--font-size-sm)' }}>Support grant management — coming soon</div>
    </div>
  </div>
);
