import React, { useState } from 'react';
import './styles/global.css';

import { setToken, setContextId, getDemoPersona, logout } from './api/client';
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

// Roles with platform-level (backstage) access
const BACKSTAGE_ROLES = new Set(['founder', 'platform_admin']);

// Attendance is visible only to HR dept or founder
function canSeeAttendance(role?: string, dept?: string): boolean {
  if (role === 'founder') return true;
  if (dept === 'HR') return true;
  return false;
}

const BACKSTAGE_NAV: NavItem[] = [
  { key: 'tenants',  label: 'Tenants',   icon: '🏢' },
  { key: 'audit',    label: 'Audit Log', icon: '🔍' },
  { key: 'support',  label: 'Support',   icon: '🛡' },
];

export const App: React.FC = () => {
  const { toasts, removeToast } = useToast();
  const [session, setSession] = useState<SessionData | null>(null);
  const [context, setContext] = useState<ContextData | null>(null);
  const [activeNav, setActiveNav] = useState('team');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [pickingContext, setPickingContext] = useState(false);

  // Derive role + dept from context (DB authoritative) → demoPersona → principal
  const personaRole = context?.roleKey
    ?? session?.demoPersona?.role
    ?? session?.principal.role;
  const personaDept = context?.roleKey
    ? undefined   // trust DB when context has role
    : (session?.demoPersona?.dept ?? (session?.principal as any)?.department);

  const isBackstage = !!(session && BACKSTAGE_ROLES.has(personaRole ?? ''));
  const showAttendance = canSeeAttendance(personaRole, personaDept);

  const navItems: NavItem[] = isBackstage ? BACKSTAGE_NAV : [
    { key: 'team',        label: 'Team',         icon: '👥' },
    { key: 'tasks',       label: 'Tasks',        icon: '✓' },
    { key: 'attendance',  label: 'Attendance',   icon: '📅', hidden: !showAttendance },
    { key: 'invitations', label: 'Invitations',  icon: '✉' },
  ];

  const handleLoginSuccess = (sess: SessionData) => {
    setSession(sess);
    setToken(sess.accessToken);
    const isBS = BACKSTAGE_ROLES.has(sess.principal.role ?? '')
      || sess.principal.email?.includes('founder');
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
    try { await logout(context?.contextId); } catch { /* ignore network */ }
    setSession(null);
    setContext(null);
    setPickingContext(false);
    setActiveNav('team');
    setToken(null);
    setContextId(null);
  };

  const renderPage = () => {
    if (isBackstage) {
      switch (activeNav) {
        case 'tenants': return <TenantsPage />;
        case 'audit':   return <PlaceholderPage icon="🔍" title="Audit Log" />;
        case 'support': return <PlaceholderPage icon="🛡" title="Support Access" />;
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

  // ── Org/workspace picker ───────────────────────────────────────────────────
  if (pickingContext && !isBackstage) {
    return (
      <SessionContext.Provider value={{ session, context, setSession, setContext }}>
        <ToastList toasts={toasts} onRemove={removeToast} />
        <OrgWorkspacePicker onContextCreated={handleContextCreated} onLogout={handleLogout} />
      </SessionContext.Provider>
    );
  }

  // ── Main shell ─────────────────────────────────────────────────────────────
  return (
    <SessionContext.Provider value={{ session, context, setSession, setContext }}>
      <ToastList toasts={toasts} onRemove={removeToast} />
      <div className="app-shell">
        <Sidebar
          items={navItems}
          active={activeNav}
          onChange={key => {
            // If attendance is hidden but someone navigates to it (direct), redirect to team
            if (key === 'attendance' && !showAttendance) return;
            setActiveNav(key);
          }}
          title={isBackstage ? 'ArchScale Platform' : (context?.organisationName ?? 'ArchScale')}
          subtitle={isBackstage ? 'Backstage' : (context?.workspaceName ?? personaDept)}
          collapsed={sidebarCollapsed}
          onCollapse={() => setSidebarCollapsed(c => !c)}
        />
        <div className="app-content">
          <TopBar
            session={session}
            context={context}
            onLogout={handleLogout}
            onSwitchContext={() => setPickingContext(true)}
          />
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {renderPage()}
          </div>
        </div>
      </div>
    </SessionContext.Provider>
  );
};

const PlaceholderPage: React.FC<{ icon: string; title: string }> = ({ icon, title }) => (
  <div className="page-body">
    <div style={{ padding: '56px 0', textAlign: 'center', color: 'var(--color-text-muted)' }}>
      <div style={{ fontSize: 36, marginBottom: 14, opacity: 0.3 }}>{icon}</div>
      <div style={{ fontWeight: 600, fontSize: 'var(--font-size-md)', color: 'var(--color-text)', marginBottom: 6 }}>{title}</div>
      <div style={{ fontSize: 'var(--font-size-sm)' }}>Coming soon</div>
    </div>
  </div>
);
