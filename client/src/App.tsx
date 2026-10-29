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
import { RolesPermissionsPage } from './pages/frontstage/RolesPermissionsPage';
import { TenantsPage } from './pages/backstage/TenantsPage';

// Roles with platform-level (backstage) access
const BACKSTAGE_ROLES = new Set(['founder', 'platform_admin']);

export const App: React.FC = () => {
  const { toasts, removeToast } = useToast();
  const [session, setSession] = useState<SessionData | null>(null);
  const [context, setContext] = useState<ContextData | null>(null);
  const [activeNav, setActiveNav] = useState('tasks');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [pickingContext, setPickingContext] = useState(false);

  // Authoritative RBAC derivation: in demo environment, demoPersona specifies role and dept
  const personaRole = session?.demoPersona?.role
    ?? context?.roleKey
    ?? session?.principal.role;
  const personaDept = session?.demoPersona?.dept
    ?? (session?.principal as any)?.department
    ?? '';

  const isBackstage = !!(session && (BACKSTAGE_ROLES.has(personaRole ?? '') || session.principal.email?.includes('founder')));
  const isTenantAdmin = personaRole === 'business_owner' || personaRole === 'tenant_admin';
  const isHR = personaDept === 'HR';
  const isManager = personaRole === 'leader' || personaRole === 'manager_coordinator';

  // Section 11: Attendance is strictly hidden from Tenant Admin, Design, Accounts
  const showAttendance = isBackstage || isHR;
  // Section 06: Invitations can only be managed by Tenant Admin
  const showInvitations = isTenantAdmin;
  // Section 13: Roles & Permissions preview visible to Tenant Admin and Managers
  const showRoles = isTenantAdmin || isManager || isBackstage;

  const backstageNav: NavItem[] = [
    { key: 'tenants', label: 'Tenants', icon: '🏢' },
    { key: 'roles',   label: 'RBAC Matrix', icon: '🛡' },
    { key: 'audit',   label: 'Audit Log', icon: '🔍' },
    { key: 'support', label: 'Support', icon: '🔧' },
  ];

  const frontstageNav: NavItem[] = [
    { key: 'tasks',       label: 'Tasks',              icon: '✓' },
    { key: 'team',        label: 'Team & Members',     icon: '👥' },
    { key: 'attendance',  label: 'Attendance',         icon: '📅', hidden: !showAttendance },
    { key: 'invitations', label: 'Invitations',        icon: '✉', hidden: !showInvitations },
    { key: 'roles',       label: 'Roles & Permissions',icon: '🛡', hidden: !showRoles },
  ];

  const navItems = isBackstage ? backstageNav : frontstageNav;

  const handleLoginSuccess = (sess: SessionData) => {
    setSession(sess);
    setToken(sess.accessToken);
    const isBS = BACKSTAGE_ROLES.has(sess.principal.role ?? '')
      || sess.principal.email?.includes('founder')
      || sess.demoPersona?.role === 'founder';
    if (isBS) {
      setActiveNav('tenants');
    } else {
      setPickingContext(true);
      setActiveNav('tasks');
    }
  };

  const handleContextCreated = (ctx: ContextData) => {
    setContext(ctx);
    setContextId(ctx.contextId);
    setPickingContext(false);
    setActiveNav('tasks');
  };

  const handleLogout = async () => {
    try { await logout(context?.contextId); } catch { /* ignore network */ }
    setSession(null);
    setContext(null);
    setPickingContext(false);
    setActiveNav('tasks');
    setToken(null);
    setContextId(null);
  };

  const renderPage = () => {
    if (isBackstage) {
      switch (activeNav) {
        case 'tenants': return <TenantsPage />;
        case 'roles':   return <RolesPermissionsPage />;
        case 'audit':   return <PlaceholderPage icon="🔍" title="Audit Log" />;
        case 'support': return <PlaceholderPage icon="🔧" title="Support Access" />;
        default:        return <TenantsPage />;
      }
    }
    switch (activeNav) {
      case 'tasks':       return <TasksPage />;
      case 'team':        return <TeamPage />;
      case 'attendance':  return <AttendancePage />;
      case 'invitations': return <InvitationsPage />;
      case 'roles':       return <RolesPermissionsPage />;
      default:            return <TasksPage />;
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
            if (key === 'attendance' && !showAttendance) return;
            if (key === 'invitations' && !showInvitations) return;
            if (key === 'roles' && !showRoles) return;
            setActiveNav(key);
          }}
          title={isBackstage ? 'ArchScale Platform' : (context?.organisationName ?? 'ArchScale')}
          subtitle={isBackstage ? 'Backstage' : (session?.demoPersona?.title ?? personaDept)}
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
