import React, { useState } from 'react';
import { logoutApi, setApiContext, setApiSession } from './api/client';
import { Header } from './components/Header';
import { BackstageView } from './pages/BackstageView';
import { FrontstageView } from './pages/FrontstageView';
import { LoginView } from './pages/LoginView';
import { AccessContext, UserSession } from './types';

export const App: React.FC = () => {
  const [session, setSession] = useState<UserSession | null>(null);
  const [context, setContext] = useState<AccessContext | null>(null);
  const [mode, setMode] = useState<'backstage' | 'frontstage'>('frontstage');
  const [isLoginModalOpen, setIsLoginModalOpen] = useState(false);

  const handleLoginSuccess = (newSession: UserSession) => {
    setSession(newSession);
    setApiSession(newSession);
    setIsLoginModalOpen(false);

    // If platform super admin, direct to Backstage; otherwise Frontstage
    if (newSession.principal.role === 'founder' || newSession.principal.email?.includes('founder')) {
      setMode('backstage');
    } else {
      setMode('frontstage');
    }
  };

  const handleLogout = async () => {
    await logoutApi();
    setSession(null);
    setContext(null);
    setApiSession(null);
    setApiContext(null);
  };

  const handleContextChange = (ctx: AccessContext | null) => {
    setContext(ctx);
    setApiContext(ctx);
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', backgroundColor: '#0b0f19' }}>
      <Header
        session={session}
        context={context}
        mode={mode}
        onModeChange={setMode}
        onLogout={handleLogout}
        onOpenLogin={() => setIsLoginModalOpen(true)}
      />

      <main style={{ flex: 1 }}>
        {!session || isLoginModalOpen ? (
          <LoginView onLoginSuccess={handleLoginSuccess} />
        ) : mode === 'backstage' ? (
          <BackstageView />
        ) : (
          <FrontstageView context={context} onContextChange={handleContextChange} />
        )}
      </main>
    </div>
  );
};
