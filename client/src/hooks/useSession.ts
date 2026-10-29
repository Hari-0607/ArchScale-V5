import { createContext, useContext } from 'react';

export interface Principal {
  id: string;
  email: string;
  sessionId?: string;
  aal: 'aal1' | 'aal2';
  role?: string;
  department?: string;
  jobRole?: string;
  personaKey?: string;
  memberId?: string;
}

export interface SessionData {
  accessToken: string;
  principal: Principal;
  mfaRequired?: boolean;
  demoPersona?: { key: string; role: string; dept: string; title: string; memberId: string };
}

export interface ContextData {
  contextId: string;
  organisationId: string;
  organisationName?: string;
  workspaceId: string;
  workspaceName?: string;
  aal: 'aal1' | 'aal2';
  expiresAt: string;
  roleKey?: string;
}

export interface SessionCtx {
  session: SessionData | null;
  context: ContextData | null;
  setSession: (s: SessionData | null) => void;
  setContext: (c: ContextData | null) => void;
}

export const SessionContext = createContext<SessionCtx>({
  session: null,
  context: null,
  setSession: () => {},
  setContext: () => {},
});

export const useSession = () => useContext(SessionContext);

