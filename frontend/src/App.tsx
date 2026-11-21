import { useCallback, useEffect, useState } from 'react';
import * as api from './api/client';
import AuthScreen from './components/AuthScreen';
import WorkflowEditor from './components/WorkflowEditor';
import type { AuthUserDto } from './types/workflow';

function App() {
  const [authChecking, setAuthChecking] = useState(true);
  const [user, setUser] = useState<AuthUserDto | null>(null);

  useEffect(() => {
    api.setOnUnauthorized(() => {
      setUser(null);
    });
    let cancelled = false;
    (async () => {
      try {
        const status = await api.fetchAuthMe();
        if (!cancelled) {
          setUser(status.authenticated ? status.user : null);
        }
      } catch {
        if (!cancelled) {
          setUser(null);
        }
      } finally {
        if (!cancelled) {
          setAuthChecking(false);
        }
      }
    })();
    return () => {
      cancelled = true;
      api.setOnUnauthorized(null);
    };
  }, []);

  const handleLogout = useCallback(async () => {
    await api.logoutUser().catch(() => undefined);
    setUser(null);
  }, []);

  if (authChecking) {
    return (
      <div
        style={{
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          background: '#0f172a',
          color: '#e2e8f0',
          fontSize: 14,
          fontWeight: 600,
        }}
      >
        Проверка сессии FloraByte…
      </div>
    );
  }

  if (!user) {
    return <AuthScreen onAuthenticated={(nextUser) => setUser(nextUser)} />;
  }

  return <WorkflowEditor key={user.id} user={user} onLogout={() => void handleLogout()} />;
}

export default App;
