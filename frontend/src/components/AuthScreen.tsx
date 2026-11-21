import { useState, type FormEvent } from 'react';
import * as api from '../api/client';
import type { AuthUserDto } from '../types/workflow';

type Mode = 'login' | 'register' | 'forgot' | 'reset';

type AuthScreenProps = {
  persistentStorage?: boolean;
  onAuthenticated: (user: AuthUserDto) => void;
};

export default function AuthScreen({ persistentStorage = true, onAuthenticated }: AuthScreenProps) {
  const [mode, setMode] = useState<Mode>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [resetCode, setResetCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const switchMode = (next: Mode) => {
    setMode(next);
    setError('');
    setNotice('');
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    setNotice('');

    if (mode === 'login') {
      setBusy(true);
      try {
        const res = await api.loginUser(email.trim(), password);
        if (res.authenticated && res.user) {
          onAuthenticated(res.user);
        } else {
          setError('Не удалось выполнить вход.');
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setBusy(false);
      }
      return;
    }

    if (mode === 'register') {
      if (password.length < 8) {
        setError('Пароль должен содержать минимум 8 символов.');
        return;
      }
      if (password !== confirmPassword) {
        setError('Пароли не совпадают.');
        return;
      }
      setBusy(true);
      try {
        const res = await api.registerUser(email.trim(), password);
        if (res.authenticated && res.user) {
          onAuthenticated(res.user);
        } else {
          setError('Не удалось завершить регистрацию.');
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setBusy(false);
      }
      return;
    }

    if (mode === 'forgot') {
      setBusy(true);
      try {
        const res = await api.forgotPassword(email.trim());
        setNotice(res.message);
        setMode('reset');
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setBusy(false);
      }
      return;
    }

    if (mode === 'reset') {
      if (password.length < 8) {
        setError('Новый пароль должен содержать минимум 8 символов.');
        return;
      }
      setBusy(true);
      try {
        const res = await api.resetPassword(email.trim(), resetCode.trim(), password);
        setPassword('');
        setResetCode('');
        setMode('login');
        setNotice(res.message);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setBusy(false);
      }
    }
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 60%, #1e1b4b 100%)',
        padding: 20,
      }}
    >
      <div
        style={{
          width: '100%',
          maxWidth: 420,
          background: '#ffffff',
          borderRadius: 14,
          boxShadow: '0 24px 60px rgba(2, 6, 23, 0.45)',
          padding: 28,
        }}
      >
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 22, fontWeight: 800, color: '#0f172a' }}>FloraByte</div>
          <div style={{ fontSize: 13, color: '#475569', marginTop: 4 }}>
            AI Security Workflow · защищённый вход
          </div>
        </div>

        {!persistentStorage && (
          <div
            style={{
              marginBottom: 14,
              padding: '9px 11px',
              borderRadius: 8,
              background: '#fffbeb',
              border: '1px solid #fde68a',
              color: '#92400e',
              fontSize: 12,
              lineHeight: 1.4,
            }}
          >
            Сервер работает на временной БД (SQLite без PostgreSQL <code>DATABASE_URL</code>): после перезапуска
            или деплоя аккаунты сбрасываются. Если вход не проходит — зарегистрируйтесь заново или подключите PostgreSQL.
          </div>
        )}

        <div
          style={{
            display: 'flex',
            gap: 6,
            background: '#f1f5f9',
            padding: 4,
            borderRadius: 9,
            marginBottom: 18,
          }}
        >
          <button
            type="button"
            onClick={() => switchMode('login')}
            style={{
              flex: 1,
              padding: '8px 10px',
              border: 'none',
              borderRadius: 7,
              cursor: 'pointer',
              fontSize: 13,
              fontWeight: 600,
              background: mode === 'login' ? '#ffffff' : 'transparent',
              color: mode === 'login' ? '#0f172a' : '#64748b',
              boxShadow: mode === 'login' ? '0 1px 3px rgba(0,0,0,0.1)' : 'none',
            }}
          >
            Вход
          </button>
          <button
            type="button"
            onClick={() => switchMode('register')}
            style={{
              flex: 1,
              padding: '8px 10px',
              border: 'none',
              borderRadius: 7,
              cursor: 'pointer',
              fontSize: 13,
              fontWeight: 600,
              background: mode === 'register' ? '#ffffff' : 'transparent',
              color: mode === 'register' ? '#0f172a' : '#64748b',
              boxShadow: mode === 'register' ? '0 1px 3px rgba(0,0,0,0.1)' : 'none',
            }}
          >
            Регистрация
          </button>
        </div>

        {error && (
          <div
            style={{
              marginBottom: 14,
              padding: '9px 12px',
              borderRadius: 8,
              background: '#fef2f2',
              border: '1px solid #fecaca',
              color: '#991b1b',
              fontSize: 12,
            }}
          >
            {error}
          </div>
        )}

        {notice && (
          <div
            style={{
              marginBottom: 14,
              padding: '9px 12px',
              borderRadius: 8,
              background: '#eff6ff',
              border: '1px solid #bfdbfe',
              color: '#1e3a8a',
              fontSize: 12,
            }}
          >
            {notice}
          </div>
        )}

        <form onSubmit={(e) => void handleSubmit(e)} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 5, fontSize: 12, fontWeight: 600, color: '#334155' }}>
            Email
            <input
              type="email"
              required
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="name@company.com"
              style={{
                padding: '9px 11px',
                borderRadius: 8,
                border: '1px solid #cbd5e1',
                fontSize: 14,
              }}
            />
          </label>

          {mode === 'reset' && (
            <label style={{ display: 'flex', flexDirection: 'column', gap: 5, fontSize: 12, fontWeight: 600, color: '#334155' }}>
              Код восстановления
              <input
                type="text"
                required
                value={resetCode}
                onChange={(e) => setResetCode(e.target.value)}
                placeholder="123456-abcd"
                style={{
                  padding: '9px 11px',
                  borderRadius: 8,
                  border: '1px solid #cbd5e1',
                  fontSize: 14,
                }}
              />
            </label>
          )}

          {mode !== 'forgot' && (
            <label style={{ display: 'flex', flexDirection: 'column', gap: 5, fontSize: 12, fontWeight: 600, color: '#334155' }}>
              {mode === 'reset' ? 'Новый пароль (мин. 8 символов)' : 'Пароль'}
              <input
                type="password"
                required
                minLength={8}
                autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                style={{
                  padding: '9px 11px',
                  borderRadius: 8,
                  border: '1px solid #cbd5e1',
                  fontSize: 14,
                }}
              />
            </label>
          )}

          {mode === 'register' && (
            <label style={{ display: 'flex', flexDirection: 'column', gap: 5, fontSize: 12, fontWeight: 600, color: '#334155' }}>
              Повторите пароль
              <input
                type="password"
                required
                minLength={8}
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="••••••••"
                style={{
                  padding: '9px 11px',
                  borderRadius: 8,
                  border: '1px solid #cbd5e1',
                  fontSize: 14,
                }}
              />
            </label>
          )}

          <button
            type="submit"
            disabled={busy}
            style={{
              marginTop: 4,
              padding: '10px 14px',
              borderRadius: 8,
              border: 'none',
              background: busy ? '#94a3b8' : '#4f46e5',
              color: '#ffffff',
              fontSize: 14,
              fontWeight: 700,
              cursor: busy ? 'wait' : 'pointer',
            }}
          >
            {busy
              ? 'Подождите…'
              : mode === 'login'
                ? 'Войти'
                : mode === 'register'
                  ? 'Создать аккаунт'
                  : mode === 'forgot'
                    ? 'Запросить восстановление'
                    : 'Обновить пароль'}
          </button>
        </form>

        <div
          style={{
            marginTop: 16,
            paddingTop: 12,
            borderTop: '1px solid #e2e8f0',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            fontSize: 12,
            color: '#64748b',
          }}
        >
          {mode === 'login' ? (
            <button
              type="button"
              onClick={() => switchMode('forgot')}
              style={{
                background: 'none',
                border: 'none',
                padding: 0,
                color: '#4f46e5',
                cursor: 'pointer',
                fontSize: 12,
                fontWeight: 600,
              }}
            >
              Забыли пароль?
            </button>
          ) : (
            <button
              type="button"
              onClick={() => switchMode('login')}
              style={{
                background: 'none',
                border: 'none',
                padding: 0,
                color: '#4f46e5',
                cursor: 'pointer',
                fontSize: 12,
                fontWeight: 600,
              }}
            >
              ← Вернуться ко входу
            </button>
          )}
          <span>HttpOnly сессия</span>
        </div>
      </div>
    </div>
  );
}
