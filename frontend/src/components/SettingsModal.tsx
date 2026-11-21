import { useState } from 'react';
import * as api from '../api/client';
import type { AuthUserDto, IntegrationsDto } from '../types/workflow';

type SettingsModalProps = {
  user: AuthUserDto;
  integrations: IntegrationsDto;
  onClose: () => void;
  onOpenIntegrations: () => void;
  onLogout: () => void;
};

export default function SettingsModal({
  user,
  integrations,
  onClose,
  onOpenIntegrations,
  onLogout,
}: SettingsModalProps) {
  const [logKind, setLogKind] = useState<'errors' | 'app'>('errors');
  const [logOpen, setLogOpen] = useState(false);
  const [logLoading, setLogLoading] = useState(false);
  const [logError, setLogError] = useState('');
  const [logData, setLogData] = useState<api.LogTailDto | null>(null);

  const loadLogs = async (kind: 'errors' | 'app') => {
    setLogKind(kind);
    setLogOpen(true);
    setLogLoading(true);
    setLogError('');
    try {
      const res = await api.getLogs(kind, 120);
      setLogData(res);
    } catch (err) {
      setLogError(err instanceof Error ? err.message : String(err));
    } finally {
      setLogLoading(false);
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(15, 23, 42, 0.55)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
        padding: 16,
      }}
    >
      <div
        style={{
          width: '100%',
          maxWidth: logOpen ? 760 : 540,
          maxHeight: '90vh',
          display: 'flex',
          flexDirection: 'column',
          background: '#ffffff',
          borderRadius: 12,
          boxShadow: '0 20px 50px rgba(0,0,0,0.28)',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            padding: '14px 18px',
            background: '#0f172a',
            color: '#f8fafc',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <div>
            <div style={{ fontSize: 15, fontWeight: 700 }}>Настройки аккаунта и безопасности</div>
            <div style={{ fontSize: 12, color: '#94a3b8' }}>
              Все токены и ключи хранятся зашифрованными на сервере для вашего аккаунта
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              color: '#cbd5e1',
              fontSize: 18,
              cursor: 'pointer',
            }}
          >
            ✕
          </button>
        </div>

        <div style={{ padding: 18, display: 'flex', flexDirection: 'column', gap: 14, overflowY: 'auto' }}>
          <div
            style={{
              padding: 14,
              borderRadius: 10,
              border: '1px solid #e2e8f0',
              background: '#f8fafc',
            }}
          >
            <div style={{ fontSize: 12, color: '#64748b', fontWeight: 600 }}>Аккаунт</div>
            <div style={{ fontSize: 15, fontWeight: 700, color: '#0f172a', marginTop: 4 }}>{user.email}</div>
            <div style={{ fontSize: 12, color: '#059669', marginTop: 4, fontWeight: 600 }}>
              ● Авторизован (защищённая HttpOnly cookie + CSRF-защита)
            </div>
          </div>

          <div
            style={{
              padding: 14,
              borderRadius: 10,
              border: '1px solid #e2e8f0',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              gap: 12,
            }}
          >
            <div>
              <div style={{ fontSize: 14, fontWeight: 700, color: '#0f172a' }}>
                Искусственный интеллект и Интеграции
              </div>
              <div style={{ fontSize: 12, color: '#475569', marginTop: 3 }}>
                AI:{' '}
                {integrations.ai.configured
                  ? `${integrations.ai.provider_label || integrations.ai.provider} (${integrations.ai.model}) ✓`
                  : 'не настроен'}{' '}
                · Telegram: {integrations.telegram.configured ? `chat ${integrations.telegram.chat_id} ✓` : 'не настроен'}
              </div>
            </div>
            <button
              type="button"
              onClick={() => {
                onClose();
                onOpenIntegrations();
              }}
              style={{
                padding: '8px 12px',
                borderRadius: 8,
                border: 'none',
                background: '#4f46e5',
                color: '#ffffff',
                fontSize: 12,
                fontWeight: 700,
                cursor: 'pointer',
                whiteSpace: 'nowrap',
              }}
            >
              Настроить ИИ и интеграции →
            </button>
          </div>

          <div
            style={{
              padding: 14,
              borderRadius: 10,
              border: '1px solid #e2e8f0',
              background: '#f8fafc',
              display: 'flex',
              flexDirection: 'column',
              gap: 10,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <div>
                <div style={{ fontSize: 14, fontWeight: 700, color: '#0f172a' }}>
                  Журнал логов и ошибок сайта
                </div>
                <div style={{ fontSize: 12, color: '#475569', marginTop: 2 }}>
                  Записываются в файлы <code>logs/florabyte.log</code> и <code>logs/errors.log</code> (секреты маскируются)
                </div>
              </div>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                <button
                  type="button"
                  onClick={() => void loadLogs('errors')}
                  style={{
                    padding: '6px 10px',
                    borderRadius: 7,
                    border: '1px solid #cbd5e1',
                    background: logOpen && logKind === 'errors' ? '#0f172a' : '#ffffff',
                    color: logOpen && logKind === 'errors' ? '#ffffff' : '#0f172a',
                    fontSize: 12,
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  Ошибки (errors.log)
                </button>
                <button
                  type="button"
                  onClick={() => void loadLogs('app')}
                  style={{
                    padding: '6px 10px',
                    borderRadius: 7,
                    border: '1px solid #cbd5e1',
                    background: logOpen && logKind === 'app' ? '#0f172a' : '#ffffff',
                    color: logOpen && logKind === 'app' ? '#ffffff' : '#0f172a',
                    fontSize: 12,
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  Все логи (florabyte.log)
                </button>
                <a
                  href={api.getLogDownloadUrl(logKind)}
                  download
                  style={{
                    padding: '6px 10px',
                    borderRadius: 7,
                    border: '1px solid #cbd5e1',
                    background: '#ffffff',
                    color: '#334155',
                    fontSize: 12,
                    fontWeight: 600,
                    textDecoration: 'none',
                  }}
                >
                  Скачать .log
                </a>
              </div>
            </div>

            {logOpen && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {logLoading && <div style={{ fontSize: 12, color: '#64748b' }}>Загрузка логов…</div>}
                {logError && <div style={{ fontSize: 12, color: '#b91c1c' }}>Ошибка загрузки логов: {logError}</div>}
                {logData && !logLoading && (
                  <>
                    <div style={{ fontSize: 11, color: '#64748b' }}>
                      Файл: <code>{logData.path}</code> · показано последних строк: {logData.total_returned}
                    </div>
                    <pre
                      style={{
                        margin: 0,
                        maxHeight: 220,
                        overflow: 'auto',
                        background: '#0f172a',
                        color: '#e2e8f0',
                        padding: 10,
                        borderRadius: 8,
                        fontSize: 11,
                        lineHeight: 1.45,
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-word',
                      }}
                    >
                      {logData.entries.length > 0 ? logData.entries.join('\n') : 'Записей пока нет.'}
                    </pre>
                  </>
                )}
              </div>
            )}
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 4 }}>
            <button
              type="button"
              onClick={() => {
                onClose();
                onLogout();
              }}
              style={{
                padding: '8px 14px',
                borderRadius: 8,
                border: '1px solid #fecaca',
                background: '#fef2f2',
                color: '#b91c1c',
                fontSize: 12,
                fontWeight: 700,
                cursor: 'pointer',
              }}
            >
              Выйти из аккаунта
            </button>
            <button
              type="button"
              onClick={onClose}
              style={{
                padding: '8px 14px',
                borderRadius: 8,
                border: '1px solid #cbd5e1',
                background: '#ffffff',
                color: '#334155',
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              Закрыть
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
