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
          maxWidth: 520,
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

        <div style={{ padding: 18, display: 'flex', flexDirection: 'column', gap: 14 }}>
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
