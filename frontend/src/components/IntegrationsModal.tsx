import { useState } from 'react';
import * as api from '../api/client';
import type { IntegrationsDto } from '../types/workflow';

type IntegrationsModalProps = {
  integrations: IntegrationsDto;
  onClose: () => void;
  onUpdated: (next: IntegrationsDto) => void;
};

export default function IntegrationsModal({
  integrations,
  onClose,
  onUpdated,
}: IntegrationsModalProps) {
  // AI state
  const [provider, setProvider] = useState(integrations.ai.provider || 'gemini');
  const [model, setModel] = useState(integrations.ai.model || 'gemini-2.5-flash');
  const [baseUrl, setBaseUrl] = useState(integrations.ai.base_url || '');
  const [apiKey, setApiKey] = useState('');
  const [aiStatusMsg, setAiStatusMsg] = useState('');
  const [aiBusy, setAiBusy] = useState(false);

  // Telegram state
  const [botToken, setBotToken] = useState('');
  const [chatId, setChatId] = useState(integrations.telegram.chat_id || '');
  const [autoSend, setAutoSend] = useState(integrations.telegram.auto_send);
  const [tgStatusMsg, setTgStatusMsg] = useState('');
  const [tgBusy, setTgBusy] = useState(false);

  const handleTestAi = async () => {
    setAiBusy(true);
    setAiStatusMsg('Проверка AI-подключения…');
    try {
      const res = await api.testAiIntegration({
        provider,
        model,
        base_url: baseUrl,
        api_key: apiKey.trim(),
      });
      setAiStatusMsg(res.ok ? `✅ ${res.detail || 'Подключено'}` : `❌ ${res.detail || 'Ошибка подключения'}`);
    } catch (err) {
      setAiStatusMsg(`❌ ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setAiBusy(false);
    }
  };

  const handleSaveAi = async () => {
    setAiBusy(true);
    setAiStatusMsg('Сохранение AI-интеграции…');
    try {
      const savedAi = await api.saveAiIntegration({
        provider,
        model,
        base_url: baseUrl,
        api_key: apiKey.trim(),
        enabled: true,
      });
      onUpdated({ ...integrations, ai: savedAi });
      setApiKey('');
      setAiStatusMsg(
        savedAi.configured
          ? `✅ AI настроен (${savedAi.provider} · ${savedAi.model}). При создании сценария блок AI Explain добавляется автоматически.`
          : 'Сохранено, но API-ключ не задан.',
      );
    } catch (err) {
      setAiStatusMsg(`❌ ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setAiBusy(false);
    }
  };

  const handleDeleteAi = async () => {
    setAiBusy(true);
    try {
      await api.deleteAiIntegration();
      const refreshed = await api.getIntegrations();
      onUpdated(refreshed);
      setApiKey('');
      setAiStatusMsg('AI-интеграция отключена.');
    } finally {
      setAiBusy(false);
    }
  };

  const handleTestTelegram = async () => {
    setTgBusy(true);
    setTgStatusMsg('Проверка Telegram-бота…');
    try {
      const res = await api.testTelegramIntegration({
        bot_token: botToken.trim(),
        chat_id: chatId.trim(),
      });
      if (res.ok) {
        const botLabel = res.bot_username ? `@${res.bot_username}` : 'Бот';
        const chatLabel = res.chat_title ? ` → чат «${res.chat_title}»` : '';
        setTgStatusMsg(`✅ Подключено: ${botLabel}${chatLabel}`);
      } else {
        setTgStatusMsg(`❌ ${res.error || 'Не удалось проверить Telegram'}`);
      }
    } catch (err) {
      setTgStatusMsg(`❌ ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setTgBusy(false);
    }
  };

  const handleSaveTelegram = async () => {
    setTgBusy(true);
    setTgStatusMsg('Проверка и сохранение Telegram…');
    try {
      const savedTg = await api.saveTelegramIntegration({
        bot_token: botToken.trim(),
        chat_id: chatId.trim(),
        auto_send: autoSend,
        enabled: true,
        verify: true,
      });
      onUpdated({ ...integrations, telegram: savedTg });
      setBotToken('');
      const botLabel = savedTg.bot_username ? `@${savedTg.bot_username}` : 'бот';
      setTgStatusMsg(
        `✅ Telegram подключён (${botLabel}, chat_id=${savedTg.chat_id}). ${
          savedTg.auto_send
            ? 'Блок Telegram будет добавляться в сценарий автоматически.'
            : 'Режим «по запросу»: отправка кнопкой из отчёта.'
        }`,
      );
    } catch (err) {
      setTgStatusMsg(`❌ ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setTgBusy(false);
    }
  };

  const handleDeleteTelegram = async () => {
    setTgBusy(true);
    try {
      await api.deleteTelegramIntegration();
      const refreshed = await api.getIntegrations();
      onUpdated(refreshed);
      setBotToken('');
      setTgStatusMsg('Telegram-интеграция отключена.');
    } finally {
      setTgBusy(false);
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
          maxWidth: 760,
          maxHeight: '90vh',
          overflowY: 'auto',
          background: '#ffffff',
          borderRadius: 12,
          padding: 20,
          boxShadow: '0 20px 50px rgba(0,0,0,0.25)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <div>
            <h2 style={{ margin: 0, fontSize: 18 }}>Настройки интеграций (1 раз для всех сценариев)</h2>
            <div style={{ fontSize: 12, color: '#64748b', marginTop: 2 }}>
              Ключи шифруются на backend (Fernet) и автоматически подключаются при создании сценария.
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            style={{
              padding: '6px 12px',
              borderRadius: 6,
              border: '1px solid #cbd5e1',
              background: '#f8fafc',
              cursor: 'pointer',
              fontWeight: 700,
            }}
          >
            Закрыть
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          {/* AI Integration */}
          <div style={{ border: '1px solid #cbd5e1', borderRadius: 10, padding: 14, background: '#f8fafc' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <strong style={{ fontSize: 14 }}>AI Explain (LLM)</strong>
              <span
                style={{
                  fontSize: 11,
                  padding: '2px 8px',
                  borderRadius: 999,
                  fontWeight: 700,
                  background: integrations.ai.configured ? '#dcfce7' : '#fef3c7',
                  color: integrations.ai.configured ? '#166534' : '#92400e',
                }}
              >
                {integrations.ai.configured ? 'Подключён' : 'Не настроен'}
              </span>
            </div>

            <label style={{ display: 'block', fontSize: 12, marginBottom: 8 }}>
              <span style={{ fontWeight: 600 }}>Провайдер</span>
              <select
                value={provider}
                onChange={(e) => {
                  const next = e.target.value;
                  setProvider(next);
                  if (next === 'ollama') {
                    if (!baseUrl || baseUrl.includes(':8000') || baseUrl.includes('googleapis')) {
                      setBaseUrl('http://localhost:11434/v1');
                    }
                    if (!model || model.startsWith('gemini') || model.startsWith('Qwen/')) {
                      setModel('llama3.2');
                    }
                  } else if (next === 'vllm') {
                    if (!baseUrl || baseUrl.includes(':11434') || baseUrl.includes('googleapis')) {
                      setBaseUrl('http://localhost:8000/v1');
                    }
                    if (!model || model.startsWith('gemini') || model === 'llama3.2') {
                      setModel('Qwen/Qwen2.5-7B-Instruct');
                    }
                  } else if (next === 'gemini') {
                    if (!model || model === 'llama3.2' || model.startsWith('Qwen/')) {
                      setModel('gemini-2.5-flash');
                    }
                  }
                }}
                style={{ width: '100%', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
              >
                <option value="gemini">Google Gemini (облако)</option>
                <option value="ollama">Ollama (локальная / закрытый контур)</option>
                <option value="vllm">vLLM (локальная / закрытый контур)</option>
                <option value="openai_compatible">OpenAI-compatible API</option>
              </select>
            </label>

            <label style={{ display: 'block', fontSize: 12, marginBottom: 8 }}>
              <span style={{ fontWeight: 600 }}>Модель</span>
              <input
                type="text"
                value={model}
                onChange={(e) => setModel(e.target.value)}
                placeholder={provider === 'ollama' ? 'llama3.2' : provider === 'vllm' ? 'Qwen/Qwen2.5-7B-Instruct' : 'gemini-2.5-flash'}
                style={{ width: '100%', boxSizing: 'border-box', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
              />
            </label>

            {provider !== 'gemini' && (
              <label style={{ display: 'block', fontSize: 12, marginBottom: 8 }}>
                <span style={{ fontWeight: 600 }}>Base URL (закрытый контур / localhost)</span>
                <input
                  type="text"
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  placeholder={provider === 'vllm' ? 'http://localhost:8000/v1' : 'http://localhost:11434/v1'}
                  style={{ width: '100%', boxSizing: 'border-box', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
                />
                <div style={{ fontSize: 11, color: '#64748b', marginTop: 3 }}>
                  Для локальных Ollama/vLLM в закрытом контуре API-ключ не обязателен.
                </div>
              </label>
            )}

            <label style={{ display: 'block', fontSize: 12, marginBottom: 8 }}>
              <span style={{ fontWeight: 600 }}>
                API-ключ {integrations.ai.api_key_preview ? `(текущий: ${integrations.ai.api_key_preview})` : ''}
              </span>
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={integrations.ai.configured ? 'Оставьте пустым, чтобы сохранить текущий' : 'Вставьте API-ключ'}
                style={{ width: '100%', boxSizing: 'border-box', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
              />
            </label>

            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 10 }}>
              <button
                type="button"
                disabled={aiBusy}
                onClick={() => void handleTestAi()}
                style={{ padding: '6px 10px', borderRadius: 6, border: '1px solid #cbd5e1', background: '#fff', fontSize: 12, cursor: 'pointer' }}
              >
                Проверить
              </button>
              <button
                type="button"
                disabled={aiBusy}
                onClick={() => void handleSaveAi()}
                style={{ padding: '6px 10px', borderRadius: 6, border: 'none', background: '#2563eb', color: '#fff', fontSize: 12, fontWeight: 700, cursor: 'pointer' }}
              >
                Сохранить AI
              </button>
              {integrations.ai.configured && (
                <button
                  type="button"
                  disabled={aiBusy}
                  onClick={() => void handleDeleteAi()}
                  style={{ padding: '6px 10px', borderRadius: 6, border: 'none', background: '#fee2e2', color: '#991b1b', fontSize: 12, cursor: 'pointer' }}
                >
                  Отключить
                </button>
              )}
            </div>

            {aiStatusMsg && (
              <div style={{ marginTop: 8, fontSize: 12, color: '#1e293b', background: '#fff', padding: 8, borderRadius: 6, border: '1px solid #e2e8f0' }}>
                {aiStatusMsg}
              </div>
            )}
          </div>

          {/* Telegram Integration */}
          <div style={{ border: '1px solid #cbd5e1', borderRadius: 10, padding: 14, background: '#f8fafc' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <strong style={{ fontSize: 14 }}>Telegram-уведомления</strong>
              <span
                style={{
                  fontSize: 11,
                  padding: '2px 8px',
                  borderRadius: 999,
                  fontWeight: 700,
                  background: integrations.telegram.configured ? '#dcfce7' : '#fef3c7',
                  color: integrations.telegram.configured ? '#166534' : '#92400e',
                }}
              >
                {integrations.telegram.configured
                  ? integrations.telegram.bot_username
                    ? `@${integrations.telegram.bot_username}`
                    : 'Подключён'
                  : 'Не настроен'}
              </span>
            </div>

            <label style={{ display: 'block', fontSize: 12, marginBottom: 8 }}>
              <span style={{ fontWeight: 600 }}>
                Bot Token из @BotFather{' '}
                {integrations.telegram.bot_token_preview ? `(текущий: ${integrations.telegram.bot_token_preview})` : ''}
              </span>
              <input
                type="password"
                value={botToken}
                onChange={(e) => setBotToken(e.target.value)}
                placeholder={integrations.telegram.configured ? 'Оставьте пустым, чтобы сохранить текущий' : '123456789:AA...'}
                style={{ width: '100%', boxSizing: 'border-box', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
              />
            </label>

            <label style={{ display: 'block', fontSize: 12, marginBottom: 8 }}>
              <span style={{ fontWeight: 600 }}>Chat ID</span>
              <input
                type="text"
                value={chatId}
                onChange={(e) => setChatId(e.target.value)}
                placeholder="Например: 123456789 или -100..."
                style={{ width: '100%', boxSizing: 'border-box', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
              />
            </label>

            <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, marginBottom: 10, cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={autoSend}
                onChange={(e) => setAutoSend(e.target.checked)}
              />
              <span>Автоматически отправлять отчёт в Telegram после сканирования</span>
            </label>

            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              <button
                type="button"
                disabled={tgBusy}
                onClick={() => void handleTestTelegram()}
                style={{ padding: '6px 10px', borderRadius: 6, border: '1px solid #cbd5e1', background: '#fff', fontSize: 12, cursor: 'pointer' }}
              >
                Проверить Telegram
              </button>
              <button
                type="button"
                disabled={tgBusy}
                onClick={() => void handleSaveTelegram()}
                style={{ padding: '6px 10px', borderRadius: 6, border: 'none', background: '#059669', color: '#fff', fontSize: 12, fontWeight: 700, cursor: 'pointer' }}
              >
                Проверить и сохранить
              </button>
              {integrations.telegram.configured && (
                <button
                  type="button"
                  disabled={tgBusy}
                  onClick={() => void handleDeleteTelegram()}
                  style={{ padding: '6px 10px', borderRadius: 6, border: 'none', background: '#fee2e2', color: '#991b1b', fontSize: 12, cursor: 'pointer' }}
                >
                  Отключить
                </button>
              )}
            </div>

            {tgStatusMsg && (
              <div style={{ marginTop: 8, fontSize: 12, color: '#1e293b', background: '#fff', padding: 8, borderRadius: 6, border: '1px solid #e2e8f0' }}>
                {tgStatusMsg}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
