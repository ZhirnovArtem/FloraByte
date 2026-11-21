import { useEffect, useState } from 'react';
import * as api from '../api/client';
import type { AiProviderSpecDto, IntegrationsDto, SavedAiProfileDto } from '../types/workflow';

const FALLBACK_PROVIDER_SPECS: AiProviderSpecDto[] = [
  {
    id: 'gemini',
    label: 'Google Gemini',
    adapter_kind: 'gemini',
    auth_type: 'api_key',
    default_base_url: 'https://generativelanguage.googleapis.com/v1beta',
    default_model: 'gemini-2.5-flash',
    supports_model_discovery: true,
    requires_url_input: false,
    key_hint: 'Google AI Studio API Key (AIza...)',
  },
  {
    id: 'gigachat',
    label: 'Sber GigaChat',
    adapter_kind: 'gigachat',
    auth_type: 'oauth2_basic',
    default_base_url: 'https://gigachat.devices.sberbank.ru/api/v1',
    default_model: 'GigaChat',
    supports_model_discovery: true,
    requires_url_input: true,
    key_hint: 'Authorization key (Base64) или client_id:client_secret',
  },
  {
    id: 'openai',
    label: 'OpenAI',
    adapter_kind: 'openai_compatible',
    auth_type: 'api_key',
    default_base_url: 'https://api.openai.com/v1',
    default_model: 'gpt-4o-mini',
    supports_model_discovery: true,
    requires_url_input: false,
    key_hint: 'OpenAI API Key (sk-...)',
  },
  {
    id: 'anthropic',
    label: 'Anthropic Claude',
    adapter_kind: 'anthropic',
    auth_type: 'api_key',
    default_base_url: 'https://api.anthropic.com/v1',
    default_model: 'claude-3-5-haiku-latest',
    supports_model_discovery: true,
    requires_url_input: false,
    key_hint: 'Anthropic API Key (sk-ant-...)',
  },
  {
    id: 'deepseek',
    label: 'DeepSeek',
    adapter_kind: 'openai_compatible',
    auth_type: 'api_key',
    default_base_url: 'https://api.deepseek.com/v1',
    default_model: 'deepseek-chat',
    supports_model_discovery: true,
    requires_url_input: false,
    key_hint: 'DeepSeek API Key (sk-...)',
  },
  {
    id: 'openrouter',
    label: 'OpenRouter',
    adapter_kind: 'openai_compatible',
    auth_type: 'api_key',
    default_base_url: 'https://openrouter.ai/api/v1',
    default_model: 'openai/gpt-4o-mini',
    supports_model_discovery: true,
    requires_url_input: false,
    key_hint: 'OpenRouter API Key (sk-or-...)',
  },
  {
    id: 'ollama',
    label: 'Ollama (локальная / закрытый контур)',
    adapter_kind: 'openai_compatible',
    auth_type: 'optional_key',
    default_base_url: 'http://localhost:11434/v1',
    default_model: 'llama3.2',
    supports_model_discovery: true,
    requires_url_input: true,
    key_hint: 'Необязателен для локального сервера',
  },
  {
    id: 'vllm',
    label: 'vLLM (локальная / закрытый контур)',
    adapter_kind: 'openai_compatible',
    auth_type: 'optional_key',
    default_base_url: 'http://localhost:8000/v1',
    default_model: 'Qwen/Qwen2.5-7B-Instruct',
    supports_model_discovery: true,
    requires_url_input: true,
    key_hint: 'Необязателен для закрытого контура',
  },
  {
    id: 'openai_compatible',
    label: 'Другой OpenAI-compatible API',
    adapter_kind: 'openai_compatible',
    auth_type: 'optional_key',
    default_base_url: '',
    default_model: '',
    supports_model_discovery: true,
    requires_url_input: true,
    key_hint: 'API-ключ (обязателен для удалённых сервисов)',
  },
];

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
  // AI Universal Provider state
  const [specs, setSpecs] = useState<AiProviderSpecDto[]>(FALLBACK_PROVIDER_SPECS);
  const [profiles, setProfiles] = useState<SavedAiProfileDto[]>([]);
  const [provider, setProvider] = useState(integrations.ai.provider || 'gemini');
  const [model, setModel] = useState(integrations.ai.model || 'gemini-2.5-flash');
  const [baseUrl, setBaseUrl] = useState(integrations.ai.base_url || '');
  const [apiKey, setApiKey] = useState('');
  const [discoveredModels, setDiscoveredModels] = useState<string[]>([]);
  const [aiStatusMsg, setAiStatusMsg] = useState('');
  const [aiBusy, setAiBusy] = useState(false);

  // Telegram state
  const [botToken, setBotToken] = useState('');
  const [chatId, setChatId] = useState(integrations.telegram.chat_id || '');
  const [autoSend, setAutoSend] = useState(integrations.telegram.auto_send);
  const [tgStatusMsg, setTgStatusMsg] = useState('');
  const [tgBusy, setTgBusy] = useState(false);

  // Email state
  const emInit = integrations.email;
  const [emailTransport, setEmailTransport] = useState<'resend' | 'smtp'>(
    emInit?.transport === 'smtp' ? 'smtp' : 'resend',
  );
  const [smtpHost, setSmtpHost] = useState(emInit?.smtp_host || 'smtp.gmail.com');
  const [smtpPort, setSmtpPort] = useState<number>(emInit?.smtp_port || 587);
  const [smtpUser, setSmtpUser] = useState(emInit?.smtp_user || '');
  const [fromEmail, setFromEmail] = useState(emInit?.from_email || '');
  const [defaultToEmail, setDefaultToEmail] = useState(emInit?.default_to || '');
  const [emailSecret, setEmailSecret] = useState('');
  const [emailStatusMsg, setEmailStatusMsg] = useState('');
  const [emailBusy, setEmailBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await api.getAiProviders();
        if (cancelled) return;
        if (res.providers.length > 0) setSpecs(res.providers);
        setProfiles(res.profiles);
      } catch {
        // keep fallback specs
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const currentSpec = specs.find((s) => s.id === provider) ?? specs[0];
  const savedProfileForProvider = profiles.find((p) => p.provider === provider);
  const activeKeyPreview =
    savedProfileForProvider?.api_key_preview ||
    (provider === integrations.ai.provider ? integrations.ai.api_key_preview : '');

  const refreshProviders = async () => {
    const res = await api.getAiProviders().catch(() => null);
    if (res) {
      if (res.providers.length > 0) setSpecs(res.providers);
      setProfiles(res.profiles);
    }
  };

  const handleProviderSelect = (nextId: string) => {
    setProvider(nextId);
    setDiscoveredModels([]);
    setApiKey('');
    setAiStatusMsg('');
    const saved = profiles.find((p) => p.provider === nextId);
    const nextSpec = specs.find((s) => s.id === nextId);
    if (saved) {
      setModel(saved.model);
      setBaseUrl(saved.base_url);
    } else if (nextSpec) {
      setModel(nextSpec.default_model);
      setBaseUrl(nextSpec.default_base_url);
    }
  };

  const handleDiscoverModels = async () => {
    setAiBusy(true);
    setAiStatusMsg('Запрос списка моделей…');
    try {
      const res = await api.discoverAiModels({
        provider,
        base_url: baseUrl,
        api_key: apiKey.trim(),
      });
      if (res.ok) {
        setDiscoveredModels(res.models);
        if (res.models.length > 0 && !res.models.includes(model)) {
          setModel(res.models[0]);
        }
        setAiStatusMsg(`✅ ${res.detail || `Найдено моделей: ${res.models.length}`}`);
      } else {
        setAiStatusMsg(`❌ ${res.detail || 'Не удалось получить список моделей'}`);
      }
    } catch (err) {
      setAiStatusMsg(`❌ ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setAiBusy(false);
    }
  };

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
      if (res.models && res.models.length > 0) {
        setDiscoveredModels(res.models);
      }
      setAiStatusMsg(res.ok ? `✅ ${res.detail || 'Подключено'}` : `❌ ${res.detail || 'Ошибка подключения'}`);
    } catch (err) {
      setAiStatusMsg(`❌ ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setAiBusy(false);
    }
  };

  const handleSaveAi = async () => {
    setAiBusy(true);
    setAiStatusMsg('Сохранение и активация провайдера…');
    try {
      const savedAi = await api.saveAiIntegration({
        provider,
        model,
        base_url: baseUrl,
        api_key: apiKey.trim(),
        enabled: true,
        activate: true,
      });
      onUpdated({ ...integrations, ai: savedAi });
      setApiKey('');
      await refreshProviders();
      setAiStatusMsg(
        savedAi.configured
          ? `✅ Активный провайдер: ${savedAi.provider_label || savedAi.provider} (${savedAi.model}). Перезапуск не требуется.`
          : 'Сохранено, но API-ключ не задан.',
      );
    } catch (err) {
      setAiStatusMsg(`❌ ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setAiBusy(false);
    }
  };

  const handleActivateProfile = async (pid: string) => {
    setAiBusy(true);
    setAiStatusMsg(`Переключение на ${pid}…`);
    try {
      const nextAi = await api.activateAiProvider(pid);
      onUpdated({ ...integrations, ai: nextAi });
      setProvider(nextAi.provider);
      setModel(nextAi.model);
      setBaseUrl(nextAi.base_url);
      setApiKey('');
      await refreshProviders();
      setAiStatusMsg(`✅ Активна нейросеть ${nextAi.provider_label || nextAi.provider} (${nextAi.model}).`);
    } catch (err) {
      setAiStatusMsg(`❌ ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setAiBusy(false);
    }
  };

  const handleDeleteAi = async () => {
    setAiBusy(true);
    try {
      await api.deleteAiIntegration(provider);
      const refreshed = await api.getIntegrations();
      onUpdated(refreshed);
      await refreshProviders();
      setApiKey('');
      setAiStatusMsg(`Профиль ${provider} удалён.`);
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

  const applyEmailPreset = (preset: 'resend' | 'gmail' | 'yandex' | 'mailru') => {
    setEmailStatusMsg('');
    if (preset === 'resend') {
      if (emailTransport !== 'resend') {
        setEmailSecret('');
      }
      setEmailTransport('resend');
      if (!fromEmail || fromEmail === 'noreply@florabyte.local' || fromEmail === smtpUser) {
        setFromEmail('onboarding@resend.dev');
      }
      return;
    }
    if (emailTransport !== 'smtp') {
      setEmailSecret('');
    }
    setEmailTransport('smtp');
    if (preset === 'gmail') {
      setSmtpHost('smtp.gmail.com');
      setSmtpPort(587);
    } else if (preset === 'yandex') {
      setSmtpHost('smtp.yandex.ru');
      setSmtpPort(465);
    } else {
      setSmtpHost('smtp.mail.ru');
      setSmtpPort(465);
    }
  };

  const savedEmailMatchesTransport =
    Boolean(integrations.email?.secret_preview) && integrations.email?.transport === emailTransport;

  const normalizeResendInput = (raw: string) => {
    let k = raw.trim().replace(/^["']|["']$/g, '').trim();
    if (k.toLowerCase().startsWith('bearer ')) {
      k = k.slice(7).trim().replace(/^["']|["']$/g, '').trim();
    }
    return k;
  };

  const validateEmailSecretClient = (): string | null => {
    const cleaned = emailTransport === 'resend' ? normalizeResendInput(emailSecret) : emailSecret.trim();
    if (!cleaned) {
      if (!savedEmailMatchesTransport) {
        return emailTransport === 'resend'
          ? 'Укажите Resend API Key (должен начинаться с «re_»). Получить ключ можно на resend.com/api-keys.'
          : 'Укажите пароль приложения SMTP.';
      }
      return null;
    }
    if (emailTransport === 'resend' && (!cleaned.startsWith('re_') || cleaned.length < 8 || /\s/.test(cleaned))) {
      return 'Некорректный формат Resend API Key: ключ должен начинаться с «re_» (не используйте пароль приложения от почты). Создайте новый ключ на resend.com/api-keys.';
    }
    return null;
  };

  const handleTestEmail = async () => {
    const clientErr = validateEmailSecretClient();
    if (clientErr) {
      setEmailStatusMsg(`❌ ${clientErr}`);
      return;
    }
    setEmailBusy(true);
    setEmailStatusMsg('Отправляем тестовое письмо…');
    try {
      const secretToSend =
        emailTransport === 'resend' ? normalizeResendInput(emailSecret) : emailSecret.trim();
      const res = await api.testEmailIntegration({
        transport: emailTransport,
        smtp_host: smtpHost,
        smtp_port: Number(smtpPort) || 587,
        smtp_user: smtpUser,
        from_email: fromEmail,
        default_to: defaultToEmail,
        use_tls: true,
        secret: secretToSend,
      });
      setEmailStatusMsg(res.ok ? `✅ ${res.detail || 'Письмо отправлено'}` : `❌ ${res.error || 'Ошибка отправки'}`);
    } catch (err) {
      setEmailStatusMsg(`❌ ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setEmailBusy(false);
    }
  };

  const handleSaveEmail = async () => {
    const clientErr = validateEmailSecretClient();
    if (clientErr) {
      setEmailStatusMsg(`❌ ${clientErr}`);
      return;
    }
    setEmailBusy(true);
    setEmailStatusMsg('Сохранение настроек почты…');
    try {
      const secretToSend =
        emailTransport === 'resend' ? normalizeResendInput(emailSecret) : emailSecret.trim();
      await api.saveEmailIntegration({
        transport: emailTransport,
        smtp_host: smtpHost,
        smtp_port: Number(smtpPort) || 587,
        smtp_user: smtpUser,
        from_email: fromEmail,
        default_to: defaultToEmail,
        use_tls: true,
        secret: secretToSend,
        enabled: true,
      });
      const refreshed = await api.getIntegrations();
      onUpdated(refreshed);
      setEmailSecret('');
      setEmailStatusMsg('✅ Почта сохранена. Теперь можно нажать «Отправить тестовое письмо» или запустить сценарий.');
    } catch (err) {
      setEmailStatusMsg(`❌ ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setEmailBusy(false);
    }
  };

  const handleDeleteEmail = async () => {
    setEmailBusy(true);
    try {
      await api.deleteEmailIntegration();
      const refreshed = await api.getIntegrations();
      onUpdated(refreshed);
      setEmailSecret('');
      setEmailStatusMsg('Почтовая интеграция отключена.');
    } finally {
      setEmailBusy(false);
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
          maxWidth: 860,
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
            <h2 style={{ margin: 0, fontSize: 18 }}>Настройки → Искусственный интеллект и Интеграции</h2>
            <div style={{ fontSize: 12, color: '#64748b', marginTop: 2 }}>
              Универсальное подключение нейросетей и Telegram (шифрование Fernet, переключение без перезапуска сервера).
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

        <div style={{ display: 'grid', gridTemplateColumns: '1.15fr 0.85fr', gap: 16 }}>
          {/* Universal AI Provider */}
          <div style={{ border: '1px solid #cbd5e1', borderRadius: 10, padding: 14, background: '#f8fafc' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <strong style={{ fontSize: 14 }}>Universal AI Provider</strong>
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
                {integrations.ai.configured
                  ? `Активен: ${integrations.ai.provider_label || integrations.ai.provider}`
                  : 'AI не настроен'}
              </span>
            </div>

            {profiles.length > 0 && (
              <div style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: '#475569', marginBottom: 4 }}>
                  Сохранённые нейросети (переключение в 1 клик):
                </div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {profiles.map((p) => (
                    <button
                      key={p.provider}
                      type="button"
                      disabled={aiBusy}
                      onClick={() => void handleActivateProfile(p.provider)}
                      style={{
                        padding: '4px 9px',
                        borderRadius: 999,
                        border: p.is_active ? '1px solid #16a34a' : '1px solid #cbd5e1',
                        background: p.is_active ? '#dcfce7' : '#ffffff',
                        color: p.is_active ? '#166534' : '#334155',
                        fontSize: 11,
                        fontWeight: 700,
                        cursor: 'pointer',
                      }}
                    >
                      {p.is_active ? '● ' : ''}
                      {p.label} ({p.model})
                    </button>
                  ))}
                </div>
              </div>
            )}

            <label style={{ display: 'block', fontSize: 12, marginBottom: 8 }}>
              <span style={{ fontWeight: 600 }}>Провайдер</span>
              <select
                value={provider}
                onChange={(e) => handleProviderSelect(e.target.value)}
                style={{ width: '100%', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
              >
                {specs.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.label}
                  </option>
                ))}
              </select>
            </label>

            <label style={{ display: 'block', fontSize: 12, marginBottom: 8 }}>
              <span style={{ fontWeight: 600 }}>
                API Key {activeKeyPreview ? `(сохранён: ${activeKeyPreview})` : ''}
              </span>
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={
                  activeKeyPreview
                    ? 'Оставьте пустым, чтобы сохранить текущий ключ'
                    : currentSpec?.key_hint || 'Введите API-ключ'
                }
                style={{ width: '100%', boxSizing: 'border-box', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
              />
            </label>

            <div style={{ fontSize: 12, marginBottom: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 600 }}>Модель</span>
                {currentSpec?.supports_model_discovery && (
                  <button
                    type="button"
                    disabled={aiBusy}
                    onClick={() => void handleDiscoverModels()}
                    style={{
                      padding: '2px 8px',
                      borderRadius: 5,
                      border: '1px solid #cbd5e1',
                      background: '#ffffff',
                      fontSize: 11,
                      cursor: 'pointer',
                    }}
                  >
                    Определить модели
                  </button>
                )}
              </div>
              {discoveredModels.length > 0 && (
                <select
                  value={discoveredModels.includes(model) ? model : ''}
                  onChange={(e) => {
                    if (e.target.value) setModel(e.target.value);
                  }}
                  style={{ width: '100%', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
                >
                  <option value="">Выберите из найденных ({discoveredModels.length}) или введите вручную…</option>
                  {discoveredModels.map((m) => (
                    <option key={m} value={m}>
                      {m}
                    </option>
                  ))}
                </select>
              )}
              <input
                type="text"
                value={model}
                onChange={(e) => setModel(e.target.value)}
                placeholder={currentSpec?.default_model || 'Название модели'}
                style={{ width: '100%', boxSizing: 'border-box', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
              />
            </div>

            {(currentSpec?.requires_url_input || baseUrl) && (
              <label style={{ display: 'block', fontSize: 12, marginBottom: 8 }}>
                <span style={{ fontWeight: 600 }}>API URL</span>
                <input
                  type="text"
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  placeholder={currentSpec?.default_base_url || 'https://.../v1'}
                  style={{ width: '100%', boxSizing: 'border-box', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
                />
                {(provider === 'ollama' || provider === 'vllm') && (
                  <div style={{ fontSize: 11, color: '#64748b', marginTop: 3 }}>
                    Для локальных моделей укажите URL, доступный Backend-серверу (в закрытом контуре или туннеле). Ключ необязателен.
                  </div>
                )}
              </label>
            )}

            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 10 }}>
              <button
                type="button"
                disabled={aiBusy}
                onClick={() => void handleTestAi()}
                style={{ padding: '6px 10px', borderRadius: 6, border: '1px solid #cbd5e1', background: '#fff', fontSize: 12, cursor: 'pointer' }}
              >
                Проверить подключение
              </button>
              <button
                type="button"
                disabled={aiBusy}
                onClick={() => void handleSaveAi()}
                style={{ padding: '6px 12px', borderRadius: 6, border: 'none', background: '#2563eb', color: '#fff', fontSize: 12, fontWeight: 700, cursor: 'pointer' }}
              >
                Сохранить и использовать
              </button>
              {(savedProfileForProvider || integrations.ai.configured) && (
                <button
                  type="button"
                  disabled={aiBusy}
                  onClick={() => void handleDeleteAi()}
                  style={{ padding: '6px 10px', borderRadius: 6, border: 'none', background: '#fee2e2', color: '#991b1b', fontSize: 12, cursor: 'pointer' }}
                >
                  Удалить ключ
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

          {/* Email Integration */}
          <div style={{ border: '1px solid #cbd5e1', borderRadius: 10, padding: 14, background: '#f8fafc' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <strong style={{ fontSize: 14 }}>Email-уведомления (отправка отчётов на почту)</strong>
              <span
                style={{
                  fontSize: 11,
                  padding: '2px 8px',
                  borderRadius: 999,
                  fontWeight: 700,
                  background: integrations.email?.configured ? '#dcfce7' : '#fef3c7',
                  color: integrations.email?.configured ? '#166534' : '#92400e',
                }}
              >
                {integrations.email?.configured
                  ? `${integrations.email.transport.toUpperCase()} · ${integrations.email.default_to}`
                  : 'Не настроена'}
              </span>
            </div>

            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
              <button
                type="button"
                onClick={() => applyEmailPreset('resend')}
                style={{
                  padding: '4px 9px',
                  borderRadius: 6,
                  border: '1px solid #cbd5e1',
                  background: emailTransport === 'resend' ? '#0f172a' : '#fff',
                  color: emailTransport === 'resend' ? '#fff' : '#334155',
                  fontSize: 11,
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Resend HTTPS API (рекомендуется для Render)
              </button>
              <button
                type="button"
                onClick={() => applyEmailPreset('gmail')}
                style={{
                  padding: '4px 9px',
                  borderRadius: 6,
                  border: '1px solid #cbd5e1',
                  background: emailTransport === 'smtp' && smtpHost === 'smtp.gmail.com' ? '#0f172a' : '#fff',
                  color: emailTransport === 'smtp' && smtpHost === 'smtp.gmail.com' ? '#fff' : '#334155',
                  fontSize: 11,
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Gmail SMTP
              </button>
              <button
                type="button"
                onClick={() => applyEmailPreset('yandex')}
                style={{
                  padding: '4px 9px',
                  borderRadius: 6,
                  border: '1px solid #cbd5e1',
                  background: emailTransport === 'smtp' && smtpHost === 'smtp.yandex.ru' ? '#0f172a' : '#fff',
                  color: emailTransport === 'smtp' && smtpHost === 'smtp.yandex.ru' ? '#fff' : '#334155',
                  fontSize: 11,
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Yandex SMTP
              </button>
              <button
                type="button"
                onClick={() => applyEmailPreset('mailru')}
                style={{
                  padding: '4px 9px',
                  borderRadius: 6,
                  border: '1px solid #cbd5e1',
                  background: emailTransport === 'smtp' && smtpHost === 'smtp.mail.ru' ? '#0f172a' : '#fff',
                  color: emailTransport === 'smtp' && smtpHost === 'smtp.mail.ru' ? '#fff' : '#334155',
                  fontSize: 11,
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Mail.ru SMTP
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 8 }}>
              <label style={{ display: 'block', fontSize: 12 }}>
                <span style={{ fontWeight: 600 }}>Email получателя (по умолчанию)</span>
                <input
                  type="email"
                  value={defaultToEmail}
                  onChange={(e) => setDefaultToEmail(e.target.value)}
                  placeholder="you@gmail.com"
                  style={{ width: '100%', boxSizing: 'border-box', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
                />
              </label>

              <label style={{ display: 'block', fontSize: 12 }}>
                <span style={{ fontWeight: 600 }}>Отправитель (From)</span>
                <input
                  type="text"
                  value={fromEmail}
                  onChange={(e) => setFromEmail(e.target.value)}
                  placeholder={emailTransport === 'resend' ? 'onboarding@resend.dev' : 'your@gmail.com'}
                  style={{ width: '100%', boxSizing: 'border-box', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
                />
              </label>
            </div>

            {emailTransport === 'smtp' && (
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 2fr', gap: 8, marginBottom: 8 }}>
                <label style={{ display: 'block', fontSize: 12 }}>
                  <span style={{ fontWeight: 600 }}>SMTP Host</span>
                  <input
                    type="text"
                    value={smtpHost}
                    onChange={(e) => setSmtpHost(e.target.value)}
                    placeholder="smtp.gmail.com"
                    style={{ width: '100%', boxSizing: 'border-box', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
                  />
                </label>
                <label style={{ display: 'block', fontSize: 12 }}>
                  <span style={{ fontWeight: 600 }}>Порт</span>
                  <input
                    type="number"
                    value={smtpPort}
                    onChange={(e) => setSmtpPort(Number(e.target.value) || 587)}
                    style={{ width: '100%', boxSizing: 'border-box', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
                  />
                </label>
                <label style={{ display: 'block', fontSize: 12 }}>
                  <span style={{ fontWeight: 600 }}>SMTP Логин</span>
                  <input
                    type="text"
                    value={smtpUser}
                    onChange={(e) => setSmtpUser(e.target.value)}
                    placeholder="your@gmail.com"
                    style={{ width: '100%', boxSizing: 'border-box', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
                  />
                </label>
              </div>
            )}

            <label style={{ display: 'block', fontSize: 12, marginBottom: 8 }}>
              <span style={{ fontWeight: 600 }}>
                {emailTransport === 'resend' ? 'Resend API Key' : 'Пароль приложения SMTP (App Password)'}{' '}
                {savedEmailMatchesTransport ? `(текущий: ${integrations.email?.secret_preview})` : ''}
              </span>
              <input
                type="password"
                value={emailSecret}
                onChange={(e) => setEmailSecret(e.target.value)}
                placeholder={
                  savedEmailMatchesTransport
                    ? 'Оставьте пустым, чтобы сохранить текущий (или вставьте новый)'
                    : emailTransport === 'resend'
                      ? 're_...'
                      : 'Пароль приложения (16 символов)'
                }
                style={{ width: '100%', boxSizing: 'border-box', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
              />
              {emailTransport === 'resend' && (
                <div style={{ fontSize: 11, color: '#64748b', marginTop: 3, lineHeight: 1.4 }}>
                  Работает по HTTPS (порт 443) даже на бесплатном тарифе Render. Ключ должен начинаться с <code>re_</code> (создаётся на resend.com/api-keys). С адресом <code>onboarding@resend.dev</code> Resend доставляет письма только на email вашего аккаунта Resend.
                </div>
              )}
            </label>

            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              <button
                type="button"
                disabled={emailBusy}
                onClick={() => void handleTestEmail()}
                style={{ padding: '6px 10px', borderRadius: 6, border: '1px solid #cbd5e1', background: '#fff', fontSize: 12, cursor: 'pointer' }}
              >
                Отправить тестовое письмо
              </button>
              <button
                type="button"
                disabled={emailBusy}
                onClick={() => void handleSaveEmail()}
                style={{ padding: '6px 10px', borderRadius: 6, border: 'none', background: '#059669', color: '#fff', fontSize: 12, fontWeight: 700, cursor: 'pointer' }}
              >
                Сохранить почту
              </button>
              {integrations.email?.configured && (
                <button
                  type="button"
                  disabled={emailBusy}
                  onClick={() => void handleDeleteEmail()}
                  style={{ padding: '6px 10px', borderRadius: 6, border: 'none', background: '#fee2e2', color: '#991b1b', fontSize: 12, cursor: 'pointer' }}
                >
                  Отключить
                </button>
              )}
            </div>

            {emailStatusMsg && (
              <div style={{ marginTop: 8, fontSize: 12, color: '#1e293b', background: '#fff', padding: 8, borderRadius: 6, border: '1px solid #e2e8f0' }}>
                {emailStatusMsg}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
