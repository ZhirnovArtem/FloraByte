import { useState } from 'react';
import type { CredentialDto, NodeTypeSpec } from '../types/workflow';
import type { SecurityNodeType } from './SecurityNode';

type NodeSettingsProps = {
  selectedNode: SecurityNodeType | null;
  nodeSpec?: NodeTypeSpec;
  credentials: CredentialDto[];
  isOpen: boolean;
  onToggle: () => void;
  variant?: 'docked' | 'drawer' | 'fullscreen';
  onSave: (nodeId: string, label: string, params: Record<string, unknown>) => void;
  onUploadZip?: (file: File) => Promise<string | null>;
  onCreateCredential?: (name: string, kind: string, value: string) => Promise<CredentialDto | null>;
};

export default function NodeSettings({
  selectedNode,
  nodeSpec,
  credentials,
  isOpen,
  onToggle,
  variant = 'docked',
  onSave,
  onUploadZip,
  onCreateCredential,
}: NodeSettingsProps) {
  const [label, setLabel] = useState<string>(selectedNode?.data.label ?? '');
  const [params, setParams] = useState<Record<string, unknown>>({ ...(selectedNode?.data.params ?? {}) });
  const [uploading, setUploading] = useState(false);
  const [credName, setCredName] = useState('');
  const [credValue, setCredValue] = useState('');
  const [showNewCred, setShowNewCred] = useState(false);

  if (!isOpen && variant !== 'fullscreen') {
    return (
      <aside
        onClick={onToggle}
        title="Развернуть настройки блока"
        style={{
          width: 40,
          padding: '10px 4px',
          background: '#f8fafc',
          borderLeft: '1px solid #e2e8f0',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: 10,
          flexShrink: 0,
          overflow: 'hidden',
          cursor: 'pointer',
          userSelect: 'none',
        }}
      >
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onToggle();
          }}
          aria-label="Развернуть настройки блока"
          style={{
            width: 28,
            height: 28,
            borderRadius: 6,
            border: '1px solid #cbd5e1',
            background: '#fff',
            color: '#334155',
            fontSize: 12,
            fontWeight: 700,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          ◀
        </button>
        <span
          style={{
            writingMode: 'vertical-rl',
            fontSize: 12,
            fontWeight: 700,
            color: '#475569',
            letterSpacing: '0.03em',
          }}
        >
          Настройки блока
        </span>
      </aside>
    );
  }

  const inputStyle: React.CSSProperties = {
    width: '100%',
    padding: '8px 9px',
    border: '1px solid #cbd5e1',
    borderRadius: 6,
    marginTop: 4,
    marginBottom: 12,
    fontSize: variant === 'fullscreen' ? 14 : 13,
  };

  const asideStyle: React.CSSProperties =
    variant === 'fullscreen'
      ? {
          width: '100%',
          flex: 1,
          minHeight: 0,
          padding: 16,
          background: '#f8fafc',
          overflowY: 'auto',
        }
      : variant === 'drawer'
        ? {
            position: 'fixed',
            top: 0,
            bottom: 0,
            right: 0,
            width: 'min(340px, 88vw)',
            padding: 18,
            background: '#f8fafc',
            borderLeft: '1px solid #cbd5e1',
            boxShadow: '-8px 0 32px rgba(15, 23, 42, 0.25)',
            overflowY: 'auto',
            zIndex: 45,
          }
        : {
            width: 310,
            padding: 18,
            background: '#f8fafc',
            borderLeft: '1px solid #e2e8f0',
            overflowY: 'auto',
            flexShrink: 0,
          };

  const collapseBtn = (
    <button
      type="button"
      onClick={onToggle}
      title={variant === 'fullscreen' ? 'Вернуться к схеме' : 'Свернуть панель настроек'}
      style={{
        padding: variant === 'fullscreen' ? '6px 10px' : '3px 7px',
        borderRadius: 6,
        border: '1px solid #cbd5e1',
        background: '#fff',
        color: '#475569',
        fontSize: variant === 'fullscreen' ? 12 : 11,
        fontWeight: 600,
        cursor: 'pointer',
        flexShrink: 0,
      }}
    >
      {variant === 'fullscreen' ? '← К схеме' : variant === 'drawer' ? '✕ Закрыть' : 'Свернуть ▶'}
    </button>
  );

  if (!selectedNode) {
    return (
      <>
        {variant === 'drawer' && (
          <div
            onClick={onToggle}
            style={{ position: 'fixed', inset: 0, background: 'rgba(15, 23, 42, 0.35)', zIndex: 44 }}
          />
        )}
        <aside style={asideStyle}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10, gap: 8 }}>
            <h3 style={{ margin: 0 }}>Настройки блока</h3>
            {collapseBtn}
          </div>
          <p style={{ color: '#64748b', fontSize: 13 }}>Выберите блок на схеме для редактирования параметров.</p>
        </aside>
      </>
    );
  }

  const schemaProps = nodeSpec?.params_schema?.properties ?? {};
  const propEntries = Object.entries(schemaProps);
  const kind = selectedNode.data.kind;

  const updateParam = (key: string, value: unknown) => {
    setParams((curr) => ({ ...curr, [key]: value }));
  };

  const handleZipChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !onUploadZip) return;
    setUploading(true);
    try {
      const uploadId = await onUploadZip(file);
      if (uploadId) {
        const nextParams = { ...params, upload_id: uploadId };
        setParams(nextParams);
        onSave(selectedNode.id, label, nextParams);
      }
    } finally {
      setUploading(false);
      e.target.value = '';
    }
  };

  const handleCreateCred = async () => {
    if (!onCreateCredential || !credName.trim() || !credValue.trim()) return;
    const credKind = kind.includes('telegram')
      ? 'telegram'
      : kind.includes('webhook')
      ? 'webhook'
      : kind.includes('ai')
      ? 'llm'
      : 'generic';
    const created = await onCreateCredential(credName.trim(), credKind, credValue.trim());
    if (created) {
      updateParam('credential_id', created.id);
      setCredName('');
      setCredValue('');
      setShowNewCred(false);
    }
  };

  return (
    <>
      {variant === 'drawer' && (
        <div
          onClick={onToggle}
          style={{ position: 'fixed', inset: 0, background: 'rgba(15, 23, 42, 0.35)', zIndex: 44 }}
        />
      )}
      <aside style={asideStyle}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6, gap: 8 }}>
          <h3 style={{ margin: 0 }}>Настройки блока</h3>
          {collapseBtn}
        </div>
      <div style={{ fontSize: 12, color: '#64748b', fontFamily: 'monospace', marginBottom: 14 }}>
        {kind}
      </div>

      <label style={{ display: 'block', fontSize: 13, fontWeight: 600 }}>
        Название блока
        <input
          style={inputStyle}
          value={label}
          onChange={(e) => setLabel(e.target.value)}
        />
      </label>

      {kind === 'trigger.schedule' && (
        <div
          style={{
            marginBottom: 12,
            padding: '8px 10px',
            borderRadius: 8,
            background: '#eff6ff',
            border: '1px solid #bfdbfe',
            color: '#1e3a8a',
            fontSize: 11,
            lineHeight: 1.45,
          }}
        >
          <strong>Повтор делает сервер</strong> (APScheduler), не стрелка в графе. Задайте{' '}
          <code>interval_seconds ≥ 30</code> (Cron пустой) или Cron-выражение, а при необходимости ограничьте число отправок через{' '}
          <code>max_runs</code> (пусто или 0 — без лимита), затем нажмите <strong>Применить</strong> и <strong>Сохранить</strong>.
        </div>
      )}

      {kind === 'source.upload_zip' && (
        <div
          style={{
            marginBottom: 12,
            padding: '8px 10px',
            borderRadius: 8,
            background: '#fffbeb',
            border: '1px solid #fde68a',
            color: '#92400e',
            fontSize: 11,
            lineHeight: 1.45,
          }}
        >
          Временный ZIP-архив подходит для ручного запуска. Для регулярных проверок по{' '}
          <strong>Schedule</strong> используйте блок <strong>Git Clone</strong>.
        </div>
      )}

      {propEntries.length === 0 && (
        <p style={{ fontSize: 12, color: '#64748b' }}>У этого блока нет настраиваемых параметров.</p>
      )}

      {propEntries.map(([key, prop]) => {
        const rawVal = params[key] !== undefined ? params[key] : prop.default;
        const val = rawVal === null || rawVal === undefined ? '' : rawVal;
        const anyOfTypes = (prop.anyOf ?? []).map((x) => x.type).filter((t): t is string => Boolean(t));
        const isNullable = anyOfTypes.includes('null');
        const fieldType = prop.type ?? anyOfTypes.find((t) => t !== 'null') ?? 'string';

        if (fieldType === 'boolean') {
          return (
            <label
              key={key}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                fontSize: 13,
                fontWeight: 600,
                marginBottom: 12,
              }}
            >
              <input
                type="checkbox"
                checked={Boolean(params[key] ?? prop.default ?? false)}
                onChange={(e) => updateParam(key, e.target.checked)}
              />
              <span>{prop.title || key}</span>
            </label>
          );
        }

        if (key === 'credential_id') {
          return (
            <div key={key} style={{ marginBottom: 12 }}>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 600 }}>
                {prop.title || 'Credential'}
                <select
                  style={{ ...inputStyle, marginBottom: 6 }}
                  value={String(val)}
                  onChange={(e) => updateParam(key, e.target.value)}
                >
                  <option value="">— из .env / не выбран —</option>
                  {credentials.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name} ({c.kind}: {c.value_preview})
                    </option>
                  ))}
                </select>
              </label>
              {onCreateCredential && (
                <button
                  type="button"
                  onClick={() => setShowNewCred((s) => !s)}
                  style={{
                    fontSize: 11,
                    padding: '4px 8px',
                    background: '#e2e8f0',
                    border: 'none',
                    borderRadius: 6,
                    cursor: 'pointer',
                  }}
                >
                  {showNewCred ? 'Скрыть форму' : '+ Новый credential'}
                </button>
              )}
              {showNewCred && (
                <div style={{ marginTop: 8, padding: 10, background: '#fff', borderRadius: 8, border: '1px solid #cbd5e1' }}>
                  <input
                    style={{ ...inputStyle, marginBottom: 6 }}
                    placeholder="Название (напр. tg-bot)"
                    value={credName}
                    onChange={(e) => setCredName(e.target.value)}
                  />
                  <input
                    type="password"
                    style={{ ...inputStyle, marginBottom: 6 }}
                    placeholder="Значение (токен / ключ)"
                    value={credValue}
                    onChange={(e) => setCredValue(e.target.value)}
                  />
                  <button
                    type="button"
                    onClick={handleCreateCred}
                    style={{
                      width: '100%',
                      padding: 7,
                      background: '#059669',
                      color: '#fff',
                      border: 'none',
                      borderRadius: 6,
                      cursor: 'pointer',
                      fontSize: 12,
                    }}
                  >
                    Сохранить секрет (Fernet)
                  </button>
                </div>
              )}
            </div>
          );
        }

        return (
          <div key={key}>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 600 }}>
              {prop.title || key}
              {prop.description && (
                <span style={{ display: 'block', fontSize: 11, fontWeight: 400, color: '#64748b' }}>
                  {prop.description}
                </span>
              )}
              <input
                type={fieldType === 'integer' || fieldType === 'number' ? 'number' : 'text'}
                min={key === 'max_runs' ? 0 : undefined}
                placeholder={isNullable ? 'Без лимита (пусто)' : undefined}
                style={inputStyle}
                value={String(val)}
                onChange={(e) => {
                  if (fieldType === 'integer') {
                    if (e.target.value === '') {
                      updateParam(key, isNullable ? null : 0);
                    } else {
                      const parsed = parseInt(e.target.value, 10);
                      updateParam(key, Number.isNaN(parsed) ? (isNullable ? null : 0) : parsed);
                    }
                  } else if (fieldType === 'number') {
                    if (e.target.value === '') {
                      updateParam(key, isNullable ? null : 0);
                    } else {
                      const parsed = parseFloat(e.target.value);
                      updateParam(key, Number.isNaN(parsed) ? (isNullable ? null : 0) : parsed);
                    }
                  } else {
                    updateParam(key, e.target.value);
                  }
                }}
              />
            </label>
            {kind === 'source.upload_zip' && key === 'upload_id' && onUploadZip && (
              <div style={{ marginTop: -6, marginBottom: 12 }}>
                <label
                  style={{
                    display: 'inline-block',
                    padding: '6px 10px',
                    background: '#0284c7',
                    color: '#fff',
                    borderRadius: 6,
                    fontSize: 12,
                    cursor: uploading ? 'wait' : 'pointer',
                  }}
                >
                  {uploading ? 'Загрузка…' : 'Выбрать .zip для этого блока'}
                  <input
                    type="file"
                    accept=".zip"
                    style={{ display: 'none' }}
                    onChange={handleZipChange}
                  />
                </label>
              </div>
            )}
          </div>
        );
      })}

      <button
        onClick={() => onSave(selectedNode.id, label, params)}
        style={{
          width: '100%',
          padding: 10,
          minHeight: variant === 'fullscreen' ? 42 : undefined,
          background: '#2563eb',
          color: '#ffffff',
          border: 'none',
          borderRadius: 8,
          cursor: 'pointer',
          fontWeight: 600,
        }}
      >
        Применить параметры
      </button>
      </aside>
    </>
  );
}
