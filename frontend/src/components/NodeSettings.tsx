import { useState } from 'react';
import type { CredentialDto, NodeTypeSpec } from '../types/workflow';
import type { SecurityNodeType } from './SecurityNode';

type NodeSettingsProps = {
  selectedNode: SecurityNodeType | null;
  nodeSpec?: NodeTypeSpec;
  credentials: CredentialDto[];
  onSave: (nodeId: string, label: string, params: Record<string, unknown>) => void;
  onUploadZip?: (file: File) => Promise<string | null>;
  onCreateCredential?: (name: string, kind: string, value: string) => Promise<CredentialDto | null>;
};

export default function NodeSettings({
  selectedNode,
  nodeSpec,
  credentials,
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

  const inputStyle: React.CSSProperties = {
    width: '100%',
    padding: '8px 9px',
    border: '1px solid #cbd5e1',
    borderRadius: 6,
    marginTop: 4,
    marginBottom: 12,
    fontSize: 13,
  };

  if (!selectedNode) {
    return (
      <aside
        style={{
          width: 310,
          padding: 18,
          background: '#f8fafc',
          borderLeft: '1px solid #e2e8f0',
          flexShrink: 0,
        }}
      >
        <h3 style={{ marginTop: 0 }}>Настройки блока</h3>
        <p style={{ color: '#64748b', fontSize: 13 }}>Выберите блок на схеме для редактирования параметров.</p>
      </aside>
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
    <aside
      style={{
        width: 310,
        padding: 18,
        background: '#f8fafc',
        borderLeft: '1px solid #e2e8f0',
        overflowY: 'auto',
        flexShrink: 0,
      }}
    >
      <h3 style={{ marginTop: 0, marginBottom: 6 }}>Настройки блока</h3>
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

      {propEntries.length === 0 && (
        <p style={{ fontSize: 12, color: '#64748b' }}>У этого блока нет настраиваемых параметров.</p>
      )}

      {propEntries.map(([key, prop]) => {
        const val = params[key] ?? prop.default ?? '';
        const fieldType = prop.type ?? 'string';

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
                style={inputStyle}
                value={String(val)}
                onChange={(e) => {
                  if (fieldType === 'integer') {
                    updateParam(key, e.target.value === '' ? 0 : parseInt(e.target.value, 10));
                  } else if (fieldType === 'number') {
                    updateParam(key, e.target.value === '' ? 0 : parseFloat(e.target.value));
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
  );
}
