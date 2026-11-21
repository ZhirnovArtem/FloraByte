import { useEffect, useState } from 'react';
import * as api from '../api/client';
import type { CustomNodeDto, CustomNodeVersionDto, PortSpec } from '../types/workflow';

const STARTER_CODE = `async def run(ctx, inputs, params):
    findings = inputs.get("findings", [])
    result = {
        "total": len(findings),
        "critical": sum(
            1 for item in findings
            if isinstance(item, dict) and item.get("severity") == "CRITICAL"
        ),
    }
    return {"result": result}
`;

const PORT_KINDS = ['Any', 'Findings', 'Report', 'Workspace', 'Boolean'];

type ParamFieldRow = {
  key: string;
  type: 'string' | 'integer' | 'number' | 'boolean';
  defaultValue: string;
  description: string;
};

type CustomNodesModalProps = {
  onClose: () => void;
  onCatalogChanged: () => Promise<void>;
  onAddToCanvas: (nodeType: string) => void;
};

function paramsSchemaToRows(schema?: { properties?: Record<string, { type?: string; default?: unknown; description?: string }> }): ParamFieldRow[] {
  const props = schema?.properties || {};
  return Object.entries(props).map(([key, val]) => ({
    key,
    type: (['string', 'integer', 'number', 'boolean'].includes(String(val?.type || ''))
      ? val.type
      : 'string') as ParamFieldRow['type'],
    defaultValue: val?.default !== undefined ? String(val.default) : '',
    description: String(val?.description || ''),
  }));
}

function rowsToParamsSchema(rows: ParamFieldRow[]): Record<string, unknown> {
  const properties: Record<string, unknown> = {};
  for (const r of rows) {
    const k = r.key.trim().replace(/[^a-zA-Z0-9_]/g, '_');
    if (!k) continue;
    let def: unknown = r.defaultValue;
    if (r.type === 'integer') def = r.defaultValue ? parseInt(r.defaultValue, 10) || 0 : 0;
    else if (r.type === 'number') def = r.defaultValue ? parseFloat(r.defaultValue) || 0 : 0;
    else if (r.type === 'boolean') def = r.defaultValue.toLowerCase() === 'true';
    properties[k] = {
      type: r.type,
      default: def,
      description: r.description.trim() || undefined,
    };
  }
  return { type: 'object', properties };
}

export default function CustomNodesModal({
  onClose,
  onCatalogChanged,
  onAddToCanvas,
}: CustomNodesModalProps) {
  const [nodes, setNodes] = useState<CustomNodeDto[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [versions, setVersions] = useState<CustomNodeVersionDto[]>([]);

  // Editor form state
  const [name, setName] = useState('Мой анализатор');
  const [description, setDescription] = useState('Анализирует переданные данные и формирует результат');
  const [group, setGroup] = useState('custom');
  const [status, setStatus] = useState<'draft' | 'active' | 'disabled'>('active');
  const [visibility, setVisibility] = useState<'private' | 'public'>('private');
  const [inputs, setInputs] = useState<PortSpec[]>([{ name: 'findings', kind: 'Findings' }]);
  const [outputs, setOutputs] = useState<PortSpec[]>([{ name: 'result', kind: 'Any' }]);
  const [paramRows, setParamRows] = useState<ParamFieldRow[]>([]);
  const [code, setCode] = useState(STARTER_CODE);

  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [testOutput, setTestOutput] = useState('');

  const loadList = async () => {
    try {
      const list = await api.listCustomNodes();
      setNodes(list);
    } catch (err) {
      setMsg(`❌ ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const list = await api.listCustomNodes();
        if (!cancelled) setNodes(list);
      } catch {
        // ignore initial fetch errors
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const resetForCreate = () => {
    setSelectedId(null);
    setVersions([]);
    setName('Новая пользовательская нода');
    setDescription('Обрабатывает входные данные сценария');
    setGroup('custom');
    setStatus('active');
    setVisibility('private');
    setInputs([{ name: 'findings', kind: 'Findings' }]);
    setOutputs([{ name: 'result', kind: 'Any' }]);
    setParamRows([]);
    setCode(STARTER_CODE);
    setMsg('');
    setTestOutput('');
  };

  const openForEdit = async (item: CustomNodeDto) => {
    setSelectedId(item.id);
    setName(item.name);
    setDescription(item.description);
    setGroup(item.group || 'custom');
    setStatus((item.status as 'draft' | 'active' | 'disabled') || 'active');
    setVisibility((item.visibility as 'private' | 'public') || 'private');
    setInputs(item.inputs.length > 0 ? item.inputs : [{ name: 'in', kind: 'Any' }]);
    setOutputs(item.outputs.length > 0 ? item.outputs : [{ name: 'result', kind: 'Any' }]);
    setParamRows(paramsSchemaToRows(item.params_schema));
    setCode(item.code);
    setMsg('');
    setTestOutput('');
    try {
      const full = await api.getCustomNode(item.id);
      setVersions(full.versions || []);
    } catch {
      setVersions([]);
    }
  };

  const handleValidate = async () => {
    setBusy(true);
    setMsg('Проверка синтаксиса и безопасности кода…');
    try {
      const res = await api.validateCustomNodeCode(code);
      if (res.ok) {
        setMsg(`✅ Код корректен и безопасен (${res.is_async ? 'async def run' : 'def run'}).`);
      } else {
        setMsg(`❌ ${res.errors.join(' | ')}`);
      }
    } catch (err) {
      setMsg(`❌ ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  const handleSave = async () => {
    if (!name.trim()) {
      setMsg('❌ Укажите название ноды.');
      return;
    }
    setBusy(true);
    setMsg('Сохранение пользовательской ноды…');
    try {
      const payload = {
        name: name.trim(),
        description: description.trim(),
        group,
        code,
        inputs: inputs.filter((p) => p.name.trim()),
        outputs: outputs.filter((p) => p.name.trim()),
        params_schema: rowsToParamsSchema(paramRows),
        status,
        visibility,
      };
      const saved = selectedId
        ? await api.updateCustomNode(selectedId, payload)
        : await api.createCustomNode(payload);
      setSelectedId(saved.id);
      setVersions(saved.versions || []);
      await loadList();
      await onCatalogChanged();
      setMsg(`✅ Нода «${saved.name}» (v${saved.version}, ${saved.status}) сохранена в БД.`);
    } catch (err) {
      setMsg(`❌ ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  const handleDuplicate = async (id: string) => {
    setBusy(true);
    try {
      const dup = await api.duplicateCustomNode(id);
      await loadList();
      await onCatalogChanged();
      await openForEdit(dup);
      setMsg(`✅ Создана копия «${dup.name}» (черновик).`);
    } catch (err) {
      setMsg(`❌ ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  const handleToggleStatus = async (item: CustomNodeDto) => {
    setBusy(true);
    try {
      const nextStatus = item.status === 'active' ? 'disabled' : 'active';
      await api.updateCustomNode(item.id, { status: nextStatus });
      await loadList();
      await onCatalogChanged();
      if (selectedId === item.id) setStatus(nextStatus);
      setMsg(`Статус ноды «${item.name}» изменён на ${nextStatus}.`);
    } catch (err) {
      setMsg(`❌ ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  const handleDelete = async (item: CustomNodeDto) => {
    setBusy(true);
    try {
      await api.deleteCustomNode(item.id);
      if (selectedId === item.id) resetForCreate();
      await loadList();
      await onCatalogChanged();
      setMsg(`Нода «${item.name}» удалена.`);
    } catch (err) {
      setMsg(`❌ ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  const handleTestRun = async () => {
    if (!selectedId) {
      setMsg('Сначала сохраните ноду (можно как черновик), чтобы запустить тест в песочнице.');
      return;
    }
    setBusy(true);
    setTestOutput('');
    try {
      const sampleInputs: Record<string, unknown> = {};
      for (const inp of inputs) {
        if (inp.kind === 'Findings') {
          sampleInputs[inp.name] = [
            { category: 'SAST', path: 'src/App.kt', class: 'sql-injection', line: 12, severity: 'CRITICAL' },
            { category: 'SECRET', path: 'src/Cfg.kt', class: 'password', line: 4, severity: 'HIGH' },
          ];
        } else {
          sampleInputs[inp.name] = {};
        }
      }
      const res = await api.testRunCustomNode(selectedId, {
        code,
        inputs: sampleInputs,
        params: {},
        outputs,
      });
      if (res.ok) {
        setTestOutput(JSON.stringify(res.output, null, 2));
        setMsg('✅ Тестовый запуск в изолированной песочнице успешен.');
      } else {
        setMsg(`❌ ${res.error || 'Ошибка тестового запуска'}`);
      }
    } catch (err) {
      setMsg(`❌ ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  const selectedNodeObj = nodes.find((n) => n.id === selectedId);
  const canEdit = !selectedNodeObj || selectedNodeObj.is_owner;

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(15, 23, 42, 0.6)',
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
          maxWidth: 1080,
          maxHeight: '92vh',
          overflowY: 'auto',
          background: '#ffffff',
          borderRadius: 12,
          padding: 20,
          boxShadow: '0 24px 60px rgba(0,0,0,0.28)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <div>
            <h2 style={{ margin: 0, fontSize: 18 }}>Мои пользовательские ноды</h2>
            <div style={{ fontSize: 12, color: '#64748b', marginTop: 2 }}>
              Создание и управление собственными блоками с изолированной средой исполнения, версионированием и хранением в БД.
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              type="button"
              onClick={resetForCreate}
              style={{
                padding: '7px 12px',
                borderRadius: 7,
                border: 'none',
                background: '#059669',
                color: '#fff',
                fontWeight: 700,
                fontSize: 12,
                cursor: 'pointer',
              }}
            >
              + Создать ноду
            </button>
            <button
              type="button"
              onClick={onClose}
              style={{
                padding: '7px 12px',
                borderRadius: 7,
                border: '1px solid #cbd5e1',
                background: '#f8fafc',
                fontWeight: 700,
                fontSize: 12,
                cursor: 'pointer',
              }}
            >
              Закрыть
            </button>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 16 }}>
          {/* Left: Custom Nodes List */}
          <div style={{ border: '1px solid #e2e8f0', borderRadius: 10, padding: 12, background: '#f8fafc', maxHeight: '72vh', overflowY: 'auto' }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#475569', marginBottom: 8 }}>
              Сохранённые блоки ({nodes.length})
            </div>
            {nodes.length === 0 ? (
              <div style={{ fontSize: 12, color: '#64748b' }}>
                Пользовательских нод пока нет. Нажмите «+ Создать ноду», чтобы добавить первую.
              </div>
            ) : (
              nodes.map((item) => {
                const activeBorder = selectedId === item.id ? '2px solid #2563eb' : '1px solid #cbd5e1';
                const statusBadge =
                  item.status === 'active'
                    ? { bg: '#dcfce7', fg: '#166534', text: 'Активна' }
                    : item.status === 'draft'
                      ? { bg: '#fef3c7', fg: '#92400e', text: 'Черновик' }
                      : { bg: '#e2e8f0', fg: '#475569', text: 'Отключена' };
                return (
                  <div
                    key={item.id}
                    style={{
                      padding: 10,
                      borderRadius: 8,
                      border: activeBorder,
                      background: '#ffffff',
                      marginBottom: 8,
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 6 }}>
                      <strong style={{ fontSize: 13 }}>{item.name}</strong>
                      <span
                        style={{
                          fontSize: 10,
                          padding: '2px 7px',
                          borderRadius: 999,
                          fontWeight: 700,
                          background: statusBadge.bg,
                          color: statusBadge.fg,
                        }}
                      >
                        {statusBadge.text}
                      </span>
                    </div>
                    <div style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>
                      Пользовательская нода · v{item.version} · {item.visibility === 'public' ? 'Публичная' : 'Приватная'}
                      {!item.is_owner ? ' · Чужая' : ''}
                    </div>
                    <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginTop: 8 }}>
                      <button
                        type="button"
                        onClick={() => void openForEdit(item)}
                        style={{ padding: '3px 7px', fontSize: 11, borderRadius: 5, border: '1px solid #cbd5e1', background: '#f8fafc', cursor: 'pointer' }}
                      >
                        {item.is_owner ? 'Редактировать' : 'Просмотр'}
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleDuplicate(item.id)}
                        style={{ padding: '3px 7px', fontSize: 11, borderRadius: 5, border: '1px solid #cbd5e1', background: '#fff', cursor: 'pointer' }}
                      >
                        Дублировать
                      </button>
                      {item.status === 'active' && (
                        <button
                          type="button"
                          onClick={() => {
                            onAddToCanvas(item.node_type);
                            onClose();
                          }}
                          style={{ padding: '3px 7px', fontSize: 11, borderRadius: 5, border: 'none', background: '#dbeafe', color: '#1d4ed8', fontWeight: 700, cursor: 'pointer' }}
                        >
                          На схему
                        </button>
                      )}
                      {item.is_owner && (
                        <>
                          <button
                            type="button"
                            onClick={() => void handleToggleStatus(item)}
                            style={{ padding: '3px 7px', fontSize: 11, borderRadius: 5, border: '1px solid #cbd5e1', background: '#fff', cursor: 'pointer' }}
                          >
                            {item.status === 'active' ? 'Откл.' : 'Вкл.'}
                          </button>
                          <button
                            type="button"
                            onClick={() => void handleDelete(item)}
                            style={{ padding: '3px 7px', fontSize: 11, borderRadius: 5, border: 'none', background: '#fee2e2', color: '#991b1b', cursor: 'pointer' }}
                          >
                            Удалить
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Right: Node Editor */}
          <div style={{ border: '1px solid #e2e8f0', borderRadius: 10, padding: 14, background: '#ffffff' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
              <label style={{ fontSize: 12 }}>
                <span style={{ fontWeight: 600 }}>Название</span>
                <input
                  type="text"
                  disabled={!canEdit}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  style={{ width: '100%', boxSizing: 'border-box', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
                />
              </label>

              <label style={{ fontSize: 12 }}>
                <span style={{ fontWeight: 600 }}>Категория</span>
                <select
                  disabled={!canEdit}
                  value={group}
                  onChange={(e) => setGroup(e.target.value)}
                  style={{ width: '100%', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
                >
                  <option value="custom">Пользовательская (Мои ноды)</option>
                  <option value="scanner">Сканер</option>
                  <option value="logic">Логика</option>
                  <option value="findings">Обработка отчёта</option>
                  <option value="notify">Уведомления</option>
                </select>
              </label>
            </div>

            <label style={{ display: 'block', fontSize: 12, marginBottom: 10 }}>
              <span style={{ fontWeight: 600 }}>Описание</span>
              <input
                type="text"
                disabled={!canEdit}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                style={{ width: '100%', boxSizing: 'border-box', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
              />
            </label>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
              <label style={{ fontSize: 12 }}>
                <span style={{ fontWeight: 600 }}>Статус</span>
                <select
                  disabled={!canEdit}
                  value={status}
                  onChange={(e) => setStatus(e.target.value as 'draft' | 'active' | 'disabled')}
                  style={{ width: '100%', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
                >
                  <option value="active">Активна (видна в палитре)</option>
                  <option value="draft">Черновик</option>
                  <option value="disabled">Отключена</option>
                </select>
              </label>

              <label style={{ fontSize: 12 }}>
                <span style={{ fontWeight: 600 }}>Доступ</span>
                <select
                  disabled={!canEdit}
                  value={visibility}
                  onChange={(e) => setVisibility(e.target.value as 'private' | 'public')}
                  style={{ width: '100%', padding: '6px 8px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
                >
                  <option value="private">Приватная (только я)</option>
                  <option value="public">Публичная (доступна всем)</option>
                </select>
              </label>
            </div>

            {/* Ports */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
              <div style={{ border: '1px solid #e2e8f0', borderRadius: 8, padding: 8, background: '#f8fafc' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                  <span style={{ fontSize: 12, fontWeight: 700 }}>Входные порты</span>
                  {canEdit && (
                    <button
                      type="button"
                      onClick={() => setInputs((prev) => [...prev, { name: `in_${prev.length + 1}`, kind: 'Any' }])}
                      style={{ fontSize: 11, padding: '2px 6px', borderRadius: 4, border: '1px solid #cbd5e1', background: '#fff', cursor: 'pointer' }}
                    >
                      + Порт
                    </button>
                  )}
                </div>
                {inputs.map((p, idx) => (
                  <div key={idx} style={{ display: 'flex', gap: 4, marginBottom: 4 }}>
                    <input
                      type="text"
                      disabled={!canEdit}
                      value={p.name}
                      onChange={(e) =>
                        setInputs((prev) => prev.map((it, i) => (i === idx ? { ...it, name: e.target.value } : it)))
                      }
                      style={{ flex: 1, padding: '4px 6px', fontSize: 11, borderRadius: 5, border: '1px solid #cbd5e1' }}
                    />
                    <select
                      disabled={!canEdit}
                      value={p.kind}
                      onChange={(e) =>
                        setInputs((prev) => prev.map((it, i) => (i === idx ? { ...it, kind: e.target.value } : it)))
                      }
                      style={{ padding: '4px', fontSize: 11, borderRadius: 5, border: '1px solid #cbd5e1' }}
                    >
                      {PORT_KINDS.map((k) => (
                        <option key={k} value={k}>
                          {k}
                        </option>
                      ))}
                    </select>
                  </div>
                ))}
              </div>

              <div style={{ border: '1px solid #e2e8f0', borderRadius: 8, padding: 8, background: '#f8fafc' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                  <span style={{ fontSize: 12, fontWeight: 700 }}>Выходные порты</span>
                  {canEdit && (
                    <button
                      type="button"
                      onClick={() => setOutputs((prev) => [...prev, { name: `out_${prev.length + 1}`, kind: 'Any' }])}
                      style={{ fontSize: 11, padding: '2px 6px', borderRadius: 4, border: '1px solid #cbd5e1', background: '#fff', cursor: 'pointer' }}
                    >
                      + Порт
                    </button>
                  )}
                </div>
                {outputs.map((p, idx) => (
                  <div key={idx} style={{ display: 'flex', gap: 4, marginBottom: 4 }}>
                    <input
                      type="text"
                      disabled={!canEdit}
                      value={p.name}
                      onChange={(e) =>
                        setOutputs((prev) => prev.map((it, i) => (i === idx ? { ...it, name: e.target.value } : it)))
                      }
                      style={{ flex: 1, padding: '4px 6px', fontSize: 11, borderRadius: 5, border: '1px solid #cbd5e1' }}
                    />
                    <select
                      disabled={!canEdit}
                      value={p.kind}
                      onChange={(e) =>
                        setOutputs((prev) => prev.map((it, i) => (i === idx ? { ...it, kind: e.target.value } : it)))
                      }
                      style={{ padding: '4px', fontSize: 11, borderRadius: 5, border: '1px solid #cbd5e1' }}
                    >
                      {PORT_KINDS.map((k) => (
                        <option key={k} value={k}>
                          {k}
                        </option>
                      ))}
                    </select>
                  </div>
                ))}
              </div>
            </div>

            {/* Parameters builder */}
            <div style={{ border: '1px solid #e2e8f0', borderRadius: 8, padding: 8, background: '#f8fafc', marginBottom: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ fontSize: 12, fontWeight: 700 }}>Параметры ноды ({paramRows.length})</span>
                {canEdit && (
                  <button
                    type="button"
                    onClick={() =>
                      setParamRows((prev) => [
                        ...prev,
                        { key: `param_${prev.length + 1}`, type: 'string', defaultValue: '', description: '' },
                      ])
                    }
                    style={{ fontSize: 11, padding: '2px 6px', borderRadius: 4, border: '1px solid #cbd5e1', background: '#fff', cursor: 'pointer' }}
                  >
                    + Параметр
                  </button>
                )}
              </div>
              {paramRows.map((row, idx) => (
                <div key={idx} style={{ display: 'grid', gridTemplateColumns: '1fr 90px 1fr 1fr auto', gap: 4, marginBottom: 4 }}>
                  <input
                    type="text"
                    disabled={!canEdit}
                    placeholder="ключ"
                    value={row.key}
                    onChange={(e) =>
                      setParamRows((prev) => prev.map((r, i) => (i === idx ? { ...r, key: e.target.value } : r)))
                    }
                    style={{ padding: '4px 6px', fontSize: 11, borderRadius: 5, border: '1px solid #cbd5e1' }}
                  />
                  <select
                    disabled={!canEdit}
                    value={row.type}
                    onChange={(e) =>
                      setParamRows((prev) =>
                        prev.map((r, i) => (i === idx ? { ...r, type: e.target.value as ParamFieldRow['type'] } : r)),
                      )
                    }
                    style={{ padding: '4px', fontSize: 11, borderRadius: 5, border: '1px solid #cbd5e1' }}
                  >
                    <option value="string">string</option>
                    <option value="integer">integer</option>
                    <option value="number">number</option>
                    <option value="boolean">boolean</option>
                  </select>
                  <input
                    type="text"
                    disabled={!canEdit}
                    placeholder="по умолчанию"
                    value={row.defaultValue}
                    onChange={(e) =>
                      setParamRows((prev) =>
                        prev.map((r, i) => (i === idx ? { ...r, defaultValue: e.target.value } : r)),
                      )
                    }
                    style={{ padding: '4px 6px', fontSize: 11, borderRadius: 5, border: '1px solid #cbd5e1' }}
                  />
                  <input
                    type="text"
                    disabled={!canEdit}
                    placeholder="описание"
                    value={row.description}
                    onChange={(e) =>
                      setParamRows((prev) =>
                        prev.map((r, i) => (i === idx ? { ...r, description: e.target.value } : r)),
                      )
                    }
                    style={{ padding: '4px 6px', fontSize: 11, borderRadius: 5, border: '1px solid #cbd5e1' }}
                  />
                  {canEdit && (
                    <button
                      type="button"
                      onClick={() => setParamRows((prev) => prev.filter((_, i) => i !== idx))}
                      style={{ padding: '2px 6px', fontSize: 11, borderRadius: 5, border: 'none', background: '#fee2e2', color: '#991b1b', cursor: 'pointer' }}
                    >
                      ✕
                    </button>
                  )}
                </div>
              ))}
            </div>

            {/* Code Editor */}
            <div style={{ marginBottom: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                <span style={{ fontSize: 12, fontWeight: 700 }}>Редактор логики (Python, изолированная песочница)</span>
                <span style={{ fontSize: 11, color: '#64748b' }}>Контракт: async def run(ctx, inputs, params) → dict</span>
              </div>
              <textarea
                disabled={!canEdit}
                value={code}
                onChange={(e) => setCode(e.target.value)}
                rows={10}
                spellCheck={false}
                style={{
                  width: '100%',
                  boxSizing: 'border-box',
                  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
                  fontSize: 12,
                  padding: 10,
                  borderRadius: 8,
                  border: '1px solid #cbd5e1',
                  background: '#0f172a',
                  color: '#e2e8f0',
                }}
              />
            </div>

            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <button
                type="button"
                disabled={busy}
                onClick={() => void handleValidate()}
                style={{ padding: '7px 12px', borderRadius: 7, border: '1px solid #cbd5e1', background: '#fff', fontSize: 12, fontWeight: 600, cursor: 'pointer' }}
              >
                Проверить код
              </button>
              {selectedId && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void handleTestRun()}
                  style={{ padding: '7px 12px', borderRadius: 7, border: '1px solid #cbd5e1', background: '#eff6ff', color: '#1d4ed8', fontSize: 12, fontWeight: 600, cursor: 'pointer' }}
                >
                  Тест в песочнице
                </button>
              )}
              {canEdit && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void handleSave()}
                  style={{ padding: '7px 14px', borderRadius: 7, border: 'none', background: '#2563eb', color: '#fff', fontSize: 12, fontWeight: 700, cursor: 'pointer' }}
                >
                  Сохранить ноду
                </button>
              )}
            </div>

            {msg && (
              <div style={{ marginTop: 10, fontSize: 12, padding: 8, borderRadius: 6, background: '#f8fafc', border: '1px solid #e2e8f0' }}>
                {msg}
              </div>
            )}

            {testOutput && (
              <pre style={{ marginTop: 8, padding: 8, borderRadius: 6, background: '#0f172a', color: '#86efac', fontSize: 11, overflowX: 'auto' }}>
                {testOutput}
              </pre>
            )}

            {versions.length > 0 && (
              <div style={{ marginTop: 12, borderTop: '1px solid #e2e8f0', paddingTop: 10 }}>
                <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 6 }}>История версий ({versions.length})</div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {versions.map((v) => (
                    <button
                      key={v.id}
                      type="button"
                      onClick={() => {
                        setCode(v.code);
                        setName(v.name);
                        setDescription(v.description);
                        setInputs(v.inputs);
                        setOutputs(v.outputs);
                        setParamRows(paramsSchemaToRows(v.params_schema));
                        setMsg(`Загружен снимок версии v${v.version} в редактор (нажмите «Сохранить ноду» чтобы применить).`);
                      }}
                      style={{
                        padding: '3px 8px',
                        borderRadius: 6,
                        border: '1px solid #cbd5e1',
                        background: '#f8fafc',
                        fontSize: 11,
                        cursor: 'pointer',
                      }}
                    >
                      v{v.version} ({v.created_at ? v.created_at.slice(0, 16).replace('T', ' ') : ''})
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
