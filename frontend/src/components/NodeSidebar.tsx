import type { NodeTypeSpec, TemplateDto } from '../types/workflow';

type NodeSidebarProps = {
  catalog: NodeTypeSpec[];
  catalogSource: 'api' | 'fallback';
  templates: TemplateDto[];
  onAddNode: (spec: NodeTypeSpec) => void;
  onApplyTemplate: (template: TemplateDto) => void;
};

const GROUP_LABELS: Record<string, string> = {
  trigger: 'Триггеры',
  source: 'Источники кода',
  scanner: 'Сканеры',
  logic: 'Логика и ветвления',
  findings: 'Сборка и отчёты',
  ai: 'AI-анализ',
  notify: 'Уведомления',
};

const GROUP_ORDER = ['trigger', 'source', 'scanner', 'logic', 'findings', 'ai', 'notify'];

export default function NodeSidebar({
  catalog,
  catalogSource,
  templates,
  onAddNode,
  onApplyTemplate,
}: NodeSidebarProps) {
  const grouped = new Map<string, NodeTypeSpec[]>();
  for (const item of catalog) {
    const g = item.group || 'other';
    const arr = grouped.get(g) ?? [];
    arr.push(item);
    grouped.set(g, arr);
  }

  const orderedGroups = [
    ...GROUP_ORDER.filter((g) => grouped.has(g)),
    ...[...grouped.keys()].filter((g) => !GROUP_ORDER.includes(g)),
  ];

  return (
    <aside
      style={{
        width: 260,
        padding: 14,
        background: '#f8fafc',
        borderRight: '1px solid #e2e8f0',
        overflowY: 'auto',
        flexShrink: 0,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
        <h3 style={{ margin: 0, fontSize: 16 }}>Блоки (ноды)</h3>
        <span
          style={{
            fontSize: 10,
            fontWeight: 700,
            padding: '2px 7px',
            borderRadius: 999,
            background: catalogSource === 'api' ? '#dcfce7' : '#fef3c7',
            color: catalogSource === 'api' ? '#166534' : '#92400e',
          }}
        >
          {catalogSource === 'api' ? 'API' : 'Offline'}
        </span>
      </div>

      {templates.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#475569', marginBottom: 6, textTransform: 'uppercase' }}>
            Готовые шаблоны
          </div>
          {templates.map((tpl) => (
            <button
              key={tpl.id}
              onClick={() => onApplyTemplate(tpl)}
              style={{
                display: 'block',
                width: '100%',
                marginBottom: 6,
                padding: '8px 10px',
                textAlign: 'left',
                background: '#eef2ff',
                border: '1px solid #c7d2fe',
                borderRadius: 8,
                cursor: 'pointer',
              }}
              title={tpl.description}
            >
              <div style={{ fontWeight: 700, fontSize: 12, color: '#3730a3' }}>{tpl.name}</div>
              {tpl.description && (
                <div style={{ fontSize: 11, color: '#4f46e5', marginTop: 2 }}>{tpl.description}</div>
              )}
            </button>
          ))}
        </div>
      )}

      {orderedGroups.map((group) => (
        <div key={group} style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#64748b', marginBottom: 6, textTransform: 'uppercase' }}>
            {GROUP_LABELS[group] ?? group}
          </div>
          {(grouped.get(group) ?? []).map((item) => (
            <button
              key={item.type}
              onClick={() => onAddNode(item)}
              style={{
                display: 'block',
                width: '100%',
                marginBottom: 6,
                padding: '8px 10px',
                textAlign: 'left',
                background: '#ffffff',
                border: '1px solid #cbd5e1',
                borderRadius: 8,
                cursor: 'pointer',
              }}
            >
              <strong style={{ fontSize: 13 }}>{item.label}</strong>
              <div style={{ fontSize: 11, color: '#64748b', marginTop: 2, fontFamily: 'monospace' }}>
                {item.type}
              </div>
            </button>
          ))}
        </div>
      ))}
    </aside>
  );
}
