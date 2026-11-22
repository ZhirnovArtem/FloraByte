import { useState } from 'react';
import type { NodeTypeSpec, TemplateDto } from '../types/workflow';

type NodeSidebarProps = {
  catalog: NodeTypeSpec[];
  catalogSource: 'api' | 'fallback';
  templates: TemplateDto[];
  isOpen: boolean;
  onToggle: () => void;
  variant?: 'docked' | 'drawer' | 'fullscreen';
  onAddNode: (spec: NodeTypeSpec) => void;
  onApplyTemplate: (template: TemplateDto) => void;
  onOpenTemplatesModal?: () => void;
  onGenerateWorkflow?: (prompt: string) => Promise<void>;
};

const GROUP_LABELS: Record<string, string> = {
  trigger: 'Триггеры',
  source: 'Источники кода',
  scanner: 'Сканеры',
  logic: 'Логика и ветвления',
  findings: 'Сборка и отчёты',
  ai: 'AI-анализ',
  notify: 'Уведомления',
  custom: 'Мои ноды',
};

const GROUP_ORDER = ['trigger', 'source', 'scanner', 'logic', 'findings', 'ai', 'notify', 'custom'];

const AI_PROMPT_EXAMPLES = [
  'Каждый день в 14:00 проверяй код из репозитория на наличие секретов и отправляй отчет на почту',
  'Проверь ZIP-архив на SAST, SCA и секреты с AI-объяснением и отправь в Telegram, если есть CRITICAL',
];

export default function NodeSidebar({
  catalog,
  catalogSource,
  templates,
  isOpen,
  onToggle,
  variant = 'docked',
  onAddNode,
  onApplyTemplate,
  onOpenTemplatesModal,
  onGenerateWorkflow,
}: NodeSidebarProps) {
  const [aiPrompt, setAiPrompt] = useState('');
  const [generating, setGenerating] = useState(false);

  if (!isOpen && variant !== 'fullscreen') {
    return (
      <aside
        onClick={onToggle}
        title="Развернуть панель блоков (нод)"
        style={{
          width: 40,
          padding: '10px 4px',
          background: '#f8fafc',
          borderRight: '1px solid #e2e8f0',
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
          aria-label="Развернуть панель блоков"
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
          ▶
        </button>
        <span
          style={{
            writingMode: 'vertical-rl',
            transform: 'rotate(180deg)',
            fontSize: 12,
            fontWeight: 700,
            color: '#475569',
            letterSpacing: '0.03em',
          }}
        >
          Блоки (ноды)
        </span>
      </aside>
    );
  }

  const asideStyle: React.CSSProperties =
    variant === 'fullscreen'
      ? {
          width: '100%',
          flex: 1,
          minHeight: 0,
          padding: 14,
          background: '#f8fafc',
          overflowY: 'auto',
        }
      : variant === 'drawer'
        ? {
            position: 'fixed',
            top: 0,
            bottom: 0,
            left: 0,
            width: 'min(320px, 85vw)',
            padding: 14,
            background: '#f8fafc',
            borderRight: '1px solid #cbd5e1',
            boxShadow: '8px 0 32px rgba(15, 23, 42, 0.25)',
            overflowY: 'auto',
            zIndex: 45,
          }
        : {
            width: 260,
            padding: 14,
            background: '#f8fafc',
            borderRight: '1px solid #e2e8f0',
            overflowY: 'auto',
            flexShrink: 0,
          };

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

  const handleGenerate = async () => {
    const trimmed = aiPrompt.trim();
    if (!trimmed || !onGenerateWorkflow || generating) return;
    setGenerating(true);
    try {
      await onGenerateWorkflow(trimmed);
    } finally {
      setGenerating(false);
    }
  };

  return (
    <>
      {variant === 'drawer' && (
        <div
          onClick={onToggle}
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(15, 23, 42, 0.35)',
            zIndex: 44,
          }}
        />
      )}
      <aside style={asideStyle}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10, gap: 6 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
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
          <button
            type="button"
            onClick={onToggle}
            title={variant === 'fullscreen' ? 'Вернуться к схеме' : 'Свернуть панель блоков'}
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
            {variant === 'fullscreen' ? '← К схеме' : variant === 'drawer' ? '✕ Закрыть' : '◀ Свернуть'}
          </button>
        </div>

      {onGenerateWorkflow && (
        <div
          style={{
            marginBottom: 14,
            padding: 10,
            borderRadius: 8,
            background: '#f0fdf4',
            border: '1px solid #bbf7d0',
          }}
        >
          <div style={{ fontSize: 11, fontWeight: 700, color: '#166534', marginBottom: 6 }}>
            AI-генератор сценария
          </div>
          <textarea
            rows={3}
            value={aiPrompt}
            onChange={(e) => setAiPrompt(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                void handleGenerate();
              }
            }}
            placeholder="Например: Каждый день в 14:00 проверяй репозиторий на секреты и отправляй отчет на почту"
            style={{
              width: '100%',
              boxSizing: 'border-box',
              padding: '6px 8px',
              borderRadius: 6,
              border: '1px solid #86efac',
              fontSize: 12,
              marginBottom: 6,
              resize: 'vertical',
              fontFamily: 'inherit',
            }}
          />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 6 }}>
            {AI_PROMPT_EXAMPLES.map((ex, i) => (
              <button
                key={i}
                type="button"
                onClick={() => setAiPrompt(ex)}
                title="Подставить пример"
                style={{
                  textAlign: 'left',
                  padding: '4px 6px',
                  borderRadius: 5,
                  border: '1px dashed #86efac',
                  background: '#ffffff',
                  color: '#166534',
                  fontSize: 10,
                  lineHeight: 1.3,
                  cursor: 'pointer',
                }}
              >
                {ex}
              </button>
            ))}
          </div>
          <button
            type="button"
            disabled={generating || !aiPrompt.trim()}
            onClick={() => void handleGenerate()}
            style={{
              width: '100%',
              padding: '6px 8px',
              borderRadius: 6,
              border: 'none',
              background: generating || !aiPrompt.trim() ? '#94a3b8' : '#16a34a',
              color: '#ffffff',
              fontSize: 12,
              fontWeight: 700,
              cursor: generating ? 'wait' : 'pointer',
            }}
          >
            {generating ? 'Генерация…' : 'Сгенерировать сценарий'}
          </button>
        </div>
      )}

      {templates.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#475569', textTransform: 'uppercase' }}>
              Готовые шаблоны
            </div>
            {onOpenTemplatesModal && (
              <button
                type="button"
                onClick={onOpenTemplatesModal}
                style={{
                  padding: '2px 7px',
                  fontSize: 10,
                  fontWeight: 700,
                  borderRadius: 6,
                  border: '1px solid #c7d2fe',
                  background: '#fff',
                  color: '#4338ca',
                  cursor: 'pointer',
                }}
              >
                Все ({templates.length})
              </button>
            )}
          </div>
          {templates.map((tpl) => {
            const visLabel = tpl.is_system ? 'system' : tpl.visibility || 'private';
            return (
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
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 6 }}>
                  <span style={{ fontWeight: 700, fontSize: 12, color: '#3730a3' }}>{tpl.name}</span>
                  <span
                    style={{
                      fontSize: 9,
                      fontWeight: 700,
                      padding: '1px 5px',
                      borderRadius: 999,
                      background:
                        visLabel === 'system' ? '#dbeafe' : visLabel === 'public' ? '#dcfce7' : '#fef3c7',
                      color:
                        visLabel === 'system' ? '#1e40af' : visLabel === 'public' ? '#166534' : '#92400e',
                      textTransform: 'uppercase',
                    }}
                  >
                    {visLabel}
                  </span>
                </div>
                {tpl.description && (
                  <div style={{ fontSize: 11, color: '#4f46e5', marginTop: 2 }}>{tpl.description}</div>
                )}
              </button>
            );
          })}
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
              draggable
              onDragStart={(e) => {
                e.dataTransfer.setData('application/florabyte-node', item.type);
                e.dataTransfer.effectAllowed = 'move';
              }}
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
                cursor: 'grab',
              }}
              title="Нажмите или перетащите блок на схему"
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 6 }}>
                <strong style={{ fontSize: 13 }}>{item.label}</strong>
                {item.is_custom && (
                  <span
                    style={{
                      fontSize: 10,
                      padding: '1px 6px',
                      borderRadius: 999,
                      background: '#ede9fe',
                      color: '#5b21b6',
                      fontWeight: 700,
                    }}
                  >
                    v{item.version ?? 1}
                  </span>
                )}
              </div>
              <div style={{ fontSize: 11, color: '#64748b', marginTop: 2, fontFamily: 'monospace' }}>
                {item.type}
              </div>
            </button>
          ))}
        </div>
      ))}
      </aside>
    </>
  );
}
