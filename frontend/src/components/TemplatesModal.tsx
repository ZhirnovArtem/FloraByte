import { useEffect, useState } from 'react';
import * as api from '../api/client';
import type { TemplateDto, WorkflowDto } from '../types/workflow';

type TemplatesModalProps = {
  templates: TemplateDto[];
  onClose: () => void;
  onChanged: (next: TemplateDto[]) => void;
  onCopied: (copiedWorkflow: WorkflowDto) => void;
};

type SectionFilter = 'all' | 'mine' | 'public' | 'system';

export default function TemplatesModal({
  templates,
  onClose,
  onChanged,
  onCopied,
}: TemplatesModalProps) {
  const [section, setSection] = useState<SectionFilter>('all');
  const [query, setQuery] = useState('');
  const [busyId, setBusyId] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState('');

  const refresh = async () => {
    const fresh = await api.listTemplates();
    onChanged(fresh);
  };

  useEffect(() => {
    void refresh().catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filtered = templates.filter((tpl) => {
    const isSystem = Boolean(tpl.is_system);
    const isOwner = Boolean(tpl.is_owner);
    const vis = tpl.visibility ?? (isSystem ? 'public' : 'private');
    if (section === 'mine' && !isOwner) return false;
    if (section === 'public' && (vis !== 'public' || isSystem)) return false;
    if (section === 'system' && !isSystem) return false;
    const q = query.trim().toLowerCase();
    if (q) {
      const hay = `${tpl.name} ${tpl.description || ''} ${tpl.owner_email || ''}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const handleCopy = async (tpl: TemplateDto) => {
    setBusyId(tpl.id);
    setStatusMsg('');
    try {
      const copied = await api.copyTemplate(tpl.id);
      onCopied(copied);
      onClose();
    } catch (err) {
      setStatusMsg(`❌ ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusyId(null);
    }
  };

  const handleToggleVisibility = async (tpl: TemplateDto) => {
    const nextVis = tpl.visibility === 'public' ? 'private' : 'public';
    setBusyId(tpl.id);
    setStatusMsg('');
    try {
      await api.updateTemplate(tpl.id, { visibility: nextVis });
      await refresh();
      setStatusMsg(
        `✅ Шаблон «${tpl.name}» теперь ${nextVis === 'public' ? 'публичный (виден всем)' : 'приватный (только вы)'}.`,
      );
    } catch (err) {
      setStatusMsg(`❌ ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusyId(null);
    }
  };

  const handleDelete = async (tpl: TemplateDto) => {
    setBusyId(tpl.id);
    setStatusMsg('');
    try {
      await api.deleteTemplate(tpl.id);
      await refresh();
      setStatusMsg(`Шаблон «${tpl.name}» удалён.`);
    } catch (err) {
      setStatusMsg(`❌ ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusyId(null);
    }
  };

  const counts = {
    all: templates.length,
    mine: templates.filter((t) => t.is_owner).length,
    public: templates.filter((t) => !t.is_system && t.visibility === 'public').length,
    system: templates.filter((t) => t.is_system).length,
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
        zIndex: 60,
        padding: 16,
      }}
    >
      <div
        style={{
          width: 'min(760px, 100%)',
          maxHeight: '88vh',
          background: '#fff',
          borderRadius: 12,
          boxShadow: '0 20px 50px rgba(0,0,0,0.35)',
          display: 'flex',
          flexDirection: 'column',
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
            <strong style={{ fontSize: 15 }}>Библиотека шаблонов</strong>
            <div style={{ fontSize: 11, color: '#94a3b8' }}>
              Системные, ваши приватные и публичные шаблоны сообщества (секреты автоматически очищены)
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            style={{ background: 'none', border: 'none', color: '#cbd5e1', fontSize: 18, cursor: 'pointer' }}
          >
            ✕
          </button>
        </div>

        <div style={{ padding: 14, borderBottom: '1px solid #e2e8f0', display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          {(
            [
              ['all', `Все (${counts.all})`],
              ['mine', `Мои (${counts.mine})`],
              ['public', `Публичные (${counts.public})`],
              ['system', `Системные (${counts.system})`],
            ] as const
          ).map(([id, label]) => (
            <button
              key={id}
              type="button"
              onClick={() => setSection(id)}
              style={{
                padding: '5px 10px',
                borderRadius: 7,
                border: '1px solid #cbd5e1',
                background: section === id ? '#0f172a' : '#fff',
                color: section === id ? '#fff' : '#334155',
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              {label}
            </button>
          ))}

          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Поиск по названию или описанию…"
            style={{
              marginLeft: 'auto',
              minWidth: 210,
              padding: '5px 9px',
              borderRadius: 7,
              border: '1px solid #cbd5e1',
              fontSize: 12,
            }}
          />
        </div>

        {statusMsg && (
          <div style={{ margin: '10px 16px 0', padding: '8px 10px', borderRadius: 7, background: '#f8fafc', border: '1px solid #cbd5e1', fontSize: 12 }}>
            {statusMsg}
          </div>
        )}

        <div style={{ padding: 16, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 10 }}>
          {filtered.length === 0 ? (
            <div style={{ color: '#64748b', fontSize: 13 }}>Шаблонов по выбранному фильтру нет.</div>
          ) : (
            filtered.map((tpl) => {
              const isSystem = Boolean(tpl.is_system);
              const vis = tpl.visibility ?? (isSystem ? 'public' : 'private');
              const badge = isSystem
                ? { label: 'SYSTEM', bg: '#dbeafe', fg: '#1e40af' }
                : vis === 'public'
                  ? { label: 'PUBLIC', bg: '#dcfce7', fg: '#166534' }
                  : { label: 'PRIVATE', bg: '#fef3c7', fg: '#92400e' };
              const busy = busyId === tpl.id;
              return (
                <div
                  key={tpl.id}
                  style={{
                    border: '1px solid #cbd5e1',
                    borderRadius: 10,
                    padding: 12,
                    background: '#f8fafc',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'flex-start',
                    gap: 12,
                    flexWrap: 'wrap',
                  }}
                >
                  <div style={{ flex: '1 1 320px', minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <strong style={{ fontSize: 14, color: '#0f172a' }}>{tpl.name}</strong>
                      <span
                        style={{
                          fontSize: 10,
                          fontWeight: 700,
                          padding: '2px 7px',
                          borderRadius: 999,
                          background: badge.bg,
                          color: badge.fg,
                        }}
                      >
                        {badge.label}
                      </span>
                      {typeof tpl.nodes_count === 'number' && (
                        <span style={{ fontSize: 11, color: '#64748b' }}>
                          {tpl.nodes_count} блок(ов)
                        </span>
                      )}
                    </div>
                    {tpl.description && (
                      <div style={{ fontSize: 12, color: '#475569', marginTop: 4 }}>{tpl.description}</div>
                    )}
                    <div style={{ fontSize: 11, color: '#64748b', marginTop: 4 }}>
                      Автор: <strong>{tpl.owner_email || (isSystem ? 'FloraByte System' : 'Вы')}</strong>
                      {tpl.published_at ? ` · ${tpl.published_at.slice(0, 10)}` : ''}
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => void handleCopy(tpl)}
                      style={{
                        padding: '6px 10px',
                        borderRadius: 7,
                        border: 'none',
                        background: '#2563eb',
                        color: '#fff',
                        fontSize: 12,
                        fontWeight: 600,
                        cursor: busy ? 'wait' : 'pointer',
                      }}
                    >
                      Копировать к себе
                    </button>

                    {tpl.is_owner && !isSystem && (
                      <>
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => void handleToggleVisibility(tpl)}
                          style={{
                            padding: '6px 10px',
                            borderRadius: 7,
                            border: '1px solid #cbd5e1',
                            background: '#fff',
                            color: '#0f172a',
                            fontSize: 12,
                            fontWeight: 600,
                            cursor: busy ? 'wait' : 'pointer',
                          }}
                        >
                          {vis === 'public' ? 'Сделать private' : 'Сделать public'}
                        </button>
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => void handleDelete(tpl)}
                          style={{
                            padding: '6px 10px',
                            borderRadius: 7,
                            border: 'none',
                            background: '#fee2e2',
                            color: '#991b1b',
                            fontSize: 12,
                            fontWeight: 600,
                            cursor: busy ? 'wait' : 'pointer',
                          }}
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
      </div>
    </div>
  );
}
