import { useState } from 'react';
import { compareRuns, downloadRunReport } from '../api/client';
import type { AiReportDto, FindingDto, RunCompareDto, RunDto, WsRunEvent } from '../types/workflow';

type ReportPanelProps = {
  run: RunDto | null;
  findings: FindingDto[];
  reportMd: string;
  events: WsRunEvent[];
  runsHistory: RunDto[];
  isOpen: boolean;
  onToggle: () => void;
  onSelectRun?: (runId: string) => void;
  onRefreshHistory?: () => void;
};

const SEV_COLORS: Record<string, { bg: string; fg: string; bar: string }> = {
  CRITICAL: { bg: '#fee2e2', fg: '#991b1b', bar: '#dc2626' },
  HIGH: { bg: '#ffedd5', fg: '#9a3412', bar: '#ea580c' },
  MEDIUM: { bg: '#fef3c7', fg: '#92400e', bar: '#d97706' },
  LOW: { bg: '#e0f2fe', fg: '#075985', bar: '#0284c7' },
};

export default function ReportPanel({
  run,
  findings,
  reportMd,
  events,
  runsHistory,
  isOpen,
  onToggle,
  onSelectRun,
  onRefreshHistory,
}: ReportPanelProps) {
  const [tab, setTab] = useState<'findings' | 'dashboard' | 'ai' | 'markdown' | 'log' | 'history'>('findings');
  const [catFilter, setCatFilter] = useState<string>('ALL');
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null);
  const [baseRunId, setBaseRunId] = useState<string>('');
  const [targetRunId, setTargetRunId] = useState<string>('');
  const [compareResult, setCompareResult] = useState<RunCompareDto | null>(null);
  const [compareErr, setCompareErr] = useState<string>('');

  const ai: AiReportDto | null = run?.ai_report ?? null;
  const filtered = catFilter === 'ALL' ? findings : findings.filter((f) => f.category === catFilter);

  const sevCounts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const catCounts: Record<string, number> = { SECRET: 0, SCA: 0, SAST: 0 };
  for (const f of findings) {
    const s = (f.severity ?? 'LOW').toUpperCase();
    sevCounts[s] = (sevCounts[s] ?? 0) + 1;
    catCounts[f.category] = (catCounts[f.category] ?? 0) + 1;
  }
  const maxSev = Math.max(1, ...Object.values(sevCounts));

  const handleCompare = async () => {
    const base = baseRunId || runsHistory[1]?.id || '';
    const target = targetRunId || run?.id || runsHistory[0]?.id || '';
    if (!base || !target) {
      setCompareErr('Нужно минимум два запуска для сравнения.');
      return;
    }
    setCompareErr('');
    try {
      const res = await compareRuns(base, target);
      setCompareResult(res);
    } catch (err) {
      setCompareErr(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <div
      style={{
        borderTop: '1px solid #cbd5e1',
        background: '#ffffff',
        display: 'flex',
        flexDirection: 'column',
        height: isOpen ? 310 : 42,
        transition: 'height 0.15s ease',
        flexShrink: 0,
      }}
    >
      <div
        style={{
          height: 42,
          padding: '0 16px',
          background: '#f1f5f9',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 12,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <button
            onClick={onToggle}
            style={{
              padding: '4px 10px',
              background: '#ffffff',
              border: '1px solid #cbd5e1',
              borderRadius: 6,
              cursor: 'pointer',
              fontSize: 12,
              fontWeight: 700,
            }}
          >
            {isOpen ? '▼ Свернуть панель' : '▲ Находки и отчёт'}
          </button>

          {run && (
            <span style={{ fontSize: 12, color: '#334155' }}>
              Run <code>{run.id.slice(0, 8)}</code> · Статус: <strong>{run.status}</strong> · Находок:{' '}
              <strong>{findings.length}</strong>
            </span>
          )}
        </div>

        {isOpen && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
            {(['findings', 'dashboard', 'ai', 'markdown', 'log', 'history'] as const).map((t) => (
              <button
                key={t}
                onClick={() => {
                  setTab(t);
                  if ((t === 'history' || t === 'dashboard') && onRefreshHistory) onRefreshHistory();
                }}
                style={{
                  padding: '4px 10px',
                  borderRadius: 6,
                  border: '1px solid #cbd5e1',
                  background: tab === t ? '#2563eb' : '#ffffff',
                  color: tab === t ? '#ffffff' : '#1e293b',
                  cursor: 'pointer',
                  fontSize: 12,
                  fontWeight: 600,
                }}
              >
                {t === 'findings' && `Находки (${findings.length})`}
                {t === 'dashboard' && 'Дашборд и сравнение'}
                {t === 'ai' && `AI-отчёт${ai ? ` (${ai.items.length})` : ''}`}
                {t === 'markdown' && 'Markdown'}
                {t === 'log' && `WS лог (${events.length})`}
                {t === 'history' && `История (${runsHistory.length})`}
              </button>
            ))}

            {run && (
              <>
                <a
                  href="#"
                  onClick={(e) => {
                    e.preventDefault();
                    void downloadRunReport(run.id, 'json').catch((error: Error) => alert(error.message));
                  }}
                  style={{ fontSize: 12, color: '#2563eb', marginLeft: 8, textDecoration: 'none', fontWeight: 600 }}
                >
                  ↓ report.json
                </a>
                <a
                  href="#"
                  onClick={(e) => {
                    e.preventDefault();
                    void downloadRunReport(run.id, 'md').catch((error: Error) => alert(error.message));
                  }}
                  style={{ fontSize: 12, color: '#2563eb', marginLeft: 4, textDecoration: 'none', fontWeight: 600 }}
                >
                  ↓ report.md
                </a>
                <a
                  href="#"
                  onClick={(e) => {
                    e.preventDefault();
                    void downloadRunReport(run.id, 'pdf').catch((error: Error) => alert(error.message));
                  }}
                  style={{ fontSize: 12, color: '#dc2626', marginLeft: 4, textDecoration: 'none', fontWeight: 700 }}
                >
                  ↓ report.pdf
                </a>
              </>
            )}
          </div>
        )}
      </div>

      {isOpen && (
        <div style={{ flex: 1, overflowY: 'auto', padding: 14 }}>
          {tab === 'findings' && (
            <div>
              <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
                {['ALL', 'SECRET', 'SCA', 'SAST'].map((c) => (
                  <button
                    key={c}
                    onClick={() => {
                      setCatFilter(c);
                      setExpandedIdx(null);
                    }}
                    style={{
                      padding: '3px 10px',
                      borderRadius: 999,
                      border: '1px solid #cbd5e1',
                      background: catFilter === c ? '#0f172a' : '#fff',
                      color: catFilter === c ? '#fff' : '#334155',
                      fontSize: 11,
                      cursor: 'pointer',
                      fontWeight: 600,
                    }}
                  >
                    {c}
                  </button>
                ))}
              </div>

              {filtered.length === 0 ? (
                <div style={{ color: '#64748b', fontSize: 13 }}>
                  {run ? 'Находок по выбранному фильтру нет.' : 'Запустите workflow, чтобы увидеть находки.'}
                </div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                  <thead>
                    <tr style={{ textAlign: 'left', borderBottom: '2px solid #e2e8f0', color: '#475569' }}>
                      <th style={{ padding: '6px 8px' }}>Категория</th>
                      <th style={{ padding: '6px 8px' }}>Severity</th>
                      <th style={{ padding: '6px 8px' }}>Путь</th>
                      <th style={{ padding: '6px 8px' }}>Класс / Advisory</th>
                      <th style={{ padding: '6px 8px' }}>Строка</th>
                      <th style={{ padding: '6px 8px' }}>Описание</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((f, idx) => {
                      const sev = SEV_COLORS[f.severity ?? ''] ?? { bg: '#f1f5f9', fg: '#334155', bar: '#64748b' };
                      const detail =
                        f.category === 'SCA'
                          ? `${f.group}:${f.artifact}@${f.version} (${f.advisoryId})`
                          : f.class ?? '—';
                      const isExpanded = expandedIdx === idx;
                      return (
                        <tr
                          key={`${f.path}-${idx}`}
                          onClick={() => setExpandedIdx(isExpanded ? null : idx)}
                          style={{
                            borderBottom: '1px solid #f1f5f9',
                            cursor: 'pointer',
                            background: isExpanded ? '#f8fafc' : 'transparent',
                          }}
                          title="Нажмите для подробностей"
                        >
                          <td style={{ padding: '6px 8px', fontWeight: 700 }}>{f.category}</td>
                          <td style={{ padding: '6px 8px' }}>
                            <span
                              style={{
                                padding: '2px 6px',
                                borderRadius: 6,
                                background: sev.bg,
                                color: sev.fg,
                                fontWeight: 700,
                                fontSize: 11,
                              }}
                            >
                              {f.severity ?? '—'}
                            </span>
                          </td>
                          <td style={{ padding: '6px 8px', fontFamily: 'monospace' }}>{f.path}</td>
                          <td style={{ padding: '6px 8px', fontFamily: 'monospace' }}>{detail}</td>
                          <td style={{ padding: '6px 8px' }}>
                            {f.line ? (f.endLine && f.endLine !== f.line ? `${f.line}–${f.endLine}` : f.line) : '—'}
                          </td>
                          <td style={{ padding: '6px 8px', color: '#334155' }}>
                            <div>{f.description ?? '—'}</div>
                            {isExpanded && f.remediation && (
                              <div style={{ marginTop: 6, padding: 6, background: '#eff6ff', borderRadius: 6, color: '#1e3a8a' }}>
                                <strong>Рекомендация:</strong> {f.remediation}
                              </div>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {tab === 'dashboard' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ padding: 12, border: '1px solid #e2e8f0', borderRadius: 8, background: '#f8fafc' }}>
                <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 8 }}>Распределение по Severity</div>
                {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((lvl) => {
                  const count = sevCounts[lvl] ?? 0;
                  const pct = Math.round((count / maxSev) * 100);
                  const c = SEV_COLORS[lvl];
                  return (
                    <div key={lvl} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, fontSize: 12 }}>
                      <span style={{ width: 70, fontWeight: 700, color: c.fg }}>{lvl}</span>
                      <div style={{ flex: 1, height: 12, background: '#e2e8f0', borderRadius: 6, overflow: 'hidden' }}>
                        <div style={{ width: `${pct}%`, height: '100%', background: c.bar }} />
                      </div>
                      <span style={{ width: 28, textAlign: 'right', fontWeight: 700 }}>{count}</span>
                    </div>
                  );
                })}
                <div style={{ marginTop: 10, fontSize: 12, color: '#475569' }}>
                  По категориям: SECRET <strong>{catCounts.SECRET}</strong> · SCA <strong>{catCounts.SCA}</strong> · SAST{' '}
                  <strong>{catCounts.SAST}</strong>
                </div>
              </div>

              <div style={{ padding: 12, border: '1px solid #e2e8f0', borderRadius: 8, background: '#f8fafc' }}>
                <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 8 }}>Сравнение запусков (Diff)</div>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap', marginBottom: 8 }}>
                  <select
                    value={baseRunId || runsHistory[1]?.id || ''}
                    onChange={(e) => setBaseRunId(e.target.value)}
                    style={{ padding: '4px 6px', fontSize: 12, borderRadius: 6, border: '1px solid #cbd5e1' }}
                  >
                    <option value="">Базовый run…</option>
                    {runsHistory.map((r) => (
                      <option key={r.id} value={r.id}>
                        {r.id.slice(0, 8)} ({r.status})
                      </option>
                    ))}
                  </select>
                  <span style={{ fontSize: 12 }}>→</span>
                  <select
                    value={targetRunId || run?.id || runsHistory[0]?.id || ''}
                    onChange={(e) => setTargetRunId(e.target.value)}
                    style={{ padding: '4px 6px', fontSize: 12, borderRadius: 6, border: '1px solid #cbd5e1' }}
                  >
                    <option value="">Целевой run…</option>
                    {runsHistory.map((r) => (
                      <option key={r.id} value={r.id}>
                        {r.id.slice(0, 8)} ({r.status})
                      </option>
                    ))}
                  </select>
                  <button
                    type="button"
                    onClick={() => void handleCompare()}
                    style={{
                      padding: '4px 10px',
                      borderRadius: 6,
                      border: 'none',
                      background: '#2563eb',
                      color: '#fff',
                      fontSize: 12,
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    Сравнить
                  </button>
                </div>
                {compareErr && <div style={{ color: '#dc2626', fontSize: 12 }}>{compareErr}</div>}
                {compareResult && (
                  <div style={{ fontSize: 12 }}>
                    <div style={{ display: 'flex', gap: 12, marginBottom: 6 }}>
                      <span style={{ color: '#dc2626', fontWeight: 700 }}>+{compareResult.summary.new_count} новых</span>
                      <span style={{ color: '#16a34a', fontWeight: 700 }}>-{compareResult.summary.fixed_count} исправлено</span>
                      <span style={{ color: '#475569' }}>{compareResult.summary.persisting_count} повторяющихся</span>
                    </div>
                    {compareResult.new.slice(0, 3).map((item, idx) => (
                      <div key={idx} style={{ color: '#991b1b', fontFamily: 'monospace', fontSize: 11 }}>
                        [NEW] {item.category} {item.path}:{item.line ?? 0}
                      </div>
                    ))}
                    {compareResult.fixed.slice(0, 3).map((item, idx) => (
                      <div key={idx} style={{ color: '#166534', fontFamily: 'monospace', fontSize: 11 }}>
                        [FIXED] {item.category} {item.path}:{item.line ?? 0}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {tab === 'ai' && (
            <div>
              {!ai ? (
                <div style={{ color: '#64748b', fontSize: 13 }}>
                  AI-отчёт отсутствует. Добавьте блок <code>ai.explain</code> в сценарий и запустите выполнение.
                </div>
              ) : (
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10, flexWrap: 'wrap' }}>
                    <strong>Резюме:</strong> <span>{ai.summary}</span>
                    {ai.validation && (
                      <span
                        style={{
                          fontSize: 11,
                          padding: '2px 8px',
                          borderRadius: 999,
                          background:
                            ai.validation.mode === 'llm'
                              ? '#dcfce7'
                              : ai.validation.mode === 'empty'
                              ? '#e0f2fe'
                              : '#fef3c7',
                          color:
                            ai.validation.mode === 'llm'
                              ? '#166534'
                              : ai.validation.mode === 'empty'
                              ? '#075985'
                              : '#92400e',
                          fontWeight: 700,
                        }}
                      >
                        {ai.validation.mode === 'llm'
                          ? 'Режим: LLM'
                          : ai.validation.mode === 'empty'
                          ? 'Режим: Нет находок'
                          : 'Режим: Fallback (без LLM)'}{' '}
                        · passed={String(ai.validation.passed)} · dropped_cve={ai.validation.dropped_cve ?? 0}
                      </span>
                    )}
                  </div>
                  {ai.validation?.mode === 'fallback' && (
                    <div
                      style={{
                        padding: '8px 10px',
                        marginBottom: 10,
                        borderRadius: 6,
                        background: '#fffbeb',
                        border: '1px solid #fcd34d',
                        color: '#92400e',
                        fontSize: 12,
                      }}
                    >
                      <strong>Внимание (резервный отчёт):</strong>{' '}
                      {ai.validation.fallback_reason ||
                        ai.validation.errors?.join('; ') ||
                        'LLM недоступна или не прошла валидацию — показан шаблонный fallback-отчёт.'}
                    </div>
                  )}
                  {ai.items.map((item, i) => (
                    <div
                      key={i}
                      style={{
                        padding: 10,
                        border: '1px solid #e2e8f0',
                        borderRadius: 8,
                        marginBottom: 8,
                        background: '#f8fafc',
                        fontSize: 12,
                      }}
                    >
                      <div style={{ fontWeight: 700 }}>
                        Finding #{item.finding_ref} {item.risk ? `· Risk: ${item.risk}` : ''}
                      </div>
                      <div style={{ marginTop: 4 }}>{item.explanation}</div>
                      {item.fix_steps?.length > 0 && (
                        <ul style={{ margin: '6px 0 0 18px', padding: 0 }}>
                          {item.fix_steps.map((step, j) => (
                            <li key={j}>{step}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {tab === 'markdown' && (
            <pre
              style={{
                margin: 0,
                fontSize: 12,
                whiteSpace: 'pre-wrap',
                background: '#f8fafc',
                padding: 12,
                borderRadius: 8,
                border: '1px solid #e2e8f0',
              }}
            >
              {reportMd || 'Отчёт пока не сформирован.'}
            </pre>
          )}

          {tab === 'log' && (
            <div style={{ fontFamily: 'monospace', fontSize: 11 }}>
              {events.length === 0 ? (
                <div style={{ color: '#64748b' }}>Событий WebSocket пока нет.</div>
              ) : (
                events.map((ev, i) => (
                  <div key={i} style={{ padding: '2px 0', borderBottom: '1px solid #f1f5f9' }}>
                    <strong>{ev.event}</strong>
                    {ev.node_id ? ` [${ev.node_id}]` : ''}
                    {ev.status ? ` status=${ev.status}` : ''}
                    {typeof ev.duration_ms === 'number' ? ` (${ev.duration_ms}ms)` : ''}
                    {ev.error ? ` ERROR: ${ev.error}` : ''}
                  </div>
                ))
              )}
            </div>
          )}

          {tab === 'history' && (
            <div>
              {runsHistory.length === 0 ? (
                <div style={{ color: '#64748b', fontSize: 13 }}>Запусков пока нет.</div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                  <thead>
                    <tr style={{ textAlign: 'left', borderBottom: '2px solid #e2e8f0', color: '#475569' }}>
                      <th style={{ padding: '6px 8px' }}>Run ID</th>
                      <th style={{ padding: '6px 8px' }}>Статус</th>
                      <th style={{ padding: '6px 8px' }}>Триггер</th>
                      <th style={{ padding: '6px 8px' }}>Находок</th>
                      <th style={{ padding: '6px 8px' }}>Запущен</th>
                      <th style={{ padding: '6px 8px' }}>Действие</th>
                    </tr>
                  </thead>
                  <tbody>
                    {runsHistory.map((item) => (
                      <tr key={item.id} style={{ borderBottom: '1px solid #f1f5f9' }}>
                        <td style={{ padding: '6px 8px', fontFamily: 'monospace' }}>{item.id.slice(0, 8)}</td>
                        <td style={{ padding: '6px 8px', fontWeight: 700 }}>{item.status}</td>
                        <td style={{ padding: '6px 8px' }}>{item.trigger}</td>
                        <td style={{ padding: '6px 8px' }}>{item.summary?.report?.findings_count ?? '—'}</td>
                        <td style={{ padding: '6px 8px' }}>{item.started_at ? item.started_at.replace('T', ' ').slice(0, 19) : '—'}</td>
                        <td style={{ padding: '6px 8px' }}>
                          {onSelectRun && (
                            <button
                              type="button"
                              onClick={() => {
                                onSelectRun(item.id);
                                setTab('findings');
                              }}
                              style={{
                                padding: '3px 8px',
                                fontSize: 11,
                                borderRadius: 6,
                                border: '1px solid #cbd5e1',
                                background: '#eff6ff',
                                color: '#1d4ed8',
                                cursor: 'pointer',
                                fontWeight: 600,
                              }}
                            >
                              Открыть
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
