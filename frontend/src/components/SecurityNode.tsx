import { Handle, Position, type Node, type NodeProps } from '@xyflow/react';
import type { NodeRunStatus, PortSpec } from '../types/workflow';

export type SecurityNodeData = {
  label: string;
  description?: string;
  kind: string; // backend node type e.g. "scanner.secrets"
  group?: string;
  inputs?: PortSpec[];
  outputs?: PortSpec[];
  params?: Record<string, unknown>;
  runStatus?: NodeRunStatus;
  durationMs?: number;
  outputPreview?: Record<string, unknown> | null;
  error?: string | null;
};

export type SecurityNodeType = Node<SecurityNodeData, 'security'>;

const groupColors: Record<string, string> = {
  trigger: '#64748b',
  source: '#0284c7',
  scanner: '#d97706',
  logic: '#0891b2',
  findings: '#4f46e5',
  ai: '#7c3aed',
  notify: '#059669',
};

const statusBadge: Record<NodeRunStatus, { bg: string; fg: string; label: string }> = {
  pending: { bg: '#f1f5f9', fg: '#475569', label: 'pending' },
  running: { bg: '#dbeafe', fg: '#1d4ed8', label: 'running…' },
  success: { bg: '#dcfce7', fg: '#15803d', label: 'success' },
  failed: { bg: '#fee2e2', fg: '#b91c1c', label: 'failed' },
  skipped: { bg: '#f3f4f6', fg: '#6b7280', label: 'skipped' },
};

function summarizePreview(preview: Record<string, unknown> | null | undefined): string | null {
  if (!preview) return null;
  const parts: string[] = [];
  for (const val of Object.values(preview)) {
    if (val && typeof val === 'object') {
      const obj = val as Record<string, unknown>;
      if (obj.kind === 'Findings' && typeof obj.count === 'number') {
        parts.push(`Находок: ${obj.count}`);
      } else if (obj.kind === 'Report' && typeof obj.findings_count === 'number') {
        parts.push(`Отчёт: ${obj.findings_count}`);
      } else if (obj.kind === 'Workspace') {
        parts.push('Workspace готов');
      }
    }
  }
  return parts.length ? parts.join(' · ') : null;
}

export default function SecurityNode({ data, selected }: NodeProps<SecurityNodeType>) {
  const color = groupColors[data.group ?? ''] ?? '#475569';
  const inputs = data.inputs ?? [];
  const outputs = data.outputs ?? [];
  const badge = data.runStatus ? statusBadge[data.runStatus] : null;
  const previewText = summarizePreview(data.outputPreview);

  return (
    <div
      style={{
        minWidth: 210,
        maxWidth: 260,
        padding: '12px 14px',
        borderRadius: 12,
        background: selected ? '#eff6ff' : '#ffffff',
        border: selected ? '3px solid #2563eb' : `2px solid ${color}`,
        boxShadow: selected
          ? '0 0 12px rgba(37,99,235,0.28)'
          : '0 2px 6px rgba(0,0,0,0.08)',
        position: 'relative',
      }}
    >
      {inputs.map((port, idx) => {
        const leftPct = inputs.length === 1 ? 50 : ((idx + 1) / (inputs.length + 1)) * 100;
        return (
          <Handle
            key={`in-${port.name}`}
            id={port.name}
            type="target"
            position={Position.Top}
            style={{ left: `${leftPct}%`, background: color }}
            title={`${port.name} (${port.kind})`}
          />
        );
      })}

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 6 }}>
        <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: '#64748b' }}>
          {data.group || 'node'}
        </span>
        {badge && (
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
            {typeof data.durationMs === 'number' && data.runStatus === 'success'
              ? ` (${data.durationMs}ms)`
              : ''}
          </span>
        )}
      </div>

      <div style={{ fontWeight: 700, color, marginTop: 4, fontSize: 14 }}>{data.label}</div>

      <div style={{ fontSize: 11, color: '#64748b', marginTop: 2, fontFamily: 'monospace' }}>
        {data.kind}
      </div>

      {previewText && (
        <div
          style={{
            marginTop: 6,
            fontSize: 11,
            color: '#1e293b',
            background: '#f8fafc',
            borderRadius: 6,
            padding: '3px 6px',
          }}
        >
          {previewText}
        </div>
      )}

      {data.error && (
        <div
          style={{
            marginTop: 6,
            fontSize: 11,
            color: '#b91c1c',
            background: '#fef2f2',
            borderRadius: 6,
            padding: '3px 6px',
            wordBreak: 'break-word',
          }}
        >
          {data.error}
        </div>
      )}

      {outputs.length > 1 && (
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-around',
            marginTop: 8,
            fontSize: 10,
            color: '#475569',
            fontWeight: 600,
          }}
        >
          {outputs.map((p) => (
            <span key={p.name}>{p.name}</span>
          ))}
        </div>
      )}

      {outputs.map((port, idx) => {
        const leftPct = outputs.length === 1 ? 50 : ((idx + 1) / (outputs.length + 1)) * 100;
        return (
          <Handle
            key={`out-${port.name}`}
            id={port.name}
            type="source"
            position={Position.Bottom}
            style={{ left: `${leftPct}%`, background: color }}
            title={`${port.name} (${port.kind})`}
          />
        );
      })}
    </div>
  );
}
