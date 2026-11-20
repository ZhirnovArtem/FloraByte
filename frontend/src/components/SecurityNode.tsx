
import {
  Handle,
  Position,
  type Node,
  type NodeProps,
} from '@xyflow/react';


export type SecurityNodeData = {
  label: string;
  description?: string;
  kind: string;

  config?: {
    repositoryUrl?: string;
    branch?: string;
    severity?: string;
    condition?: string;
    notificationUrl?: string;
  };
};


export type SecurityNodeType = Node<
  SecurityNodeData,
  'security'
>;

const colors: Record<string, string> = {
  start: '#64748b',
  secrets: '#d97706',
  sast: '#dc2626',
  sca: '#2563eb',
  ai: '#7c3aed',
  notification: '#059669',
  condition: '#0891b2',
};

export default function SecurityNode({
  data,
  selected,
}: NodeProps<SecurityNodeType>) {
  const color = colors[data.kind] ?? '#64748b';

  return (
    <div
      style={{
        minWidth: 190,
        padding: 14,
        borderRadius: 12,
        background: selected
          ? '#eff6ff'
          : '#ffffff',
        border: selected
          ? '3px solid #2563eb'
          : `2px solid ${color}`,
        boxShadow: selected
          ? '0 0 12px rgba(37,99,235,0.3)'
          : '0 2px 6px rgba(0,0,0,0.08)',
      }}
    >
      <Handle
        type="target"
        position={Position.Top}
      />

      <div
        style={{
          fontWeight: 700,
          color,
          marginBottom: 5,
        }}
      >
        {data.label}
      </div>

      {data.description && (
        <div
          style={{
            fontSize: 12,
            color: '#64748b',
          }}
        >
          {data.description}
        </div>
      )}

      <Handle
        type="source"
        position={Position.Bottom}
      />
    </div>
  );
}
