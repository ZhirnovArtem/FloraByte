
import { nodeCatalog } from '../config/nodeCatalog';

type NodeSidebarProps = {
  onAddNode: (kind: string) => void;
};

export default function NodeSidebar({
  onAddNode,
}: NodeSidebarProps) {
  return (
    <aside
      style={{
        width: 240,
        padding: 16,
        background: '#f8fafc',
        borderRight: '1px solid #e2e8f0',
        overflowY: 'auto',
        flexShrink: 0,
      }}
    >
      <h3 style={{ marginTop: 0 }}>
        Блоки сценария
      </h3>

      {nodeCatalog.map((item) => (
        <button
          key={item.kind}
          onClick={() => onAddNode(item.kind)}
          style={{
            display: 'block',
            width: '100%',
            marginBottom: 10,
            padding: 12,
            textAlign: 'left',
            background: '#ffffff',
            border: '1px solid #cbd5e1',
            borderRadius: 8,
            cursor: 'pointer',
          }}
        >
          <strong>{item.label}</strong>

          <div
            style={{
              fontSize: 12,
              color: '#64748b',
              marginTop: 4,
            }}
          >
            {item.description}
          </div>
        </button>
      ))}
    </aside>
  );
}
