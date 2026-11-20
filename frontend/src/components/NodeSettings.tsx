import { useEffect, useState } from 'react';

import type {
  SecurityNodeType,
  SecurityNodeData,
} from './SecurityNode';

type NodeConfig = NonNullable<
  SecurityNodeData['config']
>;

type NodeSettingsProps = {
  selectedNode: SecurityNodeType | null;
  onSave: (
    nodeId: string,
    label: string,
    config: NodeConfig
  ) => void;
};


export default function NodeSettings({
  selectedNode,
  onSave,
}: NodeSettingsProps) {
  const [label, setLabel] = useState('');

  const [config, setConfig] = useState<NodeConfig>({});

  useEffect(() => {
    if (!selectedNode) {
      setLabel('');
      setConfig({});
      return;
    }

    setLabel(selectedNode.data.label);
    setConfig({ ...selectedNode.data.config });
  }, [selectedNode?.id]);

  const updateConfig = (
    field: keyof NodeConfig,
    value: string
  ) => {
    setConfig((current) => ({
      ...current,
      [field]: value,
    }));
  };

  const inputStyle: React.CSSProperties = {
    width: '100%',
    padding: '9px',
    border: '1px solid #cbd5e1',
    borderRadius: '6px',
    marginTop: '5px',
    marginBottom: '15px',
  };

  if (!selectedNode) {
    return (
      <aside style={{
        width: 300,
        padding: 20,
        background: '#f8fafc',
        borderLeft: '1px solid #e2e8f0',
      }}>
        <h3>Настройки</h3>
        <p>Выберите блок на схеме.</p>
      </aside>
    );
  }

  const kind = selectedNode.data.kind;

  return (
    <aside style={{
      width: 300,
      padding: 20,
      background: '#f8fafc',
      borderLeft: '1px solid #e2e8f0',
      overflowY: 'auto',
      flexShrink: 0,
    }}>
      <h3>Настройки блока</h3>

      <p style={{ color: '#64748b' }}>
        Тип: {kind}
      </p>

      <label>
        Название блока
        <input
          style={inputStyle}
          value={label}
          onChange={(event) =>
            setLabel(event.target.value)
          }
        />
      </label>

      {['secrets', 'sast', 'sca'].includes(kind) && (
        <>
          <label>
            URL репозитория
            <input
              style={inputStyle}
              placeholder="https://github.com/..."
              value={config.repositoryUrl ?? ''}
              onChange={(event) =>
                updateConfig(
                  'repositoryUrl',
                  event.target.value
                )
              }
            />
          </label>

          <label>
            Ветка
            <input
              style={inputStyle}
              placeholder="main"
              value={config.branch ?? ''}
              onChange={(event) =>
                updateConfig(
                  'branch',
                  event.target.value
                )
              }
            />
          </label>
        </>
      )}

      {kind === 'condition' && (
        <label>
          Условие
          <input
            style={inputStyle}
            placeholder="findings_count > 0"
            value={config.condition ?? ''}
            onChange={(event) =>
              updateConfig(
                'condition',
                event.target.value
              )
            }
          />
        </label>
      )}

      {kind === 'notification' && (
        <label>
          Webhook URL
          <input
            style={inputStyle}
            placeholder="https://example.com/webhook"
            value={config.notificationUrl ?? ''}
            onChange={(event) =>
              updateConfig(
                'notificationUrl',
                event.target.value
              )
            }
          />
        </label>
      )}

      <button
        onClick={() =>
          onSave(selectedNode.id, label, config)
        }
        style={{
          width: '100%',
          padding: '10px',
          background: '#2563eb',
          color: 'white',
          border: 'none',
          borderRadius: '8px',
          cursor: 'pointer',
        }}
      >
        Сохранить
      </button>
    </aside>
  );
}
