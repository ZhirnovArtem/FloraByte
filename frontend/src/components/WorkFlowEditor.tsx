
import { useCallback } from 'react';

import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  MiniMap,
  addEdge,
  useNodesState,
  useEdgesState,
  useReactFlow,
  type Edge,
  type Connection,
} from '@xyflow/react';

import '@xyflow/react/dist/style.css';

import SecurityNode, {
  type SecurityNodeType,
} from './SecurityNode';

import NodeSidebar from './NodeSidebar';
import NodeSettings from './NodeSettings';

import { nodeCatalog } from '../config/nodeCatalog';

// Ключ, под которым сценарий хранится в браузере
const STORAGE_KEY = 'florabyte-workflow';

// Регистрируем пользовательский компонент блока
const nodeTypes = {
  security: SecurityNode,
};

// Начальные блоки
const initialNodes: SecurityNodeType[] = [
  {
    id: '1',
    type: 'security',
    position: { x: 250, y: 50 },
    data: {
      label: 'Start',
      description: 'Начало сценария',
      kind: 'start',
    },
  },
  {
    id: '2',
    type: 'security',
    position: { x: 250, y: 220 },
    data: {
      label: 'Secrets Scanner',
      description: 'Поиск секретов',
      kind: 'secrets',
    },
  },
];

// Начальное соединение
const initialEdges: Edge[] = [
  {
    id: 'e1-2',
    source: '1',
    target: '2',
  },
];

function WorkflowEditorContent() {
  // 1. Состояние блоков
  const [nodes, setNodes, onNodesChange] =
    useNodesState<SecurityNodeType>(initialNodes);

  // 2. Состояние соединений
  const [edges, setEdges, onEdgesChange] =
    useEdgesState<Edge>(initialEdges);

  // 3. Находим выделенный блок
  const selectedNode =
    nodes.find((node) => node.selected) ?? null;

  // 4. Получаем встроенный метод удаления React Flow
  const { deleteElements } = useReactFlow();

  // 5. Создание соединения между блоками
  const onConnect = useCallback(
    (connection: Connection) => {
      setEdges((currentEdges) =>
        addEdge(connection, currentEdges)
      );
    },
    [setEdges]
  );

  // 6. Добавление нового блока
  const addNode = (kind: string) => {
    const item = nodeCatalog.find(
      (node) => node.kind === kind
    );

    if (!item) {
      return;
    }

    const newNode: SecurityNodeType = {
      id: crypto.randomUUID(),
      type: 'security',
      position: {
        x: 100 + Math.random() * 300,
        y: 100 + Math.random() * 300,
      },
      data: {
        label: item.label,
        description: item.description,
        kind: item.kind,
      },
    };

    setNodes((currentNodes) => [
      ...currentNodes,
      newNode,
    ]);
  };

  // 7. Удаление выделенных блоков и линий
  const deleteSelected = async () => {
    const selectedNodes = nodes.filter(
      (node) => node.selected
    );

    const selectedEdges = edges.filter(
      (edge) => edge.selected
    );

    await deleteElements({
      nodes: selectedNodes,
      edges: selectedEdges,
    });
  };

  // 8. Сохранение настроек выбранного блока
  const saveNodeSettings = (
    nodeId: string,
    label: string,
    config: NonNullable<
      SecurityNodeType['data']['config']
    >
  ) => {
    setNodes((currentNodes) =>
      currentNodes.map((node) => {
        if (node.id !== nodeId) {
          return node;
        }

        return {
          ...node,
          data: {
            ...node.data,
            label,
            config,
          },
        };
      })
    );
  };

  // 9. Сохранение всего сценария в localStorage
  const saveWorkflow = () => {
    const workflow = {
      nodes,
      edges,
    };

    try {
      const json = JSON.stringify(workflow);

      localStorage.setItem(STORAGE_KEY, json);

      console.log(
        'Сохраняем сценарий:',
        workflow
      );

      console.log(
        'Проверяем localStorage:',
        localStorage.getItem(STORAGE_KEY)
      );

      alert('Сценарий сохранён!');
    } catch (error) {
      console.error(
        'Ошибка сохранения сценария:',
        error
      );

      alert('Не удалось сохранить сценарий');
    }
  };

  // 10. Загрузка сценария из localStorage
  const loadWorkflow = () => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);

      console.log(
        'Найденный сценарий:',
        saved
      );

      if (saved === null) {
        alert('Сохранённый сценарий не найден');
        return;
      }

      const workflow: unknown = JSON.parse(saved);

      if (
        typeof workflow !== 'object' ||
        workflow === null ||
        !('nodes' in workflow) ||
        !('edges' in workflow) ||
        !Array.isArray(workflow.nodes) ||
        !Array.isArray(workflow.edges)
      ) {
        throw new Error(
          'Неверный формат сохранённого сценария'
        );
      }

      // Базовая проверка структуры.
      // Для данных с сервера потребуется более
      // строгая валидация каждого блока и соединения.
      setNodes(workflow.nodes as SecurityNodeType[]);
      setEdges(workflow.edges as Edge[]);

      alert('Сценарий загружен!');
    } catch (error) {
      console.error(
        'Ошибка загрузки сценария:',
        error
      );

      alert('Не удалось загрузить сценарий');
    }
  };

  return (
    <div
      style={{
        display: 'flex',
        width: '100%',
        height: '100vh',
      }}
    >
      {/* Левая панель с типами блоков */}
      <NodeSidebar onAddNode={addNode} />

      {/* Центральная рабочая область */}
      <div
        style={{
          flex: 1,
          minWidth: 0,
          position: 'relative',
        }}
      >
        {/* Панель кнопок */}
        <div
          style={{
            position: 'absolute',
            top: 20,
            left: 20,
            zIndex: 10,
            display: 'flex',
            gap: 10,
            flexWrap: 'wrap',
          }}
        >
          <button
            onClick={saveWorkflow}
            style={{
              padding: '10px 15px',
              background: '#059669',
              color: '#ffffff',
              border: 'none',
              borderRadius: 8,
              cursor: 'pointer',
            }}
          >
            Сохранить
          </button>

          <button
            onClick={loadWorkflow}
            style={{
              padding: '10px 15px',
              background: '#2563eb',
              color: '#ffffff',
              border: 'none',
              borderRadius: 8,
              cursor: 'pointer',
            }}
          >
            Загрузить
          </button>

          <button
            onClick={deleteSelected}
            style={{
              padding: '10px 15px',
              background: '#dc2626',
              color: '#ffffff',
              border: 'none',
              borderRadius: 8,
              cursor: 'pointer',
            }}
          >
            Delete Selected
          </button>
        </div>

        {/* Редактор React Flow */}
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          nodesDraggable
          nodesConnectable
          elementsSelectable
          nodesFocusable
          edgesFocusable
          deleteKeyCode={['Backspace', 'Delete']}
          fitView
        >
          <Background />
          <Controls />
          <MiniMap />
        </ReactFlow>
      </div>

      {/* Правая панель настроек */}
      <NodeSettings
        key={selectedNode?.id ?? 'none'}
        selectedNode={selectedNode}
        onSave={saveNodeSettings}
      />
    </div>
  );
}

// ReactFlowProvider нужен для useReactFlow()
export default function WorkflowEditor() {
  return (
    <ReactFlowProvider>
      <WorkflowEditorContent />
    </ReactFlowProvider>
  );
}
