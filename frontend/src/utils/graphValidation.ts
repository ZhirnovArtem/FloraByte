import type { Edge } from '@xyflow/react';
import type { SecurityNodeType } from '../components/SecurityNode';
import type { BackendGraph } from '../types/workflow';

const KINDS = new Set(['Workspace', 'Findings', 'Report', 'Boolean', 'Any']);

export function connectionError(
  connection: {
    source: string;
    target: string;
    sourceHandle?: string | null;
    targetHandle?: string | null;
  },
  nodes: SecurityNodeType[],
  edges: Edge[],
): string | null {
  const src = nodes.find((n) => n.id === connection.source);
  const tgt = nodes.find((n) => n.id === connection.target);
  if (!src || !tgt) return 'Соединение содержит несуществующий блок.';
  if (src.id === tgt.id) return 'Нельзя соединить блок с самим собой.';
  const sourcePorts = src.data.outputs ?? [];
  const targetPorts = tgt.data.inputs ?? [];
  const sourcePort = connection.sourceHandle
    ? sourcePorts.find((p) => p.name === connection.sourceHandle)
    : sourcePorts.length === 1 ? sourcePorts[0] : null;
  const targetPort = connection.targetHandle
    ? targetPorts.find((p) => p.name === connection.targetHandle)
    : targetPorts[0];
  if (!sourcePort || !targetPort) return 'Не найден порт; укажите конкретный выход для ветвления.';
  if (!KINDS.has(sourcePort.kind) || !KINDS.has(targetPort.kind)) return 'Неизвестный тип порта.';
  if (sourcePort.kind !== targetPort.kind && sourcePort.kind !== 'Any' && targetPort.kind !== 'Any') {
    return `Несовместимые типы портов: ${sourcePort.kind} → ${targetPort.kind}.`;
  }
  const occupied = edges.some((e) => e.target === tgt.id &&
    (e.targetHandle ?? targetPorts[0]?.name) === targetPort.name);
  if (occupied) return `Вход ${targetPort.name} уже занят другим соединением.`;
  // DFS from destination: if we can already reach source, new edge forms a cycle.
  const visited = new Set<string>();
  const queue = [tgt.id];
  while (queue.length) {
    const id = queue.pop()!;
    if (id === src.id) return 'Соединение создаёт цикл; workflow должен быть ацикличным.';
    if (visited.has(id)) continue;
    visited.add(id);
    for (const e of edges) if (e.source === id) queue.push(e.target);
  }
  return null;
}

const SENSITIVE = /(?:token|password|passwd|api[_-]?key|secret|authorization|headers_json|bot_token)/i;
/** Never persist raw credentials in localStorage. A credential_id is an opaque reference. */
export function safeGraphForLocalStorage(graph: BackendGraph): BackendGraph {
  return {
    ...graph,
    nodes: graph.nodes.map((node) => ({
      ...node,
      params: Object.fromEntries(Object.entries(node.params).filter(([key]) =>
        key === 'credential_id' || !SENSITIVE.test(key))),
    })),
  };
}
