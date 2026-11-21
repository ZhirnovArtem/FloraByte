import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
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

import SecurityNode, { type SecurityNodeType } from './SecurityNode';
import NodeSidebar from './NodeSidebar';
import NodeSettings from './NodeSettings';
import ReportPanel from './ReportPanel';
import { fallbackNodeCatalog } from '../config/nodeCatalog';
import * as api from '../api/client';
import type {
  BackendGraph,
  CredentialDto,
  FindingDto,
  NodeRunStatus,
  NodeTypeSpec,
  RunDto,
  TemplateDto,
  WorkflowDto,
  WsRunEvent,
} from '../types/workflow';

const STORAGE_KEY = 'florabyte-workflow';
const ACTIVE_RUN_KEY = 'florabyte-active-run-id';
const TERMINAL_RUN_STATUSES = new Set(['success', 'failed', 'partial']);

const nodeTypes = {
  security: SecurityNode,
};

function defaultParamsFromSpec(spec?: NodeTypeSpec): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const props = spec?.params_schema?.properties ?? {};
  for (const [k, v] of Object.entries(props)) {
    if (v.default !== undefined) {
      out[k] = v.default;
    }
  }
  return out;
}

function toBackendGraph(nodes: SecurityNodeType[], edges: Edge[]): BackendGraph {
  return {
    nodes: nodes.map((n) => ({
      id: n.id,
      type: n.data.kind,
      params: n.data.params ?? {},
      position: { x: Math.round(n.position.x), y: Math.round(n.position.y) },
    })),
    edges: edges.map((e) => ({
      id: e.id,
      source: e.source,
      sourceHandle: e.sourceHandle ?? null,
      target: e.target,
      targetHandle: e.targetHandle ?? null,
    })),
  };
}

function fromBackendGraph(
  graph: BackendGraph,
  catalog: NodeTypeSpec[],
): { nodes: SecurityNodeType[]; edges: Edge[] } {
  const byType = new Map(catalog.map((c) => [c.type, c]));
  const nodes: SecurityNodeType[] = (graph.nodes ?? []).map((bn) => {
    const spec = byType.get(bn.type);
    return {
      id: bn.id,
      type: 'security',
      position: bn.position ?? { x: 100, y: 100 },
      data: {
        label: spec?.label ?? bn.type,
        kind: bn.type,
        group: spec?.group,
        inputs: spec?.inputs ?? [{ name: 'in', kind: 'Any' }],
        outputs: spec?.outputs ?? [{ name: 'out', kind: 'Any' }],
        params: bn.params ?? defaultParamsFromSpec(spec),
      },
    };
  });
  const edges: Edge[] = (graph.edges ?? []).map((be, idx) => ({
    id: be.id || `e-${be.source}-${be.target}-${idx}`,
    source: be.source,
    sourceHandle: be.sourceHandle ?? undefined,
    target: be.target,
    targetHandle: be.targetHandle ?? undefined,
  }));
  return { nodes, edges };
}

function buildStarterNodes(catalog: NodeTypeSpec[]): { nodes: SecurityNodeType[]; edges: Edge[] } {
  const starterGraph: BackendGraph = {
    nodes: [
      { id: 't1', type: 'trigger.manual', params: {}, position: { x: 80, y: 80 } },
      { id: 's1', type: 'source.upload_zip', params: { upload_id: '' }, position: { x: 320, y: 80 } },
      { id: 'sc1', type: 'scanner.secrets', params: {}, position: { x: 180, y: 240 } },
      { id: 'sc2', type: 'scanner.sca', params: {}, position: { x: 420, y: 240 } },
      { id: 'sc3', type: 'scanner.sast', params: {}, position: { x: 660, y: 240 } },
      { id: 'm1', type: 'findings.merge', params: {}, position: { x: 420, y: 400 } },
      { id: 'e1', type: 'findings.export', params: {}, position: { x: 420, y: 550 } },
    ],
    edges: [
      { id: 'e1', source: 't1', target: 's1' },
      { id: 'e2', source: 's1', target: 'sc1' },
      { id: 'e3', source: 's1', target: 'sc2' },
      { id: 'e4', source: 's1', target: 'sc3' },
      { id: 'e5', source: 'sc1', target: 'm1', targetHandle: 'a' },
      { id: 'e6', source: 'sc2', target: 'm1', targetHandle: 'b' },
      { id: 'e7', source: 'sc3', target: 'm1', targetHandle: 'c' },
      { id: 'e8', source: 'm1', target: 'e1' },
    ],
  };
  return fromBackendGraph(starterGraph, catalog);
}

function WorkflowEditorContent() {
  const [catalog, setCatalog] = useState<NodeTypeSpec[]>(fallbackNodeCatalog);
  const [catalogSource, setCatalogSource] = useState<'api' | 'fallback'>('fallback');
  const [templates, setTemplates] = useState<TemplateDto[]>([]);
  const [workflows, setWorkflows] = useState<WorkflowDto[]>([]);
  const [credentials, setCredentials] = useState<CredentialDto[]>([]);

  const [workflowId, setWorkflowId] = useState<string | null>(null);
  const [workflowName, setWorkflowName] = useState<string>('Security Workflow');
  const [statusMsg, setStatusMsg] = useState<string>('');
  const [lastUpload, setLastUpload] = useState<{ id: string; filename: string } | null>(null);

  const starter = useMemo(() => buildStarterNodes(fallbackNodeCatalog), []);
  const [nodes, setNodes, onNodesChange] = useNodesState<SecurityNodeType>(starter.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>(starter.edges);

  const [isRunning, setIsRunning] = useState(false);
  const [activeRun, setActiveRun] = useState<RunDto | null>(null);
  const [findings, setFindings] = useState<FindingDto[]>([]);
  const [reportMd, setReportMd] = useState<string>('');
  const [wsEvents, setWsEvents] = useState<WsRunEvent[]>([]);
  const [panelOpen, setPanelOpen] = useState(false);

  const wsRef = useRef<WebSocket | null>(null);
  const pollTimerRef = useRef<number | null>(null);
  const { deleteElements } = useReactFlow();

  const stopPolling = useCallback(() => {
    if (pollTimerRef.current !== null) {
      window.clearInterval(pollTimerRef.current);
      pollTimerRef.current = null;
    }
  }, []);

  const specByType = useMemo(() => new Map(catalog.map((c) => [c.type, c])), [catalog]);
  const selectedNode = nodes.find((node) => node.selected) ?? null;

  const syncRunState = useCallback(async (runId: string): Promise<RunDto | null> => {
    try {
      const runDetails = await api.getRun(runId);
      setActiveRun(runDetails);
      if (runDetails.nodes) {
        const byId = new Map(runDetails.nodes.map((nr) => [nr.node_id, nr]));
        setNodes((curr) =>
          curr.map((n) => {
            const nr = byId.get(n.id);
            if (!nr) return n;
            return {
              ...n,
              data: {
                ...n.data,
                runStatus: nr.status,
                outputPreview: nr.output_preview ?? null,
                error: nr.error ?? null,
              },
            };
          }),
        );
      }

      if (TERMINAL_RUN_STATUSES.has(runDetails.status)) {
        stopPolling();
        sessionStorage.removeItem(ACTIVE_RUN_KEY);
        setIsRunning(false);
        setStatusMsg(`Выполнение завершено: ${runDetails.status}`);
        const [repJson, repMd] = await Promise.all([
          api.getReportJson(runId).catch(() => ({ findings: [] })),
          api.getReportMd(runId).catch(() => ''),
        ]);
        setFindings(repJson.findings ?? runDetails.summary?.report?.findings ?? []);
        setReportMd(repMd);
        setPanelOpen(true);
      }
      return runDetails;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setStatusMsg(`Не удалось загрузить результаты запуска: ${msg}`);
      return null;
    }
  }, [setNodes, stopPolling]);

  const startPollingRun = useCallback((runId: string) => {
    stopPolling();
    pollTimerRef.current = window.setInterval(() => {
      void syncRunState(runId);
    }, 1500);
  }, [stopPolling, syncRunState]);

  const attachToRun = useCallback((runId: string) => {
    wsRef.current?.close();
    sessionStorage.setItem(ACTIVE_RUN_KEY, runId);
    let finishedSeen = false;

    const ws = api.subscribeRunEvents(
      runId,
      (ev) => {
        setWsEvents((curr) => [...curr, ev]);
        if (ev.node_id && ev.status) {
          const st = ev.status as NodeRunStatus;
          setNodes((curr) =>
            curr.map((n) =>
              n.id === ev.node_id
                ? {
                    ...n,
                    data: {
                      ...n.data,
                      runStatus: st,
                      durationMs: ev.duration_ms ?? n.data.durationMs,
                      outputPreview: ev.output_preview ?? n.data.outputPreview,
                      error: ev.error ?? null,
                    },
                  }
                : n,
            ),
          );
        }
        if (ev.event === 'run_finished') {
          finishedSeen = true;
          stopPolling();
          void syncRunState(runId);
          ws.close();
        }
      },
      () => {
        if (!finishedSeen) {
          // Verify actual run status on backend before concluding the run finished
          void syncRunState(runId).then((details) => {
            if (details && !TERMINAL_RUN_STATUSES.has(details.status)) {
              setIsRunning(true);
              setStatusMsg('WebSocket отключён — отслеживаем выполнение через polling…');
              startPollingRun(runId);
            } else if (!details) {
              setIsRunning(false);
            }
          });
        }
      },
    );
    wsRef.current = ws;
  }, [setNodes, startPollingRun, stopPolling, syncRunState]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [nodeTypesRes, tpls, wfs, creds] = await Promise.all([
          api.fetchNodeTypes(),
          api.listTemplates().catch(() => []),
          api.listWorkflows().catch(() => []),
          api.listCredentials().catch(() => []),
        ]);
        if (cancelled) return;
        if (nodeTypesRes.length > 0) {
          setCatalog(nodeTypesRes);
          setCatalogSource('api');
          // Enrich starter nodes with real ports/labels from backend
          const freshStarter = buildStarterNodes(nodeTypesRes);
          setNodes((curr) =>
            curr.length === starter.nodes.length ? freshStarter.nodes : curr,
          );
        }
        setTemplates(tpls);
        setWorkflows(wfs);
        setCredentials(creds);

        // Restore active run if page was reloaded mid-execution
        const savedRunId = sessionStorage.getItem(ACTIVE_RUN_KEY);
        if (savedRunId) {
          const runDetails = await syncRunState(savedRunId);
          if (runDetails && !TERMINAL_RUN_STATUSES.has(runDetails.status)) {
            setIsRunning(true);
            setPanelOpen(true);
            attachToRun(savedRunId);
          }
        }
      } catch {
        if (!cancelled) {
          setCatalogSource('fallback');
          setStatusMsg('Backend недоступен — используется локальный каталог и localStorage.');
        }
      }
    })();
    return () => {
      cancelled = true;
      wsRef.current?.close();
      stopPolling();
    };
  }, []);

  const onConnect = useCallback(
    (connection: Connection) => {
      setEdges((currentEdges) => addEdge(connection, currentEdges));
    },
    [setEdges],
  );

  const addNode = (spec: NodeTypeSpec) => {
    const newNode: SecurityNodeType = {
      id: `n-${crypto.randomUUID().slice(0, 8)}`,
      type: 'security',
      position: {
        x: 150 + Math.round(Math.random() * 260),
        y: 120 + Math.round(Math.random() * 240),
      },
      data: {
        label: spec.label,
        kind: spec.type,
        group: spec.group,
        inputs: spec.inputs,
        outputs: spec.outputs,
        params: defaultParamsFromSpec(spec),
      },
    };
    setNodes((curr) => [...curr, newNode]);
  };

  const deleteSelected = async () => {
    await deleteElements({
      nodes: nodes.filter((n) => n.selected),
      edges: edges.filter((e) => e.selected),
    });
  };

  const saveNodeSettings = (
    nodeId: string,
    label: string,
    params: Record<string, unknown>,
  ) => {
    setNodes((curr) =>
      curr.map((n) =>
        n.id === nodeId
          ? {
              ...n,
              data: {
                ...n.data,
                label,
                params,
              },
            }
          : n,
      ),
    );
    setStatusMsg('Параметры блока обновлены.');
  };

  const handleUploadZip = async (file: File): Promise<string | null> => {
    try {
      setStatusMsg(`Загрузка ${file.name}…`);
      const res = await api.uploadZip(file);
      setLastUpload({ id: res.upload_id, filename: res.filename });
      // Auto-populate source.upload_zip nodes
      setNodes((curr) =>
        curr.map((n) =>
          n.data.kind === 'source.upload_zip'
            ? {
                ...n,
                data: {
                  ...n.data,
                  params: { ...(n.data.params ?? {}), upload_id: res.upload_id },
                },
              }
            : n,
        ),
      );
      setStatusMsg(`ZIP загружен: ${res.filename} (upload_id=${res.upload_id.slice(0, 8)}…)`);
      return res.upload_id;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setStatusMsg(`Ошибка загрузки ZIP: ${msg}`);
      return null;
    }
  };

  const handleCreateCredential = async (name: string, kind: string, value: string) => {
    try {
      const created = await api.createCredential(name, kind, value);
      setCredentials((curr) => [...curr, created]);
      setStatusMsg(`Секрет "${created.name}" сохранён.`);
      return created;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setStatusMsg(`Ошибка сохранения credential: ${msg}`);
      return null;
    }
  };

  const saveWorkflow = async (): Promise<WorkflowDto | null> => {
    const graph = toBackendGraph(nodes, edges);
    // Всегда дублируем в localStorage как запасной вариант
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({ name: workflowName, graph_json: graph, nodes, edges }));
    } catch {
      // ignore storage quota errors
    }

    try {
      let saved: WorkflowDto;
      if (workflowId) {
        saved = await api.updateWorkflow(workflowId, { name: workflowName, graph_json: graph });
      } else {
        saved = await api.createWorkflow(workflowName, graph);
        setWorkflowId(saved.id);
      }
      const list = await api.listWorkflows().catch(() => workflows);
      setWorkflows(list);
      setStatusMsg(`Сценарий "${saved.name}" сохранён на сервере (и в localStorage).`);
      return saved;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setStatusMsg(`Сохранено только в localStorage (ошибка API: ${msg}).`);
      return null;
    }
  };

  const loadWorkflowById = async (id: string) => {
    if (!id) {
      // Load from localStorage fallback
      try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (!raw) {
          setStatusMsg('В localStorage нет сохранённого сценария.');
          return;
        }
        const parsed = JSON.parse(raw) as {
          name?: string;
          graph_json?: BackendGraph;
          nodes?: SecurityNodeType[];
          edges?: Edge[];
        };
        if (parsed.graph_json) {
          const conv = fromBackendGraph(parsed.graph_json, catalog);
          setNodes(conv.nodes);
          setEdges(conv.edges);
        } else if (Array.isArray(parsed.nodes) && Array.isArray(parsed.edges)) {
          setNodes(parsed.nodes);
          setEdges(parsed.edges);
        }
        if (parsed.name) setWorkflowName(parsed.name);
        setWorkflowId(null);
        setStatusMsg('Сценарий загружен из localStorage.');
      } catch {
        setStatusMsg('Не удалось прочитать сценарий из localStorage.');
      }
      return;
    }

    try {
      const wf = await api.getWorkflow(id);
      const conv = fromBackendGraph(wf.graph_json, catalog);
      setNodes(conv.nodes);
      setEdges(conv.edges);
      setWorkflowId(wf.id);
      setWorkflowName(wf.name);
      setStatusMsg(`Загружен сценарий "${wf.name}".`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setStatusMsg(`Ошибка загрузки: ${msg}`);
    }
  };

  const applyTemplate = async (tpl: TemplateDto) => {
    try {
      const copied = await api.copyTemplate(tpl.id);
      const conv = fromBackendGraph(copied.graph_json, catalog);
      // If user already uploaded a zip in this session, inject upload_id
      if (lastUpload) {
        conv.nodes = conv.nodes.map((n) =>
          n.data.kind === 'source.upload_zip'
            ? { ...n, data: { ...n.data, params: { ...(n.data.params ?? {}), upload_id: lastUpload.id } } }
            : n,
        );
      }
      setNodes(conv.nodes);
      setEdges(conv.edges);
      setWorkflowId(copied.id);
      setWorkflowName(copied.name);
      const list = await api.listWorkflows().catch(() => workflows);
      setWorkflows(list);
      setStatusMsg(`Шаблон "${tpl.name}" скопирован и открыт.`);
    } catch {
      const conv = fromBackendGraph(tpl.graph_json, catalog);
      setNodes(conv.nodes);
      setEdges(conv.edges);
      setWorkflowId(null);
      setWorkflowName(tpl.name);
      setStatusMsg(`Шаблон "${tpl.name}" открыт локально.`);
    }
  };

  const validateBeforeRun = (): string | null => {
    if (nodes.length === 0) {
      return 'Схема пуста — добавьте блоки перед запуском.';
    }
    const hasTrigger = nodes.some((n) => n.data.kind.startsWith('trigger.'));
    if (!hasTrigger) {
      return 'Добавьте хотя бы один триггер (например, Manual Trigger).';
    }
    const missingZip = nodes.find(
      (n) => n.data.kind === 'source.upload_zip' && !String(n.data.params?.upload_id ?? '').trim(),
    );
    if (missingZip) {
      return `У блока "${missingZip.data.label}" не указан upload_id — загрузите .zip архив перед запуском.`;
    }
    return null;
  };

  const handleRun = async () => {
    const validationErr = validateBeforeRun();
    if (validationErr) {
      setStatusMsg(validationErr);
      return;
    }

    wsRef.current?.close();
    stopPolling();
    const saved = await saveWorkflow();
    if (!saved) {
      setStatusMsg('Запуск невозможен: не удалось сохранить workflow на backend.');
      return;
    }

    // Reset node visual statuses to pending
    setNodes((curr) =>
      curr.map((n) => ({
        ...n,
        data: { ...n.data, runStatus: 'pending', durationMs: undefined, outputPreview: null, error: null },
      })),
    );
    setWsEvents([]);
    setFindings([]);
    setReportMd('');
    setIsRunning(true);
    setPanelOpen(true);
    setStatusMsg('Запуск workflow…');

    try {
      const { run_id } = await api.runWorkflow(saved.id, false);
      setActiveRun({ id: run_id, workflow_id: saved.id, status: 'running', trigger: 'manual' });
      attachToRun(run_id);
    } catch (err) {
      setIsRunning(false);
      const msg = err instanceof Error ? err.message : String(err);
      setStatusMsg(`Ошибка запуска: ${msg}`);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', width: '100%', height: '100vh' }}>
      {/* Верхняя панель управления */}
      <header
        style={{
          height: 54,
          padding: '0 14px',
          background: '#0f172a',
          color: '#f8fafc',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 10,
          flexShrink: 0,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <strong style={{ fontSize: 15 }}>FloraByte · AI Security Workflow</strong>
          <input
            value={workflowName}
            onChange={(e) => setWorkflowName(e.target.value)}
            placeholder="Название сценария"
            style={{
              padding: '5px 8px',
              borderRadius: 6,
              border: '1px solid #334155',
              background: '#1e293b',
              color: '#fff',
              fontSize: 13,
              width: 190,
            }}
          />
          <select
            value={workflowId ?? ''}
            onChange={(e) => void loadWorkflowById(e.target.value)}
            style={{
              padding: '5px 8px',
              borderRadius: 6,
              border: '1px solid #334155',
              background: '#1e293b',
              color: '#fff',
              fontSize: 12,
              maxWidth: 190,
            }}
          >
            <option value="">localStorage (запасной)</option>
            {workflows.map((wf) => (
              <option key={wf.id} value={wf.id}>
                {wf.name}
              </option>
            ))}
          </select>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <label
            style={{
              padding: '7px 12px',
              background: '#0284c7',
              color: '#fff',
              borderRadius: 7,
              cursor: 'pointer',
              fontSize: 12,
              fontWeight: 600,
            }}
          >
            {lastUpload ? `ZIP: ${lastUpload.filename}` : 'Загрузить ZIP'}
            <input
              type="file"
              accept=".zip"
              style={{ display: 'none' }}
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) void handleUploadZip(f);
                e.target.value = '';
              }}
            />
          </label>

          <button
            onClick={() => void saveWorkflow()}
            style={{
              padding: '7px 12px',
              background: '#059669',
              color: '#fff',
              border: 'none',
              borderRadius: 7,
              cursor: 'pointer',
              fontSize: 12,
              fontWeight: 600,
            }}
          >
            Сохранить
          </button>

          <button
            onClick={() => void loadWorkflowById(workflowId ?? '')}
            style={{
              padding: '7px 12px',
              background: '#2563eb',
              color: '#fff',
              border: 'none',
              borderRadius: 7,
              cursor: 'pointer',
              fontSize: 12,
              fontWeight: 600,
            }}
          >
            Загрузить
          </button>

          <button
            onClick={() => void handleRun()}
            disabled={isRunning}
            style={{
              padding: '7px 14px',
              background: isRunning ? '#94a3b8' : '#f59e0b',
              color: '#0f172a',
              border: 'none',
              borderRadius: 7,
              cursor: isRunning ? 'wait' : 'pointer',
              fontSize: 12,
              fontWeight: 700,
            }}
          >
            {isRunning ? 'Выполняется…' : '▶ Run'}
          </button>

          <button
            onClick={() => void deleteSelected()}
            style={{
              padding: '7px 11px',
              background: '#dc2626',
              color: '#fff',
              border: 'none',
              borderRadius: 7,
              cursor: 'pointer',
              fontSize: 12,
              fontWeight: 600,
            }}
          >
            Удалить
          </button>
        </div>
      </header>

      {statusMsg && (
        <div
          style={{
            padding: '5px 14px',
            background: '#eff6ff',
            borderBottom: '1px solid #bfdbfe',
            fontSize: 12,
            color: '#1e3a8a',
            display: 'flex',
            justifyContent: 'space-between',
          }}
        >
          <span>{statusMsg}</span>
          <button
            onClick={() => setStatusMsg('')}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#1e3a8a' }}
          >
            ✕
          </button>
        </div>
      )}

      {/* Основная рабочая область */}
      <div style={{ display: 'flex', flex: 1, minHeight: 0 }}>
        <NodeSidebar
          catalog={catalog}
          catalogSource={catalogSource}
          templates={templates}
          onAddNode={addNode}
          onApplyTemplate={applyTemplate}
        />

        <div style={{ flex: 1, minWidth: 0, position: 'relative' }}>
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

        <NodeSettings
          key={selectedNode?.id ?? 'none'}
          selectedNode={selectedNode}
          nodeSpec={selectedNode ? specByType.get(selectedNode.data.kind) : undefined}
          credentials={credentials}
          onSave={saveNodeSettings}
          onUploadZip={handleUploadZip}
          onCreateCredential={handleCreateCredential}
        />
      </div>

      <ReportPanel
        run={activeRun}
        findings={findings}
        reportMd={reportMd}
        events={wsEvents}
        isOpen={panelOpen}
        onToggle={() => setPanelOpen((o) => !o)}
      />
    </div>
  );
}

export default function WorkflowEditor() {
  return (
    <ReactFlowProvider>
      <WorkflowEditorContent />
    </ReactFlowProvider>
  );
}
