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
import IntegrationsModal from './IntegrationsModal';
import SettingsModal from './SettingsModal';
import CustomNodesModal from './CustomNodesModal';
import TemplatesModal from './TemplatesModal';
import { fallbackNodeCatalog } from '../config/nodeCatalog';
import * as api from '../api/client';
import { connectionError, safeGraphForLocalStorage } from '../utils/graphValidation';
import { useBreakpoint } from '../hooks/useMediaQuery';
import type {
  AuthUserDto,
  BackendGraph,
  CredentialDto,
  FindingDto,
  IntegrationsDto,
  NodeRunStatus,
  NodeTypeSpec,
  RunDto,
  TemplateDto,
  WorkflowDto,
  WsRunEvent,
} from '../types/workflow';

const DEFAULT_INTEGRATIONS: IntegrationsDto = {
  ai: {
    configured: false,
    enabled: false,
    source: 'none',
    provider: 'gemini',
    model: 'gemini-2.5-flash',
    base_url: '',
    api_key_preview: '',
  },
  telegram: {
    configured: false,
    enabled: false,
    auto_send: true,
    source: 'none',
    chat_id: '',
    bot_token_preview: '',
    bot_username: '',
    verified: false,
  },
  email: {
    configured: false,
    enabled: false,
    source: 'none',
    transport: 'resend',
    smtp_host: '',
    smtp_port: 587,
    smtp_user: '',
    from_email: '',
    default_to: '',
    use_tls: true,
    secret_preview: '',
  },
};

const STORAGE_KEY = 'florabyte-workflow';
const ACTIVE_RUN_KEY = 'florabyte-active-run-id';
const PALETTE_OPEN_KEY = 'florabyte-palette-open';
const NODE_PANEL_OPEN_KEY = 'florabyte-node-panel-open';
const TERMINAL_RUN_STATUSES = new Set(['success', 'failed', 'partial']);
const MAX_ZIP_NAME_CHARS = 22;

function formatZipLabel(filename: string): string {
  const chars = Array.from(filename);
  if (chars.length <= MAX_ZIP_NAME_CHARS) {
    return `ZIP: ${filename}`;
  }
  const dotIdx = filename.lastIndexOf('.');
  if (dotIdx > 0 && filename.length - dotIdx <= 6) {
    const ext = filename.slice(dotIdx);
    const baseChars = Array.from(filename.slice(0, dotIdx));
    const keepStart = Math.max(6, MAX_ZIP_NAME_CHARS - Array.from(ext).length - 1);
    return `ZIP: ${baseChars.slice(0, keepStart).join('')}…${ext}`;
  }
  return `ZIP: ${chars.slice(0, MAX_ZIP_NAME_CHARS - 1).join('')}…`;
}

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

function buildSmartPipelineNodes(
  catalog: NodeTypeSpec[],
  uploadId = '',
  integrations: IntegrationsDto = DEFAULT_INTEGRATIONS,
): { nodes: SecurityNodeType[]; edges: Edge[] } {
  const includeAi = integrations.ai.configured;
  const includeTelegram = integrations.telegram.configured && integrations.telegram.auto_send;

  const nodes: BackendGraph['nodes'] = [
    { id: 't1', type: 'trigger.manual', params: {}, position: { x: 40, y: 180 } },
    { id: 's1', type: 'source.upload_zip', params: { upload_id: uploadId }, position: { x: 220, y: 180 } },
    { id: 'sc1', type: 'scanner.secrets', params: {}, position: { x: 420, y: 60 } },
    { id: 'sc2', type: 'scanner.sca', params: {}, position: { x: 420, y: 180 } },
    { id: 'sc3', type: 'scanner.sast', params: {}, position: { x: 420, y: 300 } },
    { id: 'm1', type: 'findings.merge', params: {}, position: { x: 630, y: 180 } },
  ];
  const edges: BackendGraph['edges'] = [
    { id: 'e1', source: 't1', target: 's1' },
    { id: 'e2', source: 's1', target: 'sc1' },
    { id: 'e3', source: 's1', target: 'sc2' },
    { id: 'e4', source: 's1', target: 'sc3' },
    { id: 'e5', source: 'sc1', target: 'm1', targetHandle: 'a' },
    { id: 'e6', source: 'sc2', target: 'm1', targetHandle: 'b' },
    { id: 'e7', source: 'sc3', target: 'm1', targetHandle: 'c' },
  ];

  let nextX = 830;
  let prevId = 'm1';
  let prevHandle: string | null = 'findings';

  if (includeAi) {
    nodes.push({ id: 'ai1', type: 'ai.explain', params: {}, position: { x: nextX, y: 180 } });
    edges.push({
      id: 'e-ai',
      source: prevId,
      sourceHandle: prevHandle,
      target: 'ai1',
      targetHandle: 'findings',
    });
    prevId = 'ai1';
    prevHandle = 'report';
    nextX += 200;
  }

  nodes.push({ id: 'e1', type: 'findings.export', params: {}, position: { x: nextX, y: 180 } });
  edges.push({
    id: 'e-export',
    source: prevId,
    sourceHandle: prevHandle,
    target: 'e1',
    targetHandle: includeAi ? 'report' : 'findings',
  });
  nextX += 200;

  if (includeTelegram) {
    nodes.push({ id: 'tg1', type: 'notify.telegram', params: {}, position: { x: nextX, y: 180 } });
    edges.push({
      id: 'e-tg',
      source: 'e1',
      sourceHandle: 'report',
      target: 'tg1',
      targetHandle: 'report',
    });
  }

  return fromBackendGraph({ nodes, edges }, catalog);
}

function buildStarterNodes(catalog: NodeTypeSpec[]): { nodes: SecurityNodeType[]; edges: Edge[] } {
  return buildSmartPipelineNodes(catalog, '', DEFAULT_INTEGRATIONS);
}

type WorkflowEditorProps = {
  user: AuthUserDto;
  onLogout: () => void;
};

function WorkflowEditorContent({ user, onLogout }: WorkflowEditorProps) {
  const [catalog, setCatalog] = useState<NodeTypeSpec[]>(fallbackNodeCatalog);
  const [catalogSource, setCatalogSource] = useState<'api' | 'fallback'>('fallback');
  const [templates, setTemplates] = useState<TemplateDto[]>([]);
  const [workflows, setWorkflows] = useState<WorkflowDto[]>([]);
  const [credentials, setCredentials] = useState<CredentialDto[]>([]);
  const [integrations, setIntegrations] = useState<IntegrationsDto>(DEFAULT_INTEGRATIONS);
  const [integrationsOpen, setIntegrationsOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [customNodesOpen, setCustomNodesOpen] = useState(false);
  const [templatesOpen, setTemplatesOpen] = useState(false);
  const [publishOpen, setPublishOpen] = useState(false);
  const [publishName, setPublishName] = useState('');
  const [publishDesc, setPublishDesc] = useState('');
  const [publishVis, setPublishVis] = useState<'private' | 'public'>('private');
  const [publishBusy, setPublishBusy] = useState(false);
  const [publishErr, setPublishErr] = useState('');

  const [workflowId, setWorkflowId] = useState<string | null>(null);
  const [workflowName, setWorkflowName] = useState<string>('Security Workflow');
  const [deletingWorkflow, setDeletingWorkflow] = useState(false);
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
  const [runsHistory, setRunsHistory] = useState<RunDto[]>([]);
  const [panelOpen, setPanelOpen] = useState(false);

  const breakpoint = useBreakpoint();
  const isMobile = breakpoint === 'mobile';
  const isTablet = breakpoint === 'tablet';
  const [mobileTab, setMobileTab] = useState<'canvas' | 'palette' | 'settings' | 'report'>('canvas');
  const [tabletDrawer, setTabletDrawer] = useState<'none' | 'palette' | 'settings'>('none');
  const [moreMenuOpen, setMoreMenuOpen] = useState(false);

  const [paletteOpen, setPaletteOpen] = useState<boolean>(() => {
    try {
      return localStorage.getItem(PALETTE_OPEN_KEY) !== 'false';
    } catch {
      return true;
    }
  });
  const [nodePanelOpen, setNodePanelOpen] = useState<boolean>(() => {
    try {
      return localStorage.getItem(NODE_PANEL_OPEN_KEY) !== 'false';
    } catch {
      return true;
    }
  });

  const togglePalette = useCallback(() => {
    setPaletteOpen((prev) => {
      const next = !prev;
      try {
        localStorage.setItem(PALETTE_OPEN_KEY, String(next));
      } catch {
        // ignore storage errors
      }
      return next;
    });
  }, []);

  const toggleNodePanel = useCallback(() => {
    setNodePanelOpen((prev) => {
      const next = !prev;
      try {
        localStorage.setItem(NODE_PANEL_OPEN_KEY, String(next));
      } catch {
        // ignore storage errors
      }
      return next;
    });
  }, []);

  const openNodePanel = useCallback(() => {
    if (isMobile) {
      setMobileTab('settings');
      return;
    }
    if (isTablet) {
      setTabletDrawer('settings');
      return;
    }
    setNodePanelOpen(true);
    try {
      localStorage.setItem(NODE_PANEL_OPEN_KEY, 'true');
    } catch {
      // ignore storage errors
    }
  }, [isMobile, isTablet]);

  const wsRef = useRef<WebSocket | null>(null);
  const pollTimerRef = useRef<number | null>(null);
  const { deleteElements, screenToFlowPosition, fitView } = useReactFlow();

  const switchMobileTab = useCallback(
    (tab: 'canvas' | 'palette' | 'settings' | 'report') => {
      setMobileTab(tab);
      setMoreMenuOpen(false);
      if (tab === 'canvas') {
        requestAnimationFrame(() => {
          void fitView({ padding: 0.2, duration: 220 });
        });
      }
    },
    [fitView],
  );

  const stopPolling = useCallback(() => {
    if (pollTimerRef.current !== null) {
      window.clearInterval(pollTimerRef.current);
      pollTimerRef.current = null;
    }
  }, []);

  const specByType = useMemo(() => new Map(catalog.map((c) => [c.type, c])), [catalog]);
  const selectedNode = nodes.find((node) => node.selected) ?? null;

  const refreshRunsHistory = useCallback(async () => {
    const list = await api.listRuns(20).catch(() => []);
    setRunsHistory(list);
  }, []);

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
        void refreshRunsHistory();
      }
      return runDetails;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setStatusMsg(`Не удалось загрузить результаты запуска: ${msg}`);
      return null;
    }
  }, [refreshRunsHistory, setNodes, stopPolling]);

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

  const starterCount = starter.nodes.length;
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [nodeTypesRes, tpls, wfs, creds, hist, integ] = await Promise.all([
          api.fetchNodeTypes(),
          api.listTemplates().catch(() => []),
          api.listWorkflows().catch(() => []),
          api.listCredentials().catch(() => []),
          api.listRuns(20).catch(() => []),
          api.getIntegrations().catch(() => DEFAULT_INTEGRATIONS),
        ]);
        if (cancelled) return;
        setIntegrations(integ);
        if (nodeTypesRes.length > 0) {
          setCatalog(nodeTypesRes);
          setCatalogSource('api');
          const freshStarter = buildSmartPipelineNodes(nodeTypesRes, '', integ);
          setNodes((curr) => (curr.length === starterCount ? freshStarter.nodes : curr));
          setEdges((curr) => (curr.length === starter.edges.length ? freshStarter.edges : curr));
        }
        setTemplates(tpls);
        setWorkflows(wfs);
        setCredentials(creds);
        setRunsHistory(hist);

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
  }, [attachToRun, setEdges, setNodes, starter.edges.length, starterCount, stopPolling, syncRunState]);

  const onConnect = useCallback(
    (connection: Connection) => {
      const error = connectionError(connection, nodes, edges);
      if (error) {
        setStatusMsg(error);
        return;
      }
      setEdges((currentEdges) => addEdge(connection, currentEdges));
    },
    [setEdges, nodes, edges],
  );

  const addNode = useCallback(
    (spec: NodeTypeSpec, position?: { x: number; y: number }) => {
      const newNode: SecurityNodeType = {
        id: `n-${crypto.randomUUID().slice(0, 8)}`,
        type: 'security',
        position: position ?? {
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
      if (isMobile) {
        setMobileTab('canvas');
        requestAnimationFrame(() => {
          void fitView({ padding: 0.2, duration: 220 });
        });
      } else if (isTablet) {
        setTabletDrawer('none');
      }
    },
    [fitView, isMobile, isTablet, setNodes],
  );

  const onCanvasDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
  }, []);

  const onCanvasDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      const nodeType = e.dataTransfer.getData('application/florabyte-node');
      if (!nodeType) return;
      const spec = specByType.get(nodeType);
      if (!spec) return;
      const pos = screenToFlowPosition({ x: e.clientX, y: e.clientY });
      addNode(spec, { x: Math.round(pos.x), y: Math.round(pos.y) });
    },
    [addNode, screenToFlowPosition, specByType],
  );

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
      const freshInteg = await api.getIntegrations().catch(() => integrations);
      setIntegrations(freshInteg);
      const built = buildSmartPipelineNodes(catalog, res.upload_id, freshInteg);
      setNodes(built.nodes);
      setEdges(built.edges);
      setWorkflowId(null);

      const missing: string[] = [];
      if (!freshInteg.ai.configured) missing.push('AI');
      if (!freshInteg.telegram.configured) missing.push('Telegram');
      const missingNote =
        missing.length > 0
          ? ` Для автоматического подключения ${missing.join(' и ')} настройте их один раз в «Интеграции».`
          : ' AI и Telegram подключены автоматически!';
      setStatusMsg(`ZIP загружен (${res.filename}), готов сценарий проверки.${missingNote}`);
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
    // Local fallback contains NO tokens, secrets or Authorization headers.
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({
        name: workflowName,
        graph_json: safeGraphForLocalStorage(graph),
      }));
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
      const schedWarnings = saved.schedule_warnings ?? [];
      const schedEntries = saved.schedule_summary ?? [];
      const schedDesc = schedEntries
        .map((s) => (s.cron ? `cron=${s.cron}` : `interval=${s.interval_seconds}s`))
        .join(', ');
      if (schedWarnings.length > 0 && (saved.scheduled_jobs ?? 0) === 0) {
        setStatusMsg(`⚠️ Сценарий "${saved.name}" сохранён, но расписание не активно: ${schedWarnings.join(' ')}`);
      } else if (schedWarnings.length > 0 && (saved.scheduled_jobs ?? 0) > 0) {
        setStatusMsg(
          `✅ Сценарий "${saved.name}" сохранён. Schedule зарегистрирован (${schedDesc}). ⚠️ ${schedWarnings.join(' ')}`,
        );
      } else if ((saved.scheduled_jobs ?? 0) > 0) {
        setStatusMsg(`✅ Сценарий "${saved.name}" сохранён. Schedule зарегистрирован (${schedDesc}).`);
      } else {
        setStatusMsg(`Сценарий "${saved.name}" сохранён на сервере (и в localStorage).`);
      }
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
          const sanitized = safeGraphForLocalStorage(toBackendGraph(parsed.nodes, parsed.edges));
          const conv = fromBackendGraph(sanitized, catalog);
          setNodes(conv.nodes);
          setEdges(conv.edges);
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

  const handleDeleteWorkflow = async () => {
    if (!workflowId) {
      setStatusMsg('Выберите сценарий на сервере (не localStorage).');
      return;
    }
    const targetId = workflowId;
    const confirmed = window.confirm(
      `Удалить сценарий «${workflowName}»? Расписание тоже будет остановлено.`,
    );
    if (!confirmed) return;

    setDeletingWorkflow(true);
    try {
      await api.deleteWorkflow(targetId);
      const list = await api
        .listWorkflows()
        .catch(() => workflows.filter((wf) => wf.id !== targetId));
      setWorkflows(list);

      if (activeRun?.workflow_id === targetId) {
        wsRef.current?.close();
        stopPolling();
        sessionStorage.removeItem(ACTIVE_RUN_KEY);
        setIsRunning(false);
        setActiveRun(null);
        setFindings([]);
        setReportMd('');
        setWsEvents([]);
      }

      const freshStarter = buildSmartPipelineNodes(catalog, lastUpload?.id ?? '', integrations);
      setNodes(freshStarter.nodes);
      setEdges(freshStarter.edges);
      setWorkflowId(null);
      setWorkflowName('Security Workflow');
      void refreshRunsHistory();
      setStatusMsg('Сценарий удалён.');
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setStatusMsg(`Ошибка удаления сценария: ${msg}`);
      const list = await api.listWorkflows().catch(() => null);
      if (list) setWorkflows(list);
    } finally {
      setDeletingWorkflow(false);
    }
  };

  const applyCopiedWorkflow = async (copied: WorkflowDto) => {
    const conv = fromBackendGraph(copied.graph_json, catalog);
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
    setStatusMsg(`Шаблон скопирован в ваш сценарий «${copied.name}».`);
    if (isMobile) setMobileTab('canvas');
  };

  const openPublishDialog = () => {
    setPublishName(workflowName || 'Мой шаблон');
    setPublishDesc('');
    setPublishVis('private');
    setPublishErr('');
    setPublishOpen(true);
  };

  const handlePublishTemplate = async () => {
    const name = publishName.trim();
    if (!name) {
      setPublishErr('Введите название шаблона.');
      return;
    }
    setPublishBusy(true);
    setPublishErr('');
    try {
      const saved = await saveWorkflow();
      if (!saved) {
        setPublishErr('Не удалось сохранить сценарий на сервере перед публикацией.');
        return;
      }
      const created = await api.publishTemplate({
        workflow_id: saved.id,
        name,
        description: publishDesc.trim(),
        visibility: publishVis,
      });
      const freshTemplates = await api.listTemplates().catch(() => templates);
      setTemplates(freshTemplates);
      setPublishOpen(false);
      setStatusMsg(
        `✅ Шаблон «${created.name}» опубликован (${created.visibility === 'public' ? 'виден всем' : 'только для вас'}).`,
      );
    } catch (err) {
      setPublishErr(err instanceof Error ? err.message : String(err));
    } finally {
      setPublishBusy(false);
    }
  };

  const handleGenerateWorkflow = async (prompt: string) => {
    try {
      const gen = await api.generateAiWorkflow(prompt);
      const conv = fromBackendGraph(gen.graph, catalog);
      if (lastUpload) {
        conv.nodes = conv.nodes.map((n) =>
          n.data.kind === 'source.upload_zip'
            ? { ...n, data: { ...n.data, params: { ...(n.data.params ?? {}), upload_id: lastUpload.id } } }
            : n,
        );
      }
      setNodes(conv.nodes);
      setEdges(conv.edges);
      setWorkflowId(null);
      setWorkflowName(gen.name || 'AI Workflow');
      const modeLabel = gen.mode === 'llm' ? `LLM (${gen.provider || 'AI'})` : 'интеллектуальный разбор';
      setStatusMsg(
        `Сценарий создан (${modeLabel})${gen.summary ? `: ${gen.summary}` : '.'}`,
      );
      if (isMobile) setMobileTab('canvas');
      requestAnimationFrame(() => {
        void fitView({ padding: 0.2, duration: 300 });
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setStatusMsg(`Ошибка генерации сценария: ${msg}`);
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
      if (isMobile) setMobileTab('canvas');
      else if (isTablet) setTabletDrawer('none');
    } catch {
      const conv = fromBackendGraph(tpl.graph_json, catalog);
      setNodes(conv.nodes);
      setEdges(conv.edges);
      setWorkflowId(null);
      setWorkflowName(tpl.name);
      setStatusMsg(`Шаблон "${tpl.name}" открыт локально.`);
      if (isMobile) setMobileTab('canvas');
      else if (isTablet) setTabletDrawer('none');
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
    const unconfiguredTg = nodes.find(
      (n) =>
        n.data.kind === 'notify.telegram' &&
        !n.data.params?.dry_run &&
        !String(n.data.params?.credential_id ?? '').trim() &&
        !integrations.telegram.configured,
    );
    if (unconfiguredTg) {
      return 'Блок Telegram на схеме не настроен: задайте Bot Token и chat_id один раз в разделе «Интеграции» (или удалите блок).';
    }
    const unconfiguredEmail = nodes.find(
      (n) =>
        n.data.kind === 'notify.email' &&
        !n.data.params?.dry_run &&
        !integrations.email?.configured &&
        !String(n.data.params?.credential_id ?? '').trim(),
    );
    if (unconfiguredEmail) {
      return 'Блок Email не настроен: откройте «Интеграции → Email-уведомления» (Resend API или SMTP) и сохраните настройки отправки.';
    }
    const missingToEmail = nodes.find(
      (n) =>
        n.data.kind === 'notify.email' &&
        !n.data.params?.dry_run &&
        !String(n.data.params?.to_email ?? '').trim() &&
        !String(integrations.email?.default_to ?? '').trim(),
    );
    if (missingToEmail) {
      return 'У блока Email не указан адрес получателя (to_email). Укажите email в параметрах блока или в «Интеграции → Email».';
    }
    // Mirror the backend validation so invalid graphs are rejected before saving.
    for (const edge of edges) {
      const withoutEdge = edges.filter((e) => e.id !== edge.id);
      const error = connectionError({
        source: edge.source, target: edge.target,
        sourceHandle: edge.sourceHandle ?? null,
        targetHandle: edge.targetHandle ?? null,
      }, nodes, withoutEdge);
      if (error) return `Ошибка соединения ${edge.id}: ${error}`;
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
    if (isMobile) setMobileTab('report');
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
    <div className="fb-editor-root">
      {/* Верхняя панель управления */}
      {isMobile ? (
        <header
          style={{
            padding: '8px 10px',
            background: '#0f172a',
            color: '#f8fafc',
            display: 'flex',
            flexDirection: 'column',
            gap: 8,
            flexShrink: 0,
            position: 'relative',
            zIndex: 40,
          }}
        >
          {/* Строка 1: бренд, статус, выбор сценария, меню «Ещё» */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%' }}>
            <strong style={{ fontSize: 15, flexShrink: 0 }}>FloraByte</strong>
            <span
              title={`Вход выполнен как ${user.email}`}
              style={{
                padding: '2px 7px',
                borderRadius: 999,
                background: '#064e3b',
                color: '#6ee7b7',
                border: '1px solid #047857',
                fontSize: 11,
                fontWeight: 700,
                flexShrink: 0,
              }}
            >
              ●
            </span>
            <select
              aria-label="Выбор сценария"
              value={workflowId ?? ''}
              onChange={(e) => void loadWorkflowById(e.target.value)}
              style={{
                flex: 1,
                minWidth: 0,
                minHeight: 38,
                padding: '6px 8px',
                borderRadius: 6,
                border: '1px solid #334155',
                background: '#1e293b',
                color: '#fff',
                fontSize: 13,
              }}
            >
              <option value="">localStorage (черновик)</option>
              {workflows.map((wf) => (
                <option key={wf.id} value={wf.id}>
                  {wf.name}
                </option>
              ))}
            </select>
            <button
              type="button"
              onClick={() => setMoreMenuOpen((v) => !v)}
              aria-expanded={moreMenuOpen}
              style={{
                minHeight: 38,
                padding: '6px 10px',
                borderRadius: 7,
                border: '1px solid #475569',
                background: moreMenuOpen ? '#334155' : '#1e293b',
                color: '#f8fafc',
                fontSize: 13,
                fontWeight: 700,
                cursor: 'pointer',
                flexShrink: 0,
              }}
            >
              ⋯ Ещё
            </button>
          </div>

          {/* Строка 2: основные быстрые действия (Save, Run, + Блок) */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%' }}>
            <button
              type="button"
              onClick={() => void saveWorkflow()}
              style={{
                flex: 1,
                minHeight: 40,
                padding: '8px 10px',
                background: '#059669',
                color: '#fff',
                border: 'none',
                borderRadius: 7,
                cursor: 'pointer',
                fontSize: 13,
                fontWeight: 700,
              }}
            >
              Сохранить
            </button>
            <button
              type="button"
              onClick={() => void handleRun()}
              disabled={isRunning}
              style={{
                flex: 1,
                minHeight: 40,
                padding: '8px 10px',
                background: isRunning ? '#94a3b8' : '#f59e0b',
                color: '#0f172a',
                border: 'none',
                borderRadius: 7,
                cursor: isRunning ? 'wait' : 'pointer',
                fontSize: 13,
                fontWeight: 700,
              }}
            >
              {isRunning ? 'Выполняется…' : '▶ Run'}
            </button>
            <button
              type="button"
              onClick={() => switchMobileTab('palette')}
              style={{
                minHeight: 40,
                padding: '8px 12px',
                background: '#2563eb',
                color: '#fff',
                border: 'none',
                borderRadius: 7,
                cursor: 'pointer',
                fontSize: 13,
                fontWeight: 700,
                flexShrink: 0,
              }}
            >
              + Блок
            </button>
          </div>

          {/* Overflow-меню «Ещё» */}
          {moreMenuOpen && (
            <>
              <div
                onClick={() => setMoreMenuOpen(false)}
                style={{
                  position: 'fixed',
                  inset: 0,
                  background: 'rgba(15, 23, 42, 0.45)',
                  zIndex: 48,
                }}
              />
              <div
                style={{
                  position: 'fixed',
                  top: 98,
                  left: 10,
                  right: 10,
                  maxHeight: '72vh',
                  overflowY: 'auto',
                  background: '#1e293b',
                  border: '1px solid #475569',
                  borderRadius: 10,
                  padding: 12,
                  boxShadow: '0 18px 40px rgba(0,0,0,0.45)',
                  zIndex: 49,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 8,
                }}
              >
                <label style={{ fontSize: 12, color: '#cbd5e1', fontWeight: 600 }}>
                  Название сценария
                  <input
                    value={workflowName}
                    onChange={(e) => setWorkflowName(e.target.value)}
                    placeholder="Название сценария"
                    style={{
                      width: '100%',
                      marginTop: 4,
                      padding: '8px 10px',
                      borderRadius: 6,
                      border: '1px solid #475569',
                      background: '#0f172a',
                      color: '#fff',
                      fontSize: 14,
                    }}
                  />
                </label>

                <label
                  style={{
                    minHeight: 40,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    padding: '8px 12px',
                    background: '#0284c7',
                    color: '#fff',
                    borderRadius: 7,
                    cursor: 'pointer',
                    fontSize: 13,
                    fontWeight: 600,
                  }}
                >
                  {lastUpload ? `ZIP: ${formatZipLabel(lastUpload.filename)}` : 'Загрузить ZIP'}
                  <input
                    type="file"
                    accept=".zip"
                    style={{ display: 'none' }}
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      setMoreMenuOpen(false);
                      if (f) void handleUploadZip(f);
                      e.target.value = '';
                    }}
                  />
                </label>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                  <button
                    type="button"
                    onClick={() => {
                      setMoreMenuOpen(false);
                      setTemplatesOpen(true);
                    }}
                    style={{
                      minHeight: 40,
                      padding: '8px 10px',
                      background: '#4338ca',
                      color: '#fff',
                      border: 'none',
                      borderRadius: 7,
                      fontSize: 13,
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    Шаблоны
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setMoreMenuOpen(false);
                      openPublishDialog();
                    }}
                    style={{
                      minHeight: 40,
                      padding: '8px 10px',
                      background: '#0d9488',
                      color: '#fff',
                      border: 'none',
                      borderRadius: 7,
                      fontSize: 13,
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    Опубликовать
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setMoreMenuOpen(false);
                      setIntegrationsOpen(true);
                    }}
                    style={{
                      minHeight: 40,
                      padding: '8px 10px',
                      background: '#4f46e5',
                      color: '#fff',
                      border: 'none',
                      borderRadius: 7,
                      fontSize: 12,
                      fontWeight: 700,
                      cursor: 'pointer',
                    }}
                  >
                    Интеграции ({integrations.ai.configured ? 'AI ✓' : 'AI –'} · {integrations.telegram.configured ? 'TG ✓' : 'TG –'})
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setMoreMenuOpen(false);
                      setCustomNodesOpen(true);
                    }}
                    style={{
                      minHeight: 40,
                      padding: '8px 10px',
                      background: '#7c3aed',
                      color: '#fff',
                      border: 'none',
                      borderRadius: 7,
                      fontSize: 13,
                      fontWeight: 700,
                      cursor: 'pointer',
                    }}
                  >
                    Мои ноды
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setMoreMenuOpen(false);
                      setSettingsOpen(true);
                    }}
                    style={{
                      minHeight: 40,
                      padding: '8px 10px',
                      background: '#334155',
                      color: '#fff',
                      border: 'none',
                      borderRadius: 7,
                      fontSize: 13,
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    Настройки
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setMoreMenuOpen(false);
                      void loadWorkflowById(workflowId ?? '');
                    }}
                    style={{
                      minHeight: 40,
                      padding: '8px 10px',
                      background: '#2563eb',
                      color: '#fff',
                      border: 'none',
                      borderRadius: 7,
                      fontSize: 13,
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    Перезагрузить
                  </button>
                </div>

                <div style={{ display: 'flex', gap: 8 }}>
                  <button
                    type="button"
                    onClick={() => {
                      setMoreMenuOpen(false);
                      void deleteSelected();
                    }}
                    style={{
                      flex: 1,
                      minHeight: 40,
                      padding: '8px 10px',
                      background: '#dc2626',
                      color: '#fff',
                      border: 'none',
                      borderRadius: 7,
                      fontSize: 12,
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    Удалить блок
                  </button>
                  <button
                    type="button"
                    disabled={!workflowId || deletingWorkflow}
                    onClick={() => {
                      setMoreMenuOpen(false);
                      void handleDeleteWorkflow();
                    }}
                    style={{
                      flex: 1,
                      minHeight: 40,
                      padding: '8px 10px',
                      borderRadius: 7,
                      border: '1px solid #991b1b',
                      background: !workflowId || deletingWorkflow ? '#0f172a' : '#7f1d1d',
                      color: !workflowId || deletingWorkflow ? '#64748b' : '#fecaca',
                      fontSize: 12,
                      fontWeight: 600,
                      cursor: !workflowId || deletingWorkflow ? 'not-allowed' : 'pointer',
                    }}
                  >
                    Удалить сценарий
                  </button>
                </div>

                <button
                  type="button"
                  onClick={() => {
                    setMoreMenuOpen(false);
                    onLogout();
                  }}
                  style={{
                    minHeight: 40,
                    padding: '8px 12px',
                    background: '#0f172a',
                    color: '#fca5a5',
                    border: '1px solid #475569',
                    borderRadius: 7,
                    fontSize: 13,
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  Выйти из аккаунта ({user.email})
                </button>
              </div>
            </>
          )}
        </header>
      ) : (
        <header
          style={{
            minHeight: 54,
            padding: '6px 14px',
            background: '#0f172a',
            color: '#f8fafc',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 10,
            flexWrap: 'wrap',
            flexShrink: 0,
          }}
        >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <strong style={{ fontSize: 15 }}>FloraByte</strong>
          <span
            title={`Вход выполнен как ${user.email}`}
            style={{
              padding: '3px 8px',
              borderRadius: 999,
              background: '#064e3b',
              color: '#6ee7b7',
              border: '1px solid #047857',
              fontSize: 11,
              fontWeight: 700,
              whiteSpace: 'nowrap',
            }}
          >
            ● Авторизован
          </span>
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
              width: 175,
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
              maxWidth: 175,
            }}
          >
            <option value="">localStorage (запасной)</option>
            {workflows.map((wf) => (
              <option key={wf.id} value={wf.id}>
                {wf.name}
              </option>
            ))}
          </select>

          <button
            type="button"
            onClick={() => void handleDeleteWorkflow()}
            disabled={!workflowId || deletingWorkflow}
            title={
              workflowId
                ? `Удалить сценарий «${workflowName}» с сервера`
                : 'Выберите сценарий на сервере (не localStorage)'
            }
            style={{
              padding: '5px 10px',
              borderRadius: 6,
              border: '1px solid #991b1b',
              background: !workflowId || deletingWorkflow ? '#1e293b' : '#7f1d1d',
              color: !workflowId || deletingWorkflow ? '#64748b' : '#fecaca',
              cursor: !workflowId || deletingWorkflow ? 'not-allowed' : 'pointer',
              fontSize: 12,
              fontWeight: 600,
              whiteSpace: 'nowrap',
            }}
          >
            {deletingWorkflow ? 'Удаление…' : 'Удалить сценарий'}
          </button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <label
            title={lastUpload ? lastUpload.filename : 'Загрузить .zip архив'}
            style={{
              display: 'inline-block',
              maxWidth: 'min(210px, 48vw)',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              padding: '7px 12px',
              background: '#0284c7',
              color: '#fff',
              borderRadius: 7,
              cursor: 'pointer',
              fontSize: 12,
              fontWeight: 600,
              flexShrink: 0,
            }}
          >
            {lastUpload ? formatZipLabel(lastUpload.filename) : 'Загрузить ZIP'}
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
            type="button"
            onClick={() => setSettingsOpen(true)}
            style={{
              padding: '7px 11px',
              background: '#334155',
              color: '#fff',
              border: 'none',
              borderRadius: 7,
              cursor: 'pointer',
              fontSize: 12,
              fontWeight: 600,
            }}
            title={`Настройки аккаунта (${user.email})`}
          >
            Настройки
          </button>

          <button
            type="button"
            onClick={() => setIntegrationsOpen(true)}
            style={{
              padding: '7px 11px',
              background: '#4f46e5',
              color: '#fff',
              border: 'none',
              borderRadius: 7,
              cursor: 'pointer',
              fontSize: 12,
              fontWeight: 700,
            }}
            title="Настроить AI и Telegram один раз для всех сценариев"
          >
            Интеграции ({integrations.ai.configured ? 'AI ✓' : 'AI –'} · {integrations.telegram.configured ? 'TG ✓' : 'TG –'})
          </button>

          <button
            type="button"
            onClick={() => setCustomNodesOpen(true)}
            style={{
              padding: '7px 12px',
              background: '#7c3aed',
              color: '#fff',
              border: 'none',
              borderRadius: 7,
              cursor: 'pointer',
              fontSize: 12,
              fontWeight: 700,
            }}
            title="Создать и управлять собственными нодами"
          >
            Мои ноды
          </button>

          <button
            type="button"
            onClick={() => setTemplatesOpen(true)}
            style={{
              padding: '7px 11px',
              background: '#4338ca',
              color: '#fff',
              border: 'none',
              borderRadius: 7,
              cursor: 'pointer',
              fontSize: 12,
              fontWeight: 600,
            }}
            title="Открыть библиотеку шаблонов (Системные / Публичные / Мои)"
          >
            Шаблоны
          </button>

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
            type="button"
            onClick={openPublishDialog}
            style={{
              padding: '7px 11px',
              background: '#0d9488',
              color: '#fff',
              border: 'none',
              borderRadius: 7,
              cursor: 'pointer',
              fontSize: 12,
              fontWeight: 600,
            }}
            title="Опубликовать текущий сценарий как шаблон (private / public)"
          >
            Опубликовать как шаблон
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

          <button
            type="button"
            onClick={onLogout}
            style={{
              padding: '7px 11px',
              background: '#1e293b',
              color: '#fca5a5',
              border: '1px solid #475569',
              borderRadius: 7,
              cursor: 'pointer',
              fontSize: 12,
              fontWeight: 600,
            }}
            title={`Выйти (${user.email})`}
          >
            Выйти из аккаунта
          </button>
        </div>
      </header>
      )}

      {statusMsg && (
        <div
          style={{
            padding: isMobile ? '5px 10px' : '5px 14px',
            background: '#eff6ff',
            borderBottom: '1px solid #bfdbfe',
            fontSize: 12,
            color: '#1e3a8a',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: 8,
            flexShrink: 0,
          }}
        >
          <span
            title={statusMsg}
            style={
              isMobile
                ? {
                    flex: 1,
                    minWidth: 0,
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }
                : undefined
            }
          >
            {statusMsg}{' '}
            {!isMobile && (!integrations.ai.configured || !integrations.telegram.configured) && (
              <button
                type="button"
                onClick={() => setIntegrationsOpen(true)}
                style={{
                  marginLeft: 6,
                  padding: '2px 8px',
                  borderRadius: 5,
                  border: '1px solid #818cf8',
                  background: '#eef2ff',
                  color: '#3730a3',
                  fontSize: 11,
                  fontWeight: 700,
                  cursor: 'pointer',
                }}
              >
                Настроить интеграции
              </button>
            )}
          </span>
          <button
            onClick={() => setStatusMsg('')}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#1e3a8a', flexShrink: 0 }}
          >
            ✕
          </button>
        </div>
      )}

      {/* Основная рабочая область */}
      {isMobile ? (
        <>
          <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0, width: '100%' }}>
            {mobileTab === 'canvas' && (
              <div
                style={{ flex: 1, minHeight: '50vh', minWidth: 0, width: '100%', position: 'relative' }}
                onDragOver={onCanvasDragOver}
                onDrop={onCanvasDrop}
              >
                <ReactFlow
                  nodes={nodes}
                  edges={edges}
                  nodeTypes={nodeTypes}
                  onNodesChange={onNodesChange}
                  onEdgesChange={onEdgesChange}
                  onConnect={onConnect}
                  onNodeClick={openNodePanel}
                  isValidConnection={(connection) => !connectionError(connection, nodes, edges)}
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
                </ReactFlow>
              </div>
            )}

            {mobileTab === 'palette' && (
              <NodeSidebar
                catalog={catalog}
                catalogSource={catalogSource}
                templates={templates}
                isOpen
                variant="fullscreen"
                onToggle={() => switchMobileTab('canvas')}
                onAddNode={addNode}
                onApplyTemplate={applyTemplate}
                onOpenTemplatesModal={() => setTemplatesOpen(true)}
                onGenerateWorkflow={handleGenerateWorkflow}
              />
            )}

            {mobileTab === 'settings' && (
              <NodeSettings
                key={`${selectedNode?.id ?? 'none'}-${String(selectedNode?.data.params?.upload_id ?? '')}`}
                selectedNode={selectedNode}
                nodeSpec={selectedNode ? specByType.get(selectedNode.data.kind) : undefined}
                credentials={credentials}
                isOpen
                variant="fullscreen"
                onToggle={() => switchMobileTab('canvas')}
                onSave={saveNodeSettings}
                onUploadZip={handleUploadZip}
                onCreateCredential={handleCreateCredential}
              />
            )}

            {mobileTab === 'report' && (
              <ReportPanel
                run={activeRun}
                findings={findings}
                reportMd={reportMd}
                events={wsEvents}
                runsHistory={runsHistory}
                isOpen
                variant="fullscreen"
                onToggle={() => switchMobileTab('canvas')}
                onSelectRun={(runId) => {
                  setWsEvents([]);
                  void syncRunState(runId);
                }}
                onRefreshHistory={() => void refreshRunsHistory()}
                telegramConfigured={integrations.telegram.configured}
                onSendTelegram={async (runId) => {
                  try {
                    const res = await api.sendRunToTelegram(runId);
                    setStatusMsg(`Отчёт отправлен в Telegram (chat_id=${res.chat_id}).`);
                  } catch (err) {
                    setStatusMsg(`Ошибка отправки в Telegram: ${err instanceof Error ? err.message : String(err)}`);
                  }
                }}
                emailConfigured={Boolean(integrations.email?.configured)}
                onSendEmail={async (runId) => {
                  try {
                    const res = await api.sendRunToEmail(runId);
                    setStatusMsg(`Отчёт отправлен на почту ${res.to_email}.`);
                  } catch (err) {
                    setStatusMsg(`Ошибка отправки на почту: ${err instanceof Error ? err.message : String(err)}`);
                  }
                }}
              />
            )}
          </div>

          {/* Нижний мобильный Tab Bar (одной рукой + safe-area) */}
          <nav
            aria-label="Навигация редактора"
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              background: '#0f172a',
              borderTop: '1px solid #334155',
              paddingBottom: 'env(safe-area-inset-bottom)',
              flexShrink: 0,
            }}
          >
            {(
              [
                { id: 'canvas', label: 'Схема', icon: '🕸️' },
                { id: 'palette', label: 'Блоки', icon: '🧩' },
                { id: 'settings', label: 'Блок', icon: '⚙️' },
                {
                  id: 'report',
                  label: findings.length > 0 ? `Отчёт (${findings.length})` : isRunning ? 'Отчёт ●' : 'Отчёт',
                  icon: '📊',
                },
              ] as const
            ).map((item) => {
              const active = mobileTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => switchMobileTab(item.id)}
                  style={{
                    minHeight: 48,
                    padding: '6px 4px',
                    border: 'none',
                    borderTop: active ? '2px solid #38bdf8' : '2px solid transparent',
                    background: active ? '#1e293b' : 'transparent',
                    color: active ? '#f8fafc' : '#94a3b8',
                    fontSize: 12,
                    fontWeight: active ? 700 : 500,
                    cursor: 'pointer',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: 2,
                  }}
                >
                  <span style={{ fontSize: 14, lineHeight: 1 }}>{item.icon}</span>
                  <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '100%' }}>
                    {item.label}
                  </span>
                </button>
              );
            })}
          </nav>
        </>
      ) : (
        <>
          <div style={{ display: 'flex', flex: 1, minHeight: 0 }}>
            <NodeSidebar
              catalog={catalog}
              catalogSource={catalogSource}
              templates={templates}
              variant={isTablet ? 'drawer' : 'docked'}
              isOpen={isTablet ? tabletDrawer === 'palette' : paletteOpen}
              onToggle={
                isTablet
                  ? () => setTabletDrawer((d) => (d === 'palette' ? 'none' : 'palette'))
                  : togglePalette
              }
              onAddNode={addNode}
              onApplyTemplate={applyTemplate}
              onOpenTemplatesModal={() => setTemplatesOpen(true)}
              onGenerateWorkflow={handleGenerateWorkflow}
            />

            <div
              style={{ flex: 1, minWidth: 0, position: 'relative' }}
              onDragOver={onCanvasDragOver}
              onDrop={onCanvasDrop}
            >
              <ReactFlow
                nodes={nodes}
                edges={edges}
                nodeTypes={nodeTypes}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                onConnect={onConnect}
                onNodeClick={openNodePanel}
                isValidConnection={(connection) => !connectionError(connection, nodes, edges)}
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
                {!isTablet && <MiniMap />}
              </ReactFlow>
            </div>

            <NodeSettings
              key={`${selectedNode?.id ?? 'none'}-${String(selectedNode?.data.params?.upload_id ?? '')}`}
              selectedNode={selectedNode}
              nodeSpec={selectedNode ? specByType.get(selectedNode.data.kind) : undefined}
              credentials={credentials}
              variant={isTablet ? 'drawer' : 'docked'}
              isOpen={isTablet ? tabletDrawer === 'settings' : nodePanelOpen}
              onToggle={
                isTablet
                  ? () => setTabletDrawer((d) => (d === 'settings' ? 'none' : 'settings'))
                  : toggleNodePanel
              }
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
            runsHistory={runsHistory}
            isOpen={panelOpen}
            onToggle={() => setPanelOpen((o) => !o)}
            onSelectRun={(runId) => {
              setWsEvents([]);
              void syncRunState(runId);
            }}
            onRefreshHistory={() => void refreshRunsHistory()}
            telegramConfigured={integrations.telegram.configured}
            onSendTelegram={async (runId) => {
              try {
                const res = await api.sendRunToTelegram(runId);
                setStatusMsg(`Отчёт отправлен в Telegram (chat_id=${res.chat_id}).`);
              } catch (err) {
                setStatusMsg(`Ошибка отправки в Telegram: ${err instanceof Error ? err.message : String(err)}`);
              }
            }}
            emailConfigured={Boolean(integrations.email?.configured)}
            onSendEmail={async (runId) => {
              try {
                const res = await api.sendRunToEmail(runId);
                setStatusMsg(`Отчёт отправлен на почту ${res.to_email}.`);
              } catch (err) {
                setStatusMsg(`Ошибка отправки на почту: ${err instanceof Error ? err.message : String(err)}`);
              }
            }}
          />
        </>
      )}

      {settingsOpen && (
        <SettingsModal
          user={user}
          integrations={integrations}
          onClose={() => setSettingsOpen(false)}
          onOpenIntegrations={() => setIntegrationsOpen(true)}
          onLogout={onLogout}
        />
      )}

      {integrationsOpen && (
        <IntegrationsModal
          key={`${integrations.ai.configured}-${integrations.telegram.configured}-${integrations.telegram.chat_id}`}
          integrations={integrations}
          onClose={() => setIntegrationsOpen(false)}
          onUpdated={(next) => {
            setIntegrations(next);
            if (lastUpload) {
              const rebuilt = buildSmartPipelineNodes(catalog, lastUpload.id, next);
              setNodes(rebuilt.nodes);
              setEdges(rebuilt.edges);
            }
          }}
        />
      )}

      {customNodesOpen && (
        <CustomNodesModal
          onClose={() => setCustomNodesOpen(false)}
          onCatalogChanged={async () => {
            const fresh = await api.fetchNodeTypes().catch(() => []);
            if (fresh.length > 0) setCatalog(fresh);
          }}
          onAddToCanvas={(nodeType) => {
            void (async () => {
              const fresh = await api.fetchNodeTypes().catch(() => catalog);
              if (fresh.length > 0) setCatalog(fresh);
              const spec = fresh.find((s) => s.type === nodeType) ?? specByType.get(nodeType);
              if (spec) addNode(spec);
            })();
          }}
        />
      )}

      {templatesOpen && (
        <TemplatesModal
          templates={templates}
          onClose={() => setTemplatesOpen(false)}
          onChanged={setTemplates}
          onCopied={(copied) => void applyCopiedWorkflow(copied)}
        />
      )}

      {publishOpen && (
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
              width: 'min(460px, 100%)',
              background: '#fff',
              borderRadius: 12,
              boxShadow: '0 20px 50px rgba(0,0,0,0.35)',
              overflow: 'hidden',
            }}
          >
            <div
              style={{
                padding: '13px 16px',
                background: '#0f172a',
                color: '#f8fafc',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <strong style={{ fontSize: 14 }}>Опубликовать как шаблон</strong>
              <button
                type="button"
                onClick={() => setPublishOpen(false)}
                style={{ background: 'none', border: 'none', color: '#cbd5e1', fontSize: 18, cursor: 'pointer' }}
              >
                ✕
              </button>
            </div>

            <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ fontSize: 12, color: '#475569' }}>
                Будет создана отдельная копия-шаблон. Рабочий сценарий и его расписание останутся без изменений, а токены и <code>credential_id</code> автоматически очистятся.
              </div>

              <label style={{ fontSize: 12, fontWeight: 600 }}>
                Название шаблона
                <input
                  type="text"
                  value={publishName}
                  onChange={(e) => setPublishName(e.target.value)}
                  style={{ width: '100%', boxSizing: 'border-box', padding: '7px 9px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1' }}
                />
              </label>

              <label style={{ fontSize: 12, fontWeight: 600 }}>
                Описание
                <textarea
                  rows={2}
                  value={publishDesc}
                  onChange={(e) => setPublishDesc(e.target.value)}
                  placeholder="Кратко: что проверяет этот сценарий"
                  style={{ width: '100%', boxSizing: 'border-box', padding: '7px 9px', marginTop: 4, borderRadius: 6, border: '1px solid #cbd5e1', fontFamily: 'inherit' }}
                />
              </label>

              <div style={{ fontSize: 12 }}>
                <div style={{ fontWeight: 600, marginBottom: 6 }}>Приватность</div>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 5, cursor: 'pointer' }}>
                  <input
                    type="radio"
                    name="tpl-vis"
                    checked={publishVis === 'private'}
                    onChange={() => setPublishVis('private')}
                  />
                  <span>
                    <strong>Только я (private)</strong> — шаблон виден только вам
                  </span>
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                  <input
                    type="radio"
                    name="tpl-vis"
                    checked={publishVis === 'public'}
                    onChange={() => setPublishVis('public')}
                  />
                  <span>
                    <strong>Все пользователи (public)</strong> — шаблон смогут копировать другие пользователи
                  </span>
                </label>
              </div>

              {publishErr && (
                <div style={{ fontSize: 12, color: '#991b1b', background: '#fef2f2', padding: 8, borderRadius: 6, border: '1px solid #fecaca' }}>
                  ❌ {publishErr}
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 4 }}>
                <button
                  type="button"
                  onClick={() => setPublishOpen(false)}
                  style={{ padding: '7px 12px', borderRadius: 7, border: '1px solid #cbd5e1', background: '#fff', fontSize: 12, cursor: 'pointer' }}
                >
                  Отмена
                </button>
                <button
                  type="button"
                  disabled={publishBusy}
                  onClick={() => void handlePublishTemplate()}
                  style={{
                    padding: '7px 14px',
                    borderRadius: 7,
                    border: 'none',
                    background: '#0d9488',
                    color: '#fff',
                    fontSize: 12,
                    fontWeight: 700,
                    cursor: publishBusy ? 'wait' : 'pointer',
                  }}
                >
                  {publishBusy ? 'Публикация…' : 'Опубликовать'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function WorkflowEditor({ user, onLogout }: WorkflowEditorProps) {
  return (
    <ReactFlowProvider>
      <WorkflowEditorContent user={user} onLogout={onLogout} />
    </ReactFlowProvider>
  );
}
