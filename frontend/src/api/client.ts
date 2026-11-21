import type {
  AiIntegrationDto,
  AiProvidersResponseDto,
  AuthStatusDto,
  BackendGraph,
  CredentialDto,
  CustomNodeDto,
  CustomNodeValidateDto,
  FindingDto,
  GeneratedWorkflowDto,
  IntegrationsDto,
  IntegrationTestResult,
  NodeTypeSpec,
  RunCompareDto,
  RunDto,
  TelegramIntegrationDto,
  TemplateDto,
  UploadResponse,
  WorkflowDto,
  WsRunEvent,
} from '../types/workflow';

const API_BASE_URL = (import.meta.env.VITE_API_URL || '').replace(/\/+$/, '');

// Kept strictly in React/JS memory — never persisted in localStorage or sessionStorage.
let csrfTokenMemory = '';
let unauthorizedHandler: (() => void) | null = null;

export function setOnUnauthorized(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
}

export function clearSessionMemory(): void {
  csrfTokenMemory = '';
}

function requestHeaders(extra?: HeadersInit, method = 'GET'): Headers {
  const headers = new Headers(extra);
  const upper = method.toUpperCase();
  if (csrfTokenMemory && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(upper)) {
    headers.set('X-CSRF-Token', csrfTokenMemory);
  }
  return headers;
}

async function rawFetch(url: string, init?: RequestInit): Promise<Response> {
  const method = init?.method ?? 'GET';
  const res = await fetch(`${API_BASE_URL}${url}`, {
    ...init,
    credentials: 'include',
    headers: requestHeaders(init?.headers, method),
  });
  if (res.status === 401 && !url.startsWith('/api/auth/')) {
    csrfTokenMemory = '';
    unauthorizedHandler?.();
  }
  return res;
}

const _recentLogErrors = new Map<string, number>();

export function reportClientError(payload: {
  level?: 'error' | 'warning' | 'info';
  message: string;
  source?: string;
  url?: string;
  status?: number;
  stack?: string;
}): void {
  try {
    const msg = (payload.message || '').slice(0, 1800);
    if (!msg) return;
    const dedupKey = `${payload.source || 'browser'}:${payload.status || ''}:${msg.slice(0, 120)}`;
    const now = Date.now();
    const prev = _recentLogErrors.get(dedupKey) || 0;
    if (now - prev < 5000) return;
    _recentLogErrors.set(dedupKey, now);
    if (_recentLogErrors.size > 100) {
      const oldest = _recentLogErrors.keys().next().value;
      if (oldest) _recentLogErrors.delete(oldest);
    }

    const body = JSON.stringify({
      level: payload.level || 'error',
      message: msg,
      source: (payload.source || 'browser').slice(0, 120),
      url: (payload.url || (typeof window !== 'undefined' ? window.location.pathname : '')).slice(0, 500),
      status: payload.status,
      stack: (payload.stack || '').slice(0, 3500),
    });

    void fetch(`${API_BASE_URL}/api/logs/client-error`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body,
      keepalive: true,
    }).catch(() => undefined);
  } catch {
    // never throw from error reporter
  }
}

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await rawFetch(url, init);
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = (await res.json()) as { detail?: string };
      if (body?.detail) detail = body.detail;
    } catch {
      // ignore parse failure
    }
    if (!url.startsWith('/api/logs/') && res.status !== 401) {
      reportClientError({
        level: res.status >= 500 ? 'error' : 'warning',
        source: 'frontend-api',
        message: `${init?.method || 'GET'} ${url}: ${detail}`,
        url,
        status: res.status,
      });
    }
    throw new Error(detail);
  }
  return (await res.json()) as T;
}

export async function fetchAuthMe(): Promise<AuthStatusDto> {
  const data = await requestJson<AuthStatusDto>('/api/auth/me');
  csrfTokenMemory = data.authenticated ? data.csrf_token || '' : '';
  return data;
}

export async function loginUser(email: string, password: string): Promise<AuthStatusDto> {
  const data = await requestJson<AuthStatusDto>('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  csrfTokenMemory = data.csrf_token || '';
  return data;
}

export async function registerUser(email: string, password: string): Promise<AuthStatusDto> {
  const data = await requestJson<AuthStatusDto>('/api/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  csrfTokenMemory = data.csrf_token || '';
  return data;
}

export async function logoutUser(): Promise<void> {
  try {
    await requestJson<{ ok: boolean }>('/api/auth/logout', { method: 'POST' });
  } finally {
    csrfTokenMemory = '';
  }
}

export async function forgotPassword(email: string): Promise<{ ok: boolean; message: string }> {
  return requestJson<{ ok: boolean; message: string }>('/api/auth/forgot-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });
}

export async function resetPassword(
  email: string,
  token: string,
  new_password: string,
): Promise<{ ok: boolean; message: string }> {
  return requestJson<{ ok: boolean; message: string }>('/api/auth/reset-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, token, new_password }),
  });
}

export async function fetchNodeTypes(): Promise<NodeTypeSpec[]> {
  const data = await requestJson<{ nodes: NodeTypeSpec[] }>('/api/node-types');
  return data.nodes ?? [];
}

export async function listWorkflows(): Promise<WorkflowDto[]> {
  const data = await requestJson<{ workflows: WorkflowDto[] }>('/api/workflows');
  return data.workflows ?? [];
}

export async function getWorkflow(id: string): Promise<WorkflowDto> {
  return requestJson<WorkflowDto>(`/api/workflows/${encodeURIComponent(id)}`);
}

export async function createWorkflow(
  name: string,
  graph_json: BackendGraph,
  description = '',
): Promise<WorkflowDto> {
  return requestJson<WorkflowDto>('/api/workflows', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, graph_json, description }),
  });
}

export async function updateWorkflow(
  id: string,
  payload: { name?: string; graph_json?: BackendGraph; description?: string },
): Promise<WorkflowDto> {
  return requestJson<WorkflowDto>(`/api/workflows/${encodeURIComponent(id)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function listTemplates(): Promise<TemplateDto[]> {
  const data = await requestJson<{ templates: TemplateDto[] }>('/api/templates');
  return data.templates ?? [];
}

export async function copyTemplate(templateId: string): Promise<WorkflowDto> {
  return requestJson<WorkflowDto>(`/api/templates/${encodeURIComponent(templateId)}/copy`, {
    method: 'POST',
  });
}

export async function uploadZip(file: File): Promise<UploadResponse> {
  const form = new FormData();
  form.append('file', file);
  return requestJson<UploadResponse>('/api/uploads', {
    method: 'POST',
    body: form,
  });
}

export async function runWorkflow(workflowId: string, wait = false): Promise<{ run_id: string }> {
  const qs = wait ? '?wait=true' : '';
  return requestJson<{ run_id: string }>(`/api/workflows/${encodeURIComponent(workflowId)}/run${qs}`, {
    method: 'POST',
  });
}

export async function listRuns(limit = 20): Promise<RunDto[]> {
  const data = await requestJson<{ runs: RunDto[] }>(`/api/runs?limit=${limit}`);
  return data.runs ?? [];
}

export async function getRun(runId: string): Promise<RunDto> {
  return requestJson<RunDto>(`/api/runs/${encodeURIComponent(runId)}`);
}

export async function getReportJson(runId: string): Promise<{ findings: FindingDto[] }> {
  return requestJson<{ findings: FindingDto[] }>(`/api/runs/${encodeURIComponent(runId)}/report.json`);
}

export async function getReportMd(runId: string): Promise<string> {
  const res = await rawFetch(`/api/runs/${encodeURIComponent(runId)}/report.md`);
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}`);
  }
  return res.text();
}

export async function listCredentials(): Promise<CredentialDto[]> {
  const data = await requestJson<{ credentials: CredentialDto[] }>('/api/credentials');
  return data.credentials ?? [];
}

export async function createCredential(
  name: string,
  kind: string,
  value: string,
): Promise<CredentialDto> {
  return requestJson<CredentialDto>('/api/credentials', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, kind, value }),
  });
}

export function subscribeRunEvents(
  runId: string,
  onEvent: (ev: WsRunEvent) => void,
  onClose?: () => void,
): WebSocket {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsBaseUrl = API_BASE_URL
    ? API_BASE_URL.replace(/^http/, 'ws')
    : `${proto}//${window.location.host}`;
  // Browser sends the HttpOnly session cookie automatically on WS upgrade.
  const ws = new WebSocket(`${wsBaseUrl}/ws/runs/${encodeURIComponent(runId)}`);
  ws.onmessage = (msg) => {
    try {
      const parsed = JSON.parse(String(msg.data)) as WsRunEvent;
      if (parsed.event !== 'ping') {
        onEvent(parsed);
      }
    } catch {
      // ignore malformed event
    }
  };
  if (onClose) {
    ws.onclose = () => onClose();
  }
  return ws;
}

export async function downloadRunReport(runId: string, format: 'json' | 'md' | 'pdf'): Promise<void> {
  const res = await rawFetch(`/api/runs/${encodeURIComponent(runId)}/report.${format}`);
  if (!res.ok) throw new Error(`Не удалось скачать отчёт: ${res.status}`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `report.${format}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export async function compareRuns(baseId: string, targetId: string): Promise<RunCompareDto> {
  return requestJson<RunCompareDto>(
    `/api/runs/compare?base=${encodeURIComponent(baseId)}&target=${encodeURIComponent(targetId)}`,
  );
}

export async function generateAiWorkflow(prompt: string): Promise<GeneratedWorkflowDto> {
  return requestJson<GeneratedWorkflowDto>('/api/ai/generate-workflow', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt }),
  });
}

// ---------------------------------------------------------------------------
// Custom Nodes ("Мои ноды")
// ---------------------------------------------------------------------------

export async function listCustomNodes(): Promise<CustomNodeDto[]> {
  const data = await requestJson<{ custom_nodes: CustomNodeDto[] }>('/api/custom-nodes');
  return data.custom_nodes;
}

export async function getCustomNode(id: string): Promise<CustomNodeDto> {
  return requestJson<CustomNodeDto>(`/api/custom-nodes/${id}`);
}

export async function validateCustomNodeCode(code: string): Promise<CustomNodeValidateDto> {
  return requestJson<CustomNodeValidateDto>('/api/custom-nodes/validate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
}

export async function createCustomNode(payload: {
  name: string;
  description: string;
  group: string;
  code: string;
  inputs: { name: string; kind: string }[];
  outputs: { name: string; kind: string }[];
  params_schema: Record<string, unknown>;
  status: string;
  visibility: string;
}): Promise<CustomNodeDto> {
  return requestJson<CustomNodeDto>('/api/custom-nodes', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function updateCustomNode(
  id: string,
  payload: Partial<{
    name: string;
    description: string;
    group: string;
    code: string;
    inputs: { name: string; kind: string }[];
    outputs: { name: string; kind: string }[];
    params_schema: Record<string, unknown>;
    status: string;
    visibility: string;
  }>,
): Promise<CustomNodeDto> {
  return requestJson<CustomNodeDto>(`/api/custom-nodes/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function duplicateCustomNode(id: string): Promise<CustomNodeDto> {
  return requestJson<CustomNodeDto>(`/api/custom-nodes/${id}/duplicate`, { method: 'POST' });
}

export async function testRunCustomNode(
  id: string,
  payload: {
    code?: string;
    inputs: Record<string, unknown>;
    params: Record<string, unknown>;
    outputs?: { name: string; kind: string }[];
  },
): Promise<{ ok: boolean; output?: Record<string, unknown>; logs?: string[]; error?: string }> {
  return requestJson(`/api/custom-nodes/${id}/test-run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function deleteCustomNode(id: string): Promise<void> {
  await requestJson<{ ok: boolean }>(`/api/custom-nodes/${id}`, { method: 'DELETE' });
}

export async function getIntegrations(): Promise<IntegrationsDto> {
  return requestJson<IntegrationsDto>('/api/integrations');
}

export async function getAiProviders(): Promise<AiProvidersResponseDto> {
  return requestJson<AiProvidersResponseDto>('/api/integrations/ai/providers');
}

export async function discoverAiModels(payload: {
  provider: string;
  base_url: string;
  api_key?: string;
}): Promise<{ ok: boolean; provider: string; models: string[]; detail?: string }> {
  return requestJson<{ ok: boolean; provider: string; models: string[]; detail?: string }>(
    '/api/integrations/ai/models',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    },
  );
}

export async function activateAiProvider(provider: string): Promise<AiIntegrationDto> {
  return requestJson<AiIntegrationDto>('/api/integrations/ai/activate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ provider }),
  });
}

export async function saveAiIntegration(payload: {
  provider: string;
  model: string;
  base_url: string;
  api_key?: string;
  enabled?: boolean;
  activate?: boolean;
}): Promise<AiIntegrationDto> {
  return requestJson<AiIntegrationDto>('/api/integrations/ai', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function testAiIntegration(payload: {
  provider: string;
  model: string;
  base_url: string;
  api_key?: string;
}): Promise<IntegrationTestResult> {
  return requestJson<IntegrationTestResult>('/api/integrations/ai/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function deleteAiIntegration(provider?: string): Promise<void> {
  const qs = provider ? `?provider=${encodeURIComponent(provider)}` : '';
  await requestJson<{ ok: boolean }>(`/api/integrations/ai${qs}`, { method: 'DELETE' });
}

export async function saveTelegramIntegration(payload: {
  bot_token?: string;
  chat_id: string;
  auto_send: boolean;
  enabled?: boolean;
  verify?: boolean;
}): Promise<TelegramIntegrationDto> {
  return requestJson<TelegramIntegrationDto>('/api/integrations/telegram', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function testTelegramIntegration(payload: {
  bot_token?: string;
  chat_id: string;
}): Promise<IntegrationTestResult> {
  return requestJson<IntegrationTestResult>('/api/integrations/telegram/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function deleteTelegramIntegration(): Promise<void> {
  await requestJson<{ ok: boolean }>('/api/integrations/telegram', { method: 'DELETE' });
}

export async function sendRunToTelegram(runId: string): Promise<{ sent: boolean; chat_id: string }> {
  return requestJson<{ sent: boolean; chat_id: string }>(
    `/api/integrations/telegram/send-run/${encodeURIComponent(runId)}`,
    { method: 'POST' },
  );
}

export type LogTailDto = {
  kind: 'errors' | 'app';
  file_name: string;
  path: string;
  entries: string[];
  total_returned: number;
};

export async function getLogs(kind: 'errors' | 'app' = 'errors', lines = 150): Promise<LogTailDto> {
  return requestJson<LogTailDto>(`/api/logs?kind=${encodeURIComponent(kind)}&lines=${lines}`);
}

export function getLogDownloadUrl(kind: 'errors' | 'app' = 'errors'): string {
  return `${API_BASE_URL}/api/logs/download?kind=${encodeURIComponent(kind)}`;
}
