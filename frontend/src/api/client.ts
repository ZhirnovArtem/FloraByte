import type {
  BackendGraph,
  CredentialDto,
  FindingDto,
  NodeTypeSpec,
  RunDto,
  TemplateDto,
  UploadResponse,
  WorkflowDto,
  WsRunEvent,
} from '../types/workflow';

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = (await res.json()) as { detail?: string };
      if (body?.detail) detail = body.detail;
    } catch {
      // ignore parse failure
    }
    throw new Error(detail);
  }
  return (await res.json()) as T;
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
  const res = await fetch(`/api/runs/${encodeURIComponent(runId)}/report.md`);
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
  const ws = new WebSocket(`${proto}//${window.location.host}/ws/runs/${encodeURIComponent(runId)}`);
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
