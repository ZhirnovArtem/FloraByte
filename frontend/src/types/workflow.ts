export type PortSpec = {
  name: string;
  kind: string;
};

export type JsonSchemaProperty = {
  type?: string;
  title?: string;
  description?: string;
  default?: unknown;
  enum?: unknown[];
};

export type ParamsSchema = {
  type?: string;
  properties?: Record<string, JsonSchemaProperty>;
  required?: string[];
};

export type NodeTypeSpec = {
  type: string;
  label: string;
  group: string;
  inputs: PortSpec[];
  outputs: PortSpec[];
  params_schema: ParamsSchema;
};

export type BackendGraphNode = {
  id: string;
  type: string;
  params: Record<string, unknown>;
  position: { x: number; y: number };
};

export type BackendGraphEdge = {
  id: string;
  source: string;
  sourceHandle?: string | null;
  target: string;
  targetHandle?: string | null;
};

export type BackendGraph = {
  nodes: BackendGraphNode[];
  edges: BackendGraphEdge[];
};

export type WorkflowDto = {
  id: string;
  name: string;
  description: string;
  is_template: boolean;
  graph_json: BackendGraph;
  created_at?: string | null;
  updated_at?: string | null;
};

export type TemplateDto = {
  id: string;
  name: string;
  description: string;
  graph_json: BackendGraph;
};

export type UploadResponse = {
  upload_id: string;
  filename: string;
  size: number;
};

export type NodeRunStatus = 'pending' | 'running' | 'success' | 'failed' | 'skipped';

export type NodeRunDto = {
  node_id: string;
  status: NodeRunStatus;
  started_at?: string | null;
  finished_at?: string | null;
  output_preview?: Record<string, unknown> | null;
  error?: string | null;
};

export type FindingDto = {
  category: 'SECRET' | 'SAST' | 'SCA';
  path: string;
  class?: string;
  line?: number;
  endLine?: number;
  group?: string;
  artifact?: string;
  version?: string;
  advisoryId?: string;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description?: string;
  remediation?: string;
};

export type AiExplainItem = {
  finding_ref: number;
  explanation: string;
  risk?: string | null;
  fix_steps: string[];
};

export type AiReportDto = {
  summary: string;
  items: AiExplainItem[];
  validation?: {
    passed?: boolean;
    retried?: boolean;
    dropped_items?: number;
    dropped_cve?: number;
    mode?: string;
    errors?: string[];
  };
};

export type RunDto = {
  id: string;
  workflow_id: string;
  status: string;
  trigger: string;
  started_at?: string | null;
  finished_at?: string | null;
  summary?: {
    node_statuses?: Record<string, string>;
    report?: {
      findings_count?: number;
      findings?: FindingDto[];
      paths?: { json_path?: string | null; md_path?: string | null };
    };
    error?: string;
  } | null;
  ai_report?: AiReportDto | null;
  nodes?: NodeRunDto[];
};

export type WsRunEvent = {
  event: string;
  run_id?: string;
  node_id?: string;
  status?: NodeRunStatus | string;
  duration_ms?: number;
  output_preview?: Record<string, unknown> | null;
  error?: string | null;
  summary?: RunDto['summary'];
};

export type CredentialDto = {
  id: string;
  name: string;
  kind: string;
  masked_value: string;
  created_at?: string | null;
};
