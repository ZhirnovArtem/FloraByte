export type AuthUserDto = {
  id: string;
  email: string;
  created_at?: string | null;
};

export type AuthStatusDto = {
  authenticated: boolean;
  user: AuthUserDto | null;
  csrf_token: string;
  persistent_storage?: boolean;
};

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
  description?: string;
  group: string;
  inputs: PortSpec[];
  outputs: PortSpec[];
  params_schema: ParamsSchema;
  is_custom?: boolean;
  custom_node_id?: string;
  version?: number;
  visibility?: string;
};

export type CustomNodeVersionDto = {
  id: string;
  version: number;
  name: string;
  description: string;
  group: string;
  code: string;
  inputs: PortSpec[];
  outputs: PortSpec[];
  params_schema: ParamsSchema;
  created_at?: string | null;
};

export type CustomNodeDto = {
  id: string;
  node_type: string;
  owner_id?: string | null;
  is_owner: boolean;
  name: string;
  description: string;
  group: string;
  code: string;
  inputs: PortSpec[];
  outputs: PortSpec[];
  params_schema: ParamsSchema;
  version: number;
  status: 'draft' | 'active' | 'disabled' | string;
  visibility: 'private' | 'public' | string;
  created_at?: string | null;
  updated_at?: string | null;
  versions?: CustomNodeVersionDto[];
};

export type CustomNodeValidateDto = {
  ok: boolean;
  errors: string[];
  warnings: string[];
  is_async: boolean;
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
  scheduled_jobs?: number;
  schedule_summary?: Array<{
    node_id: string;
    cron?: string;
    interval_seconds?: number | null;
  }>;
  schedule_warnings?: string[];
  created_at?: string | null;
  updated_at?: string | null;
};

export type TemplateVisibility = 'private' | 'public';

export type TemplateDto = {
  id: string;
  name: string;
  description: string;
  visibility?: TemplateVisibility;
  owner_id?: string | null;
  owner_email?: string;
  is_system?: boolean;
  is_owner?: boolean;
  published_at?: string | null;
  nodes_count?: number;
  source_template_id?: string | null;
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
  priority?: string | null;
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
    ai_status?: string;
    provider?: string;
    provider_label?: string;
    model?: string;
    error?: string | null;
    fallback_reason?: string | null;
    errors?: string[];
  };
};

export type AiIntegrationDto = {
  configured: boolean;
  enabled: boolean;
  source: string;
  provider: string;
  provider_label?: string;
  model: string;
  base_url: string;
  api_key_preview: string;
};

export type AiProviderSpecDto = {
  id: string;
  label: string;
  adapter_kind: string;
  auth_type: string;
  default_base_url: string;
  default_model: string;
  supports_model_discovery: boolean;
  requires_url_input: boolean;
  key_hint: string;
};

export type SavedAiProfileDto = {
  provider: string;
  label: string;
  model: string;
  base_url: string;
  configured: boolean;
  is_active: boolean;
  api_key_preview: string;
};

export type AiProvidersResponseDto = {
  providers: AiProviderSpecDto[];
  profiles: SavedAiProfileDto[];
  active: AiIntegrationDto;
};

export type TelegramIntegrationDto = {
  configured: boolean;
  enabled: boolean;
  auto_send: boolean;
  source: string;
  chat_id: string;
  bot_token_preview: string;
  bot_username: string;
  verified: boolean;
};

export type EmailIntegrationDto = {
  configured: boolean;
  enabled: boolean;
  source: string;
  transport: string;
  smtp_host: string;
  smtp_port: number;
  smtp_user: string;
  from_email: string;
  default_to: string;
  use_tls: boolean;
  secret_preview: string;
};

export type IntegrationsDto = {
  ai: AiIntegrationDto;
  telegram: TelegramIntegrationDto;
  email?: EmailIntegrationDto;
};

export type IntegrationTestResult = {
  ok: boolean;
  detail?: string | null;
  error?: string | null;
  models?: string[];
  bot_username?: string;
  chat_title?: string;
};

export type RunDto = {
  id: string;
  workflow_id: string;
  status: string;
  trigger: string;
  started_at?: string | null;
  finished_at?: string | null;
  duration_ms?: number | null;
  summary?: {
    node_statuses?: Record<string, string>;
    failed_nodes?: Array<{ node_id: string; error: string }>;
    skipped_nodes?: string[];
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
  value_preview: string;
  created_at?: string | null;
};

export type GeneratedWorkflowDto = {
  name: string;
  summary?: string;
  mode: string;
  provider?: string | null;
  graph: BackendGraph;
};

export type RunCompareDto = {
  summary: {
    base_total: number;
    target_total: number;
    new_count: number;
    fixed_count: number;
    persisting_count: number;
    delta: number;
  };
  severity_delta: Record<string, number>;
  new: Array<FindingDto & { fingerprint?: string }>;
  fixed: Array<FindingDto & { fingerprint?: string }>;
  persisting: Array<FindingDto & { fingerprint?: string }>;
};
