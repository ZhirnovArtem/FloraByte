import type { NodeTypeSpec } from '../types/workflow';

// Запасной каталог на случай недоступности backend GET /api/node-types
export const fallbackNodeCatalog: NodeTypeSpec[] = [
  {
    type: 'trigger.manual',
    label: 'Manual Trigger',
    group: 'trigger',
    inputs: [],
    outputs: [{ name: 'out', kind: 'Any' }],
    params_schema: { type: 'object', properties: {} },
  },
  {
    type: 'trigger.schedule',
    label: 'Schedule Trigger',
    group: 'trigger',
    inputs: [],
    outputs: [{ name: 'out', kind: 'Any' }],
    params_schema: {
      type: 'object',
      properties: {
        cron: { type: 'string', default: '', description: 'Cron expression e.g. "0 9 * * 1-5" (оставьте пустым для интервала)' },
        interval_seconds: { type: 'integer', default: 60, description: 'Интервал запуска на сервере (минимум 30с; повтор делает сервер)' },
      },
    },
  },
  {
    type: 'source.upload_zip',
    label: 'Upload ZIP',
    group: 'source',
    inputs: [{ name: 'in', kind: 'Any' }],
    outputs: [{ name: 'workspace', kind: 'Workspace' }],
    params_schema: {
      type: 'object',
      properties: {
        upload_id: { type: 'string', default: '', description: 'ID from POST /api/uploads' },
        subdir: { type: 'string', default: '', description: 'Optional subdirectory inside archive' },
      },
    },
  },
  {
    type: 'source.git_clone',
    label: 'Git Clone',
    group: 'source',
    inputs: [{ name: 'in', kind: 'Any' }],
    outputs: [{ name: 'workspace', kind: 'Workspace' }],
    params_schema: {
      type: 'object',
      properties: {
        url: { type: 'string', default: 'https://github.com/TBagirov/training' },
        branch: { type: 'string', default: '' },
        subdir: { type: 'string', default: '' },
      },
    },
  },
  {
    type: 'scanner.secrets',
    label: 'Secrets Scanner',
    group: 'scanner',
    inputs: [{ name: 'workspace', kind: 'Workspace' }],
    outputs: [{ name: 'findings', kind: 'Findings' }],
    params_schema: { type: 'object', properties: {} },
  },
  {
    type: 'scanner.sca',
    label: 'SCA Scanner',
    group: 'scanner',
    inputs: [{ name: 'workspace', kind: 'Workspace' }],
    outputs: [{ name: 'findings', kind: 'Findings' }],
    params_schema: {
      type: 'object',
      properties: {
        vuln_db_path: { type: 'string', default: '', description: 'Override path to vulnerabilities.json' },
        lockfile_priority: { type: 'boolean', default: true },
      },
    },
  },
  {
    type: 'scanner.sast',
    label: 'SAST Scanner',
    group: 'scanner',
    inputs: [{ name: 'workspace', kind: 'Workspace' }],
    outputs: [{ name: 'findings', kind: 'Findings' }],
    params_schema: {
      type: 'object',
      properties: {
        exclude_tests: { type: 'boolean', default: true },
      },
    },
  },
  {
    type: 'logic.if_else',
    label: 'If / Else',
    group: 'logic',
    inputs: [
      { name: 'findings', kind: 'Findings' },
      { name: 'in', kind: 'Any' },
    ],
    outputs: [
      { name: 'true', kind: 'Any' },
      { name: 'false', kind: 'Any' },
    ],
    params_schema: {
      type: 'object',
      properties: {
        left: { type: 'string', default: 'findings.count' },
        op: { type: 'string', default: '>' },
        right: { type: 'string', default: '0' },
      },
    },
  },
  {
    type: 'logic.compare',
    label: 'Compare',
    group: 'logic',
    inputs: [
      { name: 'findings', kind: 'Findings' },
      { name: 'in', kind: 'Any' },
    ],
    outputs: [
      { name: 'true', kind: 'Any' },
      { name: 'false', kind: 'Any' },
    ],
    params_schema: {
      type: 'object',
      properties: {
        left: { type: 'string', default: 'findings.max_severity' },
        op: { type: 'string', default: '>=' },
        right: { type: 'string', default: 'HIGH' },
      },
    },
  },
  {
    type: 'logic.regex',
    label: 'Regex Match',
    group: 'logic',
    inputs: [
      { name: 'findings', kind: 'Findings' },
      { name: 'in', kind: 'Any' },
    ],
    outputs: [
      { name: 'true', kind: 'Any' },
      { name: 'false', kind: 'Any' },
    ],
    params_schema: {
      type: 'object',
      properties: {
        field: { type: 'string', default: 'findings.paths' },
        pattern: { type: 'string', default: '.*' },
      },
    },
  },
  {
    type: 'findings.merge',
    label: 'Merge Findings',
    group: 'findings',
    inputs: [
      { name: 'a', kind: 'Findings' },
      { name: 'b', kind: 'Findings' },
      { name: 'c', kind: 'Findings' },
      { name: 'findings', kind: 'Findings' },
      { name: 'in', kind: 'Findings' },
    ],
    outputs: [{ name: 'findings', kind: 'Findings' }],
    params_schema: { type: 'object', properties: {} },
  },
  {
    type: 'findings.export',
    label: 'Export Report',
    group: 'findings',
    inputs: [
      { name: 'findings', kind: 'Findings' },
      { name: 'in', kind: 'Findings' },
      { name: 'a', kind: 'Findings' },
    ],
    outputs: [{ name: 'report', kind: 'Report' }],
    params_schema: { type: 'object', properties: {} },
  },
  {
    type: 'ai.explain',
    label: 'AI Explain',
    group: 'ai',
    inputs: [
      { name: 'findings', kind: 'Findings' },
      { name: 'in', kind: 'Findings' },
    ],
    outputs: [{ name: 'report', kind: 'Report' }],
    params_schema: {
      type: 'object',
      properties: {
        credential_id: { type: 'string', default: '' },
        model: { type: 'string', default: '' },
        provider: { type: 'string', default: '' },
        base_url: { type: 'string', default: '' },
      },
    },
  },
  {
    type: 'notify.telegram',
    label: 'Telegram',
    group: 'notify',
    inputs: [
      { name: 'report', kind: 'Report' },
      { name: 'in', kind: 'Any' },
    ],
    outputs: [{ name: 'out', kind: 'Any' }],
    params_schema: {
      type: 'object',
      properties: {
        credential_id: { type: 'string', default: '' },
        chat_id: { type: 'string', default: '' },
        dry_run: { type: 'boolean', default: false },
      },
    },
  },
  {
    type: 'notify.webhook',
    label: 'Webhook',
    group: 'notify',
    inputs: [
      { name: 'report', kind: 'Report' },
      { name: 'in', kind: 'Any' },
    ],
    outputs: [{ name: 'out', kind: 'Any' }],
    params_schema: {
      type: 'object',
      properties: {
        url: { type: 'string', default: '' },
        credential_id: { type: 'string', default: '' },
        headers_json: { type: 'string', default: '{}' },
        dry_run: { type: 'boolean', default: false },
      },
    },
  },
  {
    type: 'notify.email',
    label: 'Email',
    group: 'notify',
    inputs: [
      { name: 'report', kind: 'Report' },
      { name: 'in', kind: 'Any' },
    ],
    outputs: [{ name: 'out', kind: 'Any' }],
    params_schema: {
      type: 'object',
      properties: {
        to_email: { type: 'string', default: '' },
        subject: { type: 'string', default: 'FloraByte Security Report' },
        credential_id: { type: 'string', default: '' },
        dry_run: { type: 'boolean', default: false },
      },
    },
  },
];
