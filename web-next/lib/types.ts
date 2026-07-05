// Tipi condivisi che rispecchiano le risposte del backend Python (osint_bot.web).

export interface Capabilities {
  agents: string[];
  always_on_agents: string[];
  gated_agents: string[];
  ai_enrichment: Record<string, boolean>;
  tools: ToolStatus[];
  search_providers: ProviderStatus[];
  queue: { pending: number };
}

export interface ToolStatus {
  name: string;
  available: boolean;
  health_reason?: string;
}

export interface ProviderStatus {
  name: string;
  configured: boolean;
  env_var: string;
}

export interface CaseRecord {
  id: string;
  title: string;
  status: string;
  owner: string;
  purpose?: string;
  created_at: string;
  updated_at: string;
  allowed_targets?: string[];
}

export interface Job {
  id: string;
  status: string;
  target?: string;
  target_type?: string;
  created_at: string;
  updated_at: string;
  case_id?: string;
  agents?: string[];
  progress?: { at: string; stage: string; message: string }[];
}

export interface GraphNode {
  id: string;
  kind: string;
  label: string;
  value: string;
  confidence: number;
  severity: string;
  degree: number;
  sources: string[];
}

export interface GraphLink {
  id: string;
  source: string;
  target: string;
  kind: string;
  confidence: number;
  evidence_url: string;
}

export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
  meta?: Record<string, unknown>;
}
