export type Decision = "allow" | "review" | "block";

export interface Health {
  status: "ok";
  environment: string;
  actor_mode: string;
  judge_mode: string;
  executor_mode: string;
  model_api_key_configured: boolean;
  spark_model: string;
  judge_model: string;
}

export interface SecretFinding {
  kind: string;
  location: string;
  fingerprint: string;
  confidence: "low" | "medium" | "high";
}

export interface ImpactPreview {
  action_id: string;
  action_digest: string;
  normalized_action: Record<string, unknown>;
  resolved_targets: string[];
  affected_file_count: number;
  affected_bytes: number;
  network_destination: string | null;
  secret_findings: SecretFinding[];
  protected_resource_hits: string[];
  uncertainty_flags: string[];
  truncated: boolean;
  digest: string;
}

export interface Verdict {
  action_id: string;
  decision: Decision;
  reason_codes: string[];
  explanation: string;
  evidence_refs: string[];
  source: "rule" | "judge" | "human" | "combined";
  action_digest: string;
  preview_digest: string;
  created_at: string;
}

export interface PendingReview {
  action_id: string;
  kind: "shell" | "file_write" | "file_patch" | "http" | "git_push";
  task_text: string;
  preview: ImpactPreview;
  verdict: Verdict;
  expires_at: string;
  can_approve: boolean;
  capability_note: string;
}

export interface AuditRecord {
  sequence: number;
  event_id: string;
  action_id: string;
  stage: string;
  payload: Record<string, unknown>;
  created_at: string;
  previous_hash: string;
  event_hash: string;
}

export interface IntegrityStatus {
  valid: boolean;
  event_count: number;
}

export interface LatencySummary {
  samples: number;
  average_ms: number;
  maximum_ms: number;
}

export interface TelemetrySummary {
  spark_calls: number;
  wonder_calls: number;
  wonder_escalations: number;
  judge_cache_hits: number;
  locally_avoided_judge_calls: number;
  budget_exhaustions: number;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  estimated_cost_usd: number;
  priced_model_calls: number;
  unpriced_model_calls: number;
  stage_latency: Record<string, LatencySummary>;
}

export interface ActionSummary {
  actionId: string;
  latestSequence: number;
  stage: string;
  kind: string;
  decision: Decision | null;
  preview: ImpactPreview | null;
  verdict: Verdict | null;
  executed: boolean;
  createdAt: string;
}
