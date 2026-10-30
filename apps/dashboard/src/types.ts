import type {
  AuditRecord,
  BenchmarkConfigurationView,
  BenchmarkSummaryView,
  Decision,
  HealthResponse,
  ImpactPreview,
  LatencySummary,
  PendingReviewView,
  SecretFinding,
  TelemetrySummary,
  Verdict,
} from "./generated-api";

export type {
  AuditRecord,
  Decision,
  ImpactPreview,
  LatencySummary,
  SecretFinding,
  TelemetrySummary,
  Verdict,
};
export type Health = HealthResponse;
export type PendingReview = PendingReviewView;
export type BenchmarkConfiguration = BenchmarkConfigurationView;
export type BenchmarkSummary = BenchmarkSummaryView;

export interface IntegrityStatus {
  valid: boolean;
  event_count: number;
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
