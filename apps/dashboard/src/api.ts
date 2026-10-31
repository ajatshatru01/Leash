import type {
  AuditRecord,
  BenchmarkSummary,
  DemoStatus,
  Health,
  IntegrityStatus,
  PendingReview,
  TelemetrySummary,
} from "./types";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!response.ok) {
    throw new Error(`Leash request failed (${response.status})`);
  }
  return (await response.json()) as T;
}

async function optionalRequest<T>(path: string): Promise<T | null> {
  const response = await fetch(path, { headers: { "Content-Type": "application/json" } });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`Leash request failed (${response.status})`);
  return (await response.json()) as T;
}

export async function loadDashboard() {
  const [health, integrity, events, reviews, telemetry, benchmark, managedBenchmark, demo] = await Promise.all([
    request<Health>("/health"),
    request<IntegrityStatus>("/v1/audit/verify"),
    request<AuditRecord[]>("/v1/audit/events?limit=200"),
    request<PendingReview[]>("/v1/reviews"),
    request<TelemetrySummary>("/v1/telemetry"),
    optionalRequest<BenchmarkSummary>("/v1/benchmark/latest").catch(() => null),
    optionalRequest<BenchmarkSummary>("/v1/benchmark/managed-sample").catch(() => null),
    optionalRequest<DemoStatus>("/v1/demo/status").catch(() => null),
  ]);
  return { health, integrity, events, reviews, telemetry, benchmark, managedBenchmark, demo };
}

export function resetDemo(): Promise<DemoStatus> {
  return request<DemoStatus>("/v1/demo/reset", {
    method: "POST",
    body: JSON.stringify({ confirm: "reset" }),
  });
}

export function seedDemo(): Promise<DemoStatus> {
  return request<DemoStatus>("/v1/demo/seed", {
    method: "POST",
    body: JSON.stringify({ confirm: "seed" }),
  });
}

export async function decideReview(
  review: PendingReview,
  decision: "approve" | "deny",
): Promise<void> {
  await request(`/v1/actions/${review.action_id}/decision`, {
    method: "POST",
    body: JSON.stringify({
      decision,
      action_digest: review.preview.action_digest,
      preview_digest: review.preview.digest,
    }),
  });
}
