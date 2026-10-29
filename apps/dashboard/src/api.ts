import type {
  AuditRecord,
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

export async function loadDashboard() {
  const [health, integrity, events, reviews, telemetry] = await Promise.all([
    request<Health>("/health"),
    request<IntegrityStatus>("/v1/audit/verify"),
    request<AuditRecord[]>("/v1/audit/events?limit=200"),
    request<PendingReview[]>("/v1/reviews"),
    request<TelemetrySummary>("/v1/telemetry"),
  ]);
  return { health, integrity, events, reviews, telemetry };
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
