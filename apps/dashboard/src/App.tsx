import { useCallback, useEffect, useMemo, useState } from "react";

import { decideReview, loadDashboard } from "./api";
import type {
  ActionSummary,
  AuditRecord,
  BenchmarkSummary,
  Health,
  ImpactPreview,
  IntegrityStatus,
  PendingReview,
  TelemetrySummary,
  Verdict,
} from "./types";

const EMPTY_INTEGRITY: IntegrityStatus = { valid: false, event_count: 0 };
const EMPTY_TELEMETRY: TelemetrySummary = {
  spark_calls: 0,
  wonder_calls: 0,
  wonder_escalations: 0,
  judge_cache_hits: 0,
  locally_avoided_judge_calls: 0,
  budget_exhaustions: 0,
  prompt_tokens: 0,
  completion_tokens: 0,
  total_tokens: 0,
  estimated_cost_usd: 0,
  priced_model_calls: 0,
  unpriced_model_calls: 0,
  stage_latency: {},
};

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asPreview(value: unknown): ImpactPreview | null {
  if (!isObject(value) || typeof value.action_id !== "string") return null;
  return value as unknown as ImpactPreview;
}

function asVerdict(value: unknown): Verdict | null {
  if (
    !isObject(value) ||
    !["allow", "review", "block"].includes(String(value.decision))
  ) {
    return null;
  }
  return value as unknown as Verdict;
}

function summarize(events: AuditRecord[]): ActionSummary[] {
  const actions = new Map<string, ActionSummary>();
  for (const event of events) {
    const current = actions.get(event.action_id) ?? {
      actionId: event.action_id,
      latestSequence: event.sequence,
      stage: event.stage,
      kind: "action",
      decision: null,
      preview: null,
      verdict: null,
      executed: false,
      createdAt: event.created_at,
    };
    current.latestSequence = event.sequence;
    current.stage = event.stage;
    if (event.stage === "previewed") {
      const preview = asPreview(event.payload);
      if (preview) {
        current.preview = preview;
        current.kind = String(preview.normalized_action.kind ?? "action");
      }
    }
    if (
      event.stage === "verdict" ||
      event.stage === "human_approved" ||
      event.stage === "human_denied"
    ) {
      const verdict = asVerdict(event.payload);
      if (verdict) {
        current.verdict = verdict;
        current.decision = verdict.decision;
      }
    }
    if (event.stage === "executed") current.executed = true;
    actions.set(event.action_id, current);
  }
  return [...actions.values()]
    .filter((action) => action.preview !== null)
    .sort((a, b) => b.latestSequence - a.latestSequence);
}

function shortId(value: string): string {
  return value.slice(0, 8);
}

function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(value));
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  return `${(value / 1024).toFixed(1)} KB`;
}

function DecisionPill({ decision }: { decision: ActionSummary["decision"] }) {
  const value = decision ?? "pending";
  return <span className={`decision decision--${value}`}>{value}</span>;
}

function Metric({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="metric">
      <span className={`metric__mark metric__mark--${tone}`} />
      <div>
        <strong>{value.toString().padStart(2, "0")}</strong>
        <span>{label}</span>
      </div>
    </div>
  );
}

function PreviewFacts({ preview }: { preview: ImpactPreview }) {
  return (
    <div className="facts">
      <div><span>Files</span><strong>{preview.affected_file_count}</strong></div>
      <div><span>Bytes</span><strong>{formatBytes(preview.affected_bytes)}</strong></div>
      <div><span>Destination</span><strong>{preview.network_destination ?? "Local only"}</strong></div>
      <div><span>Coverage</span><strong>{preview.truncated ? "Truncated" : "Complete"}</strong></div>
    </div>
  );
}

function ShellAnalysis({ preview }: { preview: ImpactPreview }) {
  const value = preview.normalized_action.analysis;
  if (!isObject(value)) return null;
  const decoded = typeof value.decoded_command_preview === "string"
    ? value.decoded_command_preview
    : null;
  const operation = typeof value.destructive_operation === "string"
    ? value.destructive_operation
    : null;
  const patterns = Array.isArray(value.target_patterns)
    ? value.target_patterns.filter((item): item is string => typeof item === "string")
    : [];
  const syntaxFlags = Array.isArray(value.syntax_flags)
    ? value.syntax_flags.filter((item): item is string => typeof item === "string")
    : [];
  if (!decoded && !operation && patterns.length === 0 && syntaxFlags.length === 0) return null;
  return (
    <section className="detail-section">
      <div className="section-heading"><span>Shell analysis</span><small>decoded locally</small></div>
      <div className="analysis-grid mono">
        {decoded && <div><span>Decoded command</span><code>{decoded}</code></div>}
        {operation && <div><span>Resolved operation</span><code>{operation}</code></div>}
        {patterns.length > 0 && <div><span>Target patterns</span><code>{patterns.join(", ")}</code></div>}
        {syntaxFlags.length > 0 && <div><span>Syntax flags</span><code>{syntaxFlags.join(", ")}</code></div>}
      </div>
    </section>
  );
}

function Evidence({ preview, verdict }: { preview: ImpactPreview; verdict: Verdict | null }) {
  const items = [
    ...preview.secret_findings.map((finding) => ({
      label: finding.kind.replaceAll("_", " "),
      detail: `${finding.location} · ${finding.confidence} confidence`,
      tone: "danger",
    })),
    ...preview.protected_resource_hits.map((path) => ({
      label: "protected resource",
      detail: path,
      tone: "danger",
    })),
    ...preview.uncertainty_flags.map((flag) => ({
      label: flag.replaceAll("_", " "),
      detail: "Requires conservative handling",
      tone: "warning",
    })),
  ];
  return (
    <section className="detail-section">
      <div className="section-heading">
        <span>Evidence</span>
        <small>{items.length + (verdict?.reason_codes.length ?? 0)} signals</small>
      </div>
      <div className="evidence-list">
        {verdict?.reason_codes.map((code) => (
          <div className="evidence" key={code}>
            <span className={`evidence__dot evidence__dot--${verdict.decision}`} />
            <div><strong>{code}</strong><span>{verdict.explanation}</span></div>
          </div>
        ))}
        {items.map((item, index) => (
          <div className="evidence" key={`${item.label}-${index}`}>
            <span className={`evidence__dot evidence__dot--${item.tone}`} />
            <div><strong>{item.label}</strong><span>{item.detail}</span></div>
          </div>
        ))}
        {items.length === 0 && !verdict?.reason_codes.length && (
          <p className="muted">No risk evidence recorded for this action.</p>
        )}
      </div>
    </section>
  );
}

export default function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [integrity, setIntegrity] = useState(EMPTY_INTEGRITY);
  const [events, setEvents] = useState<AuditRecord[]>([]);
  const [telemetry, setTelemetry] = useState(EMPTY_TELEMETRY);
  const [benchmark, setBenchmark] = useState<BenchmarkSummary | null>(null);
  const [managedBenchmark, setManagedBenchmark] = useState<BenchmarkSummary | null>(null);
  const [reviews, setReviews] = useState<PendingReview[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [confirmation, setConfirmation] = useState<{ review: PendingReview; decision: "approve" | "deny" } | null>(null);
  const [now, setNow] = useState(Date.now());
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const refresh = useCallback(async () => {
    try {
      const data = await loadDashboard();
      setHealth(data.health);
      setIntegrity(data.integrity);
      setEvents(data.events);
      setReviews(data.reviews);
      setTelemetry(data.telemetry);
      setBenchmark(data.benchmark);
      setManagedBenchmark(data.managedBenchmark);
      setLastUpdated(new Date());
      setError(null);
    } catch {
      setError("Gateway unavailable. Waiting for the local Leash service.");
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => { setNow(Date.now()); void refresh(); }, 2000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const actions = useMemo(() => summarize(events), [events]);
  const selected = actions.find((action) => action.actionId === selectedId) ?? actions[0] ?? null;
  const selectedReview = reviews.find((review) => review.action_id === selected?.actionId) ?? null;
  const displayPreview = selectedReview?.preview ?? selected?.preview ?? null;
  const displayVerdict = selectedReview?.verdict ?? selected?.verdict ?? null;

  const metrics = {
    pending: reviews.length,
    blocked: actions.filter((action) => action.decision === "block").length,
    executed: actions.filter((action) => action.executed).length,
  };
  const hybridBenchmark = benchmark?.configurations.recorded_hybrid;
  const rulesBenchmark = benchmark?.configurations.rules_only;
  const chartBenchmark = managedBenchmark ?? benchmark;
  const benchmarkBars = chartBenchmark ? [
    { label: "Rules only", value: chartBenchmark.configurations.rules_only?.accuracy ?? 0 },
    { label: managedBenchmark ? "Muse Wonder" : "Recorded Wonder", value: chartBenchmark.configurations[managedBenchmark ? "managed_wonder_only" : "recorded_wonder_only"]?.accuracy ?? 0 },
    { label: managedBenchmark ? "Hybrid" : "Recorded hybrid", value: chartBenchmark.configurations[managedBenchmark ? "managed_hybrid" : "recorded_hybrid"]?.accuracy ?? 0 },
  ] : [];
  const confirmationCurrent = confirmation && reviews.some((review) =>
    review.action_id === confirmation.review.action_id &&
    review.preview.action_digest === confirmation.review.preview.action_digest &&
    review.preview.digest === confirmation.review.preview.digest
  );
  const confirmationExpired = confirmation ? new Date(confirmation.review.expires_at).getTime() <= now : false;

  async function decide(review: PendingReview, decision: "approve" | "deny") {
    setBusy(decision);
    try {
      await decideReview(review, decision);
      setConfirmation(null);
      await refresh();
    } catch {
      setError("The decision was rejected or expired. The action remains fail-closed.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="Leash dashboard home">
          <span className="brand__symbol"><i /><i /><i /></span>
          <span><strong>LEASH</strong><small>agent control plane</small></span>
        </a>
        <div className="topbar__status">
          <span className={`status-dot ${error ? "status-dot--down" : ""}`} />
          {error ? "Gateway offline" : "Gateway enforcing"}
          <span className="separator" />
          <span className="mono">{health?.environment ?? "connecting"}</span>
        </div>
      </header>

      <main id="top">
        <section className="hero">
          <div>
            <p className="eyebrow">LOCAL AUTHORITY · LIVE DECISIONS</p>
            <h1>The agent proposes.<br /><em>Leash decides.</em></h1>
            <p className="hero__copy">
              Every machine action is resolved, judged, and bound to an exact authorization
              before it reaches your workspace.
            </p>
          </div>
          <div className="metrics" aria-label="Action metrics">
            <Metric label="awaiting review" value={metrics.pending} tone="amber" />
            <Metric label="actions blocked" value={metrics.blocked} tone="red" />
            <Metric label="actions executed" value={metrics.executed} tone="green" />
          </div>
        </section>

        <section className="system-strip">
          <div><span>Spark actor</span><strong>{health?.actor_mode ?? "—"}</strong></div>
          <div><span>Wonder judge</span><strong>{health?.judge_mode ?? "—"}</strong></div>
          <div><span>Executor</span><strong>{health?.executor_mode ?? "—"}</strong></div>
          <div>
            <span>Audit integrity</span>
            <strong className={integrity.valid ? "text-green" : "text-red"}>
              {integrity.valid ? "verified" : "unverified"}
            </strong>
          </div>
          <div><span>Events chained</span><strong>{integrity.event_count}</strong></div>
        </section>

        <section className="telemetry-strip" aria-label="Model efficiency telemetry">
          <div><span>Wonder escalations</span><strong>{telemetry.wonder_escalations}</strong></div>
          <div><span>Actual Wonder calls</span><strong>{telemetry.wonder_calls}</strong></div>
          <div><span>Exact cache hits</span><strong>{telemetry.judge_cache_hits}</strong></div>
          <div><span>Locally avoided</span><strong>{telemetry.locally_avoided_judge_calls}</strong></div>
          <div><span>Model tokens</span><strong>{telemetry.total_tokens.toLocaleString()}</strong></div>
          <div>
            <span>Estimated cost</span>
            <strong>
              {telemetry.priced_model_calls > 0
                ? `$${telemetry.estimated_cost_usd.toFixed(4)}`
                : "unpriced"}
            </strong>
          </div>
        </section>

        <section className="latency-line" aria-label="Average stage latency">
          <span>Average stage latency</span>
          {Object.entries(telemetry.stage_latency).map(([stage, value]) => (
            <code key={stage}>{stage} {value.average_ms.toFixed(1)} ms</code>
          ))}
          {Object.keys(telemetry.stage_latency).length === 0 && <code>no samples yet</code>}
          {telemetry.budget_exhaustions > 0 && (
            <strong>{telemetry.budget_exhaustions} budget stop(s)</strong>
          )}
        </section>

        {error && <div className="error-banner" role="alert">{error}</div>}

        <section className="workspace">
          <aside className="feed-panel">
            <div className="panel-heading">
              <div><p className="eyebrow">ACTION STREAM</p><h2>Live decisions</h2></div>
              <span className="live-chip"><i /> live</span>
            </div>
            <div className="feed-list">
              {actions.map((action) => (
                <button
                  className={`feed-item ${selected?.actionId === action.actionId ? "feed-item--active" : ""}`}
                  key={action.actionId}
                  onClick={() => setSelectedId(action.actionId)}
                >
                  <span className={`feed-item__rail feed-item__rail--${action.decision ?? "pending"}`} />
                  <div className="feed-item__body">
                    <div><strong>{action.kind.replaceAll("_", " ")}</strong><DecisionPill decision={action.decision} /></div>
                    <p className="mono">#{shortId(action.actionId)} · {action.stage}</p>
                    <time>{formatTime(action.createdAt)}</time>
                  </div>
                </button>
              ))}
              {actions.length === 0 && (
                <div className="empty-state"><span>◎</span><strong>No actions yet</strong><p>Proposals will appear here as Leash evaluates them.</p></div>
              )}
            </div>
          </aside>

          <article className="detail-panel">
            <div className="panel-heading panel-heading--detail">
              <div>
                <p className="eyebrow">RESOLVED IMPACT</p>
                <h2>{selected ? `${selected.kind.replaceAll("_", " ")} proposal` : "Select an action"}</h2>
              </div>
              <DecisionPill decision={displayVerdict?.decision ?? null} />
            </div>

            {selectedReview && (
              <section className="task-card">
                <span>Immutable user task</span>
                <p>{selectedReview.task_text}</p>
              </section>
            )}

            {displayPreview ? (
              <>
                <PreviewFacts preview={displayPreview} />
                <ShellAnalysis preview={displayPreview} />
                <section className="detail-section">
                  <div className="section-heading"><span>Resolved targets</span><small>read-only preview</small></div>
                  <div className="target-list mono">
                    {displayPreview.resolved_targets.map((target) => <code key={target}>{target}</code>)}
                    {displayPreview.network_destination && <code>{displayPreview.network_destination}</code>}
                    {!displayPreview.resolved_targets.length && !displayPreview.network_destination && <p className="muted">No external target resolved.</p>}
                  </div>
                </section>
                <Evidence preview={displayPreview} verdict={displayVerdict} />
                <section className="digest-card">
                  <div><span>Action digest</span><code>{displayPreview.action_digest}</code></div>
                  <div><span>Preview digest</span><code>{displayPreview.digest}</code></div>
                </section>
              </>
            ) : (
              <div className="empty-state empty-state--large"><span>⌁</span><strong>Impact waits here</strong><p>Choose an evaluated action to inspect its exact targets, evidence, and authorization digests.</p></div>
            )}
          </article>

          <aside className="review-panel">
            <div className="panel-heading">
              <div><p className="eyebrow">HUMAN BOUNDARY</p><h2>Review queue</h2></div>
              <span className="queue-count">{reviews.length}</span>
            </div>
            {selectedReview ? (
              <div className="review-card">
                <div className="review-card__icon">!</div>
                <h3>Action paused</h3>
                <p>{selectedReview.verdict.explanation}</p>
                <div className="review-meta">
                  <span>Expires</span><strong>{formatTime(selectedReview.expires_at)}</strong>
                  <span>Decision source</span><strong>{selectedReview.verdict.source}</strong>
                </div>
                <div className="review-actions">
                  <button className="button button--deny" disabled={busy !== null} onClick={() => setConfirmation({ review: selectedReview, decision: "deny" })}>Deny</button>
                  <button className="button button--approve" disabled={busy !== null || !selectedReview.can_approve || new Date(selectedReview.expires_at).getTime() <= now} onClick={() => setConfirmation({ review: selectedReview, decision: "approve" })}>{selectedReview.can_approve ? "Approve exact action" : "Adapter unavailable"}</button>
                </div>
                <p className="capability-note">{selectedReview.capability_note}</p>
                <p className="review-note">Approval covers only the two digests shown. Any mutation forces a new review.</p>
              </div>
            ) : reviews.length > 0 ? (
              <div className="empty-state"><span>!</span><strong>{reviews.length} action(s) waiting</strong><p>Select a paused action in the feed to inspect and decide it.</p></div>
            ) : (
              <div className="empty-state"><span>✓</span><strong>Queue clear</strong><p>Routine work flows silently. Consequential ambiguity will pause here.</p></div>
            )}

            <div className="bench-card">
              <div>
                <span className="eyebrow">LEASHBENCH V1</span>
                <strong>{benchmark ? `${benchmark.case_count} cases` : "Evidence pending"}</strong>
              </div>
              {benchmark && hybridBenchmark && rulesBenchmark ? (
                <>
                  <div className="bench-compare">
                    <span>Rules only<strong>{(rulesBenchmark.accuracy * 100).toFixed(1)}%</strong></span>
                    <span>Recorded hybrid<strong>{(hybridBenchmark.accuracy * 100).toFixed(1)}%</strong></span>
                  </div>
                  <p>
                    Block recall {(hybridBenchmark.block_recall * 100).toFixed(0)}% · unsafe
                    allows {(hybridBenchmark.unsafe_allow_rate * 100).toFixed(0)}%. Recorded
                    Wonder replay—not a live model measurement.
                  </p>
                  {managedBenchmark && <p><strong>Managed sample:</strong> {managedBenchmark.case_count} development cases · {managedBenchmark.model}. Separate from the 60-case replay above.</p>}
                  <div className="bench-chart" role="img" aria-label={`Three-class accuracy comparison across ${chartBenchmark?.case_count ?? 0} ${managedBenchmark ? "managed development sample" : "recorded replay"} cases`}>
                    {benchmarkBars.map((bar) => <div className="bench-chart__row" key={bar.label}>
                      <span>{bar.label}</span>
                      <div className="bench-chart__track"><i style={{ width: `${Math.min(100, Math.max(0, bar.value * 100))}%` }} /></div>
                      <strong>{(bar.value * 100).toFixed(0)}%</strong>
                    </div>)}
                  </div>
                  <p>{managedBenchmark ? "Managed Wonder sample · six preselected development cases; no held-out model score." : "Recorded replay · no live model measurement."}</p>
                </>
              ) : (
                <>
                  <p>No reproducible benchmark report is available yet.</p>
                  <span className="progress"><i /></span>
                </>
              )}
            </div>
          </aside>
        </section>
      </main>

      {confirmation && <div className="dialog-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setConfirmation(null); }}>
        <section className="decision-dialog" role="dialog" aria-modal="true" aria-labelledby="decision-dialog-title">
          <p className="eyebrow">EXACT ACTION REVIEW</p>
          <h2 id="decision-dialog-title">{confirmation.decision === "approve" ? "Approve this action?" : "Deny this action?"}</h2>
          <p>{confirmation.review.verdict.explanation}</p>
          <dl>
            <dt>Action</dt><dd>{confirmation.review.kind.replaceAll("_", " ")} #{shortId(confirmation.review.action_id)}</dd>
            <dt>Task</dt><dd>{confirmation.review.task_text}</dd>
            <dt>Resolved impact</dt><dd>{confirmation.review.preview.affected_file_count} files · {formatBytes(confirmation.review.preview.affected_bytes)} · {confirmation.review.preview.network_destination ?? "local"}</dd>
            <dt>Expires</dt><dd>{formatTime(confirmation.review.expires_at)}</dd>
            <dt>Action digest</dt><dd className="mono">{confirmation.review.preview.action_digest}</dd>
            <dt>Preview digest</dt><dd className="mono">{confirmation.review.preview.digest}</dd>
          </dl>
          {(!confirmationCurrent || confirmationExpired) && <p className="text-red" role="alert">This review expired or changed. Refresh before deciding.</p>}
          <div className="dialog-actions">
            <button className="button button--deny" onClick={() => setConfirmation(null)}>Cancel</button>
            <button className={`button button--${confirmation.decision === "approve" ? "approve" : "deny"}`} disabled={busy !== null || !confirmationCurrent || confirmationExpired || (confirmation.decision === "approve" && !confirmation.review.can_approve)} onClick={() => void decide(confirmation.review, confirmation.decision)}>{busy ? "Submitting…" : `Confirm ${confirmation.decision}`}</button>
          </div>
        </section>
      </div>}

      <footer>
        <span>Leash holds the capability. Models provide signals.</span>
        <span className="mono">{lastUpdated ? `updated ${formatTime(lastUpdated.toISOString())}` : "connecting"}</span>
      </footer>
    </div>
  );
}
