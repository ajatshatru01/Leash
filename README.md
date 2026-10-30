# Leash

Leash is a local policy-enforcement gateway for coding agents. Muse Spark proposes typed actions; Leash previews and evaluates them, sends only sanitized context to an independent Muse Wonder session for ambiguous semantic judgment, and retains local control over execution.

The project is being built for the Meta Global AI Developer Hackathon. See:

- [`hackathoninfo.md`](hackathoninfo.md) for competition requirements;
- [`ARCHITECTURE.md`](ARCHITECTURE.md) for threat model and system design;
- [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) for milestones and stack;
- [`AGENTS.md`](AGENTS.md) for contributor constraints;
- [`docs/PROJECT_AUDIT.md`](docs/PROJECT_AUDIT.md) for evidence-backed status and gaps;
- [`docs/THIRD_PARTY_NOTICES.md`](docs/THIRD_PARTY_NOTICES.md) for dependency provenance.

## Local configuration

The dedicated local secrets file is [`.env`](.env). It is already created and ignored by Git.
The committed [`.env.example`](.env.example) documents every setting without containing secrets.

1. Add the Meta Model API key after `MODEL_API_KEY=` in `.env`. The same key serves Spark and Wonder.
2. Keep `LEASH_ACTOR_MODE=recorded` and `LEASH_JUDGE_MODE=recorded` during routine development.
3. Change `LEASH_REDACTION_KEY` before recording the demo.
4. Never commit `.env` or paste keys into chat, logs, screenshots, fixtures, or benchmark output.

Check key presence without printing either value:

```powershell
.\.venv\Scripts\leash.exe config-status
```

Verify live access to both Meta models without printing prompts, responses, or keys:

```powershell
.\.venv\Scripts\leash.exe check-models --confirm-spend
```

The command is inert until `--confirm-spend` is supplied. One run makes one Spark request and one
Wonder request, with at most one additional Wonder retry after invalid schema output. It never
executes Spark's fixture proposal and writes only model IDs, request/token counts, schema status,
and latency to ignored `data/meta-model-validation.json`.

The sanitized October 30 validation evidence is checked in at
[`docs/evidence/meta-model-validation.json`](docs/evidence/meta-model-validation.json). It contains
no API key, prompts, model responses, task text, or workspace content.

Verify that the configured key has not escaped ignored secret files:

```powershell
.\.venv\Scripts\leash.exe secret-audit
```

Run a harmless proposal through the real isolated Docker executor:

```powershell
.\.venv\Scripts\leash.exe check-executor
```

Run the inert local exfiltration proof without any external traffic:

```powershell
# Terminal 1
.\.venv\Scripts\leash.exe capture-receiver

# Terminal 2
.\.venv\Scripts\leash.exe serve

# Terminal 3
.\scripts\egress-demo.ps1
```

See [`docs/EGRESS_DEMO.md`](docs/EGRESS_DEMO.md) for the expected zero-egress evidence.

Run the frozen 60-case LeashBench suite without executing proposals or calling model APIs:

```powershell
.\.venv\Scripts\leash.exe bench --split all
```

This rebuilds the checked-in raw JSONL and summary JSON used by the dashboard. The initial
`recorded_wonder_only` and `recorded_hybrid` configurations replay frozen semantic verdicts; they
are test-harness evidence, not a live Muse Wonder quality measurement. See
[`docs/LEASHBENCH.md`](docs/LEASHBENCH.md) for schemas, metrics, splits, and limitations.

Run the separate six-case, development-only managed Wonder sample with:

```powershell
.\.venv\Scripts\leash.exe bench-live --confirm-spend
```

This makes at most twelve API requests and never executes a proposal. Its raw JSONL and summary
are checked in under `bench/reports/`. Wonder receives the sanitized preview without rule findings;
the hybrid row combines the same Wonder decision with local rules. The October 31 sample scored
5/6 for rules-only, 5/6 for Wonder-only, and 6/6 for the hybrid. It is exploratory and is not a
held-out 60-case model score.

Build the local dashboard into the Python package, then serve it from the same FastAPI process:

```powershell
.\.venv\Scripts\leash.exe serve
```

The compiled dashboard is checked in under `src/leash/static`, so a clean checkout only needs
the Python environment to run the one-command demo. Rebuild after changing the React source with
`pnpm --dir apps/dashboard install --frozen-lockfile` and
`pnpm --dir apps/dashboard run build`. After changing API contracts, run
`.\.venv\Scripts\python.exe scripts\generate_api_types.py` first; the test suite checks that
the generated dashboard response types match FastAPI's OpenAPI schema.

Open `http://127.0.0.1:8765`. The dashboard polls the local gateway for the redacted action feed,
pending reviews, resolved impact, and audit integrity. It never receives raw proposal bodies or
file contents. Approval is disabled when no real adapter exists for an action kind. A confirmation
dialog shows the exact action and preview digests and disables submission on expiry or changed review data.
The benchmark chart reads generated summary artifacts, with the managed sample labeled separately
from the 60-case recorded replay.

## Development

```powershell
python -m uv sync --python 3.12
.\.venv\Scripts\pytest.exe
.\.venv\Scripts\leash.exe serve
```

The API listens on `http://127.0.0.1:8765` by default. `GET /health` reports whether keys are configured without revealing them.

`POST /v1/agent/run` starts the bounded Spark proposal loop. In the committed default
configuration it returns a recorded response and makes no provider request. A deliberate live run
requires changing `LEASH_ACTOR_MODE` to `managed`; Leash will then expose only typed proposal
tools plus bounded read-only inspection tools, never its executor or machine
credentials.

`GET /v1/telemetry` returns audit-derived token, configured-cost, cache, escalation, avoided-call,
budget-stop, and stage-latency metrics. Cost remains explicitly `unpriced` in the dashboard until
the optional per-million-token rates in `.env` are configured; Leash does not hard-code provider
prices that can change.

## Implemented foundation

The current key-independent vertical slice includes:

- strict, versioned proposals for shell, file-write, HTTP, and git-push actions;
- a bounded Spark actor loop with proposal-only tools, immutable task binding, denial feedback,
  deterministic history compaction, bounded recent receipts, session token/step budgets,
  secret-redacted history, single-action turns, and fail-closed provider/gateway errors;
- bounded file inspection, workspace listing, literal search, and Git-status tools that reject
  protected paths, escapes, oversized reads, excessive depth, and unredacted secret output;
- hash-bound single-replacement patches that recheck the inspected file digest immediately before
  an atomic write and deterministically reject stale or non-unique edits;
- canonical impact previews with local secret redaction and protected-path handling;
- bounded destructive impact resolution for direct, nested, chained, globbed, and PowerShell-
  encoded command shapes, including concrete file/byte counts and link-escape evidence;
- deterministic `allow`, `review`, and `block` policy precedence;
- recorded and unavailable judge modes plus a strict Muse Wonder adapter;
- selective Wonder escalation with per-session call budgets and exact sanitized-packet caching;
- cache keys bound to the Wonder model plus prompt and deterministic-policy versions;
- fail-closed handling for provider failures and invalid Muse Wonder output;
- an explicit action state machine and digest-verifying executor boundary;
- a pinned Docker shell profile with no network, read-only workspace, non-root user,
  empty host-secret environment, dropped capabilities and bounded resources/output;
- an atomic local file-write adapter bound to the authorized action and preview digests;
- an inspected loopback HTTP adapter with a host/port allowlist, no redirects, bounded payloads,
  redacted responses, and an inert hash-and-counter-only capture receiver;
- expiring, digest-bound human approvals with denial and replay protection;
- a redacted, hash-chained SQLite audit feed and integrity verifier;
- audit events for provider calls, cache hits, deterministic avoided calls, budget stops, token
  usage, configured cost estimates, and per-stage latency;
- a responsive React dashboard with live decisions, exact impact, redacted evidence, capability-
  aware approve/deny controls, audit-chain health, model-efficiency telemetry, and generated
  LeashBench comparison evidence;
- a frozen 60-case LeashBench v1 corpus with family-level results, a 48/12 development/final split,
  three-class confusion matrices, block precision/recall/F1, false-block and unsafe-allow rates,
  deterministic bootstrap intervals, stage p50/p95 latency, and machine-readable raw artifacts;
- FastAPI health, evaluation, action-event, telemetry, and audit-verification endpoints; and
- strict Ruff/Pyright checks plus security-focused tests.

The Docker profile deliberately supports only Python version checks, `unittest` runs, and bounded
`compileall` validation. Inspected
loopback HTTP is implemented; Git push remains unavailable until its typed adapter is built.
Pending reviews and the exact-packet judge cache are held only in memory, so a restart invalidates
them and fails closed. The managed benchmark is currently a six-case development sample; the
60-case Wonder comparison remains a disclosed recorded replay.

The recorded-provider test suite includes two complete coding sequences: inspect → patch → validate,
and inspect poisoned content → block credential egress → apply a safe hash-bound patch. Neither
sequence makes a managed model request.

Run the inert encoded-destruction demo with:

```powershell
.\scripts\destruction-demo.ps1
```

It decodes a PowerShell cleanup payload, resolves its fixture-only glob, reports three files and 89
bytes at risk, blocks the proposal, and verifies every file remains present. See
`docs/DESTRUCTION_DEMO.md` for the exact scenario and expected output.

