# Leash

Leash is a local policy-enforcement gateway for coding agents. Muse Spark proposes typed actions; Leash previews and evaluates them, sends only sanitized context to an independent Muse Wonder session for ambiguous semantic judgment, and retains local control over execution.

The project is being built for the Meta Global AI Developer Hackathon. See:

- [`hackathoninfo.md`](hackathoninfo.md) for competition requirements;
- [`ARCHITECTURE.md`](ARCHITECTURE.md) for threat model and system design;
- [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) for milestones and stack;
- [`AGENTS.md`](AGENTS.md) for contributor constraints.

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
.\.venv\Scripts\leash.exe check-models
```

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

Build the local dashboard and serve it from the same FastAPI process:

```powershell
pnpm --dir apps/dashboard install --frozen-lockfile
pnpm --dir apps/dashboard run build
.\.venv\Scripts\leash.exe serve
```

Open `http://127.0.0.1:8765`. The dashboard polls the local gateway for the redacted action feed,
pending reviews, resolved impact, and audit integrity. It never receives raw proposal bodies or
file contents. Approval is disabled when no real adapter exists for an action kind.

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
  aware approve/deny controls, audit-chain health, and model-efficiency telemetry;
- FastAPI health, evaluation, action-event, telemetry, and audit-verification endpoints; and
- strict Ruff/Pyright checks plus security-focused tests.

The Docker profile deliberately supports only Python version checks, `unittest` runs, and bounded
`compileall` validation. Inspected
loopback HTTP is implemented; Git push remains unavailable until its typed adapter is built.
Pending reviews and the exact-packet judge cache are held only in memory, so a restart invalidates
them and fails closed. Expanded impact previews and LeashBench are the next implementation stages.

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

