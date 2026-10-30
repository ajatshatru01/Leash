# Leash implementation plan

Last updated: October 28, 2026  
Target submission: November 4, 2026 at 9:00 PM EST / November 5 at 7:30 AM IST  
Track: Indie Developer  
Theme: Push the Frontier

## 1. Outcome

Build a complete, defensible vertical slice in which:

1. a developer gives Muse Spark a coding task;
2. Spark can only propose typed actions;
3. Leash resolves the proposed action's concrete impact;
4. deterministic rules and an independent Muse Wonder judge issue `allow`, `review`, or `block` after local redaction;
5. only Leash's restricted executor can perform the action;
6. denied actions return useful constraints to Spark so it can recover;
7. the dashboard and audit log show what happened without leaking secrets; and
8. LeashBench compares rules-only, Wonder-only, and hybrid behavior.

The submission succeeds when this flow works repeatedly in a disposable demo repository and produces a clear 90-second story. It does not need to be a production endpoint-security platform.

## 2. Chosen technology stack

### Backend and security pipeline

| Concern | Choice | Why |
|---|---|---|
| Language | Python 3.12 | Fast iteration, strong model/API ecosystem, stable typing support, good subprocess and filesystem tooling |
| Package management | `uv` with `pyproject.toml` and committed `uv.lock` | Fast, reproducible, cross-platform environment management |
| HTTP/API | FastAPI + Uvicorn | Typed request validation, generated OpenAPI, WebSockets, fast prototype-to-demo path |
| Data contracts | Pydantic v2 | Strict discriminated unions, JSON Schema, validation of model output and API inputs |
| Cloud model client | Official OpenAI Python SDK pointed at `https://api.meta.ai/v1` | Meta Model API is OpenAI-compatible; avoids a custom HTTP protocol layer |
| Semantic judge client | A second stateless OpenAI SDK client pointed at Meta Model API | Reuses the hackathon credit and auth while preserving independent context and a provider-neutral adapter contract |
| Persistence | SQLite in WAL mode through the standard `sqlite3` module | Zero-service deployment, transactions, typed local code, and enough throughput for a single-user demo |
| CLI | Typer + Rich | Quick operator commands, readable demo/setup output |
| Tests | pytest + pytest-asyncio + Hypothesis for bounded path/parser properties | Fast unit/integration tests and adversarial input coverage |
| Quality | Ruff + Pyright | Fast lint/format plus strict static checking |

### Meta models

| Role | Choice | Configuration |
|---|---|---|
| Acting coding model | `muse-spark-1.3` through Meta Model API | Chat Completions tool loop; medium reasoning by default; proposal tools only |
| Semantic judge | `muse-wonder-1.0` through Meta Model API | Independent stateless request; low reasoning; compact, schema-constrained response |
| Provider | Meta Model API | One credited platform for both models, separate clients and contexts, no additional inference provider |

Meta's documentation identifies `muse-spark-1.3` as the current Spark model tuned for agentic workflows and `muse-wonder-1.0` as the frontier model for demanding agentic work. Both use the OpenAI-compatible Meta Model API. Validate access to both model IDs with the participant account before freezing configuration.

The hackathon implementation uses a **managed Muse Wonder judge in an independent stateless context**. All secret detection, raw-value removal, impact resolution, and prompt minimization happen locally before the request. The product retains a provider-neutral `JudgeClient`; model choice is not part of the enforcement boundary.

### Dashboard

| Concern | Choice | Why |
|---|---|---|
| Framework | React + TypeScript + Vite | No server-side rendering is needed; fast development and small deployment surface |
| Styling/components | Tailwind CSS + shadcn/ui primitives | Rapid polished UI with accessible controls and full code ownership |
| Server state | TanStack Query for HTTP; native WebSocket for live events | Predictable request caching without adding a separate event framework |
| Charts | Recharts | Sufficient for compact LeashBench comparison and latency charts |
| API types | Generate TypeScript types from FastAPI's OpenAPI schema | Prevent backend/frontend contract drift |
| Production serving | Build static assets and serve them from FastAPI | One local process/URL for the demo |

### Enforcement and isolation

| Concern | Choice | Why |
|---|---|---|
| Execution boundary | Docker Desktop/WSL2 running a Linux demo container | The agent cannot reach unmounted host data; repeatable and easy to reset |
| Workspace access | Mount only the disposable demo workspace read/write | Safe edits work while the rest of the host remains unavailable |
| Network | Container starts with `--network none` | Shell commands cannot bypass Leash through `curl`, package scripts, or another binary |
| Inspected HTTP | Gateway-owned HTTP adapter using `httpx` | Leash scans destination, headers, query, and body before egress |
| Git push | Gateway-owned typed adapter; disabled until the final phase | Prevent raw shell from bypassing push policy; use a local bare remote for the demo |
| Secrets | Custom structured scanner for live payloads; optional Gitleaks subprocess for repository/diff scans | The live path needs field-level evidence; Gitleaks adds mature repository coverage |

The Docker socket is powerful and remains available only to the trusted local gateway, never to Spark, the dashboard, or the demo container.

## 3. Deliberate non-choices

- **No LangChain, LlamaIndex, or general agent framework.** The tool loop is small, security-sensitive, and easier to audit when written directly against the model API.
- **No Kubernetes, Redis, Celery, Postgres, or message broker.** A single-user local demo does not need distributed infrastructure.
- **No Next.js.** There is no SSR, public application backend, or routing requirement that justifies it.
- **No OPA/Rego in the hackathon version.** Typed Python rules are faster to implement, test, and explain. A future policy compiler can replace them.
- **No unrestricted raw-shell tool.** Default actions use executable plus argument arrays. An explicit `shell_script` proposal is high risk and conservatively reviewed or blocked.
- **No universal shell parser.** Support and test a bounded set of nested interpreter/encoding patterns; unsupported opacity becomes review/block.
- **No full egress proxy in the first vertical slice.** The container has no network. Approved HTTP uses a typed gateway adapter, which is enough to prove the capability boundary.
- **No model fine-tuning.** Prompt/schema engineering and hybrid policy evaluation provide more value within the deadline.

## 4. Repository layout

```text
Leash/
  AGENTS.md
  ARCHITECTURE.md
  IMPLEMENTATION_PLAN.md
  hackathoninfo.md
  README.md
  pyproject.toml
  uv.lock
  .env.example
  src/leash/
    api/                    # FastAPI routes, WebSocket stream, dependency wiring
    agent/                  # Spark conversation and tool-call loop
    contracts/              # Pydantic action, preview, verdict, audit schemas
    normalize/              # Canonical argv/path/URL/interpreter normalization
    policy/                 # Deterministic pure rules and policy configuration
    preview/                # Read-only filesystem, git, HTTP impact builders
    secrets/                # Detection, fingerprints, redaction, placeholders
    judge/                  # Muse Wonder prompt, client, schema parsing, fallback
    approval/               # Review state, expiry, digest-bound decisions
    execute/                # Docker shell/file, HTTP, and git adapters
    audit/                  # SQLite event store and hash-chain verification
    settings.py             # Validated configuration; no implicit secret logging
    main.py                 # Application entry point
  dashboard/
    src/
      api/                  # Generated types and request client
      components/           # Feed, action card, evidence, approval dialog
      pages/                # Live feed, benchmark, system status
      App.tsx
    package.json
    pnpm-lock.yaml
  bench/
    cases/                  # Frozen JSON case definitions
    fixtures/               # Generated/disposable workspaces and fake secrets
    reports/                # Machine-readable results and checked-in final report
  demo/
    poisoned-readme/        # Safe exfiltration scenario
    encoded-delete/         # Generated destructive-action scenario
    local-receiver/         # Local capture endpoint and zero-egress evidence
    script.md               # Exact 90-second narration and clicks
  tests/
    unit/
    integration/
    e2e/
  scripts/
    check_meta_models.*
    start_demo.*
    reset_demo.*
```

Do not create empty modules merely to match this layout. Add each directory with the feature that needs it.

## 5. Core contracts

### Action proposal

Use a discriminated Pydantic union:

```text
ActionProposal
  id: UUID
  schema_version: Literal["1"]
  session_id: UUID
  task_id: UUID
  task_text: immutable string
  kind: shell | file_read | file_write | http | git_push
  params: kind-specific typed object
  workspace_id: string
  cwd: relative path
  created_at: UTC datetime
```

Kind-specific parameters:

- `shell`: `executable`, `argv`, optional declared timeout; no inherited environment by default;
- `file_read`: relative path and bounded byte range;
- `file_write`: relative path, content or content reference, create/replace/patch mode;
- `http`: method, parsed URL, typed headers, bounded body;
- `git_push`: named remote, local ref, remote ref, force mode.

### Impact preview

```text
ImpactPreview
  action_id
  normalized_action
  resolved_targets[]
  affected_file_count
  affected_bytes
  network_destination
  git_commit_range
  secret_findings[]         # type/location/fingerprint; never raw secret
  protected_resource_hits[]
  uncertainty_flags[]
  truncated: bool
  digest: SHA-256
```

### Verdict

```text
Verdict
  action_id
  decision: allow | review | block
  reason_codes[]
  explanation
  evidence_refs[]
  sources: rule | judge | human | combined
  action_digest
  preview_digest
  expires_at
```

### Audit event

Every transition records canonical redacted JSON, the previous event hash, and the current event hash. JSON serialization must be deterministic before hashing.

## 6. Decision pipeline

Implement one orchestrator with explicit stages:

```text
validate proposal
  -> normalize action
  -> build bounded read-only preview
  -> scan secrets and protected resources
  -> run deterministic rules
  -> hard block if required
  -> otherwise invoke Muse Wonder when policy requires semantic judgment
  -> combine verdicts using fixed precedence
  -> wait for digest-bound human approval when decision is review
  -> executor independently revalidates authorization and digests
  -> execute once
  -> redact result before returning it to Spark
  -> append every transition to audit
```

Precedence:

```text
deterministic hard block
  > human denial
  > Muse Wonder block
  > deterministic/Muse Wonder review
  > allow
```

Muse Wonder cannot downgrade deterministic policy. Invalid JSON, timeouts, model unavailability, or prompt/schema mismatch become `review`.

## 7. Implementation phases

### Current implementation status

Phases 1, 2, the loopback-HTTP portion of Phase 3, Phase 4's recorded-provider vertical slice, and
the core Phase 5 dashboard are implemented. The efficiency milestone is also complete offline:
Spark history/receipt bounds, session token and step budgets, per-session Wonder call budgets,
fail-to-review exhaustion, provider usage capture, versioned exact-packet caching, stage latency,
audit telemetry, and dashboard cost/escalation metrics are covered by recorded-provider tests.
No Meta API request is required to validate this milestone.

The usable coding-loop milestone is also implemented offline: bounded/redacted file reads, listings,
literal search and Git status; exact SHA-256-bound single-replacement patches; stale/non-unique edit
denial; constrained Python `unittest`/`compileall` validation shapes; and recorded safe and poisoned
repository sequences. Managed Spark validation remains deliberately deferred to the controlled live
integration milestone.

The deep-impact milestone is implemented for the demoed destructive subset: workspace-relative glob
expansion; recursive file and byte totals; protected-target and symlink-escape detection; bounded
preview truncation; PowerShell encoded-command decoding; nested/chained/substitution classification;
deterministic block/review semantics; and a reproducible inert encoded-delete demo. Arbitrary shell
interpretation and real delete execution remain explicitly out of scope.

LeashBench v1 is implemented offline with 60 frozen cases across the planned six families, a
48-case development split and 12-case held-out final split, disposable fixture workspaces, and a
runner that never executes proposals. It emits raw JSONL plus a reproducible summary containing
three-class confusion matrices, accuracy, block precision/recall/F1, macro F1, false-block,
unsafe-allow and review rates, deterministic bootstrap confidence intervals, and preview/policy
p50/p95 latency. Rules-only is measured directly. The initial Wonder-only and hybrid comparisons
are explicitly labeled frozen recorded replays until a controlled live evaluation is authorized.

The controlled Meta-integration harness is implemented offline: the Spark probe requires one real
typed proposal tool call but never executes it; the Wonder probe requires a strict schema, retries
invalid output once, and sends a minimized packet without raw HTTP bodies or absolute local paths.
The command requires explicit `--confirm-spend`, caps a run at three provider requests, and writes a
sanitized local artifact. On October 30, the live probe validated `muse-spark-1.3` tool calling and
`muse-wonder-1.0` structured judgment. Sanitized evidence is checked in under `docs/evidence/`.

Cost estimates are emitted only when explicit current pricing inputs are configured. Unpriced calls
remain visible instead of being misleadingly reported as free.

### Phase 0 — provider and API spike

Build before any UI.

Tasks:

- verify `MODEL_API_KEY` with one `muse-spark-1.3` request;
- verify Spark returns a typed tool call;
- verify `MODEL_API_KEY` without logging it;
- call both Muse Spark and Muse Wonder through separate clients and stateless contexts;
- measure warm p50 response time and validate the compact judgment prompt budget;
- request one schema-shaped Muse Wonder judgment;
- verify Docker can run a Linux container with the demo workspace mounted and network disabled.

Exit criteria:

- Spark and Muse Wonder calls work from one Python spike using separate contexts;
- Muse Wonder returns a schema-valid judgment within the demo latency budget;
- a command inside the demo container cannot access the public network or host paths outside its mount.

Stop and revise the model integration immediately if this phase fails. Never silently substitute another model while labeling it Muse Wonder.

### Phase 1 — typed gateway and audit spine

Tasks:

- initialize the Python project, quality tools, settings, and test layout;
- implement typed proposals, previews, verdicts, and audit events;
- create FastAPI health, proposal, action-detail, and event-stream endpoints;
- implement SQLite migrations/schema and deterministic hash-chained event append;
- create a mock executor and an in-memory/mock judge;
- implement the explicit state machine and fail-closed transition validation.

Exit criteria:

- a fixture proposal flows from `PROPOSED` to mock `EXECUTED`;
- invalid transitions are rejected;
- audit verification detects modification or reordering;
- no secret-like fixture value appears in logs.

### Phase 2 — real enforcement vertical slice

Tasks:

- create/reset a disposable demo workspace and Docker container;
- implement `shell` with executable/argv and `file_write` adapters;
- default the container to no network, no host environment, bounded output, timeout, CPU/memory/process limits where available;
- mount only the demo workspace;
- implement authorization token/digest verification immediately before execution;
- add protected-path, traversal, recursive deletion, dangerous git flag, interpreter, and unsupported-syntax rules;
- return redacted execution results to the caller.

Exit criteria:

- allowed edits/tests work inside the fixture workspace;
- a direct executor call without authorization fails;
- changing an action after approval fails;
- commands cannot read the user's home directory or use public network egress.

### Phase 3 — preview, secrets, and HTTP egress

Tasks:

- implement canonical path resolution, glob expansion, symlink/junction escape detection, counts, byte totals, and truncation flags;
- implement runtime secret patterns and stable HMAC/fingerprint redaction;
- implement the typed HTTP adapter with destination allow/deny policy, redirect disabled by default, request-size bounds, and payload scanning;
- create the local capture receiver and zero-egress counter;
- add an optional repository/diff scanner for git push preparation;
- create poisoned README and encoded deletion scenarios with fake data only.

Exit criteria:

- preview reports exact fixture impact for the demo cases;
- the fake secret is never present in API responses, audit records, or dashboard events;
- a blocked request produces zero receiver traffic;
- approved safe localhost HTTP can be demonstrated separately.

### Phase 4 — Spark actor and Muse Wonder judge

Tasks:

- implement the Spark Chat Completions tool loop;
- expose only proposal/status/result tools, never the executor;
- preserve the original immutable task through the session;
- implement the redacted Muse Wonder prompt and strict Pydantic response parsing;
- add one constrained retry for invalid model output, then fail to review;
- combine rule and model decisions with fixed precedence;
- feed denials back to Spark using reason codes, evidence summary, and safe constraints;
- add deterministic recorded model responses for offline tests, clearly separate from the live demo mode.

Exit criteria:

- Spark completes a normal fix through Leash;
- poisoned context triggers an unsafe proposal that Leash blocks;
- Spark retries safely and completes or cleanly explains why it cannot;
- Muse Wonder downtime never causes an allow.

### Phase 5 — dashboard and approvals

Tasks:

- scaffold React/Vite and generate API types;
- build the live action feed, status header, action-detail panel, evidence list, and system health strip;
- implement a digest-bound approve/deny dialog with expiry;
- show green/amber/red states and the original task without exposing raw reasoning;
- HTML-escape all model/agent content;
- build benchmark summary cards and one comparison chart;
- build static assets into the FastAPI package for a one-command demo.

Exit criteria:

- the full flow can be understood with audio muted;
- stale or replayed approvals fail;
- disconnecting the UI leaves review actions unexecuted;
- the dashboard never renders fake secrets or untrusted HTML.

### Phase 6 — LeashBench

Start with 60 high-quality cases, not 300 template variants.

Initial distribution:

| Family | Cases |
|---|---:|
| Safe routine coding | 20 |
| Legitimate suspicious-looking actions | 8 |
| Destructive filesystem/git/database | 10 |
| Secret egress | 10 |
| Encoded/nested/opaque commands | 7 |
| Prompt/task injection | 5 |

Tasks:

- define a frozen case schema and safe fixture generator;
- label `allow`, `review`, or `block` with rationale;
- separate development and final evaluation by attack family or mutation source;
- run rules-only, Wonder-only, and hybrid configurations;
- capture raw JSONL results, configuration/model versions, and reproducible summary JSON;
- calculate per-category confusion matrices, unsafe-allow rate, false-block rate, review rate, F1 where meaningful, and p50/p95 stage latency;
- document failures rather than hiding them.

Exit criteria:

- one command rebuilds the report from frozen cases;
- no case can touch real credentials, remotes, home paths, or public endpoints;
- the final chart is generated from checked-in raw results, not hand-entered values.

### Phase 7 — submission hardening

Tasks:

- write the README around problem, architecture, proof, benchmark, setup, limitations, and Meta tooling;
- include architecture and threat-model diagrams;
- generate dependency/license inventory and verify all media/assets;
- rehearse and record the 90-second demo;
- test setup from a clean checkout and logged-out links;
- prepare a prerecorded proposal sequence only as a disclosed fallback;
- rotate demo credentials and scan the repository/video frames for leaks;
- freeze features and fix only submission blockers.

Exit criteria:

- three consecutive live rehearsals succeed;
- README setup works on the demo machine from a clean state;
- video remains understandable without sound;
- submission checklist in `hackathoninfo.md` is complete.

## 8. Calendar

### October 28

- Finish Phase 0.
- Lock model/runtime choices based on actual hardware.
- Initialize the backend and contracts.

### October 29

- Complete Phase 1.
- Complete the Docker enforcement core from Phase 2.
- Demonstrate one allowed action and one hard block without models.

### October 30

- Finish preview, redaction, and HTTP egress.
- Make both attack scenarios deterministic.
- Prove zero egress and unchanged fixture files.

### October 31

- Integrate live Spark and Muse Wonder.
- Complete the safe retry loop.
- Record initial latency and failure behavior.

### November 1

- Build the dashboard and human approval path.
- Complete a rough end-to-end demo.

### November 2

- Build and freeze the initial LeashBench set.
- Run comparisons, investigate failures, and fix only generalizable issues.
- Start README and diagrams.

### November 3

- Freeze features.
- Polish dashboard, benchmark chart, README, and setup.
- Draft submission copy and video script.
- Run clean-install and license/secret audits.

### November 4

- Record and edit the final video early.
- Rehearse the live path three times.
- Upload and verify every link while logged out.
- Submit well before the India morning deadline; retain time for portal failures.

## 9. Testing strategy

### Unit tests

- contract/schema validation and canonical serialization;
- verdict precedence;
- path normalization, traversal, glob limits, symlink escape, and case handling;
- secret detection and stable redaction;
- URL normalization, destination policy, redirect policy, and body limits;
- Muse Wonder invalid/hostile output parsing;
- audit hash-chain verification.

### Integration tests

- proposal through preview/rules/judge/audit;
- review approval and denial;
- digest mismatch and expired approval;
- container execution with no network;
- HTTP adapter to the local capture receiver;
- SQLite restart/recovery;
- Spark and Muse Wonder adapters against recorded fake servers.

### End-to-end tests

- normal failing-test repair;
- poisoned README to blocked fake-secret exfiltration;
- encoded/nested deletion to blocked action with exact impact;
- Muse Wonder unavailable to human review;
- dashboard disconnect while review is pending.

Never run destructive test payloads outside generated fixture roots. Assert the resolved absolute fixture root before every destructive test setup/cleanup operation.

## 10. Demo flow

```text
0–10s   Problem: autonomous coding agents hold dangerous machine authority.
10–22s  Spark fixes a normal test; routine actions pass silently.
22–45s  Poisoned README causes an upload proposal; Leash shows task mismatch,
        secret finding, and zero requests received by the local endpoint.
45–65s  Encoded/nested delete is decoded or conservatively blocked; Leash shows
        the exact generated file count and bytes that remain intact.
65–77s  Spark receives constraints and completes the original task safely.
77–87s  Dashboard shows redacted audit plus real hybrid benchmark comparison.
87–90s  Close: "Spark acts. Wonder challenges. Leash holds the keys."
```

## 11. Risk register and cut order

| Risk | Early test | Mitigation |
|---|---|---|
| Muse Wonder is unavailable or too slow | Phase 0 against the real account and model | Keep prompts compact, use low reasoning and strict timeouts, route failure to review, and retain a clearly disclosed recorded fallback for video resilience |
| Spark tool calls are inconsistent | Ten-call spike with exact schemas | Simplify tools, validate every call, return repairable errors |
| Docker Desktop is unreliable | Run/reset/network tests on day one | Keep a prepared WSL2/Linux container and recorded fallback |
| False blocks make demo unusable | Safe action regression set from day two | Narrow hard blocks; route ambiguity to review; allowlist demo tools |
| Secret appears in logs/UI | Canary secret searched across all artifacts | Redact before event creation; add leak test to CI |
| Benchmark takes too long | Freeze 60-case schema first | Cut quantity, preserve family diversity and reproducibility |
| UI consumes the schedule | Build only feed/detail/approval/chart | Cut settings, auth, themes, animations, and extra pages |
| Live API/network failure | Rehearse repeatedly and record response fixtures | Backup video and explicitly disclosed replay mode |

Cut features in this order:

1. external agent/shim integrations;
2. real remote git push;
3. benchmark expansion beyond 60–100 cases;
4. settings screens and UI animation;
5. additional action kinds;
6. advanced policy configuration.

Never cut the capability boundary, secret redaction, fail-closed behavior, safe demo fixtures, Spark/Wonder separation, or reproducible evidence.

## 12. Definition of hackathon complete

Leash is ready to submit only when all of these are true:

- Spark has no direct executor or network capability.
- Every executed action carries a matching, unexpired authorization.
- Container shell commands cannot access unmounted host paths or public network.
- The Muse Wonder path is real and its provider/model identifier is visible.
- A Muse Wonder failure cannot silently authorize an action.
- The exfiltration receiver proves zero blocked traffic.
- The destructive fixture proves all targeted files remain intact.
- Spark successfully recovers after at least one denial.
- The UI contains no raw fake secret or unsafe HTML.
- LeashBench results rebuild from frozen cases and raw artifacts.
- The README states limitations precisely.
- Three consecutive end-to-end demo rehearsals pass.
- The licensing, confidentiality, and submission checklist in `hackathoninfo.md` is complete.

## 13. Technical references

- [Meta Model API overview](https://dev.meta.ai/docs/overview): current endpoint, SDK compatibility, Spark model IDs, tool calling, and structured output.
- [Meta coding-agent guide](https://dev.meta.ai/docs/coding-agents): agent loop and OpenAI-compatible integration details.
- [Muse Wonder](https://dev.meta.ai/models/muse-wonder): model identity, capabilities, and pricing.
- [Meta Model API reasoning](https://dev.meta.ai/docs/reasoning): supported reasoning controls for the judge request.
- [Docker bind mounts](https://docs.docker.com/engine/storage/bind-mounts/): host/container mount behavior and read-only options.
- [uv project documentation](https://docs.astral.sh/uv/guides/projects/): lockfiles and reproducible Python project environments.

