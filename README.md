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
2. Keep `LEASH_JUDGE_MODE=recorded` until access to both models is explicitly tested.
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

## Development

```powershell
python -m uv sync --python 3.12
.\.venv\Scripts\pytest.exe
.\.venv\Scripts\leash.exe serve
```

The API listens on `http://127.0.0.1:8765` by default. `GET /health` reports whether keys are configured without revealing them.

## Implemented foundation

The current key-independent vertical slice includes:

- strict, versioned proposals for shell, file-write, HTTP, and git-push actions;
- canonical impact previews with local secret redaction and protected-path handling;
- deterministic `allow`, `review`, and `block` policy precedence;
- recorded and unavailable judge modes plus a strict Muse Wonder adapter;
- fail-closed handling for provider failures and invalid Muse Wonder output;
- an explicit action state machine and digest-verifying executor boundary;
- a pinned Docker shell profile with no network, read-only workspace, non-root user,
  empty host-secret environment, dropped capabilities and bounded resources/output;
- expiring, digest-bound human approvals with denial and replay protection;
- a redacted, hash-chained SQLite audit feed and integrity verifier;
- FastAPI health, evaluation, action-event, and audit-verification endpoints; and
- strict Ruff/Pyright checks plus security-focused tests.

The Docker profile deliberately supports only Python version checks and `unittest` runs. File
mutation, inspected HTTP and Git push remain unavailable until their typed adapters are implemented.
Pending reviews are held only in memory, so a restart invalidates them and fails closed. The Spark
actor loop, mutation adapters, dashboard and benchmark are the next implementation stages.

