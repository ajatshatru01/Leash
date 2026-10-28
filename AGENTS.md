# AGENTS.md

## Project mission

Leash is a local safety gateway for coding agents. It places policy enforcement between a cloud coding model and the machine capabilities that model wants to use. Muse Spark proposes actions; Leash resolves their likely effects, applies deterministic policy, redacts sensitive context locally, asks an independent Muse Wonder session for semantic judgment when useful, obtains human approval when required, and only then executes through capability-limited adapters.

The hackathon goal is not to build a complete endpoint-security product. It is to prove one defensible idea extremely well:

> A fast local policy layer plus a sanitized semantic judge can stop agent actions that rules alone miss, while allowing routine coding work with low friction.

## Current status

This repository starts from a concept brief. Do not assume any implementation, API contract, benchmark result, security guarantee, or measured latency exists until it is present in the repository and reproducible.

Read `hackathoninfo.md` before changing submission scope or priorities. Read `ARCHITECTURE.md` before making structural or security-sensitive changes. Follow `IMPLEMENTATION_PLAN.md` for the chosen stack, sequencing, milestones, and feature-cut order.

## Non-negotiable product principles

1. **The gateway owns capabilities.** The cloud agent receives proposal tools, not direct shell, filesystem-write, git-push, or network credentials. An action is enforceable only when the underlying capability is unavailable outside Leash.
2. **Fail closed at the boundary.** Parse errors, unavailable policy components, invalid model output, approval timeouts, and executor mismatches never silently become `allow`.
3. **Rules outrank the model.** A Muse Wonder response cannot downgrade a deterministic `block`. It may escalate an `allow` to `review` or `block`.
4. **Preview and execution must agree.** Execution uses the normalized action and resolved targets that were judged. Re-parsing a raw shell string after approval is prohibited.
5. **Minimize secret exposure.** Detect and replace likely secrets with stable placeholders before prompts, UI payloads, and logs. Store hashes or metadata when raw values are unnecessary.
6. **Never market the LLM as a security proof.** Muse Wonder is a probabilistic signal inside a layered control system, not a trusted oracle.
7. **Make every claim reproducible.** Performance and safety claims must link to a benchmark fixture, configuration, raw result artifact, and exact command.
8. **Preserve a useful developer experience.** Normal read/build/test/edit loops should pass silently and quickly. Human review is for genuinely consequential ambiguity.

## Hackathon scope

### Must ship

- A Spark-driven coding loop using the Meta Model API and structured proposal tools.
- A single local Leash gateway for shell, file-write, outbound HTTP, and git-push proposals.
- Deterministic checks for protected paths, destructive operations, secret-like data, unsafe egress, and task/action mismatch signals.
- Resolved previews for the demoed command classes: concrete paths, file counts, byte counts, repository/branch, network destination, and redacted payload findings.
- Muse Wonder running through Meta Model API in an independent, stateless judge context and returning a schema-validated judgment from a minimal, locally redacted request.
- `allow`, `review`, and `block` flows, including approve/deny in a small web dashboard.
- Feedback to Spark explaining a denial and inviting a safer alternative.
- An append-only audit feed with redaction and hash chaining.
- LeashBench fixtures and a reproducible comparison of rules-only, Wonder-only, and hybrid configurations.
- A rehearsed 90-second demo that works without relying on live external services except the Spark API.

### Explicitly out of scope for the hackathon

- General endpoint detection and response.
- Perfect interpretation of arbitrary shell programs.
- Kernel-level enforcement across unrelated processes.
- Windows, macOS, and Linux parity; choose and document one demo platform first.
- Container-or-VM-grade isolation implemented from scratch.
- Training or fine-tuning Muse Wonder.
- Claiming that the managed semantic judge is local or private; only local preprocessing and redaction are claimed.
- Multi-user authentication, enterprise policy management, or production compliance claims.
- Claims that Leash catches every prompt injection, obfuscation, or secret.

## Suggested repository shape

Create this structure incrementally; do not add empty scaffolding merely to match it.

```text
apps/
  gateway/              # Python API, orchestration, policy, approval state
  dashboard/            # TypeScript/React live feed and approval UI
leash/
  contracts/            # Versioned request/verdict/preview schemas
  normalize/            # Structured normalization; no execution
  policy/               # Pure deterministic rules
  preview/              # Read-only impact resolution
  judge/                # Muse Wonder client and strict output validation
  execute/              # Capability-limited adapters
  secrets/              # Detection, redaction, placeholder tracking
  audit/                 # Append-only records and integrity chain
bench/
  cases/                 # Versioned, labeled LeashBench fixtures
  scenarios/             # Isolated demo/benchmark workspaces
  runner/                # Evaluation and report generation
tests/
docs/
```

Prefer Python 3.12 with Pydantic/FastAPI for the security pipeline and benchmark runner, and TypeScript with React for the dashboard. Keep domain logic framework-independent and testable as pure functions. Pin dependencies and model/runtime versions.

## Core contracts

Use typed, versioned records. Do not pass free-form dictionaries between stages.

An `ActionProposal` must include:

- stable action ID and schema version;
- immutable user-task text or its audit-linked identifier;
- action kind (`shell`, `file_write`, `http`, `git_push`);
- typed parameters rather than only a raw command string;
- workspace root and proposed working directory;
- agent/session identifiers and timestamp.

An `ImpactPreview` must distinguish facts from uncertainty. Include resolved targets, counts and destinations, protected resources encountered, secret findings as redacted metadata, parser limitations, and a preview digest.

A `Verdict` must include `allow`, `review`, or `block`; machine-readable reason codes; a short user-facing explanation; evidence references; source (`rule`, `judge`, `human`, or `combined`); confidence only when meaningful; and the action/preview digests it covers.

The executor must verify those digests immediately before execution and record the actual result. A mismatch requires a new proposal and judgment.

## Decision semantics

- `allow`: execute without interruption because no blocking rule fired and the remaining risk is within policy.
- `review`: do not execute until a human approves this exact normalized action and preview.
- `block`: do not offer a one-click override in the normal flow. Return a reason and safer constraints to Spark.

Recommended precedence:

```text
hard deterministic block
  > human denial
  > validated Muse Wonder block
  > deterministic or Muse Wonder review
  > allow
```

Human approval may release `review`; it must not silently override a hard policy block. If a demo needs an override mode, label it as an explicit policy-admin action and audit it separately.

## Engineering rules

- Prefer structured tool calls over accepting arbitrary shell text. Support a deliberately small shell subset for the demo and mark unsupported constructs for review.
- Never execute during normalization, preview, tests, or model judgment. Preview code must be read-only.
- Resolve paths against a canonical workspace root. Treat symlinks, junctions, `..`, case differences, environment expansion, and glob expansion as security-relevant.
- Bound all scans by count, bytes, depth, and time. A truncated preview must say so and cannot be presented as complete.
- Use allowlisted executables and destinations in the demo profile. Default-deny outbound network access from the executor except through Leash's inspected adapter.
- Treat command substitution, interpreters (`sh -c`, `python -c`, PowerShell encoded commands), downloaded scripts, and opaque binaries as review or block unless handled by an isolated execution profile.
- Validate Muse Wonder output against a strict schema. One constrained retry is acceptable; otherwise return `review`, never `allow`.
- Keep the model prompt free of raw secrets. Clearly delimit untrusted file/web content and instruct the judge to treat it as evidence, not instructions.
- Escape dashboard content and never render agent/model strings as HTML.
- Do not log environment values, authorization headers, file contents, or request bodies by default.
- Make benchmark cases hermetic. They must operate only inside disposable fixture directories and must never contact real external endpoints.
- Keep demo attacks inert: use fake credentials, a local capture server, and fixture directories.

## Testing expectations

Every security-relevant change needs tests at the lowest useful layer plus an end-to-end case when behavior crosses components.

At minimum, cover:

- path traversal, symlinks/junctions, protected paths, glob expansion, and large/truncated previews;
- quoting, pipelines, chained commands, substitutions, encoded payloads, and unsupported syntax;
- secret detection across command arguments, file writes, HTTP payloads, git diffs, and split/encoded fixtures;
- prompt-injection text that attempts to influence both Spark and Wonder;
- malformed, adversarial, and unavailable Muse Wonder responses;
- approval replay, digest mismatch, stale approvals, and concurrent decisions;
- audit redaction, ordering, and hash-chain verification;
- executor denial when a capability was not explicitly approved.

For every benchmark report, include precision, recall, F1, false-block rate on safe cases, p50/p95 latency, category-level confusion matrices, and bootstrap confidence intervals where practical. Never tune on the final reported test split.

## Definition of done

A feature is done when:

1. its behavior and failure mode are documented;
2. its inputs and outputs are typed and validated;
3. unsafe or unavailable dependencies fail closed;
4. relevant tests pass in a clean environment;
5. logs and UI output contain no raw fixture secrets;
6. the audit record explains what happened in plain language;
7. any performance or safety claim has a reproducible measurement.

## Delivery order

Optimize for a convincing vertical slice, not component count.

1. Build typed proposals, deterministic policy, a no-op/mock executor, and JSONL audit.
2. Add one complete safe path and one complete blocked path from Spark proposal to dashboard.
3. Add Muse Wonder judgment with strict schema validation and a recorded fallback for demo resilience.
4. Add impact previews and bind approval to action/preview digests.
5. Add outbound secret scanning and the local exfiltration demo.
6. Build LeashBench and capture honest baseline results.
7. Polish the dashboard, failure messaging, video, and README.

If schedule pressure forces a tradeoff, preserve the real enforcement boundary, the two end-to-end attack stories, and benchmark credibility. Cut breadth before weakening those three.

