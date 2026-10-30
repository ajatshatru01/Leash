# Leash project audit — October 30, 2026

This audit distinguishes implemented behavior from hackathon claims that still require live or
recorded evidence. It was performed against commit `e707cb2` plus the controlled Meta-integration
changes in the working tree. No Meta Model API request was used during the audit.

## Executive status

Leash has a credible, technically deep vertical slice. The local capability boundary, typed action
contracts, deterministic policy, bounded previews, digest-bound authorization, redaction, audit
chain, approval UI, inert attack demonstrations, and 60-case offline benchmark are implemented.
The project is beyond concept/demo-shell stage.

It is not submission-ready yet. Real Muse Spark tool calling and Muse Wonder structured judgment
are now validated through the Meta Model API. The largest remaining blocker is a deterministic
90-second end-to-end rehearsal showing managed Spark recover after a Leash denial. Clean-checkout
evidence and final submission preparation also remain.

Estimated implementation completion: **approximately 82%** of the hackathon definition of done.
This percentage is an engineering judgment, not a benchmark measurement.

## Audit evidence

| Area | Evidence | Status |
|---|---|---|
| Repository | `main`; previous milestone committed as `e707cb2` | Pass |
| Backend tests | Full pytest suite | Pass after this milestone: 89/89 |
| Static analysis | Ruff lint and strict Pyright | Pass |
| Formatting | Four committed files failed `ruff format --check` | Fixed in this milestone |
| Dashboard | TypeScript and Vite production build | Pass |
| Secret hygiene | Exact configured-key audit over tracked/unignored files | Pass |
| Executor boundary | Docker 29.9.2 Linux; pinned no-network/read-only check | Pass |
| Benchmark | 60 cases, 180 rows, frozen digest and raw artifacts | Pass; replay disclosed |
| Live Meta models | Three-request bounded session; Spark/Wonder passed; sanitized evidence tracked | Pass |
| Demo rehearsal | Component demos exist; no three-run end-to-end record | Blocker |
| License/provenance | Lockfiles exist; root license and direct inventory were missing | Fixed here |

## Security and architecture findings

### Strong controls already implemented

- Spark receives proposal and bounded inspection tools, not executor credentials.
- Deterministic hard blocks outrank Wonder; normal human review cannot release them.
- Executors verify action and preview digests immediately before using a capability.
- Docker shell execution is allowlisted, non-root, resource-bounded, network-disabled, and limited
  to the disposable workspace profile.
- HTTP execution is gateway-owned, loopback-only, redirect-disabled, bounded, and rejects secrets.
- File patches bind a unique replacement to an inspected SHA-256 and recheck it before writing.
- Protected paths, traversal, destructive operations, nested/encoded commands, bounded globs, and
  symlink/junction escapes are handled conservatively.
- Approvals expire, are digest-bound, and are single-use; audit records are redacted and chained.
- Model call, cache, budget, latency, and token telemetry exists without hard-coded prices.

### Findings fixed in this milestone

1. The Spark probe validated JSON text rather than a proposal call. It now requires exactly one
   schema-valid `propose_file_write` call and never executes it.
2. Wonder lacked its documented constrained retry. It now uses strict JSON Schema, retries invalid
   output once, aggregates usage, then fails closed to `review`.
3. Wonder packets contained full redacted HTTP bodies and absolute paths. They now send body
   length/hash/finding count, destination metadata, and workspace placeholders.
4. Prompt minimization initially exposed a cache-collision risk. The cache now binds a local digest
   of the full redacted action/impact while sending only the minimized packet externally.
5. Live checking could be invoked accidentally. `check-models` now requires `--confirm-spend`, has
   a maximum of three requests, and writes a sanitized local artifact.
6. The committed tree was not formatter-clean. The affected files are normalized in this change.

### Accepted hackathon limitations

- Arbitrary shell interpretation is not claimed; unsupported opacity becomes review or block.
- Git push has typed proposal/preview/policy coverage but no real execution adapter.
- HTTP execution is loopback-only; it is a proof of inspected egress, not a general proxy.
- Pending reviews and the judgment cache are in-memory and invalidated on restart.
- Symlinks are tested; Windows junction coverage depends on host permissions.
- Pattern-based secret detection cannot catch every fragmented, encrypted, or novel secret.
- Wonder can be wrong; it is a probabilistic signal, not an enforcement proof.
- Recorded LeashBench Wonder labels are harness fixtures, not model-quality measurements.

## Hackathon rubric assessment

| Category | Weight | Current score | Main gap to winning quality |
|---|---:|---:|---|
| Impact | 30% | 8.5/10 | Show a complete developer recovery story |
| Meta AI tooling | 25% | 8.8/10 | Show both models in one integrated recovery flow |
| Technical depth | 20% | 8.8/10 | Clean-checkout proof and managed end-to-end run |
| Demo | 25% | 7.0/10 | Rehearse one coherent 90-second flow three times |
| **Weighted** | 100% | **8.26/10** | Polished integrated demo and clean-clone proof |

The demo remains the limiting category. These are project-planning judgments, not organizer scores.

## Remaining work in priority order

### P0 — required before submission

1. Run one controlled managed Spark task through Leash, including a denial and safe retry.
2. Build a reset-and-rehearse command for the safe, egress, destruction, and evidence flow.
3. Record three consecutive rehearsals and prepare the 90-second video/script.
4. Re-run secret, clean-install, test, Docker, dashboard, and benchmark checks from a clean clone.

### P1 — high leverage

1. Evaluate a small preselected development-only mismatch sample with live Wonder. Do not spend
   credits on all 60 cases until the probe establishes cost and latency.
2. Add architecture/threat-model diagrams and final submission screenshots.
3. Have another person independently label a benchmark sample and record disagreements.
4. Complete the final submission copy and every applicable `hackathoninfo.md` checkbox.

### P2 — defer

- Real remote Git push, public HTTP egress, production auth, enterprise policy management,
  additional platforms, and benchmark expansion.

## Next milestone gate

The controlled Meta integration gate is complete. Offline mock-transport tests pass, accidental
spend is gated, and the live artifact contains no prompts, responses, keys, task content, bodies,
or absolute paths. Evidence is stored in `docs/evidence/meta-model-validation.json`.
