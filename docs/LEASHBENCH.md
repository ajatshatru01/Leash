# LeashBench v1

LeashBench is Leash's reproducible, execution-free safety regression suite. It measures the real
local preview and deterministic-policy pipeline against frozen, labeled action proposals. Every
case is materialized inside a fresh temporary workspace, and the runner never calls an executor,
opens a network connection, or invokes a model API.

## Run it

From the repository root:

```powershell
.\.venv\Scripts\leash.exe bench --split all
```

Optional held-out-only run:

```powershell
.\.venv\Scripts\leash.exe bench --split final
```

The command writes:

- `bench/reports/leashbench-v1-results.jsonl`: one raw result per case/configuration;
- `bench/reports/leashbench-v1-summary.json`: aggregate, family, and split metrics.

The summary records the exact suite SHA-256 digest, Python/platform information, generation time,
and reproduction command. The dashboard reads only the generated summary.

## Corpus

The 60 frozen cases match the planned distribution:

| Family | Cases |
|---|---:|
| Safe routine coding | 20 |
| Legitimate suspicious-looking actions | 8 |
| Destructive filesystem/git actions | 10 |
| Secret egress | 10 |
| Encoded, nested, or opaque commands | 7 |
| Prompt/task injection | 5 |

Forty-eight cases are development cases and twelve are held-out final cases. Every case has a
distinct mutation-source identifier. Labels are three-way: `allow`, `review`, or `block`, with a
plain-language rationale stored beside the proposal.

## Configurations

1. `rules_only` runs the actual bounded preview and deterministic policy.
2. `recorded_wonder_only` replays the case's frozen semantic verdict after local preview.
3. `recorded_hybrid` combines deterministic and recorded semantic decisions using Leash's fixed
   severity precedence.

The recorded configurations are **not live Muse Wonder measurements**. They prove runner wiring,
decision combination, metrics, artifacts, and dashboard presentation without spending API credit.
They must not be presented as model accuracy. A later controlled run can replace the recorded
semantic verdict source while preserving the same case schema and reporting format.

## Metrics

Reports include:

- exact three-class accuracy and confusion matrices;
- macro F1;
- block precision, recall, and F1;
- unsafe-allow rate on cases labeled `block`;
- false-block rate on cases labeled `allow`;
- review rate;
- deterministic 1,000-resample bootstrap confidence intervals for accuracy;
- preview, policy, and total p50/p95 latency;
- per-family and per-split breakdowns.

Latency is machine-specific. Recorded judge latency is zero by definition and is not a proxy for
managed Muse Wonder latency.

## Safety and interpretation

- Inputs contain only fake credential shapes and reserved example domains.
- HTTP proposals are previewed but never sent.
- Destructive proposals target generated temporary fixtures and are never executed.
- Preview rejection counts as a fail-closed block.
- Raw results omit task text, bodies, headers, file content, and secret-shaped fixtures.
- Corpus labels are currently first-party labels; independent label review remains desirable.

The initial result intentionally preserves visible rules-only failures: task/action mismatch cases
land in `review` rather than the expected semantic `block`. This is the gap the independent judge is
designed to address; it is not hidden or relabeled after the run.
