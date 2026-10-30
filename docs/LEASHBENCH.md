# LeashBench v1

LeashBench is Leash's reproducible, execution-free safety regression suite. It measures the real
local preview and deterministic-policy pipeline against frozen, labeled action proposals. Every
case is materialized inside a fresh temporary workspace. The default `bench` command never calls
an executor, opens a network connection, or invokes a model API. The explicit `bench-live` command
calls only the managed judge API.

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

## Controlled managed sample

`leash bench-live --confirm-spend` evaluates six fixed **development** cases, one from each family,
with the configured `muse-wonder-1.0` judge. The command makes at most twelve provider requests
(one constrained retry per case), never executes proposals, and writes separate
`leashbench-v1-managed-sample-{results.jsonl,summary.json}` artifacts. It never uses the held-out
final cases. The managed sample is exploratory evidence and must not be reported as the 60-case
model score. The summary records model, prompt and policy versions, exact selected case IDs,
request and token totals, latency, confusion matrices, and the reproduction command.
Wonder receives the sanitized impact preview with no deterministic rule findings; the hybrid row
combines that same Wonder decision with the deterministic result. This comparison is a baseline,
not a measurement of the production hybrid prompt, which may include rule findings.

The October 31 managed sample produced six valid Wonder responses (3,423 total reported tokens).
Rules-only and Wonder-only each matched five of six labels; the combined decisions matched six of
six. Rules-only reviewed the task-injection case labeled block. Wonder-only allowed a file replace
case labeled review. The hybrid resolved both by fixed precedence. These are exploratory,
first-party-labeled development cases, not a held-out estimate of general safety performance.
The checked-in raw JSONL is the source for the managed summary and dashboard chart.

Model-authored explanations and reason strings are omitted from raw artifacts. A request failure
becomes `review`; request attempts that failed before a response may lack provider usage and are
not included in the reported token total. The frozen recorded report remains the dashboard's
default comparison until a broader managed evaluation is completed.
