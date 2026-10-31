# Dashboard demo integration

This is an offline, local rehearsal path. It does not call Spark or Wonder APIs.

## Start and run

From the repository root, with the Python environment installed:

```powershell
# Terminal 1
.\.venv\Scripts\leash.exe capture-receiver

# Terminal 2
.\.venv\Scripts\leash.exe serve
```

Open `http://127.0.0.1:8765`. Click **Reset demo**, then **Run recorded sequence**.
The dashboard should show one mock-executed allow, one pending review, a blocked fake-secret
HTTP proposal, and a blocked encoded deletion. The capture receiver must show **0 requests,
0 bytes**. The three generated deletion targets must show **3/3 files, 89/89 bytes**.

The reset button is available only while the loopback receiver is online. Reset rewrites only
known files in `demo/workspace/.leash-demo`, removes the demo-owned note, invalidates pending
reviews, zeros capture counters, and appends a new audit marker. It does not erase the audit chain.
The sequence uses a recorded Wonder response and mock executor even if the gateway is configured
for managed mode. Its actions are labeled `recorded / mock` in the feed.

## Muted 90-second walkthrough

| Time | On-screen action | Evidence to leave visible |
| --- | --- | --- |
| 0–10s | Show the gateway, model/policy versions, and recorded-sequence label. Click **Reset demo**. | Capture 0 requests / 0 bytes; 3/3 generated files, 89/89 bytes. |
| 10–25s | Click **Run recorded sequence**, then select **Routine edit**. | Allow and mock execution; local handling and call counters. |
| 25–45s | Select **Human review** and open its approval dialog. Cancel it to keep the review pending. | User task, resolved target, expiration, exact digests, and mock-only capability note. |
| 45–65s | Select **Secret egress**. | `SECRET_EGRESS`, redacted finding, local destination, and receiver still at zero. |
| 65–80s | Select **Encoded delete**. | Decoded command, three resolved targets, 89 bytes, block reason, and intact fixture hashes. |
| 80–90s | Show the LeashBench chart and audit integrity. | Recorded replay versus managed development sample labels; no live model claim for the demo sequence. |

The sequence is deterministic in action order and fixture bytes. Action IDs and measured latencies
change between runs. Approval in this recorded sequence executes only through the mock adapter;
the approval dialog repeats that fact.

## What the evidence means

- The local-handling percentage is the number of `judge_call_avoided` events divided by verdicts
  after the latest demo reset. Escalation rate uses `judge_escalated` over the same verdicts.
- Calls avoided combines deterministic avoided Wonder calls and exact-packet cache hits. API call
  and token counters include only actual provider calls recorded in the audit.
- The action timeline reads the selected action's `stage_latency` audit events. A skipped judge or
  execution stage is shown as such; a recorded judge latency is not a managed API latency.
- Capture proof is valid only while the receiver instance ID and reset generation match the
  audit-linked run. Restarting or resetting the receiver independently makes it **unverified**
  until the dashboard demo is reset again.
- Preservation checks the exact three generated file hashes and byte counts. Other workspace
  files are outside this fixture proof.
- LeashBench's 60-case comparison is a recorded semantic replay. The separate six-case managed
  development sample is labeled as live model evidence, not a held-out model score.

If the receiver, fixtures, benchmark report, or gateway is unavailable, the dashboard shows an
unavailable or unverified state instead of treating missing evidence as success. The review
dialog binds the action and preview digests; expired reviews cannot be submitted.
