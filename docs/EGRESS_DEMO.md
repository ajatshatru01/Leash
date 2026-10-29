# Local exfiltration demo

This scenario proves two separate facts without contacting any external endpoint:

1. a proposal containing a pattern-shaped fake credential is blocked before transport invocation;
2. a safe payload to the same loopback receiver can execute through the inspected HTTP adapter.

The receiver stores only aggregate request/byte counts, the last body SHA-256 digest, and content
type. It never retains or returns request bodies.

## Run

Start the inert receiver in one terminal:

```powershell
.\.venv\Scripts\leash.exe capture-receiver
```

Start the gateway in a second terminal:

```powershell
.\.venv\Scripts\leash.exe serve
```

Run the deterministic proof in a third terminal:

```powershell
.\scripts\egress-demo.ps1
```

Expected evidence:

```text
blocked_decision  : block
blocked_requests  : 0
blocked_bytes     : 0
safe_decision     : allow
safe_executor     : http
delivered_requests: 1
delivered_bytes   : 21
```

The fake credential is constructed in memory by the script and is never printed. The poisoned
content is in `demo/poisoned-readme/README.md`; it is explicitly a test fixture, not an instruction.
