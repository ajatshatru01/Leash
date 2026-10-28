from __future__ import annotations

from pathlib import Path

from leash.contracts import (
    ActionProposal,
    Decision,
    FileWriteActionProposal,
    GitPushActionProposal,
    HttpActionProposal,
    ImpactPreview,
    PolicyOutcome,
    RuleFinding,
)

_DECISION_RANK = {Decision.ALLOW: 0, Decision.REVIEW: 1, Decision.BLOCK: 2}
_SAFE_EXECUTABLES = {
    "git",
    "pytest",
    "python",
    "python3",
    "ruff",
    "npm",
    "pnpm",
    "node",
    "rg",
}
_INTERPRETERS = {"bash", "sh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}


class PolicyEngine:
    def __init__(self, allowed_http_hosts: tuple[str, ...]) -> None:
        self._allowed_http_hosts = {item.lower() for item in allowed_http_hosts}

    def evaluate(self, proposal: ActionProposal, preview: ImpactPreview) -> PolicyOutcome:
        findings: list[RuleFinding] = []

        def add(code: str, decision: Decision, explanation: str, evidence_ref: str) -> None:
            findings.append(
                RuleFinding(
                    code=code,
                    decision=decision,
                    explanation=explanation,
                    evidence_ref=evidence_ref,
                )
            )

        if preview.protected_resource_hits:
            add(
                "PROTECTED_RESOURCE",
                Decision.BLOCK,
                "The action targets a protected credential or configuration path.",
                "preview.protected_resource_hits",
            )
        if preview.secret_findings and isinstance(proposal, HttpActionProposal):
            add(
                "SECRET_EGRESS",
                Decision.BLOCK,
                "The outbound request contains likely credential material.",
                "preview.secret_findings",
            )

        if isinstance(proposal, HttpActionProposal):
            if preview.network_destination not in self._allowed_http_hosts:
                add(
                    "UNAPPROVED_DESTINATION",
                    Decision.REVIEW,
                    "The network destination is not locally allowlisted.",
                    "preview.network_destination",
                )
        elif isinstance(proposal, GitPushActionProposal):
            add(
                "GIT_PUSH_REQUIRES_REVIEW",
                Decision.REVIEW,
                "Git push changes a remote system and requires semantic and human review.",
                "proposal.params.remote",
            )
            if proposal.params.force:
                add(
                    "FORCE_PUSH",
                    Decision.BLOCK,
                    "Force-push is blocked by the hackathon safety policy.",
                    "proposal.params.force",
                )
        elif isinstance(proposal, FileWriteActionProposal):
            if proposal.params.mode == "replace":
                add(
                    "FILE_REPLACE",
                    Decision.REVIEW,
                    "Replacing an existing file requires impact review.",
                    "proposal.params.mode",
                )
        else:
            executable = Path(proposal.params.executable).name.lower()
            argv_lower = {item.lower() for item in proposal.params.argv}
            if executable in {"rm", "del", "erase", "rmdir"} and (
                "-rf" in argv_lower or "-r" in argv_lower or "/s" in argv_lower
            ):
                add(
                    "RECURSIVE_DELETE",
                    Decision.BLOCK,
                    "Recursive deletion is blocked by deterministic policy.",
                    "proposal.params.argv",
                )
            if (
                executable == "git"
                and "push" in argv_lower
                and ("--force" in argv_lower or "-f" in argv_lower)
            ):
                add(
                    "FORCE_PUSH",
                    Decision.BLOCK,
                    "Force-push is blocked by deterministic policy.",
                    "proposal.params.argv",
                )
            if executable in _INTERPRETERS or "nested_interpreter" in preview.uncertainty_flags:
                add(
                    "NESTED_INTERPRETER",
                    Decision.REVIEW,
                    "Nested or encoded interpreter execution requires semantic review.",
                    "preview.uncertainty_flags",
                )
            elif executable not in _SAFE_EXECUTABLES:
                add(
                    "UNKNOWN_EXECUTABLE",
                    Decision.REVIEW,
                    "The executable is not in the demo allowlist.",
                    "proposal.params.executable",
                )

        decision = Decision.ALLOW
        for finding in findings:
            if _DECISION_RANK[finding.decision] > _DECISION_RANK[decision]:
                decision = finding.decision
        return PolicyOutcome(
            decision=decision,
            findings=tuple(findings),
            requires_judge=decision == Decision.REVIEW,
        )
