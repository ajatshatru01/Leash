from __future__ import annotations

from pathlib import Path
from typing import cast

from leash.contracts import (
    ActionProposal,
    Decision,
    FilePatchActionProposal,
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
        elif isinstance(proposal, FilePatchActionProposal):
            if "expected_hash_mismatch" in preview.uncertainty_flags:
                add(
                    "STALE_FILE_SNAPSHOT",
                    Decision.BLOCK,
                    "The file changed after inspection; a fresh read and patch are required.",
                    "preview.normalized_action.current_sha256",
                )
            if "patch_match_not_unique" in preview.uncertainty_flags:
                add(
                    "PATCH_NOT_UNIQUE",
                    Decision.BLOCK,
                    "The expected patch target is missing or not unique.",
                    "preview.normalized_action.replacement_count",
                )
            if preview.secret_findings:
                add(
                    "SECRET_PATCH_CONTENT",
                    Decision.BLOCK,
                    "The proposed patch introduces likely credential material.",
                    "preview.secret_findings",
                )
        else:
            executable = Path(proposal.params.executable).name.lower()
            argv_lower = {item.lower() for item in proposal.params.argv}
            raw_analysis = preview.normalized_action.get("analysis")
            analysis = (
                cast(dict[str, object], raw_analysis) if isinstance(raw_analysis, dict) else {}
            )
            destructive = analysis.get("destructive_operation")
            recursive = analysis.get("recursive") is True
            indirect = "nested_interpreter" in preview.uncertainty_flags
            encoded = analysis.get("encoded") is True
            if isinstance(destructive, str) and (indirect or encoded):
                add(
                    "INDIRECT_DESTRUCTIVE_OPERATION",
                    Decision.BLOCK,
                    "A nested or encoded command resolves to a destructive operation.",
                    "preview.normalized_action.analysis",
                )
            elif isinstance(destructive, str) and recursive:
                add(
                    "RECURSIVE_DELETE",
                    Decision.BLOCK,
                    "Recursive deletion is blocked by deterministic policy.",
                    "preview.normalized_action.analysis",
                )
            elif isinstance(destructive, str):
                add(
                    "DESTRUCTIVE_OPERATION",
                    Decision.REVIEW,
                    "A destructive operation requires an exact impact review.",
                    "preview.resolved_targets",
                )
            if preview.truncated and isinstance(destructive, str):
                add(
                    "DESTRUCTIVE_PREVIEW_TRUNCATED",
                    Decision.BLOCK,
                    "The destructive impact preview exceeded configured bounds.",
                    "preview.truncated",
                )
            if {
                "target_escape",
                "link_target_escape",
                "link_target_unresolved",
            }.intersection(preview.uncertainty_flags):
                add(
                    "TARGET_ESCAPE",
                    Decision.BLOCK,
                    "A resolved target or symbolic link escapes the workspace boundary.",
                    "preview.uncertainty_flags",
                )
            if {
                "encoded_command_invalid",
                "encoded_command_oversized",
            }.intersection(preview.uncertainty_flags):
                add(
                    "OPAQUE_ENCODED_COMMAND",
                    Decision.BLOCK,
                    "The encoded command could not be safely decoded and bounded.",
                    "preview.uncertainty_flags",
                )
            if {
                "command_chain",
                "command_substitution",
                "environment_expansion",
            }.intersection(preview.uncertainty_flags):
                add(
                    "UNSUPPORTED_SHELL_SYNTAX",
                    Decision.REVIEW,
                    "Dynamic or chained shell syntax requires conservative review.",
                    "preview.uncertainty_flags",
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
