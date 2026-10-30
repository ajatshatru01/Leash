from __future__ import annotations

import hashlib
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit, urlunsplit

from leash.contracts import (
    ActionProposal,
    FilePatchActionProposal,
    FileWriteActionProposal,
    HttpActionProposal,
    ImpactPreview,
    SecretFinding,
    ShellActionProposal,
)
from leash.digest import sha256_digest
from leash.secrets import SecretScanner
from leash.shell_preview import ShellImpactAnalyzer


class PreviewError(ValueError):
    pass


class PreviewService:
    def __init__(
        self,
        workspace_root: Path,
        scanner: SecretScanner,
        *,
        max_targets: int = 200,
        max_preview_bytes: int = 10_000_000,
        max_depth: int = 8,
    ) -> None:
        self._workspace_root = workspace_root.resolve()
        self._scanner = scanner
        self._shell_analyzer = ShellImpactAnalyzer(
            workspace_root=self._workspace_root,
            max_targets=max_targets,
            max_bytes=max_preview_bytes,
            max_depth=max_depth,
        )

    def _resolve_workspace_path(self, value: str) -> Path:
        candidate = (self._workspace_root / value).resolve()
        if candidate != self._workspace_root and self._workspace_root not in candidate.parents:
            raise PreviewError("Resolved path escapes the configured workspace")
        return candidate

    def build(self, proposal: ActionProposal) -> ImpactPreview:
        action_digest = sha256_digest(proposal)
        normalized: dict[str, object]
        targets: tuple[str, ...] = ()
        affected_count = 0
        affected_bytes = 0
        destination: str | None = None
        findings: list[SecretFinding] = []
        protected: list[str] = []
        uncertainty: list[str] = []
        truncated = False

        if isinstance(proposal, FileWriteActionProposal):
            path = self._resolve_workspace_path(proposal.params.path)
            _, content_findings = self._scanner.scan_and_redact(
                proposal.params.content, "file_write.content"
            )
            findings.extend(content_findings)
            targets = (str(path),)
            affected_count = 1
            affected_bytes = len(proposal.params.content.encode("utf-8"))
            normalized = {
                "kind": proposal.kind,
                "path": str(path),
                "mode": proposal.params.mode,
                "content_bytes": affected_bytes,
                "content_sha256": hashlib.sha256(
                    proposal.params.content.encode("utf-8")
                ).hexdigest(),
            }
            protected_parts = {".env", ".git", ".ssh", ".aws", ".codex"}
            if protected_parts.intersection(part.lower() for part in path.parts):
                protected.append(str(path))
        elif isinstance(proposal, FilePatchActionProposal):
            unresolved = self._workspace_root / proposal.params.path
            if unresolved.is_symlink():
                raise PreviewError("Symbolic-link patch targets are prohibited")
            path = self._resolve_workspace_path(proposal.params.path)
            if not path.is_file():
                raise PreviewError("File patch requires an existing regular file")
            if path.stat().st_size > 1_000_000:
                raise PreviewError("File patch target exceeds the one-megabyte preview limit")
            raw = path.read_bytes()
            try:
                current_text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise PreviewError("File patch requires UTF-8 text") from exc
            current_hash = hashlib.sha256(raw).hexdigest()
            replacement_count = current_text.count(proposal.params.old_text)
            result_text = current_text.replace(
                proposal.params.old_text,
                proposal.params.new_text,
                1,
            )
            result_bytes = result_text.encode("utf-8")
            _, patch_findings = self._scanner.scan_and_redact(
                result_text,
                "file_patch.result",
            )
            findings.extend(patch_findings)
            targets = (str(path),)
            affected_count = 1
            affected_bytes = len(result_bytes)
            if current_hash != proposal.params.expected_sha256:
                uncertainty.append("expected_hash_mismatch")
            if replacement_count != 1:
                uncertainty.append("patch_match_not_unique")
            normalized = {
                "kind": proposal.kind,
                "path": str(path),
                "expected_sha256": proposal.params.expected_sha256,
                "current_sha256": current_hash,
                "old_text_sha256": hashlib.sha256(
                    proposal.params.old_text.encode("utf-8")
                ).hexdigest(),
                "new_text_sha256": hashlib.sha256(
                    proposal.params.new_text.encode("utf-8")
                ).hexdigest(),
                "result_sha256": hashlib.sha256(result_bytes).hexdigest(),
                "replacement_count": replacement_count,
                "result_bytes": len(result_bytes),
            }
            protected_parts = {".env", ".git", ".ssh", ".aws", ".codex"}
            if protected_parts.intersection(part.lower() for part in path.parts):
                protected.append(str(path))
        elif isinstance(proposal, HttpActionProposal):
            parsed = urlsplit(str(proposal.params.url))
            destination = (parsed.hostname or "").lower()
            raw_normalized_url = urlunsplit(
                (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.query, "")
            )
            normalized_url, url_findings = self._scanner.scan_and_redact(
                raw_normalized_url, "http.url"
            )
            findings.extend(url_findings)
            body, body_findings = self._scanner.scan_and_redact(proposal.params.body, "http.body")
            findings.extend(body_findings)
            headers: dict[str, str] = {}
            for key, value in proposal.params.headers.items():
                normalized_key = key.lower()
                location = f"http.headers.{normalized_key}"
                if normalized_key in {
                    "authorization",
                    "cookie",
                    "proxy-authorization",
                    "x-api-key",
                }:
                    redacted, header_finding = self._scanner.redact_value(
                        value, location, kind="sensitive_header"
                    )
                    headers[normalized_key] = redacted
                    findings.append(header_finding)
                else:
                    redacted, header_findings = self._scanner.scan_and_redact(value, location)
                    headers[normalized_key] = redacted
                    findings.extend(header_findings)
            normalized = {
                "kind": proposal.kind,
                "method": proposal.params.method,
                "url": normalized_url,
                "headers": headers,
                "body": body,
            }
            affected_bytes = len(proposal.params.body.encode("utf-8"))
        elif isinstance(proposal, ShellActionProposal):
            cwd = self._resolve_workspace_path(proposal.cwd)
            redacted_argv: list[str] = []
            for index, argument in enumerate(proposal.params.argv):
                redacted, argument_findings = self._scanner.scan_and_redact(
                    argument, f"shell.argv.{index}"
                )
                redacted_argv.append(redacted)
                findings.extend(argument_findings)
            impact = self._shell_analyzer.analyze(
                proposal.params.executable,
                proposal.params.argv,
                cwd,
            )
            analysis = dict(impact.analysis)
            raw_patterns = analysis.get("target_patterns")
            if isinstance(raw_patterns, list):
                safe_patterns: list[str] = []
                for index, pattern in enumerate(cast(list[object], raw_patterns)):
                    if not isinstance(pattern, str):
                        continue
                    safe_pattern, pattern_findings = self._scanner.scan_and_redact(
                        pattern,
                        f"shell.analysis.target_patterns.{index}",
                    )
                    safe_patterns.append(safe_pattern)
                    findings.extend(pattern_findings)
                analysis["target_patterns"] = safe_patterns
            if impact.decoded_command is not None:
                decoded_preview, decoded_findings = self._scanner.scan_and_redact(
                    impact.decoded_command[:4000],
                    "shell.decoded_command",
                )
                findings.extend(decoded_findings)
                analysis["decoded_command_preview"] = decoded_preview
            normalized = {
                "kind": proposal.kind,
                "executable": proposal.params.executable.lower(),
                "argv": redacted_argv,
                "cwd": str(cwd),
                "timeout_seconds": proposal.params.timeout_seconds,
                "analysis": analysis,
            }
            safe_targets: list[str] = []
            for index, target in enumerate(impact.resolved_targets):
                safe_target, target_findings = self._scanner.scan_and_redact(
                    target,
                    f"shell.resolved_targets.{index}",
                )
                safe_targets.append(safe_target)
                findings.extend(target_findings)
            has_destructive_analysis = analysis.get("destructive_operation") is not None
            has_encoded_analysis = analysis.get("encoded") is True
            targets = (
                tuple(safe_targets)
                if has_destructive_analysis or has_encoded_analysis
                else tuple(safe_targets) or (str(cwd),)
            )
            affected_count = impact.affected_file_count
            affected_bytes = impact.affected_bytes
            protected.extend(impact.protected_resource_hits)
            uncertainty.extend(impact.uncertainty_flags)
            truncated = impact.truncated
            if (
                any(
                    token in {"-c", "-command", "-encodedcommand"} for token in proposal.params.argv
                )
                and "nested_interpreter" not in uncertainty
            ):
                uncertainty.append("nested_interpreter")
        else:
            remote, remote_findings = self._scanner.scan_and_redact(
                proposal.params.remote, "git_push.remote"
            )
            findings.extend(remote_findings)
            normalized = {
                "kind": proposal.kind,
                "remote": remote,
                "local_ref": proposal.params.local_ref,
                "remote_ref": proposal.params.remote_ref,
                "force": proposal.params.force,
            }
            uncertainty.append("git_diff_not_yet_resolved")
        digest_payload = {
            "action_id": str(proposal.id),
            "action_digest": action_digest,
            "normalized_action": normalized,
            "resolved_targets": targets,
            "affected_file_count": affected_count,
            "affected_bytes": affected_bytes,
            "network_destination": destination,
            "secret_findings": [item.model_dump(mode="json") for item in findings],
            "protected_resource_hits": tuple(protected),
            "uncertainty_flags": tuple(uncertainty),
            "truncated": truncated,
        }
        return ImpactPreview(
            action_id=proposal.id,
            action_digest=action_digest,
            normalized_action=normalized,
            resolved_targets=targets,
            affected_file_count=affected_count,
            affected_bytes=affected_bytes,
            network_destination=destination,
            secret_findings=tuple(findings),
            protected_resource_hits=tuple(protected),
            uncertainty_flags=tuple(uncertainty),
            truncated=truncated,
            digest=sha256_digest(digest_payload),
        )
