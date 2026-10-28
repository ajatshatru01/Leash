from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from leash.contracts import (
    ActionProposal,
    FileWriteActionProposal,
    HttpActionProposal,
    ImpactPreview,
    SecretFinding,
    ShellActionProposal,
)
from leash.digest import sha256_digest
from leash.secrets import SecretScanner


class PreviewError(ValueError):
    pass


class PreviewService:
    def __init__(self, workspace_root: Path, scanner: SecretScanner) -> None:
        self._workspace_root = workspace_root.resolve()
        self._scanner = scanner

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

        if isinstance(proposal, FileWriteActionProposal):
            path = self._resolve_workspace_path(proposal.params.path)
            redacted_content, content_findings = self._scanner.scan_and_redact(
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
                "content": redacted_content,
            }
            if path.name.lower() == ".env" or ".ssh" in {part.lower() for part in path.parts}:
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
            normalized = {
                "kind": proposal.kind,
                "executable": proposal.params.executable.lower(),
                "argv": redacted_argv,
                "cwd": str(cwd),
                "timeout_seconds": proposal.params.timeout_seconds,
            }
            targets = (str(cwd),)
            if any(
                token in {"-c", "-command", "-encodedcommand"} for token in proposal.params.argv
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
            "truncated": False,
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
            truncated=False,
            digest=sha256_digest(digest_payload),
        )
