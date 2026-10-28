from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Literal

from leash.contracts import SecretFinding


@dataclass(frozen=True)
class _SecretPattern:
    kind: str
    regex: re.Pattern[str]
    confidence: Literal["low", "medium", "high"]


_PATTERNS = (
    _SecretPattern("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "high"),
    _SecretPattern("github_token", re.compile(r"\bgh[psuor]_[A-Za-z0-9_]{30,255}\b"), "high"),
    _SecretPattern("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "high"),
    _SecretPattern(
        "credential_assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)\b"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_./+\-=]{12,})"
        ),
        "medium",
    ),
)


class SecretScanner:
    def __init__(self, fingerprint_key: str) -> None:
        self._key = fingerprint_key.encode("utf-8")

    def _fingerprint(self, value: str) -> str:
        return hmac.new(self._key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]

    def redact_value(
        self,
        value: str,
        location: str,
        *,
        kind: str = "sensitive_field",
    ) -> tuple[str, SecretFinding]:
        fingerprint = self._fingerprint(value)
        finding = SecretFinding(
            kind=kind,
            location=location,
            fingerprint=fingerprint,
            confidence="high",
        )
        return f"<REDACTED:{kind}:{fingerprint}>", finding

    def scan_and_redact(self, text: str, location: str) -> tuple[str, tuple[SecretFinding, ...]]:
        redacted = text
        findings: list[SecretFinding] = []
        seen: set[tuple[str, str]] = set()

        for pattern in _PATTERNS:
            matches = list(pattern.regex.finditer(redacted))
            for match in reversed(matches):
                raw = match.group(1) if match.lastindex else match.group(0)
                fingerprint = self._fingerprint(raw)
                marker = f"<REDACTED:{pattern.kind}:{fingerprint}>"
                start, end = match.span(1) if match.lastindex else match.span(0)
                redacted = f"{redacted[:start]}{marker}{redacted[end:]}"
                key = (pattern.kind, fingerprint)
                if key not in seen:
                    findings.append(
                        SecretFinding(
                            kind=pattern.kind,
                            location=location,
                            fingerprint=fingerprint,
                            confidence=pattern.confidence,
                        )
                    )
                    seen.add(key)

        return redacted, tuple(reversed(findings))
