"""PII / secret masking applied to every prompt before it leaves the process.

Two classes of sensitive data:

* PII (emails, phones, IPs, card numbers, SSNs) is *pseudonymised*: replaced by
  a stable per-run token like <EMAIL_1>. The vault keeps the mapping so tokens
  the model echoes back in tool arguments are restored before execution.
* Secrets (cloud keys, tokens, private keys, password assignments) are
  *redacted*: replaced by <SECRET_n> and never stored. There is no path by
  which a secret can reach a provider, a cache entry, or come back.

Regexes are a floor, not a ceiling: they catch structured identifiers, not
free-text names. The primary control is the ontology, which never hands the
model fields it doesn't need (see FIELD_MARKINGS / notify_owner).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"),
    re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*[^\s,;]+"),
]

_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("CARD", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("PHONE", re.compile(r"(?<![\w.])\+?\d{1,3}[ .-]?\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}\b")),
    ("IP", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
]

_TOKEN_RE = re.compile(r"<(EMAIL|SSN|CARD|PHONE|IP)_(\d+)>")


def _luhn_ok(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


@dataclass
class PIIVault:
    """Per-run reversible mapping. Never persisted, never shared across runs."""

    _forward: dict[str, str] = field(default_factory=dict)
    _reverse: dict[str, str] = field(default_factory=dict)
    _counts: dict[str, int] = field(default_factory=dict)
    secrets_redacted: int = 0

    def _token(self, kind: str, value: str) -> str:
        if value in self._forward:
            return self._forward[value]
        self._counts[kind] = self._counts.get(kind, 0) + 1
        tok = f"<{kind}_{self._counts[kind]}>"
        self._forward[value] = tok
        self._reverse[tok] = value
        return tok

    # -- masking -----------------------------------------------------------
    def mask_text(self, text: str) -> str:
        for pat in _SECRET_PATTERNS:
            def _redact(m: re.Match[str]) -> str:
                self.secrets_redacted += 1
                return f"<SECRET_{self.secrets_redacted}>"

            text = pat.sub(_redact, text)
        for kind, pat in _PII_PATTERNS:
            def _sub(m: re.Match[str], kind=kind) -> str:
                if kind == "CARD" and not _luhn_ok(m.group(0)):
                    return m.group(0)
                return self._token(kind, m.group(0))

            text = pat.sub(_sub, text)
        return text

    def mask(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.mask_text(value)
        if isinstance(value, dict):
            return {k: self.mask(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.mask(v) for v in value]
        return value

    # -- unmasking ---------------------------------------------------------
    def unmask_text(self, text: str) -> str:
        return _TOKEN_RE.sub(lambda m: self._reverse.get(m.group(0), m.group(0)), text)

    def unmask(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.unmask_text(value)
        if isinstance(value, dict):
            return {k: self.unmask(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.unmask(v) for v in value]
        return value

    @property
    def pii_masked(self) -> int:
        return sum(self._counts.values())
