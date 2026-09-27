"""Append-only, hash-chained audit log.

Every run start/end, LLM call, tool call (allowed *and* denied) is an event.
Each record carries the SHA-256 of the previous record, so deleting or editing
a line breaks the chain and `verify()` reports where. This is tamper-evident,
not tamper-proof: ship the file to WORM storage / your SIEM for the latter.

Records contain masked prompts/arguments only; secrets never reach this file.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(record: dict) -> str:
    return hashlib.sha256(json.dumps(record, sort_keys=True, default=str).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None):
        self._path = Path(path) if path else None
        self._lock = threading.Lock()
        self.events: list[dict] = []
        self._prev = GENESIS
        self._seq = 0
        if self._path and self._path.exists():
            for line in self._path.read_text().splitlines():
                if line.strip():
                    rec = json.loads(line)
                    self._prev, self._seq = rec["hash"], rec["seq"]

    def write(self, event: str, **fields: Any) -> dict:
        with self._lock:
            self._seq += 1
            rec = {
                "seq": self._seq,
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": event,
                **fields,
                "prev_hash": self._prev,
            }
            rec["hash"] = _digest(rec)
            self._prev = rec["hash"]
            self.events.append(rec)
            if self._path:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with self._path.open("a") as f:
                    f.write(json.dumps(rec, default=str) + "\n")
            return rec

    def for_run(self, run_id: str) -> list[dict]:
        return [e for e in self.events if e.get("run_id") == run_id]


def verify(path: str | Path) -> tuple[bool, str]:
    prev = GENESIS
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        rec = json.loads(line)
        claimed = rec.pop("hash")
        if rec["prev_hash"] != prev:
            return False, f"line {n}: chain broken (prev_hash mismatch)"
        if _digest(rec) != claimed:
            return False, f"line {n}: record modified (hash mismatch)"
        prev = claimed
    return True, "ok"
