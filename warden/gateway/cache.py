"""Response cache.

Keys are computed over the *masked* request, and values are stored masked, so
the cache never holds raw PII or secrets. Pseudonym numbering is deterministic
by order of appearance, so identical inputs produce identical keys across runs.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import OrderedDict
from dataclasses import asdict
from typing import Any

from warden.gateway.types import ChatResponse


def cache_key(provider_model: str, payload: Any) -> str:
    blob = json.dumps({"m": provider_model, "p": payload}, sort_keys=True, default=_default)
    return hashlib.sha256(blob.encode()).hexdigest()


def _default(o: Any) -> Any:
    try:
        return asdict(o)
    except TypeError:
        return str(o)


class ResponseCache:
    def __init__(self, max_entries: int = 1024, ttl_seconds: float = 3600):
        self._data: OrderedDict[str, tuple[float, ChatResponse]] = OrderedDict()
        self._max = max_entries
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> ChatResponse | None:
        with self._lock:
            item = self._data.get(key)
            if item is None or time.monotonic() - item[0] > self._ttl:
                self._data.pop(key, None)
                self.misses += 1
                return None
            self._data.move_to_end(key)
            self.hits += 1
            return item[1]

    def put(self, key: str, value: ChatResponse) -> None:
        with self._lock:
            self._data[key] = (time.monotonic(), value)
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)
