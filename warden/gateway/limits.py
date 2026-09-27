"""Rate limits and token budgets.

* Request rate: token bucket per (principal, model alias). Protects the
  provider quota from one noisy caller or a runaway loop.
* Token budget: tokens per agent per UTC day. Hard stop, not a warning.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from datetime import datetime, timezone


class LimitExceeded(Exception):
    pass


class TokenBucket:
    def __init__(self, rate_per_minute: float, burst: int | None = None):
        self.capacity = float(burst or max(1, int(rate_per_minute)))
        self.refill_per_s = rate_per_minute / 60.0
        self.tokens = self.capacity
        self.updated = time.monotonic()

    def try_take(self) -> float:
        """Take one token. Returns 0 on success, else seconds until one is available."""
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.refill_per_s)
        self.updated = now
        if self.tokens >= 1:
            self.tokens -= 1
            return 0.0
        return (1 - self.tokens) / self.refill_per_s


class Limiter:
    def __init__(self, requests_per_minute: float, daily_tokens_per_agent: dict[str, int],
                 default_daily_tokens: int, max_wait_s: float = 10.0):
        self._rpm = requests_per_minute
        self._daily = daily_tokens_per_agent
        self._default_daily = default_daily_tokens
        self._max_wait = max_wait_s
        self._buckets: dict[tuple[str, str], TokenBucket] = {}
        self._spent: dict[tuple[str, str], int] = defaultdict(int)
        self._lock = threading.Lock()

    @staticmethod
    def _day() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def acquire(self, principal_id: str, model_alias: str, agent: str) -> None:
        with self._lock:
            budget = self._daily.get(agent, self._default_daily)
            if self._spent[(agent, self._day())] >= budget:
                raise LimitExceeded(f"agent '{agent}' exhausted its daily budget of {budget} tokens")
            bucket = self._buckets.setdefault(
                (principal_id, model_alias), TokenBucket(self._rpm)
            )
        waited = 0.0
        while True:
            with self._lock:
                wait = bucket.try_take()
            if wait == 0:
                return
            if waited + wait > self._max_wait:
                raise LimitExceeded(
                    f"rate limit for {principal_id} on {model_alias}: {self._rpm}/min"
                )
            time.sleep(wait)
            waited += wait

    def record(self, agent: str, tokens: int) -> None:
        with self._lock:
            self._spent[(agent, self._day())] += tokens

    def spent_today(self, agent: str) -> int:
        with self._lock:
            return self._spent[(agent, self._day())]
