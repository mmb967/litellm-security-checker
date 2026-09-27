"""Cron trigger.

A scheduled run has no human at the keyboard, so it runs as the service
principal named in `run_as`. That principal is a normal entry in policy.yaml
with its own narrow grants and a named human `owner`, which is recorded on
every audit event. Schedules never inherit an administrator's rights.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone

from croniter import croniter

from warden.config import Warden

log = logging.getLogger(__name__)


@dataclass
class Schedule:
    name: str
    cron: str
    agent: str
    run_as: str
    purpose: str
    input: str


class Scheduler:
    def __init__(self, warden: Warden, now=lambda: datetime.now(timezone.utc)):
        self.warden = warden
        self._now = now
        self.schedules = [
            Schedule(name=n, **cfg) for n, cfg in (warden.triggers.get("schedules") or {}).items()
        ]
        for s in self.schedules:
            if s.run_as not in warden.principals:
                raise ValueError(f"schedule '{s.name}' runs as unknown principal '{s.run_as}'")
            if not croniter.is_valid(s.cron):
                raise ValueError(f"schedule '{s.name}' has invalid cron '{s.cron}'")
        start = self._now()
        self._next = {s.name: croniter(s.cron, start).get_next(datetime) for s in self.schedules}
        self._stop = threading.Event()

    def fire(self, s: Schedule):
        return self.warden.runtime.run(
            s.agent,
            s.input,
            principal=self.warden.principals[s.run_as],
            purpose=s.purpose,
            trigger="schedule",
            trigger_detail={"schedule": s.name, "cron": s.cron},
        )

    def tick(self) -> list:
        """Fire every schedule whose time has come. Returns the run results."""
        now = self._now()
        results = []
        for s in self.schedules:
            if now >= self._next[s.name]:
                self._next[s.name] = croniter(s.cron, now).get_next(datetime)
                try:
                    results.append(self.fire(s))
                except Exception:  # one broken schedule must not stop the others
                    log.exception("schedule %s failed", s.name)
        return results

    def run_forever(self, poll_s: float = 20.0) -> None:
        while not self._stop.wait(poll_s):
            self.tick()

    def start_background(self) -> threading.Thread:
        t = threading.Thread(target=self.run_forever, name="warden-scheduler", daemon=True)
        t.start()
        return t

    def stop(self) -> None:
        self._stop.set()
