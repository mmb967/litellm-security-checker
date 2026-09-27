"""Who is running the agent.

The agent never has an identity of its own. Every run carries the Principal of
the human (or the explicitly-configured service account) that started it, and
every permission check downstream is made against that Principal.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Principal:
    id: str
    kind: str  # "user" | "service"
    roles: frozenset[str]
    # Data markings this principal is cleared to see (e.g. PROD, PII, EXEC).
    clearances: frozenset[str]
    # Purposes this principal may act under (e.g. incident_response, reporting).
    purposes: frozenset[str]
    # For service principals: the human who owns / approved this service account.
    # Recorded on every audit event so automated runs are still attributable.
    owner: str | None = None
    display_name: str = ""

    @property
    def is_service(self) -> bool:
        return self.kind == "service"


@dataclass(frozen=True)
class RunContext:
    """Everything a single agent run is bound to. Immutable for the whole run."""

    run_id: str
    agent: str
    principal: Principal
    purpose: str
    trigger: str  # "api" | "webhook" | "schedule" | "eval" | "cli"
    trigger_detail: dict = field(default_factory=dict)
