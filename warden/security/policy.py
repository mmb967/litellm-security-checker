"""Three-way access control: role, data marking, purpose.

    role     -> may this principal perform this *kind* of action at all?
    marking  -> may this principal see / touch this *particular* object?
    purpose  -> is this action / this data permitted for *why* the run exists?

All three must pass. The checks are pure functions over config so they are
cheap to unit-test and identical no matter which trigger started the run.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Iterable

from warden.security.principal import Principal


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str

    def __bool__(self) -> bool:
        return self.allowed


ALLOW = Decision(True, "allowed")


class Policy:
    def __init__(self, roles: dict[str, list[str]], markings: dict[str, dict]):
        self._roles = {r: frozenset(p) for r, p in roles.items()}
        # marking -> set of purposes under which data carrying it may be used
        # (None = any purpose the principal holds).
        self._marking_purposes: dict[str, frozenset[str] | None] = {
            m: (frozenset(cfg["purposes"]) if cfg and cfg.get("purposes") else None)
            for m, cfg in markings.items()
        }

    @classmethod
    def from_config(cls, cfg: dict) -> "Policy":
        return cls(roles=cfg["roles"], markings=cfg.get("markings", {}))

    # -- role --------------------------------------------------------------
    def permissions(self, principal: Principal) -> frozenset[str]:
        perms: set[str] = set()
        for role in principal.roles:
            perms |= self._roles.get(role, frozenset())
        return frozenset(perms)

    def has_permission(self, principal: Principal, permission: str) -> bool:
        # Grants may be glob patterns: "*", "incident:*", "agent:*:run".
        return any(fnmatchcase(permission, p) for p in self.permissions(principal))

    # -- purpose -----------------------------------------------------------
    @staticmethod
    def purpose_ok(principal: Principal, purpose: str, allowed: Iterable[str]) -> Decision:
        if purpose not in principal.purposes:
            return Decision(False, f"principal '{principal.id}' is not granted purpose '{purpose}'")
        allowed = frozenset(allowed)
        if allowed and purpose not in allowed:
            return Decision(False, f"purpose '{purpose}' not in allowed purposes {sorted(allowed)}")
        return ALLOW

    # -- marking -----------------------------------------------------------
    def can_see(self, principal: Principal, markings: Iterable[str], purpose: str) -> Decision:
        for m in markings:
            if m not in principal.clearances:
                return Decision(False, f"missing clearance for marking '{m}'")
            if m not in self._marking_purposes:
                # Unknown markings fail closed.
                return Decision(False, f"unknown marking '{m}'")
            allowed_purposes = self._marking_purposes[m]
            if allowed_purposes is not None and purpose not in allowed_purposes:
                return Decision(False, f"marking '{m}' may not be used for purpose '{purpose}'")
        return ALLOW

    # -- combined ----------------------------------------------------------
    def check_action(
        self,
        principal: Principal,
        permission: str,
        purpose: str,
        action_purposes: Iterable[str],
    ) -> Decision:
        if not self.has_permission(principal, permission):
            return Decision(False, f"role check failed: needs permission '{permission}'")
        return self.purpose_ok(principal, purpose, action_purposes)
