"""Business objects the agent reasons about.

The model never sees tables, columns or SQL. It sees these typed objects, as
projected by `view_for()` (which drops objects and fields the caller may not
see), and it changes them only through the actions in `actions.py`.
"""

from __future__ import annotations

from enum import Enum
from typing import ClassVar

from pydantic import BaseModel, Field


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class IncidentStatus(str, Enum):
    open = "open"
    triaged = "triaged"
    contained = "contained"
    resolved = "resolved"


# Allowed incident transitions. The action layer enforces this; the model
# cannot skip "contained" and mark a live compromise "resolved".
INCIDENT_TRANSITIONS: dict[IncidentStatus, set[IncidentStatus]] = {
    IncidentStatus.open: {IncidentStatus.triaged},
    IncidentStatus.triaged: {IncidentStatus.contained, IncidentStatus.resolved},
    IncidentStatus.contained: {IncidentStatus.resolved},
    IncidentStatus.resolved: set(),
}


class OntologyObject(BaseModel):
    TYPE: ClassVar[str] = "object"
    # field name -> marking required to see that field
    FIELD_MARKINGS: ClassVar[dict[str, str]] = {}

    id: str
    markings: list[str] = Field(default_factory=list)


class Person(OntologyObject):
    TYPE: ClassVar[str] = "person"
    FIELD_MARKINGS: ClassVar[dict[str, str]] = {"email": "PII", "phone": "PII"}

    name: str
    team: str
    email: str
    phone: str | None = None


class Asset(OntologyObject):
    TYPE: ClassVar[str] = "asset"

    hostname: str
    environment: str  # prod | staging | dev | laptop
    owner_id: str
    status: str = "active"  # active | quarantined


class Installation(OntologyObject):
    TYPE: ClassVar[str] = "installation"

    asset_id: str
    package: str
    version: str
    location: str


class Advisory(OntologyObject):
    TYPE: ClassVar[str] = "advisory"

    package: str
    affected_versions: list[str]
    severity: Severity
    summary: str


class Finding(OntologyObject):
    TYPE: ClassVar[str] = "finding"

    asset_id: str
    kind: str
    severity: Severity
    # Evidence is collected from machines and is UNTRUSTED text. It is passed to
    # the model as data; it can contain prompt-injection attempts.
    evidence: str
    status: str = "new"  # new | linked | dismissed
    incident_id: str | None = None


class Credential(OntologyObject):
    TYPE: ClassVar[str] = "credential"

    asset_id: str
    kind: str  # aws | gcp | ssh | github | kube | db
    fingerprint: str  # last 4 / key id suffix only, never the secret
    status: str = "active"  # active | rotation_requested | rotated


class Incident(OntologyObject):
    TYPE: ClassVar[str] = "incident"

    title: str
    severity: Severity
    status: IncidentStatus = IncidentStatus.open
    asset_ids: list[str] = Field(default_factory=list)
    summary: str = ""
    notes: list[str] = Field(default_factory=list)
    opened_by: str = ""


class Notification(OntologyObject):
    TYPE: ClassVar[str] = "notification"

    person_id: str
    message: str
    sent_by: str


OBJECT_TYPES: dict[str, type[OntologyObject]] = {
    cls.TYPE: cls
    for cls in (Person, Asset, Installation, Advisory, Finding, Credential, Incident, Notification)
}
