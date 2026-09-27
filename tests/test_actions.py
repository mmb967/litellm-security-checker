import pytest

from warden.config import build
from warden.ontology.actions import (
    REGISTRY,
    ActionContext,
    ActionError,
    GetAssetArgs,
    NotifyOwnerArgs,
    OpenIncidentArgs,
    QuarantineArgs,
    SearchAssetsArgs,
    UpdateIncidentStatusArgs,
)
from warden.ontology.objects import Asset, Incident, Notification
from warden.security.principal import RunContext


@pytest.fixture
def w():
    return build(db_path=":memory:", audit_path="")


def ctx(w, who, purpose="incident_response"):
    run = RunContext("run_test", "triage", w.principals[who], purpose, "test")
    return ActionContext(store=w.store, policy=w.runtime.policy, run=run)


def test_no_generic_data_access_tool_exists():
    names = set(REGISTRY)
    assert not any(k in n for n in names for k in ("sql", "query", "http", "exec", "shell"))


def test_marked_objects_are_invisible_not_forbidden(w):
    c = ctx(w, "dave")  # PROD only
    hosts = {a["hostname"] for a in REGISTRY["search_assets"].fn(c, SearchAssetsArgs())}
    assert "exec-mbp-dortiz" not in hosts and "build-dp-02" not in hosts
    assert "ml-train-01" in hosts
    # Same error text as a missing id: no existence oracle.
    with pytest.raises(ActionError, match="asset 'A-004' not found"):
        REGISTRY["get_asset"].fn(c, GetAssetArgs(asset_id="A-004"))
    with pytest.raises(ActionError, match="asset 'A-999' not found"):
        REGISTRY["get_asset"].fn(c, GetAssetArgs(asset_id="A-999"))


def test_field_level_marking_withholds_pii_for_wrong_purpose(w):
    ir = REGISTRY["get_asset"].fn(ctx(w, "alice"), GetAssetArgs(asset_id="A-003"))
    assert ir["owner"]["email"] == "priya.nair@example.com"
    rep = REGISTRY["get_asset"].fn(ctx(w, "alice", "reporting"), GetAssetArgs(asset_id="A-003"))
    assert rep["owner"]["email"].startswith("[withheld")
    # Credentials are SECRET_META, usable only for incident response.
    assert rep["credentials"] == []


def test_seen_markings_are_tracked(w):
    c = ctx(w, "alice")
    REGISTRY["get_asset"].fn(c, GetAssetArgs(asset_id="A-001"))
    assert {"PROD", "SECRET_META", "PII"} <= c.seen_markings


def test_incident_state_machine(w):
    c = ctx(w, "alice")
    fn = REGISTRY["update_incident_status"].fn
    with pytest.raises(ActionError, match="cannot move INC-0001 from 'open' to 'resolved'"):
        fn(c, UpdateIncidentStatusArgs(incident_id="INC-0001", status="resolved", note="x"))
    fn(c, UpdateIncidentStatusArgs(incident_id="INC-0001", status="triaged", note="looked"))
    assert w.store.get(Incident, "INC-0001").status.value == "triaged"


def test_open_incident_inherits_asset_markings(w):
    c = ctx(w, "alice")
    inc = REGISTRY["open_incident"].fn(c, OpenIncidentArgs(
        title="t", severity="high", asset_ids=["A-001", "A-003"], finding_ids=["F-001"], summary="s"))
    assert inc["markings"] == ["PROD"]
    # ...so a viewer without PROD clearance cannot see it.
    assert not w.runtime.policy.can_see(w.principals["bob"], inc["markings"], "reporting")
    assert w.runtime.policy.can_see(w.principals["dave"], inc["markings"], "reporting")


def test_prod_quarantine_needs_extra_permission(w):
    with pytest.raises(ActionError, match="quarantine_prod"):
        REGISTRY["quarantine_asset"].fn(ctx(w, "alice"), QuarantineArgs(asset_id="A-001", reason="r"))
    REGISTRY["quarantine_asset"].fn(ctx(w, "carol"), QuarantineArgs(asset_id="A-001", reason="r"))
    assert w.store.get(Asset, "A-001").status == "quarantined"


def test_notify_owner_never_returns_contact_details(w):
    out = REGISTRY["notify_owner"].fn(ctx(w, "alice"), NotifyOwnerArgs(asset_id="A-003", message="m"))
    assert "@" not in str(out)
    assert w.store.list(Notification)[0].person_id == "P-001"


def test_tool_schemas_are_closed():
    for a in REGISTRY.values():
        assert a.input_schema().get("additionalProperties") is False, a.name
