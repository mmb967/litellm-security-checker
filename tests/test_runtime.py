from warden.gateway.types import ToolResult
from warden.observability.audit import verify
from warden.ontology.objects import Credential, Incident

from .conftest import script


def offered_tools(sp):
    return {t.name for t in sp.requests[0].tools}


def test_tools_offered_are_intersection_of_agent_and_principal(make_warden):
    w, sp = make_warden(script("ok"))
    w.runtime.run("triage", "hi", principal=w.principals["dave"], purpose="incident_response",
                  trigger="test")
    assert "request_credential_rotation" not in offered_tools(sp)
    assert "quarantine_asset" not in offered_tools(sp)
    assert "open_incident" in offered_tools(sp)


def test_run_denied_without_agent_permission_never_calls_model(make_warden):
    w, sp = make_warden(script("ok"))
    r = w.runtime.run("triage", "hi", principal=w.principals["bob"], purpose="reporting",
                      trigger="test")
    assert r.status == "denied" and sp.requests == []


def test_unoffered_tool_call_is_denied_and_audited(make_warden):
    w, _ = make_warden(script([("request_credential_rotation",
                                {"credential_id": "C-003", "reason": "x"})], "gave up"))
    r = w.runtime.run("triage", "rotate", principal=w.principals["dave"],
                      purpose="incident_response", trigger="test")
    assert r.tool_calls[0].allowed is False
    assert w.store.get(Credential, "C-003").status == "active"
    assert any(e["event"] == "tool_denied" for e in w.audit.events)


def test_invalid_arguments_are_returned_to_model_not_executed(make_warden):
    w, sp = make_warden(script([("open_incident", {"title": "t", "severity": "apocalyptic",
                                                   "asset_ids": ["A-003"], "summary": "s"})], "ok"))
    r = w.runtime.run("triage", "x", principal=w.principals["alice"], purpose="incident_response",
                      trigger="test")
    assert r.tool_calls[0].ok is False
    assert w.store.list(Incident, lambda i: i.id != "INC-0001") == []
    result = [b for m in sp.requests[1].messages for b in m.content if isinstance(b, ToolResult)][0]
    assert result.is_error and "invalid arguments" in result.content


def test_full_run_masks_pii_in_tool_results_and_writes_valid_audit_chain(make_warden, tmp_path):
    w, sp = make_warden(script(
        [("list_findings", {"asset_id": "A-001"}), ("get_asset", {"asset_id": "A-001"})],
        [("request_credential_rotation", {"credential_id": "C-001", "reason": "exposed"})],
        "done",
    ))
    r = w.runtime.run("triage", "go", principal=w.principals["alice"],
                      purpose="incident_response", trigger="test")
    assert r.status == "completed" and r.steps == 3
    assert w.store.get(Credential, "C-001").status == "rotation_requested"

    wire = " ".join(str(req.messages) for req in sp.requests)
    assert "AKIAIOSFODNN7EXAMPLE" not in wire          # secret from finding evidence
    assert "marcus.webb@example.com" not in wire       # PII from evidence and owner record
    assert "<SECRET_1>" in wire and "<EMAIL_1>" in wire

    ok, msg = verify(tmp_path / "audit.jsonl")
    assert ok, msg
    events = [e["event"] for e in w.audit.for_run(r.run_id)]
    assert events[0] == "run_start" and events[-1] == "run_end"
    assert events.count("llm_call") == 3 and events.count("tool_call") == 3
    assert "AKIA" not in (tmp_path / "audit.jsonl").read_text()


def test_audit_chain_detects_tampering(make_warden, tmp_path):
    w, _ = make_warden(script("ok"))
    w.runtime.run("triage", "x", principal=w.principals["alice"], purpose="incident_response",
                  trigger="test")
    path = tmp_path / "audit.jsonl"
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:1] + lines[2:]) + "\n")  # delete one event
    assert verify(path)[0] is False


def test_service_principal_runs_are_attributed_to_owner(make_warden):
    w, _ = make_warden(script("ok"))
    r = w.runtime.run("triage", "x", principal=w.principals["svc-nightly-sweep"],
                      purpose="incident_response", trigger="schedule")
    start = w.audit.for_run(r.run_id)[0]
    assert start["principal_kind"] == "service" and start["on_behalf_of"] == "carol"


def test_step_limit(make_warden):
    w, _ = make_warden(script(*[[("list_findings", {})]] * 50))
    r = w.runtime.run("reporter", "x", principal=w.principals["bob"], purpose="reporting",
                      trigger="test")
    assert r.status == "step_limit" and r.steps == w.runtime.agents["reporter"].max_steps


def test_model_swap_via_env(make_warden, monkeypatch):
    monkeypatch.setenv("WARDEN_MODEL_TRIAGE", "local-medium")
    w, _ = make_warden(script("ok"))
    r = w.runtime.run("triage", "x", principal=w.principals["alice"], purpose="incident_response",
                      trigger="test")
    assert r.models_used == ["local-medium"]
