import json
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from warden.triggers.http import create_app, sign
from warden.triggers.scheduler import Scheduler

from .conftest import script


@pytest.fixture
def client(make_warden, monkeypatch):
    monkeypatch.setenv("WARDEN_API_TOKENS", "tok-alice:alice,tok-bob:bob,tok-svc:svc-scanner-hook")
    monkeypatch.setenv("WARDEN_WEBHOOK_SECRET_SCANNER", "s3cret")
    w, sp = make_warden(script("done"))
    return TestClient(create_app(w, start_scheduler=False)), w, sp


def test_api_runs_as_caller(client):
    c, w, _ = client
    r = c.post("/v1/agents/triage/runs", json={"input": "go", "purpose": "incident_response"},
               headers={"Authorization": "Bearer tok-alice"})
    assert r.status_code == 200 and r.json()["status"] == "completed"
    assert w.audit.for_run(r.json()["run_id"])[0]["principal"] == "alice"


def test_api_auth(client):
    c, _, _ = client
    body = {"input": "go", "purpose": "incident_response"}
    assert c.post("/v1/agents/triage/runs", json=body).status_code == 401
    assert c.post("/v1/agents/triage/runs", json=body,
                  headers={"Authorization": "Bearer nope"}).status_code == 401
    # Service accounts cannot be used interactively.
    assert c.post("/v1/agents/triage/runs", json=body,
                  headers={"Authorization": "Bearer tok-svc"}).status_code == 401
    # Authenticated but not permitted.
    assert c.post("/v1/agents/triage/runs", json=body,
                  headers={"Authorization": "Bearer tok-bob"}).status_code == 403


def _hook(c, body: bytes, secret="s3cret", ts=None):
    ts = str(ts or int(time.time()))
    return c.post("/v1/hooks/scanner", content=body, headers={
        "X-Warden-Timestamp": ts, "X-Warden-Signature": sign(secret, ts, body)})


def test_webhook_signed_runs_as_service_principal(client):
    c, w, sp = client
    r = _hook(c, json.dumps({"finding": "litellm 1.64.1 on ci-runner-07"}).encode())
    assert r.status_code == 200
    start = w.audit.for_run(r.json()["run_id"])[0]
    assert start["principal"] == "svc-scanner-hook" and start["trigger"] == "webhook"
    assert "untrusted" in sp.requests[0].messages[0].content[0].text


def test_webhook_rejects_bad_or_stale_signatures(client):
    c, _, _ = client
    body = b'{"x": 1}'
    assert _hook(c, body, secret="wrong").status_code == 401
    assert _hook(c, body, ts=int(time.time()) - 3600).status_code == 401
    assert c.post("/v1/hooks/scanner", content=body).status_code == 401


def test_scheduler_fires_due_schedules_as_service_principal(make_warden):
    w, _ = make_warden(script("done"))
    now = [datetime(2026, 9, 27, 2, 0, tzinfo=timezone.utc)]
    s = Scheduler(w, now=lambda: now[0])
    assert s.tick() == []
    now[0] += timedelta(minutes=20)  # past 02:17
    [res] = s.tick()
    start = w.audit.for_run(res.run_id)[0]
    assert start["principal"] == "svc-nightly-sweep" and start["trigger"] == "schedule"
    assert s.tick() == []  # not again until tomorrow


def test_same_agent_behind_all_three_triggers(client):
    c, w, _ = client
    c.post("/v1/agents/triage/runs", json={"input": "go", "purpose": "incident_response"},
           headers={"Authorization": "Bearer tok-alice"})
    _hook(c, b"{}")
    sched = Scheduler(w)
    sched.fire(sched.schedules[0])
    triggers = {(e["trigger"], e["agent"]) for e in w.audit.events if e["event"] == "run_start"}
    assert triggers == {("api", "triage"), ("webhook", "triage"), ("schedule", "triage")}
