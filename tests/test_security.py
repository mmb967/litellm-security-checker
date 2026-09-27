import pytest

from warden.config import DEFAULT_CONFIG_DIR, _load, load_principals
from warden.locality import NonLocalEndpointError, assert_local, is_local_host
from warden.security.policy import Policy

POLICY = _load(DEFAULT_CONFIG_DIR / "policy.yaml")
P = load_principals(POLICY["principals"])
policy = Policy.from_config(POLICY)


def test_role_check_with_globs():
    assert policy.has_permission(P["alice"], "agent:triage:run")  # agent:*:run
    assert policy.has_permission(P["alice"], "incident:write")    # incident:*
    assert not policy.has_permission(P["alice"], "asset:quarantine_prod")
    assert policy.has_permission(P["carol"], "asset:quarantine_prod")  # asset:*
    assert not policy.has_permission(P["bob"], "agent:triage:run")


def test_marking_requires_clearance():
    assert policy.can_see(P["alice"], ["PROD"], "incident_response")
    assert not policy.can_see(P["alice"], ["EXEC"], "incident_response")
    assert policy.can_see(P["carol"], ["EXEC"], "incident_response")


def test_marking_restricted_by_purpose():
    # Alice is cleared for PII, but PII may only be used for incident response.
    assert policy.can_see(P["alice"], ["PII"], "incident_response")
    d = policy.can_see(P["alice"], ["PII"], "reporting")
    assert not d and "purpose" in d.reason


def test_unknown_marking_fails_closed():
    assert not policy.can_see(P["carol"], ["TOP_SECRET"], "incident_response")


def test_purpose_must_be_granted_to_principal():
    assert not policy.purpose_ok(P["bob"], "incident_response", [])
    assert policy.purpose_ok(P["bob"], "reporting", [])


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "10.20.0.5", "192.168.1.9",
                                  "172.16.4.4", "fd00::1", "ollama.localhost"])
def test_local_hosts(host):
    assert is_local_host(host)


@pytest.mark.parametrize("url", ["https://api.openai.com/v1", "http://8.8.8.8:8000",
                                 "https://cloud.langfuse.com/api/public/otel",
                                 "http://inference.internal:8000/v1"])
def test_non_local_endpoints_rejected(url):
    with pytest.raises(NonLocalEndpointError):
        assert_local(url, "test")


def test_allowlisted_hostname_accepted():
    assert_local("http://inference.internal:8000/v1", "test", frozenset({"inference.internal"}))
