"""Local-only enforcement.

Warden is designed to run with no data leaving the machine (or the private
network it is deployed on). This module is the check: any endpoint the system
would send data to (model servers, trace collectors) must be

  * a loopback address or `localhost`,
  * a private / link-local IP literal (RFC 1918, RFC 4193, 169.254/16), or
  * a hostname explicitly listed in `gateway.local_only.allowed_hosts`.

Hostnames are NOT resolved: DNS can point anywhere, so a name is trusted only
if an operator listed it. The check runs at startup for every configured
endpoint and again before every model call, so a runtime-registered model
cannot bypass it.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


class NonLocalEndpointError(Exception):
    pass


def is_local_host(host: str, allowed_hosts: frozenset[str] = frozenset()) -> bool:
    host = host.strip("[]").lower()
    if host in allowed_hosts or host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def assert_local(url: str, what: str, allowed_hosts: frozenset[str] = frozenset()) -> None:
    parsed = urlparse(url)
    if not parsed.hostname:
        raise NonLocalEndpointError(f"{what}: cannot parse host from '{url}'")
    if not is_local_host(parsed.hostname, allowed_hosts):
        raise NonLocalEndpointError(
            f"{what}: '{parsed.hostname}' is not a local endpoint. Warden runs local-only; "
            "use a loopback/private address or add the host to gateway.local_only.allowed_hosts."
        )
