"""Outbound-request destination checks (SSRF).

Two policies, because oc8 makes two kinds of outbound request:

* **Untrusted URLs** -- anything an agent, a web page or a pasted link can
  steer (`fetch_url`, website/knowledge imports, skill archives). Only
  globally routable addresses are allowed. Use `untrusted_transport()`: it
  checks the address *at connect time*, on the very IP the socket opens, so a
  hostname that resolves to a public IP for a pre-flight check and to
  127.0.0.1 a millisecond later (DNS rebinding) cannot slip through. TLS still
  verifies against the original hostname -- httpcore wraps the stream with the
  origin's host as `server_hostname` after `connect_tcp` returns.

* **Operator-configured endpoints** -- a model provider's `base_url`, an MCP
  server URL, a plugin's HTTP hook. These legitimately point at the LAN
  (Ollama, an in-house MCP server), so private ranges stay allowed. What is
  refused is what no legitimate endpoint needs and every SSRF wants: the
  link-local range that hosts cloud metadata services (169.254.169.254,
  fe80::/10), unspecified/multicast addresses, and -- outside dev -- loopback,
  which inside a container is the backend itself. Use
  `check_operator_endpoint()`.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

import anyio
import httpcore
import httpx

_ALLOWED_SCHEMES = {"http", "https"}


class BlockedDestinationError(ValueError):
    """The request's destination is not allowed by the active policy."""


def _ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        addr = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return None
    # ::ffff:127.0.0.1 must be judged as the IPv4 address it carries.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def is_public_ip(value: str) -> bool:
    """True only for a globally routable unicast address."""
    addr = _ip(value)
    if addr is None:
        return False
    return not (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
        or not addr.is_global
    )


def is_allowed_operator_ip(value: str, *, allow_loopback: bool) -> bool:
    addr = _ip(value)
    if addr is None:
        return False
    if addr.is_link_local or addr.is_unspecified or addr.is_multicast:
        return False
    if addr.is_loopback and not allow_loopback:
        return False
    return True


async def check_operator_endpoint(url: str, *, allow_loopback: bool) -> None:
    """Refuse an operator-configured URL that targets metadata/loopback.

    Resolution runs off the event loop (`anyio.getaddrinfo`). A name that does
    not resolve is let through: the request will fail on its own, and refusing
    here would only turn a clear connection error into a confusing policy one.
    """
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise BlockedDestinationError(f"scheme not allowed: {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise BlockedDestinationError("missing host")
    try:
        infos = await anyio.getaddrinfo(host, parsed.port or 0, type=socket.SOCK_STREAM)
    except OSError:
        return
    ips = [str(info[4][0]) for info in infos]
    for ip in ips:
        if not is_allowed_operator_ip(ip, allow_loopback=allow_loopback):
            raise BlockedDestinationError(f"blocked destination {host!r} -> {ip}")


class _PublicOnlyBackend(httpcore.AsyncNetworkBackend):
    """Resolves, checks and connects in one step, to the checked address."""

    def __init__(self) -> None:
        self._inner = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109 -- httpcore's interface
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        try:
            infos = await anyio.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise httpcore.ConnectError(f"cannot resolve {host!r}: {exc}") from exc
        ips = [str(info[4][0]) for info in infos]
        if not ips:
            raise httpcore.ConnectError(f"cannot resolve {host!r}")
        for ip in ips:
            if not is_public_ip(ip):
                raise BlockedDestinationError(f"blocked host {host!r} -> {ip}")
        return await self._inner.connect_tcp(
            ips[0],
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109 -- httpcore's interface
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise BlockedDestinationError("unix sockets are not allowed")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def untrusted_transport() -> httpx.AsyncHTTPTransport:
    """An httpx transport that only ever connects to public addresses.

    Pass it as `transport=` (which also disables environment proxies -- a
    proxy would resolve the name itself and defeat the check).
    """
    transport = httpx.AsyncHTTPTransport()
    # httpx 0.28 exposes no `network_backend` argument; the pool keeps it here.
    transport._pool._network_backend = _PublicOnlyBackend()
    return transport
