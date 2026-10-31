"""oc8.net.ssrf: connect-time checks for untrusted URLs (DNS rebinding) and
the metadata/loopback policy for operator-configured endpoints."""

from __future__ import annotations

import socket
import uuid
from typing import Any

import anyio
import httpcore
import pytest

import oc8.knowledge.connectors.fetcher as fetcher
from oc8.config import Settings
from oc8.knowledge.connectors.base import ConnectorError
from oc8.modelrouter.router import ModelRouter
from oc8.modelrouter.types import CompletionRequest, ModelParams
from oc8.net import ssrf
from oc8.net.ssrf import BlockedDestinationError, check_operator_endpoint, is_public_ip

pytestmark = pytest.mark.asyncio


def _resolving_to(*ips: str):
    async def fake_getaddrinfo(host: str, port: int, **_: Any) -> list[Any]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]

    return fake_getaddrinfo


@pytest.mark.parametrize("ip", ["::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1"])
def test_ipv4_mapped_ipv6_is_judged_as_ipv4(ip: str) -> None:
    assert is_public_ip(ip) is False


def test_public_ip_allowed() -> None:
    assert is_public_ip("93.184.216.34") is True


async def test_dns_rebinding_is_refused_at_connect_time(monkeypatch: pytest.MonkeyPatch) -> None:
    """The pre-flight check sees a public address; the name then resolves to
    loopback when the socket is opened. The connect-time check must refuse it."""
    monkeypatch.setattr(fetcher, "_resolve_ips", lambda host: ["93.184.216.34"])
    monkeypatch.setattr(anyio, "getaddrinfo", _resolving_to("127.0.0.1"))

    with pytest.raises(ConnectorError, match="blocked host"):
        await fetcher.safe_fetch("http://rebind.example/")


async def test_metadata_address_is_refused_at_connect_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fetcher, "_resolve_ips", lambda host: ["93.184.216.34"])
    monkeypatch.setattr(anyio, "getaddrinfo", _resolving_to("93.184.216.34", "169.254.169.254"))

    with pytest.raises(ConnectorError, match=r"169.254.169.254"):
        await fetcher.safe_fetch_bytes("http://mixed.example/archive.zip")


async def test_the_socket_opens_to_the_address_that_was_checked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fetcher, "_resolve_ips", lambda host: ["93.184.216.34"])
    monkeypatch.setattr(anyio, "getaddrinfo", _resolving_to("93.184.216.34"))
    connected: list[str] = []

    async def fake_connect(self: Any, host: str, port: int, **_: Any) -> Any:
        connected.append(host)
        raise httpcore.ConnectError("stop here")

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", fake_connect)

    with pytest.raises(Exception):  # noqa: B017 -- only the connect target matters
        await fetcher.safe_fetch("http://pinned.example/")
    assert connected == ["93.184.216.34"]


@pytest.mark.parametrize(
    ("ip", "allow_loopback", "allowed"),
    [
        ("10.0.0.5", False, True),
        ("192.168.1.20", False, True),
        ("8.8.8.8", False, True),
        ("169.254.169.254", True, False),
        ("127.0.0.1", False, False),
        ("127.0.0.1", True, True),
        ("0.0.0.0", True, False),
    ],
)
async def test_operator_endpoint_policy(
    monkeypatch: pytest.MonkeyPatch, ip: str, allow_loopback: bool, allowed: bool
) -> None:
    monkeypatch.setattr(anyio, "getaddrinfo", _resolving_to(ip))
    if allowed:
        await check_operator_endpoint(
            "http://endpoint.example:11434/v1", allow_loopback=allow_loopback
        )
    else:
        with pytest.raises(BlockedDestinationError):
            await check_operator_endpoint(
                "http://endpoint.example:11434/v1", allow_loopback=allow_loopback
            )


async def test_operator_endpoint_rejects_non_http_schemes() -> None:
    with pytest.raises(BlockedDestinationError):
        await check_operator_endpoint("file:///etc/passwd", allow_loopback=True)


async def test_operator_endpoint_lets_an_unresolvable_name_fail_on_its_own(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail(*_: Any, **__: Any) -> list[Any]:
        raise socket.gaierror("no such host")

    monkeypatch.setattr(anyio, "getaddrinfo", fail)
    await check_operator_endpoint("http://nowhere.invalid/", allow_loopback=False)


async def test_model_router_refuses_a_metadata_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(anyio, "getaddrinfo", _resolving_to("169.254.169.254"))
    router = ModelRouter(Settings(env="prod", anthropic_api_key="sk-test", _env_file=None))
    req = CompletionRequest(
        provider="anthropic",
        model="m",
        messages=[],
        params=ModelParams(),
        tenant_id=uuid.uuid4(),
        api_key="sk-test",
        base_url="http://metadata.example/",
    )
    with pytest.raises(BlockedDestinationError):
        await router.complete(req)


def test_untrusted_transport_uses_the_public_only_backend() -> None:
    transport = ssrf.untrusted_transport()
    assert isinstance(transport._pool._network_backend, ssrf._PublicOnlyBackend)
