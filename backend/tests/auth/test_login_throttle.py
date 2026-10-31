# ruff: noqa: F811 -- pytest fixtures imported from the password-auth suite
"""Failed-attempt throttling on /auth/login and /auth/totp/verify
(oc8.auth.login_throttle), plus the startup refusal of a public JWT secret."""

from __future__ import annotations

import pyotp
import pytest
import redis.asyncio as redis
from httpx import AsyncClient

from oc8 import models as m
from oc8.config import Settings, get_settings
from oc8.main import _DEFAULT_JWT_SECRET, refuse_insecure_jwt_secret

# Fixtures shared with the password-auth suite (imported, not redefined).
from tests.auth.test_password_auth import (  # noqa: F401
    _kek,
    app_with_db,
    client,
    db_session,
    org_in_db,
)

pytestmark = pytest.mark.asyncio

PASSWORD = "SecurePassword123!"


@pytest.fixture
async def throttle_on(redis_url: str, monkeypatch: pytest.MonkeyPatch):
    """Turn the throttle back on (conftest disables it suite-wide) against a
    clean slate of counters in the test Redis."""
    monkeypatch.setattr(get_settings(), "auth_throttle_enabled", True)
    r = redis.from_url(redis_url)
    try:
        keys = [k async for k in r.scan_iter("oc8:auth-throttle:*")]
        if keys:
            await r.delete(*keys)
        yield
        keys = [k async for k in r.scan_iter("oc8:auth-throttle:*")]
        if keys:
            await r.delete(*keys)
    finally:
        await r.aclose()


async def _setup_admin(client: AsyncClient, email: str) -> str:
    r = await client.post(
        "/api/v1/auth/setup",
        json={"email": email, "password": PASSWORD, "displayName": "A"},
    )
    assert r.status_code == 201, r.text
    return r.json()["token"]


async def _login(client: AsyncClient, email: str, password: str):
    return await client.post("/api/v1/auth/login", json={"email": email, "password": password})


async def test_login_locks_an_account_after_ten_failures(
    client: AsyncClient, org_in_db: m.Organization, throttle_on: None
) -> None:
    email = "locked@example.com"
    await _setup_admin(client, email)

    for _ in range(10):
        assert (await _login(client, email, "wrong")).status_code == 401

    blocked = await _login(client, email, "wrong")
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0
    # The correct password is refused too while locked: the check happens
    # before the credential is looked at.
    assert (await _login(client, email, PASSWORD)).status_code == 429


async def test_successful_login_resets_the_account_counter(
    client: AsyncClient, org_in_db: m.Organization, throttle_on: None
) -> None:
    email = "reset@example.com"
    await _setup_admin(client, email)

    for _ in range(9):
        assert (await _login(client, email, "wrong")).status_code == 401
    assert (await _login(client, email, PASSWORD)).status_code == 200
    for _ in range(9):
        assert (await _login(client, email, "wrong")).status_code == 401
    assert (await _login(client, email, PASSWORD)).status_code == 200


async def test_unknown_addresses_are_throttled_like_known_ones(
    client: AsyncClient, org_in_db: m.Organization, throttle_on: None
) -> None:
    """Otherwise the 429 itself would reveal which addresses exist."""
    for _ in range(10):
        assert (await _login(client, "ghost@example.com", "wrong")).status_code == 401
    assert (await _login(client, "ghost@example.com", "wrong")).status_code == 429


async def test_totp_verify_locks_after_five_wrong_codes(
    client: AsyncClient, org_in_db: m.Organization, throttle_on: None
) -> None:
    email = "totp-locked@example.com"
    setup_token = await _setup_admin(client, email)
    auth = {"Authorization": f"Bearer {setup_token}"}
    secret = (await client.post("/api/v1/auth/totp/enroll", headers=auth)).json()["secret"]
    confirm = await client.post(
        "/api/v1/auth/totp/confirm",
        json={"secret": secret, "code": pyotp.TOTP(secret).now()},
        headers=auth,
    )
    assert confirm.status_code == 200, confirm.text

    login = await _login(client, email, PASSWORD)
    assert login.status_code == 200, login.text
    challenge = {"Authorization": f"Bearer {login.json()['token']}"}

    valid = pyotp.TOTP(secret).now()
    wrong = "000000" if valid != "000000" else "111111"
    for _ in range(5):
        r = await client.post("/api/v1/auth/totp/verify", json={"code": wrong}, headers=challenge)
        assert r.status_code == 401, r.text

    r = await client.post("/api/v1/auth/totp/verify", json={"code": valid}, headers=challenge)
    assert r.status_code == 429


def test_non_dev_refuses_the_public_default_jwt_secret() -> None:
    with pytest.raises(RuntimeError, match="OC8_JWT_SECRET"):
        refuse_insecure_jwt_secret(
            Settings(env="prod", jwt_secret=_DEFAULT_JWT_SECRET, _env_file=None)
        )


def test_non_dev_refuses_a_short_jwt_secret() -> None:
    with pytest.raises(RuntimeError):
        refuse_insecure_jwt_secret(Settings(env="prod", jwt_secret="short", _env_file=None))


def test_non_dev_accepts_a_real_jwt_secret() -> None:
    refuse_insecure_jwt_secret(Settings(env="prod", jwt_secret="a" * 64, _env_file=None))


def test_dev_keeps_the_default_jwt_secret() -> None:
    refuse_insecure_jwt_secret(Settings(env="dev", _env_file=None))
