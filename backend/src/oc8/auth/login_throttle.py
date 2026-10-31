"""Failed-attempt throttling for the pre-auth credential endpoints.

`POST /auth/login` and `POST /auth/totp/verify` both answer an unbounded
number of guesses without it: a password can be brute-forced against one
address, and a six-digit TOTP code can be enumerated within the lifetime of a
single `totp:challenge` token -- which defeats the second factor outright.

Counters live in Redis (shared by every API replica), one per key, with a
fixed window that starts at the first failure. A key at or over its limit is
refused with 429 BEFORE the credential is checked, so a locked-out attacker
learns nothing more. A success clears the key.

Fail-open on a Redis outage, deliberately: refusing every login because the
cache is down would lock the operator out of the instance they need to fix.
The outage is logged so it does not go unnoticed.
"""

from __future__ import annotations

import hashlib
import logging

import redis.asyncio as redis
from fastapi import HTTPException, Request, status

from oc8.config import get_settings

logger = logging.getLogger(__name__)

_PREFIX = "oc8:auth-throttle:"


def _key(kind: str, value: str) -> str:
    # Hashed so an email address never sits in Redis in plain text.
    digest = hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()
    return f"{_PREFIX}{kind}:{digest}"


def client_ip(request: Request) -> str:
    """The caller's address as Caddy saw it.

    Caddy's `reverse_proxy` does not trust an incoming X-Forwarded-For from an
    untrusted client: it replaces it with the real peer address, so the
    left-most entry is the client. Without a proxy in front, fall back to the
    socket peer.
    """
    forwarded = request.headers.get("x-forwarded-for", "")
    first = forwarded.split(",")[0].strip()
    if first:
        return first
    return request.client.host if request.client else "unknown"


def _redis() -> redis.Redis:
    return redis.from_url(
        get_settings().redis_url,
        decode_responses=True,
        socket_connect_timeout=1.0,
        socket_timeout=1.0,
    )


class AttemptThrottle:
    def __init__(self, *, kind: str, limit: int, window_seconds: int) -> None:
        self.kind = kind
        self.limit = limit
        self.window_seconds = window_seconds

    def keys(self, *values: str) -> list[str]:
        return [_key(self.kind, v) for v in values if v]

    async def ensure_allowed(self, keys: list[str]) -> None:
        if not keys or not get_settings().auth_throttle_enabled:
            return
        try:
            r = _redis()
            try:
                counts = await r.mget(keys)
                ttls = [await r.ttl(k) for k in keys]
            finally:
                await r.aclose()
        except redis.RedisError as exc:
            logger.warning("auth throttle unavailable (fail-open): %s", exc)
            return
        for count, ttl in zip(counts, ttls, strict=True):
            if count is not None and int(count) >= self.limit:
                retry_after = ttl if ttl and ttl > 0 else self.window_seconds
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many failed attempts. Try again later.",
                    headers={"Retry-After": str(retry_after)},
                )

    async def record_failure(self, keys: list[str]) -> None:
        if not keys or not get_settings().auth_throttle_enabled:
            return
        try:
            r = _redis()
            try:
                async with r.pipeline(transaction=False) as pipe:
                    for k in keys:
                        pipe.incr(k)
                        pipe.expire(k, self.window_seconds, nx=True)
                    await pipe.execute()
            finally:
                await r.aclose()
        except redis.RedisError as exc:
            logger.warning("auth throttle unavailable (fail-open): %s", exc)

    async def reset(self, keys: list[str]) -> None:
        if not keys or not get_settings().auth_throttle_enabled:
            return
        try:
            r = _redis()
            try:
                await r.delete(*keys)
            finally:
                await r.aclose()
        except redis.RedisError as exc:
            logger.warning("auth throttle unavailable (fail-open): %s", exc)


#: Per account: 10 wrong passwords in 15 minutes. Per IP: 50, so one address
#: cannot spray many accounts either, while an office behind one NAT still fits.
LOGIN_ACCOUNT_THROTTLE = AttemptThrottle(kind="login-acct", limit=10, window_seconds=900)
LOGIN_IP_THROTTLE = AttemptThrottle(kind="login-ip", limit=50, window_seconds=900)

#: Per member: 5 wrong codes in 15 minutes -- 5 of 1,000,000 codes per window.
TOTP_THROTTLE = AttemptThrottle(kind="totp", limit=5, window_seconds=900)
