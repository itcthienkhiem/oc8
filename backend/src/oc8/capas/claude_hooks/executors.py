"""Execute individual Claude hook actions (command, http, mcp_tool, …)."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any

import httpx

from oc8.capas.manifest import CLAUDE_HOOK_PERMISSIONS, ClaudeHookAction
from oc8.config import get_settings
from oc8.net.ssrf import BlockedDestinationError, check_operator_endpoint

logger = logging.getLogger(__name__)

COMMAND_TIMEOUT_S = 30.0
HTTP_TIMEOUT_S = 15.0
_MATCHER_SEP = re.compile(r"\|")


@dataclass(frozen=True)
class HookResult:
    blocked: bool = False
    reason: str = ""
    output: dict[str, Any] | None = None


def matcher_matches(matcher: str, tool_name: str) -> bool:
    if not matcher:
        return True
    patterns = [p.strip() for p in _MATCHER_SEP.split(matcher) if p.strip()]
    if not patterns:
        return True
    return any(tool_name == p or tool_name.startswith(p) for p in patterns)


class ClaudeHookExecutors:
    def __init__(
        self,
        *,
        capa_path: str,
        granted_permissions: list[str],
        trust_level: str,
    ) -> None:
        self.capa_path = capa_path
        self.granted = set(granted_permissions)
        self.trust_level = trust_level

    def _perm_for(self, action_type: str) -> str | None:
        return CLAUDE_HOOK_PERMISSIONS.get(action_type)

    async def run(self, action: ClaudeHookAction, payload: dict[str, Any]) -> HookResult:
        perm = self._perm_for(action.type)
        if perm and perm not in self.granted:
            logger.warning("Claude hook %s skipped: missing permission %s", action.type, perm)
            return HookResult()
        if action.type == "command":
            return await self._command(action, payload)
        if action.type == "http":
            return await self._http(action, payload)
        if action.type == "mcp_tool":
            return HookResult()  # wired via gateway in runner when session available
        if action.type in ("prompt", "agent"):
            logger.info("Claude hook type %s is not executed in oc8 v1", action.type)
            return HookResult()
        logger.warning("unknown Claude hook type %r", action.type)
        return HookResult()

    async def _command(self, action: ClaudeHookAction, payload: dict[str, Any]) -> HookResult:
        cmd = action.command.strip()
        if not cmd:
            return HookResult()
        env = {
            k: os.environ[k]
            for k in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR")
            if k in os.environ
        }
        env["CLAUDE_PLUGIN_ROOT"] = self.capa_path
        env["OC8_HOOK_PAYLOAD"] = json.dumps(payload)
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                cwd=self.capa_path,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=COMMAND_TIMEOUT_S
            )
        except TimeoutError:
            return HookResult(blocked=True, reason="hook command timed out")
        except Exception as exc:
            logger.warning("Claude command hook failed: %s", exc)
            return HookResult()
        text = (stdout or b"").decode(errors="replace")
        if proc.returncode != 0:
            logger.warning(
                "Claude command hook exit %s: %s",
                proc.returncode,
                (stderr or b"").decode(errors="replace")[:500],
            )
        return _parse_hook_output(text)

    async def _http(self, action: ClaudeHookAction, payload: dict[str, Any]) -> HookResult:
        url = action.url.strip()
        if not url:
            return HookResult()
        try:
            await check_operator_endpoint(url, allow_loopback=get_settings().is_dev)
        except BlockedDestinationError as exc:
            logger.warning("Claude http hook refused: %s", exc)
            return HookResult()
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_S) as client:
                resp = await client.post(url, json=payload)
                text = resp.text
        except Exception as exc:
            logger.warning("Claude http hook failed: %s", exc)
            return HookResult()
        return _parse_hook_output(text)


def _parse_hook_output(text: str) -> HookResult:
    text = text.strip()
    if not text:
        return HookResult()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return HookResult(output={"message": text})
    if not isinstance(data, dict):
        return HookResult()
    decision = data.get("decision") or data.get("hookSpecificOutput", {}).get("decision")
    if decision == "block":
        reason = str(data.get("reason") or data.get("message") or "blocked by plugin hook")
        return HookResult(blocked=True, reason=reason, output=data)
    return HookResult(output=data)
