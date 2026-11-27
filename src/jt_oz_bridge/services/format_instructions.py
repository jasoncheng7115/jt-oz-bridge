"""Tell a bound session's AI that its replies are read in Zulip.

Before a prompt goes to an original session, the bridge makes sure that session
carries one API-managed instruction entry (``jt-oz-bridge.zulip``): GET the
entries, PUT only when this one is absent or different. A session that has it is
not asked again for an hour in this process. Nothing here may stop a prompt: a
refused, failed or slow read/write is logged by type and the prompt goes ahead.
Turned off by ``runtime.zulip_format_instructions_enabled = false``.
"""

import asyncio
import logging
import time
from collections.abc import Callable, Mapping
from typing import Any, cast

from jt_oz_bridge.adapters.opencode.instructions import V2SessionInstructions
from jt_oz_bridge.domain.control import InteractionSnapshot, SessionSnapshot
from jt_oz_bridge.domain.execution import Admission, ExecutionClient
from jt_oz_bridge.domain.models import Capability, SessionRef

LOG = logging.getLogger(__name__)

KEY = "jt-oz-bridge.zulip"
GUIDANCE = (
    "Your replies are shown in a Zulip chat (often on a phone). Lead with the answer. "
    "Use short paragraphs, bullet lists, **bold** for key points, and tables for "
    "comparisons. Mark severity with 🔴 urgent / 🟠 warning / 🟢 ok. Put long details, "
    "logs or raw tables in a collapsible block:\n"
    "```spoiler <title>\n...\n```\n"
    "Use ```diff for changes and fenced code blocks with a language for code and "
    "commands. Zulip does not support colored text or HTML."
)
TIMEOUT_SECONDS = 5.0
RECHECK_SECONDS = 3600.0
RETRY_SECONDS = 300.0


class ZulipFormatInstructions:
    def __init__(
        self,
        clients: Mapping[str, V2SessionInstructions],
        *,
        clock: Callable[[], float] = time.monotonic,
        timeout: float = TIMEOUT_SECONDS,
    ) -> None:
        self.clients = dict(clients)
        self.clock, self.timeout = clock, timeout
        self._due: dict[tuple[str, str, str], float] = {}
        self._locks: dict[tuple[str, str, str], asyncio.Lock] = {}
        self._unattested: set[str] = set()

    async def ensure(self, reference: SessionRef) -> None:
        """Never raises, except when the caller itself is cancelled."""
        client = self.clients.get(reference.backend_id)
        if client is None:
            return
        if not client.writable():
            if reference.backend_id not in self._unattested:
                self._unattested.add(reference.backend_id)
                LOG.warning("zulip_format_instructions_not_attested")
            return
        key = (reference.backend_id, reference.backend_identity, reference.upstream_session_id)
        if self._due.get(key, 0.0) > self.clock():
            return
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            if self._due.get(key, 0.0) > self.clock():
                return
            try:
                async with asyncio.timeout(self.timeout):
                    current = await client.entries(reference.upstream_session_id)
                    if current.get(KEY) != GUIDANCE:
                        await client.put(reference.upstream_session_id, KEY, GUIDANCE)
                        LOG.info("zulip_format_instructions_put")
            except Exception as error:
                # Type only: an upstream body could carry session content.
                LOG.warning("zulip_format_instructions_failed error_type=%s", type(error).__name__)
                self._due[key] = self.clock() + RETRY_SECONDS
                return
            self._due[key] = self.clock() + RECHECK_SECONDS


class FormattedExecution:
    """The dispatcher's execution client: the same calls, a prompt ensures the entry first.

    Every other call, and the prompt itself, goes to the wrapped client unchanged.
    """

    def __init__(self, client: ExecutionClient, instructions: ZulipFormatInstructions) -> None:
        self.client, self.instructions = client, instructions

    def __getattr__(self, name: str) -> Any:
        return getattr(self.client, name)

    def contract_for(self, reference: SessionRef) -> str:
        return self.client.contract_for(reference)

    def capabilities(self, reference: SessionRef) -> dict[str, Capability]:
        return self.client.capabilities(reference)

    async def snapshot(self, reference: SessionRef) -> SessionSnapshot:
        return await self.client.snapshot(reference)

    async def interaction(self, reference: SessionRef, request_id: str) -> InteractionSnapshot:
        return await self.client.interaction(reference, request_id)

    async def submit(
        self,
        reference: SessionRef,
        payload: dict[str, Any],
        action_id: str,
        *,
        steer: bool = False,
    ) -> Admission:
        if payload.get("operation") == "prompt":
            await self.instructions.ensure(reference)
        if steer:
            # `steer_supported` reaches the wrapped client through `__getattr__`, so the
            # dispatcher steers through here too; dropping it failed every steer.
            submit_steer: Any = self.client.submit
            return cast(Admission, await submit_steer(reference, payload, action_id, steer=True))
        return await self.client.submit(reference, payload, action_id)
