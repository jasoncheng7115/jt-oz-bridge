"""API-managed session instruction entries of installed OpenCode v2.0.32.

Native keeps each entry with the session and announces a change to the model at
its next step boundary. There is no per-prompt ``system`` field. Only the list
read and one put are used here; the put is a mutation, so it stays refused unless
the backend's enrollment verified it like every other Native write.
"""

from typing import Any, Protocol

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.transport import ContractAttestation

LIST = "experimental.session.instructions.entry.list"
PUT = "experimental.session.instructions.entry.put"
MAX_ENTRIES = 1000


class InstructionTransport(Protocol):
    attestation: ContractAttestation | None

    async def request(
        self,
        operation_id: str,
        *,
        path: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
    ) -> Any: ...


class V2SessionInstructions:
    def __init__(self, transport: InstructionTransport) -> None:
        self.transport = transport

    def writable(self) -> bool:
        """The put is in the enrolled backend's verified operations."""
        attestation = self.transport.attestation
        return attestation is not None and PUT in attestation.verified_operations

    async def entries(self, session_id: str) -> dict[str, Any]:
        value = await self.transport.request(LIST, path={"sessionID": session_id})
        rows = value["data"]
        if len(rows) > MAX_ENTRIES or len({row["key"] for row in rows}) != len(rows):
            raise ContractError("native_instruction_entries_unbounded_or_duplicate")
        return {row["key"]: row["value"] for row in rows}

    async def put(self, session_id: str, key: str, value: Any) -> None:
        await self.transport.request(
            PUT, path={"sessionID": session_id, "key": key}, body={"value": value}
        )
