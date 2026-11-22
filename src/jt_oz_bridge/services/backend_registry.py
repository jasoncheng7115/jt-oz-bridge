"""Immutable enrolled routing; no identity inference, discovery or live certification."""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, cast

from jt_oz_bridge.domain.checks import CheckAuthority
from jt_oz_bridge.domain.control import InteractionSnapshot, SessionSnapshot
from jt_oz_bridge.domain.execution import (
    Admission,
    ExecutionClient,
    MutationNotSent,
    SteerNotReady,
)
from jt_oz_bridge.domain.models import Capability, SessionRef
from jt_oz_bridge.domain.operations import CURRENT_OPERATIONS
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.storage.durable import Conflict


async def _lifecycle_read(client: object, name: str, reference: SessionRef) -> Any:
    read = getattr(client, name, None)
    if not callable(read):
        raise Conflict("session_lifecycle_read_unavailable")
    return await read(reference)


@dataclass(frozen=True)
class RegisteredBackend:
    identity: str
    contract_sha256: str
    projects: Mapping[str, str]
    client: ExecutionClient

    def __post_init__(self) -> None:
        if (
            not self.identity
            or not re.fullmatch(r"[0-9a-f]{64}", self.contract_sha256)
            or not self.projects
            or any(not key or not value for key, value in self.projects.items())
        ):
            raise ValueError("invalid_backend_registration")
        object.__setattr__(self, "projects", MappingProxyType(dict(self.projects)))


@dataclass(frozen=True)
class BackendRegistry:
    backends: Mapping[str, RegisteredBackend]

    def __post_init__(self) -> None:
        if not self.backends or any(not key for key in self.backends):
            raise ValueError("backend_registry_requires_explicit_entries")
        object.__setattr__(self, "backends", MappingProxyType(dict(self.backends)))

    def selected(self, reference: SessionRef) -> RegisteredBackend:
        entry = self.backends.get(reference.backend_id)
        if (
            entry is None
            or entry.identity != reference.backend_identity
            or entry.projects.get(reference.project_id) != reference.canonical_directory
            or not reference.upstream_session_id
        ):
            raise AccessDenied("backend_registry_scope_mismatch")
        if entry.client.contract_for(reference) != entry.contract_sha256:
            raise Conflict("backend_registry_contract_changed")
        return entry

    def contract_for(self, reference: SessionRef) -> str:
        return self.selected(reference).contract_sha256

    def capabilities(self, reference: SessionRef) -> dict[str, Capability]:
        return {
            key: value.model_copy(deep=True)
            for key, value in self.selected(reference).client.capabilities(reference).items()
            if key in CURRENT_OPERATIONS
        }

    async def snapshot(self, reference: SessionRef) -> SessionSnapshot:
        entry = self.selected(reference)
        snapshot = await entry.client.snapshot(reference)
        self.selected(reference)
        if snapshot.reference != reference:
            raise Conflict("backend_snapshot_reference_mismatch")
        if (
            len(set(snapshot.descendants)) != len(snapshot.descendants)
            or reference in snapshot.descendants
        ):
            raise Conflict("backend_snapshot_duplicate_lineage")
        for child in snapshot.descendants:
            if (
                child.backend_id,
                child.backend_identity,
                child.project_id,
                child.canonical_directory,
            ) != (
                reference.backend_id,
                reference.backend_identity,
                reference.project_id,
                reference.canonical_directory,
            ):
                raise AccessDenied("backend_snapshot_lineage_scope_mismatch")
            self.selected(child)
        return snapshot

    async def pending_revert(self, reference: SessionRef) -> str | None:
        value = await _lifecycle_read(self.selected(reference).client, "pending_revert", reference)
        self.selected(reference)
        return cast("str | None", value)

    async def recent_user_messages(self, reference: SessionRef) -> tuple[Any, ...]:
        value = await _lifecycle_read(
            self.selected(reference).client, "recent_user_messages", reference
        )
        self.selected(reference)
        return cast("tuple[Any, ...]", value)

    async def prompt_readback(
        self, reference: SessionRef, action_id: str, operation_digest: str, text: str
    ) -> str | None:
        read = getattr(self.selected(reference).client, "prompt_readback", None)
        if not callable(read):
            raise Conflict("prompt_readback_unavailable")
        value = await read(reference, action_id, operation_digest, text)
        self.selected(reference)
        return cast("str | None", value)

    async def prompt_never_arrived(
        self, reference: SessionRef, action_id: str, operation_digest: str, sent_after: float
    ) -> bool:
        read = getattr(self.selected(reference).client, "prompt_never_arrived", None)
        if not callable(read):
            return False
        value = await read(reference, action_id, operation_digest, sent_after)
        self.selected(reference)
        return value is True

    async def interaction(self, reference: SessionRef, request_id: str) -> InteractionSnapshot:
        if not request_id:
            raise ValueError("native_request_identity_required")
        entry = self.selected(reference)
        interaction = await entry.client.interaction(reference, request_id)
        self.selected(reference)
        if interaction.reference != reference or interaction.upstream_request_id != request_id:
            raise Conflict("backend_interaction_reference_mismatch")
        return interaction

    async def submit_check(
        self,
        reference: SessionRef,
        payload: dict[str, Any],
        action_id: str,
        authority: CheckAuthority,
    ) -> Admission:
        if payload.get("operation") != "check.run":
            raise MutationNotSent("check_authority_operation_mismatch")
        return await self._submit(reference, payload, action_id, authority=authority)

    def steer_supported(self, reference: SessionRef) -> bool:
        try:
            supported = getattr(self.selected(reference).client, "steer_supported", None)
            return callable(supported) and supported(reference) is True
        except Exception:
            return False

    async def submit(
        self,
        reference: SessionRef,
        payload: dict[str, Any],
        action_id: str,
        *,
        steer: bool = False,
    ) -> Admission:
        return await self._submit(reference, payload, action_id, authority=None, steer=steer)

    async def _submit(
        self,
        reference: SessionRef,
        payload: dict[str, Any],
        action_id: str,
        *,
        authority: CheckAuthority | None,
        steer: bool = False,
    ) -> Admission:
        # Freeze before calling any awaited backend method. This does not make a
        # native mutation idempotent or replace the dispatcher's authorization.
        try:
            encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False)
            if len(encoded.encode()) > 32 * 1024 * 1024:
                raise ValueError("oversized")
            frozen = json.loads(encoded)
        except (ValueError, TypeError, RecursionError):
            raise ValueError("invalid_backend_submission") from None
        if not action_id or len(action_id) > 128:
            raise ValueError("bridge_action_identity_required")
        entry = self.selected(reference)
        if "reference" in frozen and SessionRef.model_validate(frozen["reference"]) != reference:
            raise AccessDenied("backend_submission_reference_mismatch")
        operation = frozen.get("operation")
        capability = (
            self.capabilities(reference).get(operation) if isinstance(operation, str) else None
        )
        if capability is None or not capability.supported:
            raise AccessDenied("backend_operation_not_supported")
        if operation == "check.run":
            submit_check = getattr(entry.client, "submit_check", None)
            if authority is None or not callable(submit_check):
                raise MutationNotSent("backend_check_final_authority_not_supported")
            result = await submit_check(reference, frozen, action_id, authority)
            self.selected(reference)
            return Admission.model_validate(result.model_dump(mode="python"))
        if steer:
            if operation != "prompt" or not self.steer_supported(reference):
                raise SteerNotReady("backend_steer_not_supported")
            submit: Any = entry.client.submit
            return cast(Admission, await submit(reference, frozen, action_id, steer=True))
        return await entry.client.submit(reference, frozen, action_id)
