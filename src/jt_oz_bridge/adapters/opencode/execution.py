"""V2 RPC mapping gated by externally qualified original-execution evidence.

No default proof provider exists. Listing/active/PID/URL are not ownership proofs.
"""

import asyncio
import logging
import time
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Any, Literal, Protocol

from pydantic import Field

from jt_oz_bridge.adapters.opencode.attachments import (
    ATTACHMENT_SEMANTICS,
    inline_files,
    verify_admitted_files,
)
from jt_oz_bridge.adapters.opencode.catalog import V2CatalogProject
from jt_oz_bridge.adapters.opencode.checks import (
    CHECK_READS,
    CHECK_SEMANTICS,
    CheckExecutionAttestation,
    V2CheckRunner,
)
from jt_oz_bridge.adapters.opencode.contracts import ContractError, SnapshotBoundaryChanged
from jt_oz_bridge.adapters.opencode.forms import normalize_form, normalize_permission
from jt_oz_bridge.adapters.opencode.info_projection import info_fingerprint
from jt_oz_bridge.adapters.opencode.model_catalog import V2ModelCatalog
from jt_oz_bridge.adapters.opencode.model_settings import ModelSettingsAttestation
from jt_oz_bridge.adapters.opencode.transport import (
    ContractAttestation,
    TransportNotSent,
    V2HTTPTransport,
)
from jt_oz_bridge.domain.attachments import (
    PreparedPromptAttachments,
    PromptAttachmentManifest,
    PromptAttachmentProvider,
    WorkspaceAttachmentManifest,
)
from jt_oz_bridge.domain.check_dispatch import CheckDispatchPreflight
from jt_oz_bridge.domain.checks import CheckAuthority, CheckSelection, check_message_id
from jt_oz_bridge.domain.control import (
    ControlModel,
    ExecutionState,
    FieldAnswer,
    InteractionSnapshot,
    SessionSnapshot,
    validate_answers,
    wire_answers,
)
from jt_oz_bridge.domain.execution import (
    SEND_PROOF_MOVED,
    STEER_STATES,
    UNSTEERABLE_PAYLOAD,
    Admission,
    HumanMessage,
    MutationNotSent,
    SteerNotReady,
)
from jt_oz_bridge.domain.git_publish import GitPublishRequest
from jt_oz_bridge.domain.model_catalog import ModelSelection, ModelSettingOutcome
from jt_oz_bridge.domain.models import WATCH_PENDING, Capability, SessionRef
from jt_oz_bridge.domain.schedules import scheduled_text
from jt_oz_bridge.domain.session_lifecycle import (
    LIFECYCLE_OPERATIONS,
    SessionLifecycleOutcome,
    SessionLifecycleRequest,
    SessionMessageChoice,
    SessionRename,
    SessionRenameOutcome,
)
from jt_oz_bridge.domain.workspace_attachments import (
    PreparedWorkspaceAttachments,
    WorkspaceAttachmentProvider,
)
from jt_oz_bridge.security.admin import token_hash
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.services.menu_shortcuts import expand
from jt_oz_bridge.storage.cipher_types import checked_json
from jt_oz_bridge.storage.durable import digest

LOG = logging.getLogger(__name__)
# A refused proof is read again within seconds; name its cause at most this often.
PROOF_DETAIL_SECONDS = 600
# An uncertain prompt is looked for among this many newest user messages.
PROMPT_READBACK_LIMIT = 50
# Transport refusals that only mean the proof moved before the request was complete.
PROOF_MOVED_AT_SEND = frozenset(
    {
        "mutation_guard_rejected",
        "native_mutation_write_boundary_rejected",
        "native_mutation_body_withheld",
    }
)

OPERATIONS = {
    "prompt": ("session.prompt",),
    "interrupt": ("session.interrupt",),
    "permission.reply": ("session.permission.list", "session.permission.reply"),
    "form.reply": ("session.form.get", "session.form.reply"),
    "form.cancel": ("session.form.get", "session.form.cancel"),
    "model.switch": ("model.list", "model.default", "session.switchModel"),
    "session.rename": ("session.get", "session.update"),
    # The last name is the single Native mutation; the others are required reads.
    "session.fork": ("session.get", "session.message.list", "session.fork"),
    "session.compact": ("session.get", "session.compact"),
    "session.revert.stage": ("session.get", "session.message.list", "session.revert.stage"),
    "session.revert.clear": ("session.get", "session.revert.clear"),
    "session.revert.commit": ("session.get", "session.revert.commit"),
    "check.run": (*sorted(CHECK_READS), "session.shell"),
    # An ordinary prompt; the reads are what the preview and the result check use.
    "git.publish": ("vcs.get", "vcs.branch.list", "vcs.base", "vcs.diff", "session.prompt"),
    "agent.switch": (
        "session.get",
        "session.message.list",
        "agent.list",
        "plugin.list",
        "permission.saved.list",
        "mcp.list",
        "session.switchAgent",
    ),
}


def policy_operation(operation: str) -> str:
    """A Git publish request is one ordinary prompt to Native, under the prompt policy."""
    return "prompt" if operation == "git.publish" else operation


class OriginalExecutionProof(ControlModel):
    """Trusted provider output tied to its reconciled stream/owner evidence.

    Constructing this DTO from public session metadata does not qualify a provider.
    """

    reference: SessionRef
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    session_info_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ownership_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    connection_epoch: str = Field(min_length=1, max_length=255)
    issued_at: float = Field(ge=0, allow_inf_nan=False)
    expires_at: float = Field(ge=0, allow_inf_nan=False)
    state: ExecutionState
    cursor: str = Field(min_length=1, max_length=8192)
    descendants: tuple[SessionRef, ...] = Field(max_length=1000)
    resource_fence: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class ExecutionProofProvider(Protocol):
    """Trusted enrollment dependency, never a configurable chat assertion.

    Implementations must prove the original owner and reconcile snapshot + stream,
    invalidate epochs on owner/connection changes and index exact request kinds.
    The optional leaf-root provider rejects unqualified descendants/background
    work. No provider is enabled by default.
    """

    def certified_epoch(self, reference: SessionRef, contract_sha256: str) -> str | None: ...

    async def prove(
        self, reference: SessionRef, contract_sha256: str, session_info_sha256: str
    ) -> OriginalExecutionProof: ...

    async def interaction_kind(
        self, reference: SessionRef, request_id: str, connection_epoch: str
    ) -> Literal["permission", "form"] | None: ...


class MutationScopeGuard(Protocol):
    def enrolled(self, reference: SessionRef, operation: str) -> bool: ...

    async def authorize(
        self, reference: SessionRef, operation: str, proof: OriginalExecutionProof
    ) -> object: ...

    def current(
        self, reference: SessionRef, operation: str, proof: OriginalExecutionProof, witness: object
    ) -> bool: ...


class V2ExecutionClient:
    def __init__(
        self,
        transport: V2HTTPTransport,
        projects: Mapping[str, V2CatalogProject],
        *,
        proofs: ExecutionProofProvider | None = None,
        scope_guard: MutationScopeGuard | None = None,
        attachments: PromptAttachmentProvider | None = None,
        workspace_attachments: WorkspaceAttachmentProvider | None = None,
        check_attestations: Mapping[SessionRef, CheckExecutionAttestation] | None = None,
    ) -> None:
        if not projects or any(key != value.scope.project_id for key, value in projects.items()):
            raise ValueError("invalid_v2_execution_project_registration")
        if (
            len(
                {(item.scope.backend_id, item.scope.backend_identity) for item in projects.values()}
            )
            != 1
        ):
            raise ValueError("v2_execution_cannot_mix_backend_instances")
        self.transport, self.projects = transport, MappingProxyType(dict(projects))
        self.proofs = proofs
        self.scope_guard = scope_guard
        self._proof_logged: dict[tuple[str, str], float] = {}
        self.attachments = attachments
        self.workspace_attachments = workspace_attachments
        self.models = V2ModelCatalog(transport, self.projects)
        self.checks = V2CheckRunner(self, check_attestations or {})

    def policy_available(self, reference: SessionRef, operation: str) -> bool:
        # Stopping already scoped original work does not grant tools or extend
        # their permissions. Keep emergency interruption independent of drift.
        if operation == "interrupt":
            return True
        if operation == "check.run":
            try:
                self.checks.catalog(reference)
                if not callable(getattr(self.scope_guard, "authorize_check", None)):
                    return False
            except (ValueError, TypeError):
                return False
        if operation == "model.switch":
            qualification = getattr(self.proofs, "model_settings", None)
            if not isinstance(qualification, ModelSettingsAttestation):
                return False
            try:
                qualification.require(reference, self.transport.profile.sha256)
            except ValueError:
                return False
        if operation == "agent.switch" and self.scope_guard is None:
            return False
        if self.scope_guard is None:
            return getattr(self.proofs, "requires_project_policy", False) is not True
        try:
            return self.scope_guard.enrolled(reference, policy_operation(operation)) is True
        except Exception:
            return False

    def selected(self, reference: SessionRef) -> V2CatalogProject:
        entry = self.projects.get(reference.project_id)
        if entry is None or not entry.scope.contains(reference):
            raise ContractError("v2_execution_project_scope_mismatch")
        self.transport.profile.prepare(
            "session.get", path={"sessionID": reference.upstream_session_id}
        )
        attestation = self.transport.attestation
        if (
            attestation is None
            or attestation.backend_identity != reference.backend_identity
            or attestation.schema_sha256 != self.transport.profile.sha256
            or "session.get" not in attestation.verified_operations
        ):
            raise ContractError("v2_execution_installed_read_contract_not_attested")
        return entry

    def contract_for(self, reference: SessionRef) -> str:
        self.selected(reference)
        return self.transport.profile.sha256

    def epoch(self, reference: SessionRef) -> str:
        contract = self.contract_for(reference)
        value = self.proofs.certified_epoch(reference, contract) if self.proofs else None
        if not isinstance(value, str) or not value or len(value) > 255:
            raise ContractError("v2_original_execution_proof_unavailable")
        return value

    def capabilities(self, reference: SessionRef) -> dict[str, Capability]:
        watched = True
        try:
            try:
                self.epoch(reference)
            except ContractError:
                watched = False
                raise
            verified = (
                self.transport.attestation.verified_operations
                if self.transport.attestation
                else frozenset()
            )
            base = self.transport.verify_identity is not None
        except Exception:
            verified, base = frozenset(), False
        return {
            name: Capability(
                supported=base
                and self.policy_available(reference, name)
                and all(operation in verified for operation in required),
                scope="session",
                reason="requires separately qualified original-owner provider and installed operation attestation"
                if watched
                else WATCH_PENDING,
                verification="injected_installed_evidence_required",
            )
            for name, required in OPERATIONS.items()
        }

    async def peer(self, reference: SessionRef) -> None:
        self.selected(reference)
        if self.transport.verify_identity is None or not await self.transport.verify_identity():
            raise ContractError("v2_execution_backend_identity_unverified")
        self.selected(reference)

    def current(self, reference: SessionRef, proof: OriginalExecutionProof) -> None:
        now = time.time()
        resource_guard = getattr(self.proofs, "valid_fence", None)
        # Every condition by name, so a refusal that keeps coming says which one holds.
        checks: tuple[tuple[str, Callable[[], bool]], ...] = (
            ("reference", lambda: proof.reference != reference),
            ("contract", lambda: proof.contract_sha256 != self.contract_for(reference)),
            ("connection_epoch", lambda: proof.connection_epoch != self.epoch(reference)),
            (
                "resource_fence",
                lambda: (
                    proof.resource_fence is not None
                    and (
                        not callable(resource_guard)
                        or resource_guard(reference, proof.resource_fence) is not True
                    )
                ),
            ),
            ("expired", lambda: not proof.issued_at <= now < proof.expires_at),
            ("lifetime", lambda: not 0 < proof.expires_at - proof.issued_at <= 30),
            (
                "state",
                lambda: proof.state in {ExecutionState.UNKNOWN, ExecutionState.DISCONNECTED},
            ),
            ("self_descendant", lambda: reference in proof.descendants),
            ("duplicate_descendant", lambda: len(set(proof.descendants)) != len(proof.descendants)),
            (
                "descendant_scope",
                lambda: any(
                    not self.selected(reference).scope.contains(child)
                    for child in proof.descendants
                ),
            ),
        )
        for name, changed in checks:
            if changed():
                key = (reference.upstream_session_id, name)
                if now - self._proof_logged.get(key, -PROOF_DETAIL_SECONDS) >= (
                    PROOF_DETAIL_SECONDS
                ):
                    self._proof_logged[key] = now
                    LOG.warning(
                        "native_execution_proof_detail session=%s check=%s",
                        reference.upstream_session_id,
                        name,
                    )
                raise ContractError("v2_execution_owner_or_snapshot_evidence_changed")

    async def qualified_snapshot(
        self, reference: SessionRef
    ) -> tuple[SessionSnapshot, OriginalExecutionProof]:
        entry = self.selected(reference)
        epoch = self.epoch(reference)
        await self.peer(reference)
        raw = (
            await self.transport.request(
                "session.get", path={"sessionID": reference.upstream_session_id}
            )
        )["data"]
        if (
            raw["id"] != reference.upstream_session_id
            or raw["projectID"] != entry.upstream_project_id
            or raw["location"]["directory"] != reference.canonical_directory
        ):
            raise ContractError("v2_execution_native_session_scope_mismatch")
        info_sha = info_fingerprint(self.proofs, reference, raw)
        if self.proofs is None:
            raise ContractError("v2_original_execution_proof_unavailable")
        output = await self.proofs.prove(reference, self.transport.profile.sha256, info_sha)
        proof = OriginalExecutionProof.model_validate(output.model_dump(mode="python"))
        await self.peer(reference)
        self.current(reference, proof)
        if proof.session_info_sha256 != info_sha or proof.connection_epoch != epoch:
            raise ContractError("v2_execution_snapshot_proof_mismatch")
        for child in proof.descendants:
            self.selected(child)
        return SessionSnapshot(
            reference=reference,
            title=raw.get("title", raw["id"]),
            state=proof.state,
            cursor=proof.cursor,
            reconciled=True,
            descendants=proof.descendants,
        ), proof

    async def rename_readback(
        self,
        reference: SessionRef,
        change: SessionRename,
        original: OriginalExecutionProof,
        attestation: ContractAttestation | None,
    ) -> tuple[SessionSnapshot, OriginalExecutionProof]:
        """Reconcile a single acknowledged title PATCH using bounded GETs only.

        The rename event can invalidate a strict resource fence while the first
        readback is in progress. A new complete snapshot may settle that race;
        changed owners, contracts, scopes or titles never authorize a retry.
        """
        async with asyncio.timeout(5):
            for attempt in range(4):
                await self.peer(reference)
                if (
                    self.epoch(reference) != original.connection_epoch
                    or self.transport.attestation is not attestation
                    or attestation is None
                    or "session.update" not in attestation.verified_operations
                ):
                    raise ContractError("v2_session_rename_readback_identity_changed")
                try:
                    snapshot, proof = await self.qualified_snapshot(reference)
                except SnapshotBoundaryChanged:
                    if attempt == 3:
                        raise
                    await asyncio.sleep(0.05 * (attempt + 1))
                    continue
                self.current(reference, proof)
                if (
                    snapshot.title != change.target_title
                    or proof.connection_epoch != original.connection_epoch
                    or self.transport.attestation is not attestation
                ):
                    raise ContractError("v2_session_rename_readback_not_verified")
                return snapshot, proof
        raise ContractError("v2_session_rename_readback_not_verified")

    async def snapshot(self, reference: SessionRef) -> SessionSnapshot:
        snapshot, _ = await self.qualified_snapshot(reference)
        return snapshot

    async def _session_info(self, reference: SessionRef) -> dict[str, Any]:
        """The same original session, by exact ID, project and directory."""
        entry = self.selected(reference)
        await self.peer(reference)
        raw: dict[str, Any] = (
            await self.transport.request(
                "session.get", path={"sessionID": reference.upstream_session_id}
            )
        )["data"]
        if (
            raw["id"] != reference.upstream_session_id
            or raw["projectID"] != entry.upstream_project_id
            or raw["location"]["directory"] != reference.canonical_directory
        ):
            raise ContractError("v2_execution_native_session_scope_mismatch")
        return raw

    async def pending_revert(self, reference: SessionRef) -> str | None:
        """Native's current staged boundary, read fresh for every preview and send."""
        raw = await self._session_info(reference)
        revert = raw.get("revert")
        return str(revert["messageID"]) if revert else None

    async def recent_user_messages(
        self, reference: SessionRef, limit: int = 10
    ) -> tuple[SessionMessageChoice, ...]:
        """Newest human turns of this session, the only boundaries a menu offers."""
        await self.peer(reference)
        value = await self.transport.request(
            "session.message.list",
            path={"sessionID": reference.upstream_session_id},
            query={"limit": str(limit), "order": "desc", "type": "user"},
        )
        return tuple(
            SessionMessageChoice(
                message_id=item["id"], preview=" ".join(str(item["text"]).split())[:120]
            )
            for item in value["data"][:limit]
            if item["type"] == "user"
        )

    async def prompt_readback(
        self, reference: SessionRef, action_id: str, operation_digest: str, text: str
    ) -> str | None:
        """The user message an uncertain prompt became, found by its own tag; read only.

        None means not among the newest user messages, which proves nothing either way.
        """
        self.selected(reference)
        await self.peer(reference)
        value = await self.transport.request(
            "session.message.list",
            path={"sessionID": reference.upstream_session_id},
            query={"limit": str(PROMPT_READBACK_LIMIT), "order": "desc", "type": "user"},
        )
        tag = {"action_id": action_id, "operation_digest": operation_digest}
        found = [
            item
            for item in value["data"]
            if item["type"] == "user" and item.get("metadata", {}).get("jt_oz_bridge") == tag
        ]
        if not found:
            return None
        if (
            len(found) != 1
            or found[0]["text"] != text
            or any(found[0].get(k) for k in ("files", "agents", "skills"))
            or not isinstance(found[0]["id"], str)
            or not 1 <= len(found[0]["id"]) <= 255
        ):
            raise ContractError("v2_prompt_readback_mismatch")
        self.selected(reference)
        return found[0]["id"]

    async def prompt_never_arrived(
        self, reference: SessionRef, action_id: str, operation_digest: str, sent_after: float
    ) -> bool:
        """True only when OpenCode provably holds no trace of this prompt; read only.

        The Root is idle by a qualified snapshot, nothing waits in its inbox, and
        two reads of every user message since the prompt was made lack its tag.
        """
        tag = {"action_id": action_id, "operation_digest": operation_digest}

        async def absent() -> str | None:
            value = await self.transport.request(
                "session.message.list",
                path={"sessionID": reference.upstream_session_id},
                query={"limit": str(PROMPT_READBACK_LIMIT), "order": "desc", "type": "user"},
            )
            items = value["data"]
            if any(item.get("metadata", {}).get("jt_oz_bridge") == tag for item in items):
                return "tagged_message"
            # A full page must reach back before the prompt existed.
            if len(items) < PROMPT_READBACK_LIMIT or (
                type(items[-1]["time"]["created"]) is int
                and items[-1]["time"]["created"] < sent_after * 1000
            ):
                return None
            return "history_not_reached"

        async def failing() -> str | None:
            attestation = self.transport.attestation
            if (
                attestation is None
                or not {
                    "session.message.list",
                    "session.inbox.list",
                }
                <= attestation.verified_operations
            ):
                return "reads_not_attested"
            snapshot, _ = await self.qualified_snapshot(reference)
            if snapshot.state != ExecutionState.IDLE:
                return "not_idle"
            if (check := await absent()) is not None:
                return check
            inbox = (
                await self.transport.request(
                    "session.inbox.list", path={"sessionID": reference.upstream_session_id}
                )
            )["data"]
            if not isinstance(inbox, list) or inbox:
                return "inbox_not_empty"
            if (check := await absent()) is not None:
                return check
            self.selected(reference)
            return None

        check = await failing()
        if check is None:
            return True
        key = (reference.upstream_session_id, "never_arrived:" + check)
        now = time.time()
        if now - self._proof_logged.get(key, -PROOF_DETAIL_SECONDS) >= PROOF_DETAIL_SECONDS:
            self._proof_logged[key] = now
            LOG.warning(
                "uncertain_prompt_not_proven_absent session=%s check=%s",
                reference.upstream_session_id,
                check,
            )
        return False

    async def lifecycle_outcome(
        self,
        reference: SessionRef,
        request: SessionLifecycleRequest,
        value: Any,
        proof: OriginalExecutionProof,
        attestation: ContractAttestation | None,
    ) -> Admission:
        """Check the one acknowledgement and read back with GETs only.

        Anything unexpected here stays uncertain: the mutation is never sent again.
        """
        operation, change = request.operation, request.change
        new_session_id = native_request_id = None
        observed = proof
        if operation == "session.fork":
            raw = value["data"]
            fork = raw.get("fork", {})
            entry = self.selected(reference)
            if (
                raw["id"] == reference.upstream_session_id
                or fork.get("sessionID") != reference.upstream_session_id
                or raw["projectID"] != entry.upstream_project_id
                or raw["location"]["directory"] != reference.canonical_directory
                or (
                    change.message_id is not None
                    and fork.get("boundary") != {"type": "before", "messageID": change.message_id}
                )
            ):
                raise ContractError("v2_session_fork_acknowledgement_mismatch")
            new_session_id = raw["id"]
            child = (await self.transport.request("session.get", path={"sessionID": raw["id"]}))[
                "data"
            ]
            if child["id"] != raw["id"] or child.get("fork", {}) != fork:
                raise ContractError("v2_session_fork_readback_not_verified")
            await self._session_info(reference)
        elif operation == "session.compact":
            raw = value["data"]
            if (
                raw["sessionID"] != reference.upstream_session_id
                or raw["type"] != "compaction"
                or raw["delivery"] != "queue"
            ):
                raise ContractError("v2_session_compact_acknowledgement_mismatch")
            native_request_id = raw["id"]
            await self._session_info(reference)
        else:
            staged = change.message_id if operation == "session.revert.stage" else None
            if (staged is None and value is not None) or (
                staged is not None and value["data"]["messageID"] != staged
            ):
                raise ContractError("v2_session_revert_acknowledgement_mismatch")
            observed = await self._revert_readback(reference, staged, proof, attestation)
        return Admission(
            status="completed",
            details=SessionLifecycleOutcome(
                operation=operation,
                change=change,
                session_id=reference.upstream_session_id,
                new_session_id=new_session_id,
                native_request_id=native_request_id,
                owner_evidence_sha256=observed.ownership_evidence_sha256,
                session_info_sha256=observed.session_info_sha256,
            ).model_dump(mode="json"),
        )

    async def _revert_readback(
        self,
        reference: SessionRef,
        staged: str | None,
        original: OriginalExecutionProof,
        attestation: ContractAttestation | None,
    ) -> OriginalExecutionProof:
        """Same bounded reads as a title change: a moving resource fence may settle."""
        async with asyncio.timeout(5):
            for attempt in range(4):
                if self.transport.attestation is not attestation or attestation is None:
                    raise ContractError("v2_session_revert_readback_identity_changed")
                try:
                    _, proof = await self.qualified_snapshot(reference)
                except SnapshotBoundaryChanged:
                    if attempt == 3:
                        raise
                    await asyncio.sleep(0.05 * (attempt + 1))
                    continue
                if (
                    proof.connection_epoch != original.connection_epoch
                    or await self.pending_revert(reference) != staged
                ):
                    raise ContractError("v2_session_revert_readback_not_verified")
                return proof
        raise ContractError("v2_session_revert_readback_not_verified")

    async def pending(
        self, reference: SessionRef, request_id: str, proof: OriginalExecutionProof
    ) -> InteractionSnapshot:
        self.current(reference, proof)
        if self.proofs is None:
            raise ContractError("v2_original_execution_proof_unavailable")
        kind = await self.proofs.interaction_kind(reference, request_id, proof.connection_epoch)
        self.current(reference, proof)
        operation = (
            "session.permission.list"
            if kind == "permission"
            else "session.form.get"
            if kind == "form"
            else None
        )
        attestation = self.transport.attestation
        if not operation or not attestation or operation not in attestation.verified_operations:
            raise ContractError("v2_interaction_kind_or_read_contract_unverified")
        await self.peer(reference)
        if (
            self.transport.attestation is None
            or operation not in self.transport.attestation.verified_operations
        ):
            raise ContractError("v2_interaction_read_contract_changed")
        if kind == "permission":
            items = (
                await self.transport.request(
                    operation, path={"sessionID": reference.upstream_session_id}
                )
            )["data"]
            ids = [item["id"] for item in items]
            if len(set(ids)) != len(ids) or any(
                item["sessionID"] != reference.upstream_session_id for item in items
            ):
                raise ContractError("v2_permission_catalog_scope_or_identity_changed")
            found = [item for item in items if item["id"] == request_id]
            if len(found) != 1:
                raise ContractError("v2_permission_pending_not_proven")
            result = normalize_permission(
                self.transport.profile,
                reference,
                found[0],
                proof.connection_epoch,
                pending_catalog=True,
            )
        else:
            raw = (
                await self.transport.request(
                    operation,
                    path={"sessionID": reference.upstream_session_id, "formID": request_id},
                )
            )["data"]
            if raw["id"] != request_id:
                raise ContractError("v2_form_request_identity_changed")
            result = normalize_form(self.transport.profile, reference, raw, proof.connection_epoch)
        await self.peer(reference)
        if (
            self.transport.attestation is None
            or operation not in self.transport.attestation.verified_operations
        ):
            raise ContractError("v2_interaction_read_contract_changed")
        self.current(reference, proof)
        return result

    async def interaction(self, reference: SessionRef, request_id: str) -> InteractionSnapshot:
        _, proof = await self.qualified_snapshot(reference)
        return await self.pending(reference, request_id, proof)

    async def submit_check(
        self,
        reference: SessionRef,
        payload: dict[str, Any],
        action_id: str,
        authority: CheckAuthority,
    ) -> Admission:
        if payload.get("operation") != "check.run":
            raise MutationNotSent("check_authority_cannot_submit_other_operations")
        return await self.submit(reference, payload, action_id, authorize_check=authority)

    def steer_supported(self, reference: SessionRef) -> bool:
        """A busy session's pending inbox can be read before a steer is sent."""
        try:
            self.selected(reference)
            attestation = self.transport.attestation
            return bool(
                attestation is not None
                and "session.inbox.list" in attestation.verified_operations
                and self.capabilities(reference)["prompt"].supported
            )
        except Exception:
            return False

    async def pending_inbox(self, reference: SessionRef) -> tuple[tuple[str, str], ...]:
        """Kind and delivery of each input Native has admitted but not delivered yet.

        Native promotes every pending steer before any queued input, so a steer
        sent while a queued prompt (or a control item) waits would run first.
        """
        attestation = self.transport.attestation
        if attestation is None or "session.inbox.list" not in attestation.verified_operations:
            raise ContractError("v2_inbox_read_not_attested")
        await self.peer(reference)
        items = (
            await self.transport.request(
                "session.inbox.list", path={"sessionID": reference.upstream_session_id}
            )
        )["data"]
        if not isinstance(items, list) or len(items) > 1000:
            raise ContractError("v2_inbox_capacity_or_shape_changed")
        ids = [item["id"] for item in items]
        if len(set(ids)) != len(ids) or any(
            item["sessionID"] != reference.upstream_session_id for item in items
        ):
            raise ContractError("v2_inbox_scope_or_identity_changed")
        return tuple((str(item["type"]), str(item["delivery"])) for item in items)

    async def join_delivery(
        self, reference: SessionRef, state: ExecutionState, frozen: dict[str, Any]
    ) -> str:
        """How a prompt joins a session that is not idle, or `SteerNotReady`.

        Running, with only steers pending: a plain prompt steers into the turn at
        its next step, after those steers. Not running, with only inputs a stop
        parked: any prompt is queued; the post wakes them and it runs after them.
        An idle session gets its ordinary turn later, never a steer now.
        """
        if state not in STEER_STATES:
            raise SteerNotReady("prompt_session_not_running_or_parked")
        pending = await self.pending_inbox(reference)
        if any(kind not in {"user", "synthetic"} for kind, _ in pending):
            raise SteerNotReady("prompt_session_control_input_pending")
        if state == ExecutionState.RUNNING:
            if UNSTEERABLE_PAYLOAD & set(frozen) or any(d != "steer" for _, d in pending):
                raise SteerNotReady("prompt_cannot_steer_past_queued_input")
            return "steer"
        if not pending:
            raise SteerNotReady("prompt_session_parked_input_changed")
        return "queue"

    async def submit(
        self,
        reference: SessionRef,
        payload: dict[str, Any],
        action_id: str,
        *,
        authorize_check: CheckAuthority | None = None,
        steer: bool = False,
    ) -> Admission:
        """`steer=True` lets a prompt join a busy session instead of waiting (see
        `join_delivery`). If the session no longer qualifies, nothing is sent and
        `SteerNotReady` says so; the prompt keeps its place in the queue.
        """
        # Before the one Native mutation, providers may publish authorized bridge-owned
        # input copies; all Native operations remain read-only until transport send.
        policy_witness: object | None = None
        model_qualification: ModelSettingsAttestation | None = None
        rename_attestation = None
        lifecycle_request: SessionLifecycleRequest | None = None
        publish_request: GitPublishRequest | None = None
        check_qualification: CheckExecutionAttestation | None = None
        check_deadline = 0.0
        check_transport_attestation = None
        check_context: CheckDispatchPreflight | None = None
        attachment_provider = self.attachments
        attachment_manifest: PromptAttachmentManifest | None = None
        prepared_attachments: PreparedPromptAttachments | None = None
        workspace_provider = self.workspace_attachments
        workspace_manifest: WorkspaceAttachmentManifest | None = None
        prepared_workspace: PreparedWorkspaceAttachments | None = None
        projected_text: str | None = None
        delivery = "queue"
        try:
            frozen = strict_loads(checked_json(payload))
            operation = frozen.get("operation")
            if steer and operation != "prompt":
                raise ValueError("only_prompts_can_join_a_busy_session")
            if (
                operation not in OPERATIONS
                # Only the dedicated one-attempt coordinator owns this setter.
                or operation == "agent.switch"
                or not isinstance(action_id, str)
                or not 1 <= len(action_id) <= 255
            ):
                raise ValueError("unsupported_operation")
            if (
                SessionRef.model_validate(frozen["reference"]) != reference
                or not self.capabilities(reference)[operation].supported
            ):
                raise ValueError("unqualified_operation_target")
            if (operation == "check.run") != (authorize_check is not None):
                raise ValueError("original_check_send_authority_required")
            source = HumanMessage.model_validate(frozen["source"])
            # A phone's `!N` stands for the model row it picked; the row keeps its token.
            parsed = expand(
                source.text, frozen.get("shortcut") if operation == "model.switch" else None
            )
            if source.deleted or source.is_bot:
                raise ValueError("human_source_required")
            if "workspace_attachments" in frozen and "attachments" in frozen:
                raise ValueError("native_attachment_transports_cannot_mix")
            if "workspace_attachments" in frozen:
                if operation != "prompt" or workspace_provider is None:
                    raise ValueError("native_workspace_provider_unavailable")
                workspace_manifest = WorkspaceAttachmentManifest.model_validate(
                    frozen["workspace_attachments"]
                )
                workspace_manifest.checked(source)
                if (
                    parsed.kind != "prompt"
                    or parsed.arguments != frozen.get("text")
                    or not workspace_provider.qualified(reference, self.transport.profile.sha256)
                ):
                    raise ValueError("native_workspace_original_prompt_or_contract_required")
                prepared_workspace = await workspace_provider.prepare(
                    reference, action_id, source, workspace_manifest, frozen["text"]
                )
                if prepared_workspace.operation_digest != digest(frozen):
                    raise ValueError("native_workspace_original_operation_digest_required")
                projected_text = prepared_workspace.checked(
                    reference, action_id, source, workspace_manifest, frozen["text"]
                )
            if "attachments" in frozen:
                if operation != "prompt" or attachment_provider is None:
                    raise ValueError("native_attachment_provider_unavailable")
                attachment_manifest = PromptAttachmentManifest.model_validate(frozen["attachments"])
                attachment_manifest.checked(source)
                if not attachment_provider.qualified(reference, self.transport.profile.sha256):
                    raise ValueError("native_attachment_bytes_contract_unqualified")
                # Resolve authenticated bytes before obtaining the short-lived
                # Native execution proof. Staging never supplies a remote path.
                prepared_attachments = await attachment_provider.prepare(
                    reference, action_id, source, attachment_manifest
                )
                prepared_attachments.checked(attachment_manifest)
            snapshot, proof = await self.qualified_snapshot(reference)
            path = {"sessionID": reference.upstream_session_id}
            query: dict[str, str] = {}
            body = None
            if operation == "prompt":
                allowed = {"operation", "reference", "text", "source", "reply_locale"}
                if attachment_manifest is not None:
                    allowed.add("attachments")
                if workspace_manifest is not None:
                    allowed.add("workspace_attachments")
                if frozen.get("reply_locale", "en") not in {"en", "zh-TW"}:
                    raise ValueError("prompt_reply_locale_invalid")
                expected = parsed.arguments
                if "schedule" in frozen:
                    # A timed send carries the task its source asks to repeat, nothing else.
                    if attachment_manifest is not None or workspace_manifest is not None:
                        raise ValueError("scheduled_prompt_cannot_carry_attachments")
                    allowed.add("schedule")
                    expected = scheduled_text(source.text, frozen["schedule"])
                if parsed.kind != "prompt" or expected != frozen["text"]:
                    raise ValueError("fresh_idle_prompt_source_required")
                if steer:
                    delivery = await self.join_delivery(reference, snapshot.state, frozen)
                elif snapshot.state != ExecutionState.IDLE:
                    raise ValueError("fresh_idle_prompt_source_required")
                body = {
                    "text": projected_text if projected_text is not None else frozen["text"],
                    "delivery": delivery,
                    "metadata": {
                        "jt_oz_bridge": {"action_id": action_id, "operation_digest": digest(frozen)}
                    },
                }
                if attachment_manifest is not None:
                    assert prepared_attachments is not None
                    body["files"] = inline_files(attachment_manifest, prepared_attachments)
            elif operation == "git.publish":
                # The text is the bridge's fixed instruction for the previewed plan; the
                # Human source is the `!confirm` that spent this exact plan's token.
                allowed = set(GitPublishRequest.model_fields)
                publish_request = GitPublishRequest.model_validate(frozen)
                if (
                    publish_request.reference != reference
                    or snapshot.state != ExecutionState.IDLE
                    or not time.time() < publish_request.confirm_expires_at
                    or parsed.kind != "command"
                    or parsed.command != "confirm"
                    or publish_request.text != publish_request.plan.prompt()
                ):
                    raise ValueError("git_publish_confirmed_idle_prompt_required")
                body = {
                    "text": publish_request.text,
                    "delivery": "queue",
                    "metadata": {
                        "jt_oz_bridge": {"action_id": action_id, "operation_digest": digest(frozen)}
                    },
                }
            elif operation == "check.run":
                allowed = {
                    "operation",
                    "reference",
                    "source",
                    "selection",
                    "selection_token_sha256",
                    "reply_locale",
                    "choice_expires_at",
                    "binding_id",
                    "binding_revision",
                }
                if (
                    not isinstance(frozen.get("binding_id"), str)
                    or not 1 <= len(frozen["binding_id"]) <= 36
                    or type(frozen.get("binding_revision")) is not int
                    or frozen["binding_revision"] < 1
                ):
                    raise ValueError("native_check_original_binding_context_required")
                choice = CheckSelection.model_validate(frozen["selection"])
                check_catalog = self.checks.catalog(reference)
                check_deadline = frozen.get("choice_expires_at", 0)
                if (
                    type(check_deadline) not in {int, float}
                    or not time.time() < check_deadline <= time.time() + 301
                ):
                    raise ValueError("native_check_choice_expired")
                if (
                    choice.reference != reference
                    or choice.catalog_sha256 != digest(check_catalog.model_dump(mode="json"))
                    or choice.check not in check_catalog.checks
                    or choice.qualification_sha256 != self.checks.qualification_for(reference)
                    or snapshot.state != ExecutionState.IDLE
                    or parsed.kind != "command"
                    or parsed.command != "check"
                    or source.revision != 0
                    or len(parsed.arguments.split()) != 1
                    or token_hash(parsed.arguments) != frozen.get("selection_token_sha256")
                    or frozen.get("reply_locale", "en") not in {"en", "zh-TW"}
                ):
                    raise ValueError("native_check_original_selection_required")
                check_transport_attestation = self.transport.attestation
                check_qualification = self.checks.selected(reference, choice.check)
                await self.checks.location(reference)
                self.current(reference, proof)
                body = {"id": check_message_id(action_id), "command": choice.check.command}
            elif operation == "session.rename":
                rename_attestation = self.transport.attestation
                allowed = {"operation", "reference", "source", "change", "reply_locale"}
                change = SessionRename.model_validate(frozen["change"])
                if (
                    parsed.kind != "command"
                    or parsed.command != "rename"
                    or source.revision != 0
                    or parsed.arguments.strip() != change.target_title
                    or snapshot.title != change.previous_title
                    or frozen.get("reply_locale", "en") not in {"en", "zh-TW"}
                ):
                    raise ValueError("explicit_original_session_rename_source_required")
                body = {"title": change.target_title}
            elif operation in LIFECYCLE_OPERATIONS:
                rename_attestation = self.transport.attestation
                allowed = set(SessionLifecycleRequest.model_fields)
                lifecycle_request = SessionLifecycleRequest.model_validate(frozen)
                if (
                    snapshot.state != ExecutionState.IDLE
                    or not time.time() < lifecycle_request.confirm_expires_at
                    or await self.pending_revert(reference)
                    != lifecycle_request.change.pending_revert_message_id
                ):
                    raise ValueError("session_lifecycle_preview_no_longer_current")
                body = lifecycle_request.change.wire_body()
            elif operation == "model.switch":
                allowed = {
                    "operation",
                    "reference",
                    "source",
                    "selection",
                    "selection_token_sha256",
                    "reply_locale",
                    "shortcut",
                }
                selection = ModelSelection.model_validate(frozen["selection"])
                model_qualification = getattr(self.proofs, "model_settings", None)
                if not isinstance(model_qualification, ModelSettingsAttestation):
                    raise ValueError("native_model_settings_qualification_required")
                model_qualification.require(reference, self.transport.profile.sha256)
                arguments = parsed.arguments.split()
                if (
                    parsed.kind != "command"
                    or parsed.command != selection.origin
                    or source.revision != 0
                    or len(arguments) != 1
                    or not 1 <= len(arguments[0]) <= 128
                    or token_hash(arguments[0]) != frozen["selection_token_sha256"]
                    or frozen.get("reply_locale", "en") not in {"en", "zh-TW"}
                ):
                    raise ValueError("explicit_model_selection_token_required")
                catalog = await self.models.read(reference)
                if (
                    digest(catalog.model_dump(mode="json")) != selection.catalog_sha256
                    or catalog.selected != selection.previous
                    or catalog.option(selection.target) is None
                ):
                    raise ValueError("native_model_catalog_or_selection_changed")
                body = {"model": selection.target.wire()}
            else:
                expected_command = {
                    "interrupt": {"stop"},
                    "permission.reply": {"approve", "deny"},
                    "form.reply": {"answer"},
                    "form.cancel": {"confirm"},
                }[operation]
                if parsed.kind != "command" or parsed.command not in expected_command:
                    raise ValueError("explicit_control_source_required")
                allowed = {"operation", "reference", "source"}
                if operation == "interrupt":
                    query = {"resume": "false"}
                else:
                    allowed |= {"interaction_id", "request_id", "generation"}
                    current = await self.pending(reference, frozen["request_id"], proof)
                    if not current.pending or current.generation != frozen["generation"]:
                        raise ValueError("native_request_changed")
                    expected_kind = "permission" if operation == "permission.reply" else "form"
                    if current.kind != expected_kind:
                        raise ValueError("native_request_kind_changed")
                    path["requestID" if current.kind == "permission" else "formID"] = (
                        current.upstream_request_id
                    )
                    if operation == "permission.reply":
                        allowed |= {"decision", "answers", "reason"}
                        if frozen.get("decision") not in {"once", "reject"} or frozen.get(
                            "answers", {}
                        ):
                            raise ValueError("broad_permission_or_form_payload_unavailable")
                        if parsed.command != (
                            "approve" if frozen["decision"] == "once" else "deny"
                        ):
                            raise ValueError("permission_source_decision_mismatch")
                        body = {"decision": frozen["decision"]}
                        if "reason" in frozen:
                            reason = frozen["reason"]
                            if (
                                frozen["decision"] != "reject"
                                or not isinstance(reason, str)
                                or len(reason) > 10000
                            ):
                                raise ValueError("invalid_denial_reason")
                            body["message"] = reason
                    elif operation == "form.reply":
                        allowed |= {"answers", "decision"}
                        if frozen.get("decision") is not None:
                            raise ValueError("form_permission_payload_unavailable")
                        answers = {
                            key: FieldAnswer.model_validate(value)
                            for key, value in frozen["answers"].items()
                        }
                        validate_answers(current.fields, answers)
                        body = {"answer": wire_answers(current.fields, answers)}
            if set(frozen) - allowed:
                raise ValueError("unsupported_native_operation_fields")
            native_operation = OPERATIONS[operation][-1]
            self.transport.profile.prepare(native_operation, path=path, query=query, body=body)
            self.current(reference, proof)
            if operation != "interrupt" and self.scope_guard is not None:
                if operation == "check.run":
                    policy_authorize_check = getattr(self.scope_guard, "authorize_check", None)
                    if not callable(policy_authorize_check):
                        raise ValueError("native_check_original_policy_guard_required")
                    policy_witness = await policy_authorize_check(
                        reference, proof, choice.check.command
                    )
                else:
                    policy_witness = await self.scope_guard.authorize(
                        reference, policy_operation(operation), proof
                    )
                self.current(reference, proof)
        except SteerNotReady:
            raise SteerNotReady("v2_native_steer_session_not_running") from None
        except SnapshotBoundaryChanged:
            # A running session moved between two reads. Nothing was sent; a steer
            # keeps its place instead of being refused.
            if steer:
                raise SteerNotReady("v2_native_steer_snapshot_moved") from None
            raise MutationNotSent("v2_native_mutation_preflight_rejected") from None
        except Exception:
            raise MutationNotSent("v2_native_mutation_preflight_rejected") from None

        def ready() -> None:
            self.current(reference, proof)
            if attachment_manifest is not None and (
                self.attachments is not attachment_provider
                or attachment_provider is None
                or prepared_attachments is None
                or not attachment_provider.qualified(reference, self.transport.profile.sha256)
                or not attachment_provider.current(reference, action_id, prepared_attachments)
            ):
                raise ContractError("native_attachment_provider_or_authority_changed")
            if workspace_manifest is not None and (
                self.workspace_attachments is not workspace_provider
                or workspace_provider is None
                or prepared_workspace is None
                or not workspace_provider.qualified(reference, self.transport.profile.sha256)
                or not workspace_provider.current(reference, action_id, prepared_workspace)
            ):
                raise ContractError("native_workspace_provider_or_authority_changed")
            if (
                operation == "session.rename" or operation in LIFECYCLE_OPERATIONS
            ) and self.transport.attestation is not rename_attestation:
                raise ContractError("v2_session_rename_attestation_changed")
            if (
                lifecycle_request is not None
                and not time.time() < lifecycle_request.confirm_expires_at
            ):
                raise ContractError("v2_session_lifecycle_confirmation_expired")
            if publish_request is not None and not time.time() < publish_request.confirm_expires_at:
                raise ContractError("v2_git_publish_confirmation_expired")
            if not self.capabilities(reference)[operation].supported:
                raise ContractError("v2_execution_operation_attestation_changed")
            if operation == "check.run" and (
                check_qualification is None
                or self.transport.attestation is not check_transport_attestation
                or not time.time() < check_deadline
                or self.checks.selected(reference, choice.check) is not check_qualification
            ):
                raise ContractError("native_check_qualification_changed")
            if operation == "check.run" and check_context is not None:
                owner = getattr(self.proofs, "dispatch_owner_epoch", None)
                if not callable(owner) or owner(reference, proof) != check_context.owner_epoch:
                    raise ContractError("native_check_final_owner_changed")
            if operation == "model.switch" and (
                getattr(self.proofs, "model_settings", None) is not model_qualification
            ):
                raise ContractError("v2_model_settings_qualification_changed")
            if operation != "interrupt" and self.scope_guard is not None:
                if (
                    self.scope_guard.current(
                        reference, policy_operation(operation), proof, policy_witness
                    )
                    is not True
                ):
                    raise ContractError("v2_native_project_policy_guard_changed")

        async def authorize_native_check() -> None:
            nonlocal check_context
            ready()
            owner = getattr(self.proofs, "dispatch_owner_epoch", None)
            if not callable(owner) or authorize_check is None:
                raise ContractError("native_check_original_dispatch_owner_required")
            if proof.state != ExecutionState.IDLE:
                raise ContractError("native_check_original_dispatch_idle_required")
            anchor = getattr(self.proofs, "dispatch_idle_anchor", None)
            check_context = CheckDispatchPreflight(
                action_id=action_id,
                operation_digest=digest(frozen),
                reference=reference,
                binding_id=frozen["binding_id"],
                binding_revision=frozen["binding_revision"],
                contract_sha256=self.contract_for(reference),
                qualification_sha256=choice.qualification_sha256,
                message_id=check_message_id(action_id),
                owner_epoch=owner(reference, proof),
                connection_epoch=proof.connection_epoch,
                ownership_evidence_sha256=proof.ownership_evidence_sha256,
                issued_at=proof.issued_at,
                expires_at=proof.expires_at,
                state="idle",
                idle_anchor=anchor(reference, proof) if callable(anchor) else None,
            )
            await authorize_check(check_context)

        try:
            value = await self.transport.request(
                native_operation,
                path=path,
                query=query,
                body=body,
                before_send=ready,
                authorize_send=authorize_native_check if operation == "check.run" else None,
            )
        except TransportNotSent as error:
            if steer:
                # Typically the turn ended after the preflight; still nothing was sent.
                raise SteerNotReady("v2_native_steer_transport_did_not_send") from None
            if str(error) in PROOF_MOVED_AT_SEND:
                # The proof moved between the preflight and the wire; a fresh one may hold.
                raise MutationNotSent(SEND_PROOF_MOVED) from None
            raise MutationNotSent("v2_native_transport_did_not_send") from None
        # From this point any malformed acknowledgement is uncertain, never unsent.
        if operation == "check.run":
            if value is not None:
                raise ContractError("native_check_expected_no_content")
            return Admission(
                status="admitted",
                upstream_id=check_message_id(action_id),
                details={
                    "operation": "check.run",
                    "check_id": choice.check.id,
                    "qualification_sha256": choice.qualification_sha256,
                    "semantics_sha256": CHECK_SEMANTICS,
                    "turn_completed": False,
                    "check_passed": False,
                },
            )
        if publish_request is not None:
            raw = value["data"]
            if (
                raw["sessionID"] != reference.upstream_session_id
                or raw["payload"]["text"] != publish_request.text
                or raw["delivery"] != "queue"
                or raw["payload"].get("files")
            ):
                raise ContractError("v2_git_publish_acknowledgement_mismatch")
            # Admission only: whether Git did anything is read back after the turn.
            return Admission(
                status="admitted",
                upstream_id=raw["id"],
                details={
                    "operation": "git.publish",
                    "delivery": "queue",
                    "turn_completed": False,
                    "git_verified": False,
                },
            )
        if operation == "prompt":
            raw = value["data"]
            if (
                raw["sessionID"] != reference.upstream_session_id
                or raw["payload"]["text"]
                != (projected_text if projected_text is not None else frozen["text"])
                or raw["delivery"] != delivery
                or delivery == "steer"
                and (
                    raw["type"] != "user"
                    or raw["payload"].get("files")
                    or raw["payload"].get("metadata", {}).get("jt_oz_bridge")
                    != {"action_id": action_id, "operation_digest": digest(frozen)}
                )
            ):
                raise ContractError("v2_prompt_acknowledgement_mismatch")
            attachment_details: dict[str, Any] = {}
            if attachment_manifest is not None:
                assert prepared_attachments is not None
                if raw["payload"].get("metadata", {}).get("jt_oz_bridge") != {
                    "action_id": action_id,
                    "operation_digest": digest(frozen),
                }:
                    raise ContractError("native_attachment_acknowledgement_correlation_changed")
                projections = verify_admitted_files(
                    raw["payload"].get("files"), attachment_manifest, prepared_attachments
                )
                attachment_details = {
                    "attachments": list(projections),
                    "attachment_semantics_sha256": ATTACHMENT_SEMANTICS,
                    "model_visibility": "unverified",
                }
            elif workspace_manifest is not None:
                assert prepared_workspace is not None
                if (
                    raw["payload"].get("files")
                    or raw["payload"].get("agents")
                    or raw["payload"].get("skills")
                    or raw["payload"].get("metadata", {}).get("jt_oz_bridge")
                    != {"action_id": action_id, "operation_digest": digest(frozen)}
                ):
                    raise ContractError("native_workspace_acknowledgement_correlation_changed")
                attachment_details = {
                    "workspace_projection": prepared_workspace.projection.model_dump(mode="json"),
                    "model_visibility": "unverified",
                }
            elif raw["payload"].get("files"):
                raise ContractError("v2_prompt_unexpected_attachment_admission")
            return Admission(
                status="admitted",
                upstream_id=raw["id"],
                details={
                    "operation": operation,
                    "delivery": delivery,
                    "turn_completed": False,
                    **attachment_details,
                },
            )
        if operation == "interrupt":
            return Admission(
                status="completed",
                details={
                    "operation": operation,
                    "interrupted": value["interrupted"],
                    "resume": False,
                    "children_verified_stopped": False,
                    "turn_completed": False,
                },
            )
        if lifecycle_request is not None:
            return await self.lifecycle_outcome(
                reference, lifecycle_request, value, proof, rename_attestation
            )
        if operation == "session.rename":
            renamed, observed = await self.rename_readback(
                reference, change, proof, rename_attestation
            )
            return Admission(
                status="completed",
                details=SessionRenameOutcome(
                    change=change,
                    observed_title=renamed.title,
                    owner_evidence_sha256=observed.ownership_evidence_sha256,
                    session_info_sha256=observed.session_info_sha256,
                ).model_dump(mode="json"),
            )
        if operation == "model.switch":
            # A 204 acknowledges the fixed setter, not an execution turn. Any
            # failed/changed readback is uncertain after that one POST; callers
            # retain an ambiguous action and must never automatically retry it.
            after = await self.models.read(reference)
            if (
                after.selected is None
                or not selection.target.same_native_selection(after.selected)
                or model_qualification is None
            ):
                raise ContractError("v2_model_switch_readback_not_verified")
            return Admission(
                status="completed",
                details=ModelSettingOutcome(
                    operation="model.switch",
                    target=selection.target,
                    observed=after.selected,
                    effect="subsequent_provider_turns",
                    catalog_before_sha256=selection.catalog_sha256,
                    model_settings_semantics_sha256=model_qualification.semantics_sha256,
                    model_settings_evidence_sha256=model_qualification.installed_evidence_sha256,
                    owner_evidence_sha256=proof.ownership_evidence_sha256,
                    starts_execution=False,
                    turn_completed=False,
                ).model_dump(mode="json"),
            )
        return Admission(
            status="completed",
            upstream_id=frozen["request_id"],
            details={"operation": operation, "request_settled": True, "turn_completed": False},
        )
