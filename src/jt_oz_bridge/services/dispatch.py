"""One-attempt mutation dispatch with durable admission and uncertainty handling.

The caller owns a valid fenced consumer lease. No production worker is started
merely by importing this module; live adapters require separate certification.
"""

import asyncio
import logging
import re
import time
from collections.abc import Callable, Mapping
from contextlib import AbstractAsyncContextManager, AsyncExitStack
from typing import TYPE_CHECKING, Any
from weakref import WeakValueDictionary

from sqlalchemy import and_, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.selectable import Exists

from jt_oz_bridge.adapters.opencode.contracts import ContractError, SnapshotBoundaryChanged
from jt_oz_bridge.adapters.zulip.client import ZulipReadUnavailable
from jt_oz_bridge.domain.check_dispatch import CheckDispatchPreflight
from jt_oz_bridge.domain.checks import CheckSelection
from jt_oz_bridge.domain.control import ExecutionState, InteractionSnapshot
from jt_oz_bridge.domain.delivery import DeliveryRateLimited
from jt_oz_bridge.domain.execution import (
    SEND_PROOF_MOVED,
    STEER_STATES,
    UNSTEERABLE_PAYLOAD,
    Admission,
    AnswerRejected,
    ExecutionClient,
    HumanMessage,
    MutationNotSent,
    MutationRejected,
    SourceReader,
    SteerNotReady,
)
from jt_oz_bridge.domain.git_publish import CONFIRM_TOKEN as PUBLISH_CONFIRM
from jt_oz_bridge.domain.git_publish import GIT_PUBLISH, GitPublishRequest
from jt_oz_bridge.domain.model_catalog import ModelSelection
from jt_oz_bridge.domain.models import WATCH_PENDING, ActionState, SessionRef
from jt_oz_bridge.domain.session_lifecycle import (
    LIFECYCLE_OPERATIONS,
    SessionLifecycleRequest,
    SessionRename,
)
from jt_oz_bridge.domain.worktree_switch import WorkspaceConcurrencyPolicy
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.security.admin import token_hash
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.attachment_imports import AttachmentImportJournal
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.check_dispatch_records import CheckDispatchRecords
from jt_oz_bridge.services.execution_receipts import ExecutionReceipt
from jt_oz_bridge.services.generated_capture_plans import capture_blocks
from jt_oz_bridge.services.interactions import InteractionService
from jt_oz_bridge.services.menu_shortcuts import verify
from jt_oz_bridge.services.prompt_attachments import source_uploads
from jt_oz_bridge.services.queue import QueueService
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.storage.control_models import Binding, ControlToken, PendingInteraction
from jt_oz_bridge.storage.durable import Conflict, DurableStore, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.guards import enrollment
from jt_oz_bridge.storage.models import Action, AuditEvent, Grant, WorkerLease
from jt_oz_bridge.storage.session_configuration_heads import configuration_barrier

LOG = logging.getLogger(__name__)
# How long a prompt waits for a Root that has no watch yet before it is held instead.
WATCH_GRACE_SECONDS = 120
DEDICATED_OPERATIONS = frozenset({"worktree.create", "agent.switch", "agent.adopt"})
# Operations that start an agent turn on the Root: one at a time, idle only, in FIFO order.
TURNS = ("prompt", "check.run", GIT_PUBLISH)
# How long an unreachable OpenCode is retried before a waiting message is refused.
TRANSIENT_RETRY_SECONDS = 300
# An uncertain prompt younger than this may still be settling; it is not read back yet.
UNCERTAIN_PROMPT_SETTLE_SECONDS = 60
# Only this old may an uncertain prompt OpenCode holds no trace of be called unsent.
UNCERTAIN_PROMPT_ABSENT_SECONDS = 600
NEVER_ARRIVED = "native_prompt_never_arrived"
# A prompt proven unsent at the wire waits here for its next full attempt.
SEND_RETRY = "send_proof_moved_retry"
PREFLIGHT_UNAVAILABLE = "preflight_unavailable"
# A Root the registry does not hold right now, such as a chat-created Root whose
# restore is retried every 30 seconds; refused only after the same window.
SESSION_UNAVAILABLE = "session_unavailable"
# OpenCode kept answering the pre-send state read with a contract refusal, for example
# while a reply was still settling just after a reconnect; nothing was sent.
NATIVE_UNCONFIRMED = "native_state_unconfirmed"
# A refusal's own fixed code, such as `leaf_pending_scope_changed`, is safe to log.
ERROR_CODE = re.compile(r"[a-z0-9_]{1,80}")


def error_code(error: BaseException) -> str:
    return text if ERROR_CODE.fullmatch(text := str(error)) else "-"


def transient_preflight(error: BaseException) -> bool:
    """A read that may succeed next time; never a sign the message itself changed."""
    from jt_oz_bridge.adapters.opencode.contracts import SnapshotBoundaryChanged
    from jt_oz_bridge.adapters.opencode.transport import TransportError, TransportNotSent

    return (
        isinstance(error, TransportError)
        and not isinstance(error, TransportNotSent)
        or isinstance(error, SnapshotBoundaryChanged)
        or type(error) is Conflict
        and str(error) == "execution owner unavailable"
    )


# A join refused unsent: the prompt now waits for an idle session and its own turn.
STEER_NOT_READY = "steer_not_ready"

# A refusal at the start of the body counts as unsent, so a steer that cannot join
# the running turn keeps its place and waits for its own turn.
STEER_INTO_RUNNING_TURNS = True


if TYPE_CHECKING:
    from jt_oz_bridge.services.prompt_schedules import PromptSchedules
    from jt_oz_bridge.services.zulip_recovery_guards import ReviewWitness


class Dispatcher:
    def __init__(
        self,
        bindings: BindingService,
        client: ExecutionClient,
        reader: SourceReader,
        holder: str,
        fencing: int,
        *,
        max_global: int = 4,
        max_backend: int = 2,
        require_control_source: bool = True,
        attachment_imports: AttachmentImportJournal | None = None,
        attachment_realm_url: str | None = None,
        workspace_ready: Callable[[SessionRef, str], bool] | None = None,
        workspace_scope: Callable[[SessionRef], bool] | None = None,
        processing: Callable[[Binding], AbstractAsyncContextManager[None]] | None = None,
    ) -> None:
        if max_global < 1 or max_backend < 1:
            raise ValueError("positive dispatch limits required")
        self.bindings, self.db, self.client, self.reader = bindings, bindings.db, client, reader
        self.holder, self.fencing = holder, fencing
        self.max_global, self.max_backend = max_global, max_backend
        self.require_control_source = require_control_source
        if attachment_imports is not None and (
            attachment_imports.db is not self.db
            or attachment_imports.fence != ConsumerFence(holder, fencing)
            or attachment_realm_url != attachment_imports.importer.zulip.url
        ):
            raise ValueError("attachment_import_dispatch_scope_mismatch")
        if workspace_ready is not None and (
            attachment_imports is None
            or attachment_imports.transport != "workspace"
            or attachment_imports.importer.source is not reader
            or attachment_imports.artifacts.bindings is not bindings
        ):
            raise ValueError("workspace_dispatch_requires_original_importer_source_and_scope")
        self.workspace_ready = workspace_ready
        self.workspace_scope = workspace_scope
        self.processing = processing
        self.attachment_imports = attachment_imports
        self.attachment_realm_url = attachment_realm_url
        self.store, self.queue = DurableStore(self.db), QueueService(bindings)
        # Trusted composition only; without it a timed prompt is refused, never sent.
        self.schedules: PromptSchedules | None = None
        self._locks: WeakValueDictionary[str, asyncio.Lock] = WeakValueDictionary()
        # First transient preflight failure per still-queued action (monotonic).
        self._transient: dict[str, float] = {}
        # Apart from `_transient`, which a successful claim clears: each of these
        # attempts claims, so their window must outlive the claims.
        self._unsent: dict[str, float] = {}
        # Uncertain prompts already said to be left alone, so each is logged once.
        self._uncertain_noted: dict[str, str] = {}
        self._reservations = asyncio.Lock()
        self._workspace_policies: Mapping[tuple[str, str, str], WorkspaceConcurrencyPolicy] = {}
        self._workspace_policy_configured = False

    def configure_workspace_policies(
        self, policies: tuple[WorkspaceConcurrencyPolicy, ...]
    ) -> None:
        from types import MappingProxyType

        from jt_oz_bridge.domain.worktree_switch import WorkspaceConcurrencyPolicy

        if self._workspace_policy_configured:
            raise ValueError("workspace_policy_already_composed")
        checked = tuple(WorkspaceConcurrencyPolicy.model_validate(p.model_dump()) for p in policies)
        keys = [(p.backend_id, p.backend_identity, p.canonical_directory) for p in checked]
        if len(checked) > 128 or len(set(keys)) != len(keys):
            raise ValueError("workspace_policy_explicit_unique_scope_required")
        self._workspace_policies = MappingProxyType(dict(zip(keys, checked, strict=True)))
        self._workspace_policy_configured = True

    async def _workspace_blocked(
        self, session: AsyncSession, binding: Binding, operation: str, *, steer: bool = False
    ) -> bool:
        if (
            operation not in {*TURNS, "model.switch", "session.rename"}
            and operation not in LIFECYCLE_OPERATIONS
        ):
            return False
        key = (binding.backend_id, binding.backend_identity, binding.canonical_directory)
        policy = self._workspace_policies.get(key)
        if policy is None or policy.mode != "exclusive":
            return False
        aliases = [
            p.canonical_directory
            for p in self._workspace_policies.values()
            if (p.backend_id, p.backend_identity, p.device, p.inode)
            == (policy.backend_id, policy.backend_identity, policy.device, policy.inode)
        ]
        query = (
            select(Action.id)
            .join(Binding, Binding.id == Action.binding_id)
            .where(
                Binding.backend_id == policy.backend_id,
                Binding.backend_identity == policy.backend_identity,
                Binding.canonical_directory.in_(aliases),
                Action.operation.in_([*TURNS, "model.switch", "session.rename"]),
                Action.state.in_(["dispatching", "admitted", "running", "ambiguous"]),
            )
            .limit(1)
        )
        if steer:
            # A steer joins the turn already running on this same session; it does
            # not start a second one. claim() checks exactly what that turn is.
            query = query.where(
                ~and_(
                    Binding.session_id == binding.session_id,
                    Action.operation == "prompt",
                    Action.state.in_(["admitted", "running"]),
                )
            )
        active = await session.scalar(query)
        return active is not None

    async def blocked_by_workspace(self, action_id: str) -> bool:
        """SQL-only deny hint, never permission or a reservation."""
        async with self.db.sessions() as session:
            action = await session.get(Action, action_id)
            binding = await session.get(Binding, action.binding_id) if action else None
            return bool(
                action
                and binding
                and await self._workspace_blocked(
                    session, binding, action.operation, steer=bool(self.join_states(action))
                )
            )

    @staticmethod
    def steer_candidate(action: Action) -> bool:
        """A fresh plain prompt that may join a running turn; SQL/payload hint only.

        Attachments, timed sends and anything held, resumed, edited or recovered
        keep the ordinary queue: each waits for an idle session and its own turn.
        """
        payload = action.payload if isinstance(action.payload, dict) else {}
        return (
            action.operation == "prompt"
            and payload.get("operation") == "prompt"
            and not UNSTEERABLE_PAYLOAD & set(payload)
            and action.state in {"queued", "dispatching"}
            and action.version == 1
            and action.status_reason is None
        )

    @classmethod
    def join_states(cls, action: Action) -> frozenset[str]:
        """Non-idle Native states this queued row may be sent into; a hint only.

        Running: only a fresh plain prompt steers into the turn, and only while
        `STEER_INTO_RUNNING_TURNS` is on. Queued (no execution, only inputs a stop
        parked): any prompt may wake them and then run after them, as it would on
        an idle session.
        """
        payload = action.payload if isinstance(action.payload, dict) else {}
        if (
            action.operation != "prompt"
            or payload.get("operation") != "prompt"
            or action.status_reason == STEER_NOT_READY
        ):
            return frozenset()
        if STEER_INTO_RUNNING_TURNS and cls.steer_candidate(action):
            return STEER_STATES
        return frozenset({"queued"})

    async def _joinable(self, action: Action, binding: Binding) -> frozenset[str]:
        states = self.join_states(action)
        supported = getattr(self.client, "steer_supported", None)
        if not states or not callable(supported) or supported(reference(binding)) is not True:
            return frozenset()
        if "running" in states:
            from jt_oz_bridge.storage.zulip_recovery_models import ZulipRecoveryItem

            async with self.db.sessions() as session:
                recovered = await session.scalar(
                    select(ZulipRecoveryItem.id).where(ZulipRecoveryItem.action_id == action.id)
                )
            if recovered is not None:
                return frozenset({"queued"})
        return states

    async def join_hint(self, action: Action, binding: Binding) -> frozenset[str]:
        """Busy states worth a dispatch attempt; local reads only, the claim decides.

        A prompt that cannot steer now (no inbox read, or another turn in flight)
        waits for an idle session instead of re-reading its source every poll.
        """
        states = await self._joinable(action, binding)
        if "running" in states:
            async with self.db.sessions() as session:
                if not await self._steer_target(session, action, binding):
                    return states - {"running"}
        return states

    @staticmethod
    async def _steer_target(session: AsyncSession, action: Action, binding: Binding) -> bool:
        """Every in-flight turn on this Root is an acknowledged prompt of this topic."""
        rows = (
            await session.execute(
                select(Action.binding_id, Action.binding_revision, Action.operation, Action.state)
                .join(Binding, Binding.id == Action.binding_id)
                .where(
                    Binding.backend_id == binding.backend_id,
                    Binding.backend_identity == binding.backend_identity,
                    Binding.session_id == binding.session_id,
                    Action.id != action.id,
                    Action.operation.in_(list(TURNS)),
                    Action.state.in_(["dispatching", "admitted", "running", "ambiguous"]),
                )
            )
        ).all()
        return all(
            (row[0], row[1], row[2]) == (binding.id, action.binding_revision, "prompt")
            and row[3] in {"admitted", "running"}
            for row in rows
        )

    async def load(self, action_id: str) -> Action:
        async with self.db.sessions() as session:
            action = await session.get(Action, action_id)
        if action is None:
            raise Conflict("action unavailable")
        return action

    def lease(self) -> Exists:
        return (
            select(WorkerLease.role)
            .where(
                WorkerLease.role == "consumer",
                WorkerLease.holder == self.holder,
                WorkerLease.fencing == self.fencing,
                WorkerLease.expires_at > time.time(),
            )
            .exists()
        )

    async def held(self, action: Action, code: str, *, rejected: bool = False) -> str:
        target = ActionState.REJECTED if rejected else ActionState.HELD
        async with self.db.sessions.begin() as session:
            await session.execute(
                update(Action)
                .where(
                    Action.id == action.id,
                    Action.state == "queued",
                    Action.version == action.version,
                    self.lease(),
                )
                .values(state=target, version=Action.version + 1, status_reason=code)
            )
        return (await self.load(action.id)).state

    def _retry_later(self, action_id: str, window: dict[str, float] | None = None) -> bool:
        """True while a transient failure is still inside its bounded retry window."""
        window = self._transient if window is None else window
        now = time.monotonic()
        first = window.setdefault(action_id, now)
        if len(window) > 1024:
            oldest = min(window, key=window.__getitem__)
            if oldest != action_id:
                window.pop(oldest)
        return now - first < TRANSIENT_RETRY_SECONDS

    async def _fifo_head(self, session: AsyncSession, binding_id: str, revision: int) -> str | None:
        # Only this topic revision's work takes turns: an action left from before a
        # rebind can never be sent, so it must not stop everything after it.
        identity: str | None = await session.scalar(
            select(Action.id)
            .where(
                Action.binding_id == binding_id,
                Action.binding_revision == revision,
                Action.state.in_(["queued", "held"]),
                Action.operation.in_([*TURNS, "model.switch"]),
            )
            .order_by(Action.created_at, Action.id)
            .limit(1)
        )
        return identity

    async def blocked_by_fifo(self, action_id: str) -> bool:
        """SQL-only denial hint; False grants no authority and is never a claim."""
        async with self.db.sessions() as session:
            action = await session.get(Action, action_id)
            if action is None or action.state != "queued" or action.operation not in TURNS:
                return False
            from jt_oz_bridge.storage.zulip_recovery_models import ZulipRecoveryItem

            recovery = await session.scalar(
                select(ZulipRecoveryItem).where(ZulipRecoveryItem.action_id == action.id)
            )
            if recovery is not None and (
                recovery.state != "reviewed" or recovery.review_receipt_id is None
            ):
                return True
            earlier = await self._fifo_head(session, action.binding_id, action.binding_revision)
            return earlier is not None and earlier != action.id

    async def claim(
        self,
        action: Action,
        binding: Binding,
        permission: Permission,
        *,
        recovery_witness: "ReviewWitness | None" = None,
        steer: bool = False,
    ) -> bool:
        if action.operation in DEDICATED_OPERATIONS:
            return False  # Only the dedicated one-attempt coordinator owns this operation.
        async with self._reservations:
            async with self.db.sessions.begin() as session:
                locked = await session.execute(
                    update(WorkerLease)
                    .where(
                        WorkerLease.role == "consumer",
                        WorkerLease.holder == self.holder,
                        WorkerLease.fencing == self.fencing,
                        WorkerLease.expires_at > time.time(),
                    )
                    .values(expires_at=WorkerLease.expires_at)
                )
                if locked.rowcount != 1:  # type: ignore[attr-defined]
                    return False
                if steer and (
                    action.operation != "prompt"
                    or not await self._steer_target(session, action, binding)
                ):
                    return False
                if await self._workspace_blocked(session, binding, action.operation, steer=steer):
                    return False
                if await capture_blocks(session, binding):
                    return False
                from jt_oz_bridge.services.zulip_recovery_guards import require_claim_review

                try:
                    await require_claim_review(session, action, binding, recovery_witness)
                except Conflict:
                    return False
                operation = action.payload.get("operation")
                if action.operation != operation:
                    return False
                if operation != "interrupt" and (
                    await configuration_barrier(session, reference(binding)) is not None
                    or await self._agent_setting_inflight(session, binding)
                ):
                    # The whole original Root waits, whichever realm or Binding
                    # asks. Interrupt stays an independent emergency control.
                    return False
                if operation in {*TURNS, "model.switch"}:
                    # A setting request with an uncertain acknowledgement can
                    # still affect this same original root after a rebind. Do
                    # not send another setting/prompt through that uncertainty.
                    model_inflight = await session.scalar(
                        select(Action.id)
                        .join(Binding, Binding.id == Action.binding_id)
                        .where(
                            Binding.backend_id == binding.backend_id,
                            Binding.backend_identity == binding.backend_identity,
                            Binding.session_id == binding.session_id,
                            Action.operation == "model.switch",
                            Action.state.in_(["dispatching", "ambiguous"]),
                        )
                        .limit(1)
                    )
                    if model_inflight is not None:
                        return False
                if await self._lifecycle_conflict(session, action, binding):
                    return False
                if (
                    operation in {*TURNS, "model.switch", "session.rename"}
                    or operation in LIFECYCLE_OPERATIONS
                ):
                    active_check = await session.scalar(
                        select(Action.id)
                        .join(Binding, Binding.id == Action.binding_id)
                        .where(
                            Binding.backend_id == binding.backend_id,
                            Binding.backend_identity == binding.backend_identity,
                            Binding.session_id == binding.session_id,
                            Action.operation == "check.run",
                            Action.state.in_(["dispatching", "admitted", "running", "ambiguous"]),
                        )
                        .limit(1)
                    )
                    if active_check is not None:
                        return False
                if operation == "model.switch":
                    earlier_model = await session.scalar(
                        select(Action.id)
                        .where(
                            Action.binding_id == binding.id,
                            Action.binding_revision == binding.revision,
                            Action.state.in_(["queued", "held"]),
                            Action.operation == "model.switch",
                        )
                        .order_by(Action.created_at, Action.id)
                        .limit(1)
                    )
                    if earlier_model != action.id:
                        return False
                if operation == "session.rename":
                    uncertain_title = await session.scalar(
                        select(Action.id)
                        .join(Binding, Binding.id == Action.binding_id)
                        .where(
                            Binding.backend_id == binding.backend_id,
                            Binding.backend_identity == binding.backend_identity,
                            Binding.session_id == binding.session_id,
                            Action.operation == "session.rename",
                            Action.state.in_(["dispatching", "ambiguous"]),
                        )
                        .limit(1)
                    )
                    earlier_title = await session.scalar(
                        select(Action.id)
                        .where(
                            Action.binding_id == binding.id,
                            Action.binding_revision == binding.revision,
                            Action.operation == "session.rename",
                            Action.state.in_(["queued", "held"]),
                        )
                        .order_by(Action.created_at, Action.id)
                        .limit(1)
                    )
                    if uncertain_title is not None or earlier_title != action.id:
                        return False
                if operation in TURNS:
                    active = (
                        await session.execute(
                            select(Binding.backend_id, Binding.backend_identity, Binding.session_id)
                            .join(Action, Action.binding_id == Binding.id)
                            .where(
                                Action.state.in_(
                                    ["dispatching", "admitted", "running", "ambiguous"]
                                ),
                                Action.operation.in_(list(TURNS)),
                            )
                            .distinct()
                        )
                    ).all()
                    key = (binding.backend_id, binding.backend_identity, binding.session_id)
                    if key in active and not steer:
                        return False
                    if key not in active and (
                        len(active) >= self.max_global
                        or sum(row[0] == binding.backend_id for row in active) >= self.max_backend
                    ):
                        return False
                    earlier = await self._fifo_head(session, binding.id, action.binding_revision)
                    if earlier != action.id:
                        return False
                allowed_roles = [
                    role for role, permissions in ROLES.items() if permission in permissions
                ]
                grant = (
                    select(Grant.id)
                    .where(
                        Grant.realm_id == binding.realm_id,
                        Grant.user_id == action.actor_id,
                        Grant.project_id == binding.project_id,
                        Grant.active.is_(True),
                        Grant.role.in_(allowed_roles),
                    )
                    .exists()
                )
                lease = (
                    select(WorkerLease.role)
                    .where(
                        WorkerLease.role == "consumer",
                        WorkerLease.holder == self.holder,
                        WorkerLease.fencing == self.fencing,
                        WorkerLease.expires_at > time.time(),
                    )
                    .exists()
                )
                scope = select(Binding.id).where(
                    Binding.id == binding.id,
                    Binding.state == "active",
                    Binding.revision == action.binding_revision,
                )
                if (
                    operation in {*TURNS, "model.switch", "session.rename"}
                    or operation in LIFECYCLE_OPERATIONS
                ):
                    scope = scope.where(Binding.dispatch_paused.is_(False))
                if operation == "check.run":
                    clock = (
                        (func.julianday("now") - 2440587.5) * 86400.0
                        if self.db.engine.dialect.name == "sqlite"
                        else func.extract("epoch", func.clock_timestamp())
                    )
                    scope = scope.where(
                        select(ControlToken.token_hash)
                        .where(
                            ControlToken.token_hash == action.payload.get("selection_token_sha256"),
                            ControlToken.kind == "native-check-choice",
                            ControlToken.used.is_(True),
                            ControlToken.binding_id == binding.id,
                            ControlToken.binding_revision == binding.revision,
                            ControlToken.user_id == action.actor_id,
                            ControlToken.realm_id == binding.realm_id,
                            ControlToken.expires_at > clock,
                            ControlToken.expires_at == action.payload.get("choice_expires_at"),
                        )
                        .exists()
                    )
                result = await session.execute(
                    update(Action)
                    .where(
                        Action.id == action.id,
                        Action.version == action.version,
                        Action.state == "queued",
                        grant,
                        lease,
                        scope.exists(),
                        *enrollment(binding, self.client.contract_for(reference(binding))),
                    )
                    .values(state="dispatching", version=Action.version + 1, status_reason=None)
                )
                return result.rowcount == 1  # type: ignore[attr-defined,no-any-return]

    @staticmethod
    async def _agent_setting_inflight(session: AsyncSession, binding: Binding) -> bool:
        found = await session.scalar(
            select(Action.id)
            .join(Binding, Binding.id == Action.binding_id)
            .where(
                Binding.backend_id == binding.backend_id,
                Binding.backend_identity == binding.backend_identity,
                Binding.session_id == binding.session_id,
                Action.operation == "agent.switch",
                Action.state.in_(["dispatching", "admitted"]),
            )
            .limit(1)
        )
        return found is not None

    @staticmethod
    async def _lifecycle_conflict(session: AsyncSession, action: Action, binding: Binding) -> bool:
        """One Native mutation at a time on an original session, in either direction.

        A prompt waits only while a fork/compact/revert is being sent. An unknown
        result is reported and never resent; each later preview rereads Native.
        """
        lifecycle = sorted(LIFECYCLE_OPERATIONS)
        if action.operation in LIFECYCLE_OPERATIONS:
            others = [*lifecycle, *TURNS, "model.switch", "session.rename"]
            states = ["dispatching", "admitted", "running"]
        elif action.operation in {*TURNS, "model.switch", "session.rename"}:
            others, states = lifecycle, ["dispatching"]
        else:
            return False
        found = await session.scalar(
            select(Action.id)
            .join(Binding, Binding.id == Action.binding_id)
            .where(
                Binding.backend_id == binding.backend_id,
                Binding.backend_identity == binding.backend_identity,
                Binding.session_id == binding.session_id,
                Action.id != action.id,
                Action.operation.in_(others),
                Action.state.in_(states),
            )
            .limit(1)
        )
        return found is not None

    async def validate_lifecycle_sources(self, action: Action, binding: Binding) -> None:
        """Both the preview and its !confirm must still be the unedited originals."""
        request = SessionLifecycleRequest.model_validate(action.payload)
        if (
            request.operation != action.operation
            or request.reference != reference(binding)
            or action.dedupe_key != "session-lifecycle:" + request.confirmation_token_sha256
        ):
            raise Conflict("session_lifecycle_action_identity_changed")
        for source in request.preview_sources:
            if (source.realm_id, source.author_id, source.channel_id, source.topic) != (
                binding.realm_id,
                action.actor_id,
                binding.channel_id,
                binding.topic,
            ) or await self.reader.read(source.realm_id, source.message_id) != source:
                raise Conflict("session_lifecycle_preview_source_changed")
        async with self.db.sessions() as session:
            saved = await session.get(ControlToken, request.confirmation_token_sha256)
        if (
            saved is None
            or saved.kind != "session-lifecycle-confirm"
            or not saved.used
            or saved.realm_id != binding.realm_id
            or saved.user_id != action.actor_id
            or (saved.binding_id, saved.binding_revision) != (binding.id, binding.revision)
        ):
            raise Conflict("session_lifecycle_confirmation_token_changed")

    async def validate_git_publish(self, action: Action, binding: Binding) -> None:
        """The previewed command and its !confirm are unedited; the token was spent on it."""
        request = GitPublishRequest.model_validate(action.payload)
        if (
            request.reference != reference(binding)
            or action.dedupe_key != "git-publish:" + request.confirmation_token_sha256
            or (request.preview.realm_id, request.preview.author_id)
            != (
                binding.realm_id,
                action.actor_id,
            )
            or (request.preview.channel_id, request.preview.topic)
            != (binding.channel_id, binding.topic)
            or await self.reader.read(request.preview.realm_id, request.preview.message_id)
            != request.preview
        ):
            raise Conflict("git_publish_preview_source_changed")
        async with self.db.sessions() as session:
            saved = await session.get(ControlToken, request.confirmation_token_sha256)
        if (
            saved is None
            or saved.kind != PUBLISH_CONFIRM
            or not saved.used
            or saved.realm_id != binding.realm_id
            or saved.user_id != action.actor_id
            or (saved.binding_id, saved.binding_revision) != (binding.id, binding.revision)
            or saved.context_hash != digest(saved.context)
            or saved.context.get("plan") != request.plan.model_dump(mode="json")
        ):
            raise Conflict("git_publish_confirmation_token_changed")

    async def validate_control_source(self, action: Action, binding: Binding) -> None:
        raw = action.payload.get("source")
        if raw is None:
            if self.require_control_source:
                raise Conflict("control_source_required")
            return
        source = HumanMessage.model_validate(raw)
        if (
            source.is_bot
            or source.deleted
            or (source.realm_id, source.author_id, source.channel_id, source.topic)
            != (binding.realm_id, action.actor_id, binding.channel_id, binding.topic)
        ):
            raise Conflict("control_source_scope_changed")
        latest = await self.reader.read(source.realm_id, source.message_id)
        if latest != source:
            raise Conflict("control_source_edited_or_deleted")
        shortcut = action.payload.get("shortcut")
        if shortcut is not None and action.payload.get("operation") != "model.switch":
            raise Conflict("menu_shortcut_operation_changed")
        parsed = await verify(self.db, binding, source, shortcut)
        expected = {
            "interrupt": "stop",
            "session.rename": "rename",
            "check.run": "check",
            "form.reply": "answer",
            "form.cancel": "confirm",
            "permission.reply": "approve" if action.payload.get("decision") == "once" else "deny",
            **dict.fromkeys(LIFECYCLE_OPERATIONS, "confirm"),
            GIT_PUBLISH: "confirm",
        }.get(str(action.payload.get("operation")))
        if action.payload.get("operation") == "model.switch":
            expected = ModelSelection.model_validate(action.payload.get("selection")).origin
        if parsed.kind != "command" or parsed.command != expected:
            raise Conflict("control_source_operation_changed")

    async def validate_model_selection(self, action: Action, binding: Binding) -> None:
        source = HumanMessage.model_validate(action.payload.get("source"))
        parsed = await verify(self.db, binding, source, action.payload.get("shortcut"))
        choice = ModelSelection.model_validate(action.payload.get("selection"))
        parts = parsed.arguments.split()
        identity = action.payload.get("selection_token_sha256")
        async with self.db.sessions() as session:
            saved = await session.get(ControlToken, identity) if isinstance(identity, str) else None
        if (
            source.revision != 0
            or parsed.kind != "command"
            or parsed.command != choice.origin
            or len(parts) != 1
            or token_hash(parts[0]) != identity
            or saved is None
            or saved.kind != "native-model-choice"
            or not saved.used
            or saved.realm_id != binding.realm_id
            or saved.user_id != action.actor_id
            or saved.binding_id != binding.id
            or saved.binding_revision != binding.revision
            or saved.expires_at <= time.time()
            or saved.context_hash != digest(saved.context)
            or saved.context != choice.model_dump(mode="json")
            or action.dedupe_key != "model-choice:" + saved.token_hash
        ):
            raise Conflict("model_selection_token_or_source_changed")

    async def validate_check_selection(self, action: Action, binding: Binding) -> None:
        source = HumanMessage.model_validate(action.payload.get("source"))
        parsed = parse_input(source.text, bound=True)
        choice = CheckSelection.model_validate(action.payload.get("selection"))
        identity = action.payload.get("selection_token_sha256")
        async with self.db.sessions() as session:
            saved = await session.get(ControlToken, identity) if isinstance(identity, str) else None
        if (
            source.revision != 0
            or parsed.kind != "command"
            or parsed.command != "check"
            or len(parsed.arguments.split()) != 1
            or token_hash(parsed.arguments) != identity
            or choice.reference != reference(binding)
            or saved is None
            or saved.kind != "native-check-choice"
            or not saved.used
            or saved.realm_id != binding.realm_id
            or saved.user_id != action.actor_id
            or saved.binding_id != binding.id
            or saved.binding_revision != binding.revision
            or saved.expires_at <= time.time()
            or saved.expires_at != action.payload.get("choice_expires_at")
            or saved.context_hash != digest(saved.context)
            or saved.context != choice.model_dump(mode="json")
            or action.dedupe_key != "check-choice:" + saved.token_hash
        ):
            raise Conflict("check_selection_token_or_source_changed")

    async def validate_interaction(self, action: Action, binding: Binding) -> None:
        async with self.db.sessions() as session:
            saved = await session.get(PendingInteraction, action.payload.get("interaction_id"))
        if (
            not saved
            or saved.action_id != action.id
            or saved.state != "reply_queued"
            or saved.winner_user_id != action.actor_id
            or saved.expires_at <= time.time()
            or saved.binding_revision != binding.revision
        ):
            raise Conflict("interaction decision expired or changed")
        snapshot = InteractionSnapshot.model_validate(saved.snapshot)
        current = await self.client.interaction(snapshot.reference, snapshot.upstream_request_id)
        if current == snapshot.model_copy(update={"pending": False}):
            async with self.db.sessions.begin() as session:
                await session.execute(
                    update(PendingInteraction)
                    .where(
                        PendingInteraction.id == saved.id,
                        PendingInteraction.state == "reply_queued",
                        PendingInteraction.action_id == action.id,
                        PendingInteraction.version == saved.version,
                        self.lease(),
                    )
                    .values(state="resolved", version=PendingInteraction.version + 1)
                )
        if current != snapshot or not current.pending:
            raise Conflict("interaction resolved or changed upstream")

    async def reopen_rejected_form(self, action: Action, binding: Binding) -> None:
        """A proven invalid answer permits a new human attempt, never a POST retry."""
        await self.reopen_unadmitted_interaction(action, binding, known_unsent=False)

    async def reopen_unadmitted_interaction(
        self, action: Action, binding: Binding, *, known_unsent: bool, after_claim: bool = False
    ) -> None:
        if action.payload.get("operation") not in {"permission.reply", "form.reply", "form.cancel"}:
            return
        expected_version = action.version + (2 if after_claim or not known_unsent else 1)
        states = ["held", "rejected"] if known_unsent else ["rejected"]
        async with self.db.sessions() as session:
            saved = await session.get(PendingInteraction, action.payload.get("interaction_id"))
            current_action = await session.get(Action, action.id)
        if (
            not saved
            or saved.action_id != action.id
            or saved.state != "reply_queued"
            or not current_action
            or current_action.state not in states
            or current_action.version != expected_version
            or current_action.upstream_id is not None
        ):
            return
        snapshot = InteractionSnapshot.model_validate(saved.snapshot)
        if not known_unsent and snapshot.kind != "form":
            return
        try:
            current_binding = await self.bindings.get(
                binding.id,
                binding.realm_id,
                action.actor_id,
                Permission.VIEW,
            )
            await InteractionService(self.bindings).lineage(current_binding, snapshot)
            current = await self.client.interaction(
                snapshot.reference, snapshot.upstream_request_id
            )
            if current_binding.revision != saved.binding_revision:
                return
            if current == snapshot:
                reopened_state = "pending"
            elif current == snapshot.model_copy(update={"pending": False}):
                reopened_state = "resolved"
            else:
                return
        except Exception:
            # Only read-only verification failed. Keep the original durable state.
            return
        async with self.db.sessions.begin() as session:
            reopened = await session.execute(
                update(PendingInteraction)
                .where(
                    PendingInteraction.id == saved.id,
                    PendingInteraction.state == "reply_queued",
                    PendingInteraction.action_id == action.id,
                    PendingInteraction.version == saved.version,
                    self.lease(),
                    select(Binding.id)
                    .where(
                        Binding.id == binding.id,
                        Binding.state == "active",
                        Binding.revision == saved.binding_revision,
                    )
                    .exists(),
                    select(Action.id)
                    .where(
                        Action.id == action.id,
                        Action.state.in_(states),
                        Action.version == expected_version,
                        Action.upstream_id.is_(None),
                    )
                    .exists(),
                )
                .values(
                    state=reopened_state,
                    winner_user_id=None,
                    action_id=None,
                    version=PendingInteraction.version + 1,
                )
            )
            if reopened.rowcount == 1:  # type: ignore[attr-defined]
                session.add(
                    AuditEvent(
                        actor="worker",
                        event="interaction_reopened_without_admission",
                        object_id=saved.id,
                    )
                )

    def check_lease(self) -> Exists:
        clock = (
            (func.julianday("now") - 2440587.5) * 86400.0
            if self.db.engine.dialect.name == "sqlite"
            else func.extract("epoch", func.clock_timestamp())
        )
        return (
            select(WorkerLease.role)
            .where(
                WorkerLease.role == "consumer",
                WorkerLease.holder == self.holder,
                WorkerLease.fencing == self.fencing,
                WorkerLease.expires_at > clock,
            )
            .exists()
        )

    async def check_transition(self, action: Action, target: str) -> str:
        try:
            async with self.db.sessions.begin() as session:
                await ConsumerFence(self.holder, self.fencing).lock(session)
                await session.execute(
                    update(Action)
                    .where(
                        Action.id == action.id,
                        Action.state == "dispatching",
                        Action.version == action.version + 1,
                        self.check_lease(),
                    )
                    .values(state=target, version=Action.version + 1)
                )
        except Conflict:
            # A stale worker records no new outcome; its successor reconciles
            # the already-owned attempt. It never grants a POST retry.
            pass
        return (await self.load(action.id)).state

    async def reject_not_sent(self, action: Action, *, reason: str | None = None) -> str:
        """Record only the typed adapter proof, with the original claim and lease.

        The fixed reason is also the durable feedback eligibility marker. Never
        infer it from exception text, a generic rejection or a missing receipt.
        """
        from jt_oz_bridge.services.dispatch_feedback import NOT_SENT

        try:
            async with self.db.sessions.begin() as session:
                await ConsumerFence(self.holder, self.fencing).lock(session)
                await session.execute(
                    update(Action)
                    .where(
                        Action.id == action.id,
                        Action.state == "dispatching",
                        Action.version == action.version + 1,
                        Action.operation_digest == action.operation_digest,
                        Action.upstream_id.is_(None),
                        self.lease(),
                    )
                    .values(
                        state="rejected",
                        status_reason=reason or NOT_SENT,
                        version=Action.version + 1,
                    )
                )
        except Conflict:
            pass  # A successor owns reconciliation; no Native retry is granted.
        return (await self.load(action.id)).state

    async def reconcile_uncertain_prompts(self, limit: int = 20) -> int:
        """Admit an uncertain prompt only by reading back the user message it became.

        A send that failed after it may have reached OpenCode is never retried,
        and it held every later prompt of its session forever, even when OpenCode
        had already answered it. Its own action/digest tag in the session, with
        the same text, is the admission it lost. Nothing found keeps it uncertain,
        unless OpenCode provably never received it: then it is refused as unsent.
        """
        from jt_oz_bridge.adapters.opencode.transport import TransportError

        readback = getattr(self.client, "prompt_readback", None)
        if not callable(readback):
            if "" not in self._uncertain_noted:
                self._uncertain_noted[""] = "unavailable"
                LOG.warning("uncertain_prompt_readback_unavailable")
            return 0
        cutoff = time.time() - UNCERTAIN_PROMPT_SETTLE_SECONDS
        async with self.db.sessions() as session:
            rows = (
                await session.execute(
                    select(Action, Binding)
                    .join(Binding, Binding.id == Action.binding_id)
                    .where(
                        Action.operation == "prompt",
                        Action.state == "ambiguous",
                        Action.upstream_id.is_(None),
                        Action.created_at < cutoff,
                        Binding.state == "active",
                        Binding.revision == Action.binding_revision,
                    )
                    .order_by(Action.created_at, Action.id)
                    .limit(limit)
                )
            ).all()
        admitted = 0
        for action, binding in rows:
            payload = action.payload
            selected = reference(binding)
            try:
                same_root = SessionRef.model_validate(payload.get("reference")) == selected
            except ValueError:
                same_root = False
            skipped = next(
                (
                    name
                    for name, failed in (
                        ("admission", bool(action.admission)),
                        ("digest", digest(payload) != action.operation_digest),
                        ("operation", payload.get("operation") != "prompt"),
                        ("files", "attachments" in payload or "workspace_attachments" in payload),
                        ("text", not isinstance(payload.get("text"), str)),
                        ("root", not same_root),
                    )
                    if failed
                ),
                None,
            )
            if skipped is not None:
                if action.id not in self._uncertain_noted and len(self._uncertain_noted) < 1024:
                    self._uncertain_noted[action.id] = skipped
                    LOG.warning("uncertain_prompt_left_for_review check=%s", skipped)
                continue
            try:
                message_id = await readback(
                    selected, action.id, action.operation_digest, payload["text"]
                )
                if message_id is None:
                    absent = getattr(self.client, "prompt_never_arrived", None)
                    if (
                        time.time() - action.created_at >= UNCERTAIN_PROMPT_ABSENT_SECONDS
                        and callable(absent)
                        and await absent(
                            selected, action.id, action.operation_digest, action.created_at
                        )
                        is True
                    ):
                        await self._settle_never_arrived(action)
                    continue
                receipt = ExecutionReceipt(
                    action_id=action.id,
                    operation_digest=action.operation_digest,
                    reference=selected,
                    contract_sha256=self.client.contract_for(selected),
                    admission=Admission(
                        status="admitted",
                        upstream_id=message_id,
                        details={
                            "operation": "prompt",
                            "delivery": "queue",
                            "turn_completed": False,
                        },
                    ),
                ).model_dump(mode="json")
                async with self.db.sessions.begin() as session:
                    await ConsumerFence(self.holder, self.fencing).lock(session)
                    result = await session.execute(
                        update(Action)
                        .where(
                            Action.id == action.id,
                            Action.state == "ambiguous",
                            Action.version == action.version,
                            Action.operation_digest == action.operation_digest,
                            Action.upstream_id.is_(None),
                        )
                        .values(
                            state="admitted",
                            owner="opencode",
                            upstream_id=message_id,
                            admission=receipt,
                            version=Action.version + 1,
                        )
                    )
                    if result.rowcount != 1:  # type: ignore[attr-defined]
                        continue
                    session.add(
                        AuditEvent(
                            actor="worker",
                            event="uncertain_prompt_read_back_admitted",
                            object_id=action.id,
                        )
                    )
            except (ContractError, Conflict, AccessDenied, TransportError, ValueError) as error:
                LOG.warning(
                    "uncertain_prompt_readback_refused kind=%s code=%s",
                    type(error).__name__,
                    error_code(error),
                )
                continue
            admitted += 1
            LOG.warning("uncertain_prompt_read_back_admitted")
        return admitted

    async def _settle_never_arrived(self, action: Action) -> None:
        """OpenCode provably never received it: refused as not sent, said once."""
        async with self.db.sessions.begin() as session:
            await ConsumerFence(self.holder, self.fencing).lock(session)
            result = await session.execute(
                update(Action)
                .where(
                    Action.id == action.id,
                    Action.state == "ambiguous",
                    Action.version == action.version,
                    Action.operation_digest == action.operation_digest,
                    Action.upstream_id.is_(None),
                )
                .values(
                    state="rejected",
                    status_reason=NEVER_ARRIVED,
                    version=Action.version + 1,
                )
            )
            if result.rowcount == 1:  # type: ignore[attr-defined]
                session.add(
                    AuditEvent(
                        actor="worker",
                        event="uncertain_prompt_never_arrived",
                        object_id=action.id,
                    )
                )
                LOG.warning("uncertain_prompt_never_arrived")

    async def requeue_unsent_steer(self, action: Action, *, reason: str = STEER_NOT_READY) -> str:
        """Undo only this claim after the adapter proved no steer (or prompt) was sent.

        The version and reason move on, so it never tries to join a busy session
        again: it waits for an idle session and gets its own turn, fully rechecked.
        """
        try:
            async with self.db.sessions.begin() as session:
                await ConsumerFence(self.holder, self.fencing).lock(session)
                await session.execute(
                    update(Action)
                    .where(
                        Action.id == action.id,
                        Action.state == "dispatching",
                        Action.version == action.version + 1,
                        Action.operation_digest == action.operation_digest,
                        Action.upstream_id.is_(None),
                        self.lease(),
                    )
                    .values(state="queued", version=Action.version + 1, status_reason=reason)
                )
        except Conflict:
            pass  # A successor owns reconciliation; no Native retry is granted.
        return (await self.load(action.id)).state

    async def revalidate_check_send(
        self, action: Action, binding: Binding, context: CheckDispatchPreflight
    ) -> None:
        # This callback runs after the Native adapter's final awaited identity
        # check. It grants no operation and is never serialized into payloads.
        context = CheckDispatchPreflight.model_validate(context.model_dump(mode="python"))
        selection = CheckSelection.model_validate(action.payload.get("selection"))
        if (
            context.action_id != action.id
            or context.operation_digest != action.operation_digest
            or context.reference != reference(binding)
            or context.binding_id != binding.id
            or context.binding_revision != binding.revision
            or action.payload.get("binding_id") != binding.id
            or action.payload.get("binding_revision") != binding.revision
            or context.contract_sha256 != self.client.contract_for(reference(binding))
            or context.qualification_sha256 != selection.qualification_sha256
        ):
            raise Conflict("check_final_original_dispatch_context_changed")
        await self.validate_control_source(action, binding)
        current = await self.bindings.get(
            binding.id, binding.realm_id, action.actor_id, Permission.OPERATE
        )
        if (
            current.revision != binding.revision
            or reference(current) != reference(binding)
            or current.dispatch_paused
        ):
            raise Conflict("check_final_binding_or_pause_changed")
        await self.validate_control_source(action, current)
        await self.validate_check_selection(action, current)
        clock = (
            (func.julianday("now") - 2440587.5) * 86400.0
            if self.db.engine.dialect.name == "sqlite"
            else func.extract("epoch", func.clock_timestamp())
        )
        async with self.db.sessions.begin() as session:
            await ConsumerFence(self.holder, self.fencing).lock(session)
            await lock_output_scope(self.bindings, session, current)
            saved = await session.scalar(
                select(Action).where(Action.id == action.id).with_for_update()
            )
            lease = await session.scalar(
                select(WorkerLease.role).where(
                    WorkerLease.role == "consumer",
                    WorkerLease.holder == self.holder,
                    WorkerLease.fencing == self.fencing,
                    WorkerLease.expires_at > clock,
                )
            )
            grant = await session.scalar(
                select(Grant.id)
                .where(
                    Grant.realm_id == current.realm_id,
                    Grant.project_id == current.project_id,
                    Grant.user_id == action.actor_id,
                    Grant.active.is_(True),
                    Grant.role.in_(
                        [
                            role
                            for role, permissions in ROLES.items()
                            if Permission.OPERATE in permissions
                        ]
                    ),
                )
                .with_for_update()
            )
            token = await session.scalar(
                select(ControlToken.token_hash).where(
                    ControlToken.token_hash == action.payload.get("selection_token_sha256"),
                    ControlToken.kind == "native-check-choice",
                    ControlToken.used.is_(True),
                    ControlToken.expires_at > clock,
                    ControlToken.expires_at == action.payload.get("choice_expires_at"),
                )
            )
            if (
                saved is None
                or saved.state != "dispatching"
                or saved.version != action.version + 1
                or saved.operation != "check.run"
                or saved.operation_digest != action.operation_digest
                or saved.payload != action.payload
                or saved.binding_revision != current.revision
                or lease is None
                or grant is None
                or token is None
            ):
                raise Conflict("check_final_local_authority_changed")
            await CheckDispatchRecords(
                self.bindings, ConsumerFence(self.holder, self.fencing)
            ).record_in_session(session, context, expected_action_version=action.version + 1)

    async def advance(self, action_id: str) -> str:
        action = await self.load(action_id)
        if action.operation in DEDICATED_OPERATIONS:
            return action.state
        if action.state != "queued":
            return action.state
        async with self.db.sessions() as session:
            stored_binding = await session.get(Binding, action.binding_id)
        if stored_binding is None:
            return await self.held(action, "binding_unavailable", rejected=True)
        if stored_binding.state != "active":
            return action.state  # Denial only: keep old queue/evidence byte-identical.
        lock_key = digest(reference(stored_binding).model_dump())
        lock = self._locks.setdefault(lock_key, asyncio.Lock())
        async with lock, AsyncExitStack() as processing:
            action = await self.load(action_id)
            if action.state != "queued":
                return action.state
            operation = action.payload.get("operation")
            if operation not in {
                "prompt",
                "permission.reply",
                "form.reply",
                "form.cancel",
                "interrupt",
                "model.switch",
                "session.rename",
                "check.run",
                GIT_PUBLISH,
                *LIFECYCLE_OPERATIONS,
            }:
                return await self.held(action, "operation_not_implemented")
            if action.operation != operation:
                return await self.held(action, "operation_index_changed")
            if operation in LIFECYCLE_OPERATIONS or operation == GIT_PUBLISH:
                # A confirmation answers one preview. It never waits to fire later.
                deadline = action.payload.get("confirm_expires_at")
                if not isinstance(deadline, int | float) or not time.time() < deadline:
                    return await self.held(
                        action,
                        "git_publish_confirmation_expired"
                        if operation == GIT_PUBLISH
                        else "lifecycle_confirmation_expired",
                        rejected=True,
                    )
            if await self.blocked_by_workspace(action.id):
                return action.state
            if await self.blocked_by_fifo(action.id):
                return action.state
            permission = (
                Permission.APPROVE if operation == "permission.reply" else Permission.OPERATE
            )
            phase = "binding"
            steer = False
            joinable: frozenset[str] = frozenset()
            try:
                binding = await self.bindings.get(
                    action.binding_id, stored_binding.realm_id, action.actor_id, permission
                )
                if binding.revision != action.binding_revision:
                    raise Conflict("binding revision changed")
                capability = self.client.capabilities(reference(binding)).get(operation)
                if operation in LIFECYCLE_OPERATIONS and (
                    not capability or not capability.supported
                ):
                    return await self.held(action, "lifecycle_not_available", rejected=True)
                if operation in LIFECYCLE_OPERATIONS and binding.dispatch_paused:
                    return await self.held(action, "lifecycle_queue_paused", rejected=True)
                if operation == GIT_PUBLISH and (not capability or not capability.supported):
                    return await self.held(action, "git_publish_not_available", rejected=True)
                if operation == GIT_PUBLISH and binding.dispatch_paused:
                    return await self.held(action, "git_publish_queue_paused", rejected=True)
                if (
                    capability is not None
                    and capability.reason == WATCH_PENDING
                    and time.time() - action.created_at < WATCH_GRACE_SECONDS
                ):
                    # Not watched yet, typically right after connecting: wait, don't hold.
                    return action.state
                if not capability or not capability.supported:
                    unavailable = await self.held(action, "installed_contract_not_certified")
                    await self.reopen_unadmitted_interaction(action, binding, known_unsent=True)
                    return unavailable
                if operation in {"prompt", "model.switch", "check.run"} and binding.dispatch_paused:
                    return await self.held(action, "queue_paused")
                from jt_oz_bridge.services.zulip_recovery_guards import verify_review

                phase = "recovery_review"
                recovery_witness = await verify_review(
                    self.bindings, self.reader, action, binding, self.holder, self.fencing
                )
                if self.processing is not None:
                    await processing.enter_async_context(self.processing(binding))
                if operation == "prompt":
                    original = action.payload["source"]
                    phase = "source"
                    latest = await self.reader.read(binding.realm_id, original["message_id"])
                    phase = "queue_refresh"
                    if "schedule" in action.payload:
                        # A timed send is not the source's own prompt; its schedule checks it.
                        if self.schedules is None:
                            return await self.held(action, "schedule_unavailable", rejected=True)
                        action = await self.schedules.refresh(action, binding, latest)
                    else:
                        receipt = await self.queue.receive(binding.id, latest)
                        action = await self.load(receipt.action_id)
                    if action.state != "queued":
                        return action.state
                    if action.payload.get("source") != latest.model_dump(mode="json"):
                        raise Conflict("source_message_revision_unverified")
                    if self.attachment_realm_url is not None and source_uploads(
                        latest, self.attachment_realm_url
                    ):
                        # A Root outside the explicit incoming scope behaves as if
                        # incoming were off: nothing is imported before the hold.
                        if self.attachment_imports is None or (
                            self.workspace_scope is not None
                            and not self.workspace_scope(reference(binding))
                        ):
                            # Refused, not held: a held message would block this topic's queue.
                            return await self.held(
                                action, "attachments_not_qualified", rejected=True
                            )
                        action = await self.attachment_imports.stage(action.id)
                    if "_workspace_attachment_import" in action.payload:
                        return await self.held(action, "workspace_attachment_import_pending")
                    if "workspace_attachments" in action.payload:
                        # Only trusted runtime composition can make the original
                        # backend provider available. The adapter rechecks its
                        # opaque prepared object immediately before the POST.
                        if self.workspace_ready is None or not self.workspace_ready(
                            reference(binding), self.client.contract_for(reference(binding))
                        ):
                            return await self.held(action, "workspace_attachments_not_qualified")
                    if "_attachment_import" in action.payload:
                        return await self.held(action, "attachment_import_pending")
                    # Decided on the refreshed queue row: imports or edits change it.
                    joinable = await self._joinable(action, binding)
                phase = "native_snapshot"
                try:
                    state = await self.client.snapshot(reference(binding))
                except SnapshotBoundaryChanged:
                    if not joinable:
                        raise
                    # A busy session moved between two reads: look again later.
                    return action.state
                phase = "final_identity"
                if state.reference != reference(binding) or not state.reconciled:
                    raise Conflict("execution owner unavailable")
                selected = SessionRef.model_validate(
                    action.payload.get("reference", reference(binding).model_dump())
                )
                if operation in {
                    "prompt",
                    "interrupt",
                    "model.switch",
                    "session.rename",
                    "check.run",
                    GIT_PUBLISH,
                    *LIFECYCLE_OPERATIONS,
                } and selected != reference(binding):
                    raise Conflict("operation target changed")
                if operation in {
                    "permission.reply",
                    "form.reply",
                    "form.cancel",
                } and selected not in (
                    reference(binding),
                    *state.descendants,
                ):
                    raise Conflict("interaction lineage changed")
                if (
                    selected.backend_id != binding.backend_id
                    or selected.backend_identity != binding.backend_identity
                    or selected.project_id != binding.project_id
                    or selected.canonical_directory != binding.canonical_directory
                    or digest(action.payload) != action.operation_digest
                ):
                    raise Conflict("operation identity or digest changed")
                if operation in TURNS and state.state != ExecutionState.IDLE:
                    if state.state not in joinable:
                        return "queued"
                    steer = True
                # Idle: the ordinary queued turn, after the previous one is collected.
                if operation in LIFECYCLE_OPERATIONS:
                    if state.state != ExecutionState.IDLE:
                        return await self.held(action, "lifecycle_session_busy", rejected=True)
                    await self.validate_lifecycle_sources(action, binding)
                if operation in {"permission.reply", "form.reply", "form.cancel"}:
                    await self.validate_interaction(action, binding)
                if operation == "check.run":
                    await self.validate_check_selection(action, binding)
                if operation == GIT_PUBLISH:
                    await self.validate_git_publish(action, binding)
                if operation == "model.switch":
                    await self.validate_model_selection(action, binding)
                if operation == "session.rename":
                    change = SessionRename.model_validate(action.payload.get("change"))
                    source = HumanMessage.model_validate(action.payload.get("source"))
                    if (
                        source.revision != 0
                        or parse_input(source.text, bound=True).arguments.strip()
                        != change.target_title
                        or state.title != change.previous_title
                    ):
                        raise Conflict("session_rename_original_title_or_source_changed")
                if operation != "prompt":
                    await self.validate_control_source(action, binding)
                phase = "recovery_final_review"
                recovery_witness = await verify_review(
                    self.bindings, self.reader, action, binding, self.holder, self.fencing
                )
                contract_at_dispatch = self.client.contract_for(selected)
            except AccessDenied as error:
                unregistered = str(error) == "original_session_not_registered"
                if unregistered and operation == "prompt" and self._retry_later(action.id):
                    # Nothing was sent; the Root may be restored in a moment.
                    LOG.warning("dispatch_preflight_retry phase=%s kind=AccessDenied", phase)
                    return action.state
                self._transient.pop(action.id, None)
                preflight_state = await self.held(
                    action,
                    SESSION_UNAVAILABLE
                    if unregistered and operation == "prompt"
                    else "authorization_revoked",
                    rejected=True,
                )
                await self.reopen_unadmitted_interaction(action, stored_binding, known_unsent=True)
                return preflight_state
            except (DeliveryRateLimited, ZulipReadUnavailable):
                # These typed failures occur before claim or any Native write.
                # They are scheduling/read availability, never evidence that
                # the Human Source changed. The runtime backs off and restarts
                # the entire authorization/source/Native preflight next time.
                raise
            except (Conflict, ValueError) as error:
                # Fixed phase/type labels and code-shaped refusal codes diagnose a
                # refusal without logging provider content, Source text or credentials.
                # OpenCode's own state read refusing a prompt says nothing about the
                # message: it is read again, like an unreachable OpenCode, not refused.
                unconfirmed = (
                    operation == "prompt"
                    and phase == "native_snapshot"
                    and isinstance(error, ContractError)
                    and not transient_preflight(error)
                )
                if (transient_preflight(error) or unconfirmed) and self._retry_later(action.id):
                    # OpenCode briefly unreachable or mid-update: nothing was sent
                    # and nothing is known to have changed, so try again shortly.
                    LOG.warning(
                        "dispatch_preflight_retry phase=%s kind=%s code=%s",
                        phase,
                        type(error).__name__,
                        error_code(error),
                    )
                    return action.state
                category = type(error).__name__
                if category not in {
                    "Conflict",
                    "ContractError",
                    "SnapshotBoundaryChanged",
                    "TransportError",
                    "ZulipError",
                    "ValidationError",
                    "ValueError",
                }:
                    category = "ValueError"
                LOG.warning(
                    "dispatch_preflight_held phase=%s kind=%s code=%s",
                    phase,
                    category,
                    error_code(error),
                )
                if operation == GIT_PUBLISH:
                    # A confirmation never waits to fire later; a held one would also
                    # stop every later prompt in this topic.
                    return await self.held(action, "git_publish_source_changed", rejected=True)
                self._transient.pop(action.id, None)
                # A prompt that cannot be sent as written is refused and the person
                # told once; held, it would stop every later message in this topic.
                preflight_state = await self.held(
                    action,
                    PREFLIGHT_UNAVAILABLE
                    if operation == "prompt" and transient_preflight(error)
                    else NATIVE_UNCONFIRMED
                    if unconfirmed
                    else "source_or_identity_changed",
                    rejected=operation == "prompt",
                )
                await self.reopen_unadmitted_interaction(action, stored_binding, known_unsent=True)
                return preflight_state
            if not await self.claim(
                action, binding, permission, recovery_witness=recovery_witness, steer=steer
            ):
                # Still waiting: a passing read between refusals must not restart the
                # window, or a refusal that keeps returning is retried forever.
                return (await self.load(action_id)).state
            self._transient.pop(action.id, None)
            try:
                if operation == "check.run":
                    submit_check = getattr(self.client, "submit_check", None)
                    if not callable(submit_check):
                        raise MutationNotSent("check_final_authority_not_supported")

                    async def authorize_check(context: CheckDispatchPreflight) -> None:
                        await self.revalidate_check_send(action, binding, context)

                    native_result = await submit_check(
                        selected, action.payload, action.id, authorize_check
                    )
                elif steer:
                    # Joins the busy session; the adapter refuses unsent if it cannot.
                    submit_steer: Any = self.client.submit
                    native_result = await submit_steer(
                        selected, action.payload, action.id, steer=True
                    )
                else:
                    native_result = await self.client.submit(selected, action.payload, action.id)
                self._unsent.pop(action.id, None)
                admitted = Admission.model_validate(native_result.model_dump(mode="python"))
                if steer:
                    LOG.warning("dispatch_steered")
                receipt_document = ExecutionReceipt(
                    action_id=action.id,
                    operation_digest=action.operation_digest,
                    reference=selected,
                    contract_sha256=contract_at_dispatch,
                    admission=admitted,
                ).model_dump(mode="json")
            except MutationRejected as error:
                if isinstance(error, SteerNotReady) and steer:
                    # Nothing was sent: keep its place for an ordinary turn later.
                    LOG.warning("dispatch_steer_deferred code=%s", error_code(error))
                    return await self.requeue_unsent_steer(action)
                if (
                    operation == "prompt"
                    and str(error) == SEND_PROOF_MOVED
                    and self._retry_later(action.id, self._unsent)
                ):
                    # Nothing was sent and nothing is known to have changed about the
                    # message: it goes again shortly, after the whole preflight.
                    LOG.warning("dispatch_send_retry operation=prompt code=%s", SEND_PROOF_MOVED)
                    return await self.requeue_unsent_steer(action, reason=SEND_RETRY)
                self._unsent.pop(action.id, None)
                if isinstance(error, MutationNotSent):
                    rejection_state = await self.reject_not_sent(action)
                    if rejection_state == "rejected":
                        await self.reopen_unadmitted_interaction(
                            action, binding, known_unsent=True, after_claim=True
                        )
                    return rejection_state
                if operation == "check.run":
                    return await self.check_transition(action, "rejected")
                if operation in LIFECYCLE_OPERATIONS:
                    # A verified refusal changed nothing, and the person was told it was sent.
                    return await self.reject_not_sent(action, reason="lifecycle_native_refused")
                await self.store.transition(
                    action.id, ActionState.DISPATCHING, ActionState.REJECTED, action.version + 1
                )
                if isinstance(error, AnswerRejected) and operation == "form.reply":
                    await self.reopen_rejected_form(action, binding)
                return "rejected"
            except asyncio.CancelledError:
                if operation == "check.run":
                    await asyncio.shield(self.check_transition(action, "ambiguous"))
                    raise
                await asyncio.shield(
                    self.store.transition(
                        action.id,
                        ActionState.DISPATCHING,
                        ActionState.AMBIGUOUS,
                        action.version + 1,
                    )
                )
                raise
            except Exception as error:
                # Code-shaped only: says why without provider content or Source text.
                LOG.warning(
                    "dispatch_outcome_uncertain operation=%s steer=%s kind=%s code=%s",
                    operation,
                    steer,
                    type(error).__name__,
                    error_code(error),
                )
                if operation == "check.run":
                    return await self.check_transition(action, "ambiguous")
                # Includes timeouts and malformed success receipts: no automatic retry.
                await self.store.transition(
                    action.id, ActionState.DISPATCHING, ActionState.AMBIGUOUS, action.version + 1
                )
                return "ambiguous"
            async with self.db.sessions.begin() as session:
                if operation == "check.run":
                    await ConsumerFence(self.holder, self.fencing).lock(session)
                result = await session.execute(
                    update(Action)
                    .where(
                        *([self.check_lease()] if operation == "check.run" else []),
                        Action.id == action.id,
                        Action.state == "dispatching",
                        Action.version == action.version + 1,
                    )
                    .values(
                        state="completed" if admitted.status == "completed" else "admitted",
                        owner=admitted.owner,
                        upstream_id=admitted.upstream_id,
                        admission=receipt_document,
                        version=Action.version + 2,
                    )
                )
                if result.rowcount != 1:  # type: ignore[attr-defined]
                    raise Conflict("admission state changed; reconcile")
                if (
                    operation in {"permission.reply", "form.reply", "form.cancel"}
                    and admitted.status == "completed"
                ):
                    await session.execute(
                        update(PendingInteraction)
                        .where(PendingInteraction.action_id == action.id)
                        .values(state="resolved", version=PendingInteraction.version + 1)
                    )
            return "completed" if admitted.status == "completed" else "admitted"
