"""Sealed own transcript observations and scan state, never native positions."""

from collections.abc import Set
from typing import Any, Literal, Self

from pydantic import Field, StrictInt, model_serializer, model_validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from jt_oz_bridge.adapters.opencode.transcript import NativeTranscriptPage, TranscriptEntry
from jt_oz_bridge.domain.control import ControlModel, ExecutionState
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import DeliveryBatch
from jt_oz_bridge.storage.transcript_models import (
    TranscriptMessage,
    TranscriptPublication,
    TranscriptStream,
    TranscriptVersion,
)


def scope_key(binding: Binding) -> str:
    return digest(
        {
            "binding": binding.id,
            "revision": binding.revision,
            "realm": binding.realm_id,
            "channel": binding.channel_id,
            "topic": binding.topic,
            "reference": reference(binding).model_dump(),
        }
    )


class TranscriptObservation(ControlModel):
    reference: SessionRef
    contract_sha256: str
    semantics_sha256: str
    installed_evidence_sha256: str
    owner_epoch: str
    connection_epoch: str
    resource_fence: str
    observed_at: float
    expires_at: float
    entry: TranscriptEntry
    page_hashes: tuple[str, ...] = Field(max_length=20)
    entry_index: StrictInt = Field(ge=0, le=19)
    state: ExecutionState = ExecutionState.UNKNOWN

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if (
            not self.observed_at < self.expires_at
            or self.entry_index >= len(self.page_hashes)
            or self.page_hashes[self.entry_index] != self.entry.projection_sha256
        ):
            raise ValueError("transcript_observation_page_changed")
        return self

    @classmethod
    def capture(cls, page: NativeTranscriptPage, index: int) -> Self:
        return cls(
            reference=page.reference,
            contract_sha256=page.contract_sha256,
            semantics_sha256=page.semantics_sha256,
            installed_evidence_sha256=page.installed_evidence_sha256,
            owner_epoch=page.owner_epoch,
            connection_epoch=page.connection_epoch,
            resource_fence=page.resource_fence,
            observed_at=page.observed_at,
            expires_at=page.expires_at,
            entry=page.entries[index],
            page_hashes=tuple(e.projection_sha256 for e in page.entries),
            entry_index=index,
            state=page.state,
        )


class TranscriptScan(ControlModel):
    id: str
    cursor: str | None = None
    head_id: str | None = None
    anchor: str | None
    remaining_open: tuple[str, ...] = ()
    found_anchor: bool = False
    offset: StrictInt = Field(default=0, ge=0, le=10000)
    total_bytes: StrictInt = Field(default=0, ge=0, le=16 * 1024 * 1024)
    cursor_hashes: tuple[str, ...] = Field(default=(), max_length=10000)
    recovering: bool = False


MAX_OWNER_TRANSITIONS = 32


class TranscriptOwnerTransition(ControlModel):
    """A scoped bridge transition, not a replacement Native identity.

    A ``confirmed`` transition names the person and `!ok` message that approved
    it. An ``automatic`` one was proven by Bridge alone after a Native restart
    (same session, directory, contract, semantics and installed evidence), so
    it names no person: actor and source message are 0 and the source hash
    seals the automatic proof. Confirmed records keep their original bytes and
    checksum because the default kind is never serialized.
    """

    kind: Literal["confirmed", "automatic"] = "confirmed"
    id: str = Field(min_length=1, max_length=64)
    scope_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    generation: StrictInt = Field(ge=1, le=MAX_OWNER_TRANSITIONS)
    old_owner: str = Field(pattern=r"^[0-9a-f]{64}$")
    new_owner: str = Field(pattern=r"^[0-9a-f]{64}$")
    previous_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    previous_stream_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    actor_id: StrictInt = Field(ge=0)
    source_message_id: StrictInt = Field(ge=0)
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    proof_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    # Preserve notices already queued before the transition, byte for byte.
    previous_gap_plan: dict[str, Any] | None = None
    checksum: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_serializer(mode="wrap")
    def serialize_transition(self, handler: Any) -> dict[str, Any]:
        value: dict[str, Any] = handler(self)
        if self.kind == "confirmed":
            value.pop("kind", None)
        return value

    def facts(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"checksum"})

    @model_validator(mode="after")
    def sealed(self) -> Self:
        named = self.actor_id > 0 and self.source_message_id > 0
        unnamed = self.actor_id == 0 and self.source_message_id == 0
        if (
            self.old_owner == self.new_owner
            or not (named if self.kind == "confirmed" else unnamed)
            or digest(self.facts()) != self.checksum
        ):
            raise ValueError("transcript_owner_transition_seal_changed")
        return self


class TranscriptState(ControlModel):
    format: Literal["native-transcript-stream-v1", "native-transcript-stream-v2"] = (
        "native-transcript-stream-v1"
    )
    owner_transitions: tuple[TranscriptOwnerTransition, ...] = Field(
        default=(), max_length=MAX_OWNER_TRANSITIONS
    )
    key: str
    revision: StrictInt = Field(default=1, ge=1)
    binding_id: str
    binding_revision: int
    realm_id: str
    channel_id: int
    topic: str
    reference: SessionRef
    contract_sha256: str
    semantics_sha256: str
    owner_epoch: str
    connection_epoch: str
    anchor: str | None = None
    open_ids: tuple[str, ...] = Field(default=(), max_length=10000)
    last_input_action_id: str | None = None
    status: Literal["live", "scanning", "gap"] = "live"
    scan: TranscriptScan | None = None
    bootstrap_versions: tuple[str, ...] = Field(default=(), max_length=20)
    bootstrap_plan: dict[str, Any] | None = None
    last_batch_id: str | None = None
    gap_reason: str | None = None
    gap_plan: dict[str, Any] | None = None
    # The topic's queue revision when this gap paused it; None when the topic
    # was already paused. Only an unchanged revision lets a reconnect lift the
    # pause, so a person's `!stop` during the gap always stays.
    gap_resume_revision: StrictInt | None = Field(default=None, ge=0)
    native_state: ExecutionState = ExecutionState.UNKNOWN
    latest_idle_ordinal: StrictInt = Field(default=0, ge=0)

    @model_serializer(mode="wrap")
    def serialize_stream(self, handler: Any) -> dict[str, Any]:
        value: dict[str, Any] = handler(self)
        if self.format == "native-transcript-stream-v1":
            value.pop("owner_transitions", None)
        if self.gap_resume_revision is None:
            # Streams that never recorded it keep their exact original bytes.
            value.pop("gap_resume_revision", None)
        return value

    @model_validator(mode="after")
    def owner_chain(self) -> Self:
        if (self.format == "native-transcript-stream-v2") != bool(self.owner_transitions):
            raise ValueError("transcript_owner_chain_format_changed")
        previous = "0" * 64
        owner = self.owner_transitions[0].old_owner if self.owner_transitions else self.owner_epoch
        owners = {owner}
        identities = set()
        for generation, transition in enumerate(self.owner_transitions, 1):
            if (
                transition.scope_key != self.key
                or transition.generation != generation
                or transition.previous_hash != previous
                or transition.old_owner != owner
                or transition.new_owner in owners
                or transition.id in identities
            ):
                raise ValueError("transcript_owner_chain_changed")
            owners.add(transition.new_owner)
            identities.add(transition.id)
            previous, owner = transition.checksum, transition.new_owner
        if owner != self.owner_epoch:
            raise ValueError("transcript_owner_chain_head_changed")
        return self

    def owner_for(self, generation: int) -> str:
        if not 0 <= generation <= len(self.owner_transitions):
            raise Conflict("transcript_snapshot_generation_unavailable")
        if generation == 0:
            return (
                self.owner_transitions[0].old_owner if self.owner_transitions else self.owner_epoch
            )
        return self.owner_transitions[generation - 1].new_owner

    def gap_source(self, generation: int | None = None) -> str:
        selected = len(self.owner_transitions) if generation is None else generation
        return (
            self.key + ":gap" + (":" + self.owner_transitions[selected - 1].id if selected else "")
        )

    def notice_plans(self) -> list[tuple[dict[str, Any], str]]:
        result = []
        if self.bootstrap_plan is not None:
            result.append((self.bootstrap_plan, self.key + ":bootstrap"))
        for generation, transition in enumerate(self.owner_transitions):
            if transition.previous_gap_plan is not None:
                result.append((transition.previous_gap_plan, self.gap_source(generation)))
        if self.gap_plan is not None:
            result.append((self.gap_plan, self.gap_source()))
        return result


def read_stream(row: TranscriptStream, binding: Binding) -> TranscriptState:
    if digest(row.payload) != row.payload_hash:
        raise Conflict("transcript_stream_seal_changed")
    state = TranscriptState.model_validate(row.payload)
    if (
        state.key,
        state.binding_id,
        state.binding_revision,
        state.realm_id,
        state.channel_id,
        state.topic,
        state.reference,
    ) != (
        scope_key(binding),
        binding.id,
        binding.revision,
        binding.realm_id,
        binding.channel_id,
        binding.topic,
        reference(binding),
    ) or (row.key, row.binding_id, row.binding_revision) != (
        state.key,
        state.binding_id,
        state.binding_revision,
    ):
        raise Conflict("transcript_stream_scope_changed")
    if (state.status == "scanning") != (state.scan is not None):
        raise Conflict("transcript_scan_state_changed")
    if (state.status == "gap") != (state.gap_reason is not None):
        raise Conflict("transcript_gap_state_changed")
    return state


def write_stream(row: TranscriptStream, state: TranscriptState) -> TranscriptState:
    state = state.model_copy(update={"revision": state.revision + 1})
    row.payload = state.model_dump(mode="json")
    row.payload_hash = digest(row.payload)
    return state


class TranscriptSnapshot(ControlModel):
    format: Literal["native-transcript-snapshot-v1", "native-transcript-snapshot-v2"] = (
        "native-transcript-snapshot-v1"
    )
    owner_generation: StrictInt | None = Field(default=None, ge=1, le=MAX_OWNER_TRANSITIONS)
    id: str
    record_id: str
    scope_key: str
    own_ordinal: StrictInt = Field(ge=1)
    version: StrictInt = Field(ge=1)
    observation: TranscriptObservation
    historical: bool
    recovering: bool
    source_action_id: str | None = None
    context_action_id: str | None = None

    @model_serializer(mode="wrap")
    def serialize_snapshot(self, handler: Any) -> dict[str, Any]:
        value: dict[str, Any] = handler(self)
        if self.format == "native-transcript-snapshot-v1":
            value.pop("owner_generation", None)
        return value

    @model_validator(mode="after")
    def generation_format(self) -> Self:
        if (self.format == "native-transcript-snapshot-v2") != (self.owner_generation is not None):
            raise ValueError("transcript_snapshot_generation_format_changed")
        return self


def read_snapshot(
    row: TranscriptVersion, record: TranscriptMessage, state: TranscriptState
) -> TranscriptSnapshot:
    if digest(row.payload) != row.payload_hash:
        raise Conflict("transcript_snapshot_seal_changed")
    value = TranscriptSnapshot.model_validate(row.payload)
    observation = value.observation
    if (
        (
            value.id,
            value.record_id,
            value.scope_key,
            value.own_ordinal,
            value.version,
            observation.entry.native_id,
            observation.reference,
            observation.contract_sha256,
            observation.semantics_sha256,
            observation.owner_epoch,
        )
        != (
            row.id,
            record.id,
            state.key,
            record.ordinal,
            row.version,
            record.native_id,
            state.reference,
            state.contract_sha256,
            state.semantics_sha256,
            state.owner_for(value.owner_generation or 0),
        )
        or not 1 <= row.version <= record.current_version
        or (row.version == record.current_version and record.current_hash != row.payload_hash)
        or (row.source_action_id, row.context_action_id)
        != (value.source_action_id, value.context_action_id)
        or row.record_id != record.id
        or record.scope_key != state.key
    ):
        raise Conflict("transcript_snapshot_scope_changed")
    return value


def incomplete(entry: TranscriptEntry) -> bool:
    value = entry.projection()
    return (
        entry.kind == "assistant"
        and "completed" not in value["time"]
        or entry.kind in {"shell", "compaction"}
        and value.get("status") == "running"
    )


type PublicationMode = Literal[
    "bootstrap",
    "gap",
    "queued",
    "historical",
    "echo",
    "empty",
    "superseded",
    "needs_full_output",
    "draft_owned",
    # An edit that adds a tool step to its turn's progress message.
    "progress",
]


class TranscriptPublicationPlan(ControlModel):
    format: Literal["native-transcript-publication-v1"] = "native-transcript-publication-v1"
    scope_key: str
    binding_id: str
    binding_revision: int
    realm_id: str
    channel_id: int
    topic: str
    reference: SessionRef
    source_id: str
    source_hash: str
    mode: PublicationMode
    batch_id: str | None = None
    after_batch_id: str | None = None
    plan_hash: str | None = None
    renderer: str
    bot_user_id: int
    locale: Literal["en", "zh-TW"]
    message_limit: int
    topic_limit: int


async def validate_transcript_batch(
    session: AsyncSession,
    batch_id: str,
    binding: Binding,
    bot_user_id: int,
    before_batch_id: str | None,
) -> None:
    """Verify archived projection evidence on every generic outbox/delivery path."""
    from sqlalchemy import select

    batch = await session.get(DeliveryBatch, batch_id)
    publication = await session.scalar(
        select(TranscriptPublication).where(TranscriptPublication.batch_id == batch_id)
    )
    if batch is None or (
        batch.renderer_version != "native-transcript-output-v2" and publication is None
    ):
        return
    stream = await session.get(TranscriptStream, scope_key(binding))
    if stream is None:
        raise Conflict("transcript_batch_stream_missing")
    state = read_stream(stream, binding)
    if publication is not None:
        if digest(publication.payload) != publication.payload_hash:
            raise Conflict("transcript_batch_publication_seal_changed")
        plan = TranscriptPublicationPlan.model_validate(publication.payload)
        version = await session.get(TranscriptVersion, publication.version_id)
        record = await session.get(TranscriptMessage, version.record_id) if version else None
        if version is None or record is None:
            raise Conflict("transcript_batch_version_missing")
        read_snapshot(version, record, state)
        if (plan.source_id, plan.source_hash) != (version.id, version.payload_hash):
            raise Conflict("transcript_batch_source_changed")
    else:
        matches = [
            (TranscriptPublicationPlan.model_validate(value), source_id)
            for value, source_id in state.notice_plans()
            if value.get("batch_id") == batch_id
        ]
        if len(matches) != 1:
            raise Conflict("transcript_batch_notice_missing")
        plan, expected_source = matches[0]
        if plan.source_id != expected_source or plan.mode not in {"bootstrap", "gap"}:
            raise Conflict("transcript_batch_notice_source_changed")
    if (
        plan.scope_key,
        plan.binding_id,
        plan.binding_revision,
        plan.realm_id,
        plan.channel_id,
        plan.topic,
        plan.reference,
        plan.bot_user_id,
        plan.batch_id,
        plan.after_batch_id,
        plan.plan_hash,
        plan.renderer,
        plan.message_limit,
        plan.topic_limit,
    ) != (
        state.key,
        binding.id,
        binding.revision,
        binding.realm_id,
        binding.channel_id,
        binding.topic,
        reference(binding),
        bot_user_id,
        batch.id,
        before_batch_id,
        batch.plan_hash,
        batch.renderer_version,
        batch.message_limit,
        batch.topic_limit,
    ):
        raise Conflict("transcript_batch_scope_changed")


def mirrored_bindings(references: Set[SessionRef]) -> ColumnElement[bool]:
    """Exact root scopes whose output is owned by the transcript publisher."""
    from sqlalchemy import and_, or_, select

    return or_(
        select(TranscriptStream.key)
        .where(
            TranscriptStream.binding_id == Binding.id,
            TranscriptStream.binding_revision == Binding.revision,
        )
        .exists(),
        *(
            and_(
                Binding.backend_id == ref.backend_id,
                Binding.backend_identity == ref.backend_identity,
                Binding.project_id == ref.project_id,
                Binding.canonical_directory == ref.canonical_directory,
                Binding.session_id == ref.upstream_session_id,
            )
            for ref in references
        ),
    )


async def refuse_transcript_output(session: AsyncSession, binding: Binding) -> None:
    if await session.get(TranscriptStream, scope_key(binding)) is not None:
        raise Conflict("output_owned_by_native_transcript")
