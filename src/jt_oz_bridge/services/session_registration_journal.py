"""Fenced ownDB identity journal, never a Native send or a replay instruction.

A prepared row survives a crash before/after in-memory registration. Recovery
must GET and prove the same original graph again through the existing-session
factory. Neither an active row nor its historic owner supplies live authority.
The controller supplies current Source/audience checks and locked SQL grants.
"""

import hashlib
import json
import math
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.session_adoption import (
    LEGACY_RECORD_FORMAT,
    RECORD_FORMAT,
    OriginalSessionNode,
    SessionAdoptionRecord,
    same_original_graph,
)
from jt_oz_bridge.domain.session_graph_extension import require_original_extension
from jt_oz_bridge.storage.cipher_types import checked_json
from jt_oz_bridge.storage.control_models import EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.session_registration_models import (
    REGISTRATION_SEAL_FIELDS,
    SessionRegistration,
    SessionRegistrationExtension,
    registration_history_seal,
)

LockedAuthority = Callable[[AsyncSession], Awaitable[None]]
CurrentProof = Callable[[], bool]
MAX_REGISTRATIONS = 1000
MAX_EXTENSIONS = 999


def registration_key(realm_id: str, root: SessionRef) -> str:
    if not realm_id or len(realm_id) > 255:
        raise ValueError("registration_realm_required")
    return digest({"realm_id": realm_id, "root": root.model_dump(mode="json")})


def registration_identity(record: SessionAdoptionRecord) -> str:
    value = record.model_dump(mode="json", exclude={"observed_at", "observed_owner_epoch"})
    value["nodes"] = sorted(
        value["nodes"], key=lambda node: node["reference"]["upstream_session_id"]
    )
    return digest(value)


@dataclass(frozen=True)
class RegistrationReceipt:
    key: str
    realm_id: str
    project_id: str
    identity_hash: str
    payload_hash: str
    revision: int
    prepared_holder: str
    prepared_fencing: int


@dataclass(frozen=True)
class SavedSessionRegistration:
    receipt: RegistrationReceipt
    record: SessionAdoptionRecord
    state: str
    extension_count: int = 0
    extension_tip_hash: str | None = None


@dataclass(frozen=True)
class SavedGraphExtension:
    """Reconstructed historical records, never current resource qualification."""

    sequence: int
    predecessor: SavedSessionRegistration
    successor: SavedSessionRegistration
    added_nodes: tuple[OriginalSessionNode, ...]


def decode_registration(row: SessionRegistration) -> SavedSessionRegistration:
    """Validate encrypted payload against every persisted identity projection."""
    try:
        record = SessionAdoptionRecord.model_validate(row.payload)
        if (
            row.history_seal
            != registration_history_seal(
                {field: getattr(row, field) for field in REGISTRATION_SEAL_FIELDS}
            )
            or row.key != registration_key(row.realm_id, record.root)
            or row.project_id != record.root.project_id
            or row.payload_hash != digest(row.payload)
            or row.identity_hash != registration_identity(record)
            or row.state not in {"prepared", "active"}
            or type(row.revision) is not int
            or row.revision < 1
            or not row.prepared_holder
            or len(row.prepared_holder) > 255
            or type(row.prepared_fencing) is not int
            or row.prepared_fencing < 1
            or row.activated_fencing != (row.prepared_fencing if row.state == "active" else None)
            or not math.isfinite(row.created_at)
            or not math.isfinite(row.updated_at)
            or row.created_at < 0
            or row.updated_at < row.created_at
            or type(row.extension_count) is not int
            or not 0 <= row.extension_count <= min(MAX_EXTENSIONS, len(record.nodes) - 1)
            or (
                row.extension_tip_hash is not None
                if row.extension_count == 0
                else (
                    not isinstance(row.extension_tip_hash, str)
                    or re.fullmatch(r"[0-9a-f]{64}", row.extension_tip_hash) is None
                )
            )
        ):
            raise ValueError("registration projection mismatch")
    except (ValueError, TypeError):
        raise Conflict("original_session_registration_invalid") from None
    return SavedSessionRegistration(
        RegistrationReceipt(
            row.key,
            row.realm_id,
            row.project_id,
            row.identity_hash,
            row.payload_hash,
            row.revision,
            row.prepared_holder,
            row.prepared_fencing,
        ),
        record,
        row.state,
        row.extension_count,
        row.extension_tip_hash,
    )


def _saved(
    receipt: RegistrationReceipt,
    record: SessionAdoptionRecord,
    state: str,
    *,
    extension_count: int = 0,
    extension_tip_hash: str | None = None,
) -> SavedSessionRegistration:
    """Use the head decoder for receipts reconstructed from encrypted deltas."""
    value = SessionRegistration(
        **asdict(receipt),
        payload=record.model_dump(mode="json"),
        state=state,
        activated_fencing=receipt.prepared_fencing if state == "active" else None,
        created_at=0,
        updated_at=0,
        extension_count=extension_count,
        extension_tip_hash=extension_tip_hash,
    )
    _reseal(value)
    validated = decode_registration(value)
    # Callers supply freshly revalidated input snapshots. Keep those frozen
    # nodes shared across historical records,
    # rather than retaining another full set for every reconstructed generation.
    return SavedSessionRegistration(
        validated.receipt,
        record,
        validated.state,
        validated.extension_count,
        validated.extension_tip_hash,
    )


def _reseal(row: SessionRegistration) -> None:
    row.history_seal = registration_history_seal(
        {field: getattr(row, field) for field in REGISTRATION_SEAL_FIELDS}
    )


def _order(record: SessionAdoptionRecord) -> list[int]:
    indexes = {
        node.reference: i
        for i, node in enumerate(
            sorted(record.nodes, key=lambda n: n.reference.upstream_session_id)
        )
    }
    return [indexes[node.reference] for node in record.nodes]


def _extension_delta(
    previous: SavedSessionRegistration,
    new: SessionAdoptionRecord,
    receipt: RegistrationReceipt,
    additions: tuple[OriginalSessionNode, ...],
    sequence: int,
) -> dict[str, Any]:
    return {
        "format": "original-session-extension-delta-v1",
        "sequence": sequence,
        "previous_header": previous.record.model_dump(mode="json", exclude={"nodes"}),
        "previous_order": _order(previous.record),
        "previous_receipt": asdict(previous.receipt),
        "previous_state": previous.state,
        "previous_extension_count": previous.extension_count,
        "previous_extension_tip_hash": previous.extension_tip_hash,
        "next_header": new.model_dump(mode="json", exclude={"nodes"}),
        "next_order": _order(new),
        "next_receipt": asdict(receipt),
        "added_nodes": [node.model_dump(mode="json") for node in additions],
    }


def _wire(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def _record_hash(header: dict[str, Any], nodes: bytes, *, identity: bool = False) -> str:
    fields = {
        key: _wire(value)
        for key, value in header.items()
        if not identity or key not in {"observed_at", "observed_owner_epoch"}
    }
    fields["nodes"] = nodes
    return hashlib.sha256(
        b"{" + b",".join(_wire(key) + b":" + fields[key] for key in sorted(fields)) + b"}"
    ).hexdigest()


def _scan_history(
    rows: tuple[SessionRegistrationExtension, ...],
    head: SavedSessionRegistration,
    *,
    materialize: bool,
) -> tuple[SavedGraphExtension, ...]:
    """Validate every delta/hash with one node encoding, without repeated full DTOs.

    The current head has already passed the complete graph DTO validator. Old
    generations may only remove exactly their authenticated additions. Closure,
    header schema, order, graph/identity/payload hashes and receipt projections
    are checked at each step; no earlier verification or connection is cached.
    """
    try:
        if (
            len(rows) != head.extension_count
            or len(rows) > MAX_EXTENSIONS
            or len(rows) >= len(head.record.nodes)
        ):
            raise ValueError("extension_history_capacity")
        if [row.sequence for row in rows] != list(range(1, len(rows) + 1)):
            raise ValueError("extension_history_sequence")
        # Resolve full references once for this scan. Every generation still
        # verifies all original bytes/hashes below; integer ranks only avoid
        # rehashing the same Pydantic references for each historical node.
        nodes = tuple(
            sorted(head.record.nodes, key=lambda node: node.reference.upstream_session_id)
        )
        reference_ranks = {node.reference: rank for rank, node in enumerate(nodes)}
        ranked = list(range(len(nodes)))
        wire_nodes = tuple(_wire(node.model_dump(mode="json")) for node in nodes)
        origins = tuple(
            {
                "reference": node.reference.model_dump(mode="json"),
                "native_project_id": head.record.native_project_id,
                "created_at": node.native_created_at,
                "parent_id": node.parent_reference.upstream_session_id
                if node.parent_reference
                else None,
            }
            for node in nodes
        )
        facts = []
        children: list[set[int]] = [set() for _ in nodes]
        for rank, node in enumerate(nodes):
            origin = dict(origins[rank])
            if node.parent_reference is not None:
                parent_rank = reference_ranks[node.parent_reference]
                origin.update(
                    parent_origin_sha256=digest(origins[parent_rank]),
                    parent_created_at=node.parent_created_at,
                )
                children[parent_rank].add(rank)
            facts.append(
                _wire(
                    {
                        "reference": node.reference.model_dump(mode="json"),
                        "origin_sha256": digest(origin),
                        "policy_sha256": node.policy_sha256,
                    }
                )
            )
        root_rank = reference_ranks[head.record.root]
        root = nodes[root_rank]
        singleton_sha = hashlib.sha256(b'{"nodes":[' + facts[root_rank] + b"]}").hexdigest()
        fixed = head.record.model_dump(mode="json", exclude={"nodes"})
        constants = (
            "format",
            "root",
            "native_project_id",
            "contract_sha256",
            "qualification_sha256",
            "starts_execution",
            "creates_binding",
        )

        def header(raw: Any) -> dict[str, Any]:
            if (
                not isinstance(raw, dict)
                or set(raw) != set(fixed)
                or any(raw[key] != fixed[key] for key in constants)
            ):
                raise ValueError("extension_history_header_scope")
            sha = raw["graph_sha256"]
            if not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{64}", sha) is None:
                raise ValueError("extension_history_graph_hash")
            # Validate every field/unknown key against the original DTO schema,
            # using an independently valid singleton solely for header parsing.
            parsed = SessionAdoptionRecord.model_validate(
                {**raw, "graph_sha256": singleton_sha, "nodes": (root,)}
            )
            return parsed.model_dump(mode="json", exclude={"nodes"}) | {"graph_sha256": sha}

        def ordered(raw: Any, refs: list[int]) -> tuple[int, ...]:
            if (
                not isinstance(raw, list)
                or len(raw) != len(refs)
                or any(type(i) is not int for i in raw)
                or sorted(raw) != list(range(len(refs)))
            ):
                raise ValueError("extension_history_order")
            return tuple(refs[index] for index in raw)

        def receipt(raw: Any) -> RegistrationReceipt:
            value = RegistrationReceipt(**raw)
            if (
                value.key != head.receipt.key
                or value.realm_id != head.receipt.realm_id
                or value.project_id != head.receipt.project_id
                or type(value.revision) is not int
                or value.revision < 1
                or type(value.prepared_fencing) is not int
                or value.prepared_fencing < 1
                or not isinstance(value.prepared_holder, str)
                or not 1 <= len(value.prepared_holder) <= 255
                or any(
                    not isinstance(v, str) or re.fullmatch(r"[0-9a-f]{64}", v) is None
                    for v in (value.identity_hash, value.payload_hash)
                )
            ):
                raise ValueError("extension_history_receipt")
            return value

        def node_array(refs: tuple[int, ...] | list[int]) -> bytes:
            return b"[" + b",".join(wire_nodes[ref] for ref in refs) + b"]"

        def saved(
            value: RegistrationReceipt,
            parsed: dict[str, Any],
            refs: tuple[int, ...],
            state: str,
            count: int,
            tip: str | None,
        ) -> SavedSessionRegistration:
            # Every constituent and complete hash was verified above; keep the
            # immutable node instances shared when history is requested.
            record = SessionAdoptionRecord.model_construct(
                **(parsed | {"root": head.record.root, "nodes": tuple(nodes[ref] for ref in refs)})
            )
            return SavedSessionRegistration(value, record, state, count, tip)

        cursor_receipt, cursor_count, cursor_tip = (
            head.receipt,
            head.extension_count,
            head.extension_tip_hash,
        )
        cursor_graph = head.record.graph_sha256
        result = []
        expected_fields = {
            "format",
            "sequence",
            "previous_header",
            "previous_order",
            "previous_receipt",
            "previous_state",
            "previous_extension_count",
            "previous_extension_tip_hash",
            "next_header",
            "next_order",
            "next_receipt",
            "added_nodes",
        }
        for row in reversed(rows):
            delta = row.delta
            if (
                not isinstance(delta, dict)
                or set(delta) != expected_fields
                or delta["format"] != "original-session-extension-delta-v1"
                or type(delta["sequence"]) is not int
                or delta["sequence"] != row.sequence
                or digest(delta) != row.delta_hash
                or not math.isfinite(row.created_at)
                or row.created_at < 0
                or not isinstance(delta["added_nodes"], list)
            ):
                raise ValueError("extension_history_delta")
            next_header = header(delta["next_header"])
            next_order = ordered(delta["next_order"], ranked)
            next_receipt = receipt(delta["next_receipt"])
            if (
                cursor_count != row.sequence
                or cursor_tip != row.delta_hash
                or cursor_receipt.identity_hash != next_receipt.identity_hash
                or cursor_receipt.revision < next_receipt.revision
                or cursor_receipt.revision == next_receipt.revision
                and cursor_receipt != next_receipt
                or next_header["graph_sha256"] != cursor_graph
                or next_receipt.payload_hash != _record_hash(next_header, node_array(next_order))
            ):
                raise ValueError("extension_history_successor")
            additions = tuple(
                OriginalSessionNode.model_validate(value) for value in delta["added_nodes"]
            )
            added_ranks = tuple(reference_ranks[node.reference] for node in additions)
            added_ids = set(added_ranks)
            if (
                not additions
                or len(added_ids) != len(additions)
                or root_rank in added_ids
                or any(
                    nodes[rank] != node for rank, node in zip(added_ranks, additions, strict=True)
                )
                or not added_ids <= set(ranked)
                or added_ranks != tuple(rank for rank in next_order if rank in added_ids)
            ):
                raise ValueError("extension_history_additions")
            old_ranked = [rank for rank in ranked if rank not in added_ids]
            remaining = set(old_ranked)
            if any(children[rank] & remaining for rank in added_ids):
                raise ValueError("extension_history_disconnected_predecessor")
            previous_header = header(delta["previous_header"])
            previous_order = ordered(delta["previous_order"], old_ranked)
            previous_receipt = receipt(delta["previous_receipt"])
            previous_graph = hashlib.sha256(
                b'{"nodes":[' + b",".join(facts[ref] for ref in old_ranked) + b"]}"
            ).hexdigest()
            previous_count, previous_tip, previous_state = (
                delta["previous_extension_count"],
                delta["previous_extension_tip_hash"],
                delta["previous_state"],
            )
            if (
                type(previous_count) is not int
                or previous_count != row.sequence - 1
                or (
                    previous_tip is not None
                    if previous_count == 0
                    else not isinstance(previous_tip, str)
                    or re.fullmatch(r"[0-9a-f]{64}", previous_tip) is None
                )
                or previous_state not in {"prepared", "active"}
                or previous_header["graph_sha256"] != previous_graph
                or previous_receipt.identity_hash
                != _record_hash(previous_header, node_array(old_ranked), identity=True)
                or previous_receipt.payload_hash
                != _record_hash(previous_header, node_array(previous_order))
                or row.registration_key != head.receipt.key
                or row.predecessor_revision != previous_receipt.revision
                or row.successor_revision != next_receipt.revision
                or next_receipt.revision != previous_receipt.revision + 1
                or row.predecessor_identity_hash != previous_receipt.identity_hash
                or row.successor_identity_hash != next_receipt.identity_hash
                or row.predecessor_payload_hash != previous_receipt.payload_hash
                or row.successor_payload_hash != next_receipt.payload_hash
                or type(row.added_count) is not int
                or row.added_count != len(additions)
            ):
                raise ValueError("extension_history_predecessor")
            if materialize:
                result.append(
                    SavedGraphExtension(
                        row.sequence,
                        saved(
                            previous_receipt,
                            previous_header,
                            previous_order,
                            previous_state,
                            previous_count,
                            previous_tip,
                        ),
                        saved(
                            next_receipt,
                            next_header,
                            next_order,
                            "prepared",
                            row.sequence,
                            row.delta_hash,
                        ),
                        additions,
                    )
                )
            ranked = old_ranked
            cursor_receipt, cursor_count, cursor_tip, cursor_graph = (
                previous_receipt,
                previous_count,
                previous_tip,
                previous_graph,
            )
        return tuple(reversed(result))
    except (ValueError, TypeError, KeyError, AttributeError):
        raise Conflict("original_session_extension_history_invalid") from None


def _decode_history(
    rows: tuple[SessionRegistrationExtension, ...], head: SavedSessionRegistration
) -> tuple[SavedGraphExtension, ...]:
    return _scan_history(rows, head, materialize=True)


class SessionRegistrationJournal:
    def __init__(self, db: Database, fence: ConsumerFence) -> None:
        self.db, self.fence = db, fence

    async def ready(self) -> None:
        if not await self.db.ready():
            raise Conflict("original_session_registration_database_not_ready")

    @staticmethod
    def require_current(current: CurrentProof, record: SessionAdoptionRecord | None = None) -> None:
        now = time.time()
        if (
            current() is not True
            or record is not None
            and not (record.observed_at <= now < record.observed_at + 5)
        ):
            raise Conflict("original_session_registration_proof_expired")

    async def enrollment(
        self, session: AsyncSession, realm_id: str, record: SessionAdoptionRecord
    ) -> None:
        await self.enrollment_scope(session, realm_id, record.root, record.contract_sha256)

    async def enrollment_scope(
        self, session: AsyncSession, realm_id: str, root: SessionRef, contract_sha256: str
    ) -> None:
        """Check original project scope without requiring an already registered ID."""
        backend = await session.scalar(
            select(EnrolledBackend)
            .where(EnrolledBackend.id == root.backend_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        project = await session.scalar(
            select(EnrolledProject)
            .where(EnrolledProject.id == root.project_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if (
            backend is None
            or not backend.enabled
            or not backend.verified
            or backend.identity != root.backend_identity
            or backend.contract_hash != contract_sha256
            or project is None
            or not project.enabled
            or project.backend_id != root.backend_id
            or project.realm_id != realm_id
            or project.canonical_directory != root.canonical_directory
        ):
            raise Conflict("original_session_registration_enrollment_changed")

    @staticmethod
    def expected(value: SavedSessionRegistration) -> SavedSessionRegistration:
        try:
            return _saved(
                value.receipt,
                SessionAdoptionRecord.model_validate(value.record.model_dump(mode="python")),
                value.state,
                extension_count=value.extension_count,
                extension_tip_hash=value.extension_tip_hash,
            )
        except (ValueError, TypeError, AttributeError):
            raise Conflict("original_session_extension_expected_invalid") from None

    async def _history_rows(
        self, session: AsyncSession, head: SavedSessionRegistration
    ) -> tuple[SessionRegistrationExtension, ...]:
        return tuple(
            (
                await session.scalars(
                    select(SessionRegistrationExtension)
                    .where(SessionRegistrationExtension.registration_key == head.receipt.key)
                    .order_by(SessionRegistrationExtension.sequence)
                    .limit(MAX_EXTENSIONS + 1)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
            ).all()
        )

    async def _history(
        self, session: AsyncSession, head: SavedSessionRegistration
    ) -> tuple[SavedGraphExtension, ...]:
        return _decode_history(await self._history_rows(session, head), head)

    async def _verify_history(self, session: AsyncSession, head: SavedSessionRegistration) -> int:
        rows = await self._history_rows(session, head)
        _scan_history(rows, head, materialize=False)
        return len(rows)

    async def _fresh_head(self, session: AsyncSession, expected: SavedSessionRegistration) -> None:
        row = await session.scalar(
            select(SessionRegistration)
            .where(SessionRegistration.key == expected.receipt.key)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if row is None or decode_registration(row) != expected:
            raise Conflict("original_session_registration_changed_before_commit")
        await self._verify_history(session, expected)

    async def history(
        self,
        expected: SavedSessionRegistration,
        *,
        lock_authority: LockedAuthority,
        current: CurrentProof,
    ) -> tuple[SavedGraphExtension, ...]:
        """Authorized, validated historical deltas; not live execution evidence."""
        expected = self.expected(expected)
        await self.ready()
        self.require_current(current)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await self.enrollment(session, expected.receipt.realm_id, expected.record)
            await lock_authority(session)
            row = await session.scalar(
                select(SessionRegistration)
                .where(SessionRegistration.key == expected.receipt.key)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if row is None or decode_registration(row) != expected:
                raise Conflict("original_session_extension_predecessor_changed")
            result = await self._history(session, expected)
            await lock_authority(session)
            await self.enrollment(session, expected.receipt.realm_id, expected.record)
            await self.fence.lock(session)
            await self._fresh_head(session, expected)
            self.require_current(current)
        return result

    async def extend(
        self,
        expected: SavedSessionRegistration,
        new_record: SessionAdoptionRecord,
        *,
        lock_authority: LockedAuthority,
        current: CurrentProof,
    ) -> RegistrationReceipt:
        """CAS one strictly larger original graph plus its encrypted delta.

        A prepared head survives an in-memory publication crash. This method
        performs no registry publication, Binding creation or Native operation.
        Only the current fenced controller can subsequently activate its receipt.
        """
        expected = self.expected(expected)
        try:
            new_record = SessionAdoptionRecord.model_validate(new_record.model_dump(mode="python"))
            additions = require_original_extension(expected.record, new_record)
        except (ValueError, TypeError, AttributeError):
            raise Conflict("original_session_extension_identity_changed") from None
        payload = new_record.model_dump(mode="json")
        checked_json(payload)
        receipt = RegistrationReceipt(
            expected.receipt.key,
            expected.receipt.realm_id,
            expected.receipt.project_id,
            registration_identity(new_record),
            digest(payload),
            expected.receipt.revision + 1,
            self.fence.holder,
            self.fence.fencing,
        )
        # Validate receipt projections independently before any SQL mutation.
        _saved(receipt, new_record, "prepared")
        await self.ready()
        self.require_current(current, new_record)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await self.enrollment(session, receipt.realm_id, new_record)
            await lock_authority(session)
            row = await session.scalar(
                select(SessionRegistration)
                .where(SessionRegistration.key == receipt.key)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if row is None or decode_registration(row) != expected:
                raise Conflict("original_session_extension_predecessor_changed")
            sequence = await self._verify_history(session, expected) + 1
            if sequence > MAX_EXTENSIONS:
                raise Conflict("original_session_extension_capacity")
            delta = _extension_delta(expected, new_record, receipt, additions, sequence)
            checked_json(delta)
            successor = _saved(
                receipt,
                new_record,
                "prepared",
                extension_count=sequence,
                extension_tip_hash=digest(delta),
            )
            await self.enrollment(session, receipt.realm_id, new_record)
            self.require_current(current, new_record)
            session.add(
                SessionRegistrationExtension(
                    registration_key=receipt.key,
                    sequence=sequence,
                    predecessor_revision=expected.receipt.revision,
                    successor_revision=receipt.revision,
                    predecessor_identity_hash=expected.receipt.identity_hash,
                    successor_identity_hash=receipt.identity_hash,
                    predecessor_payload_hash=expected.receipt.payload_hash,
                    successor_payload_hash=receipt.payload_hash,
                    added_count=len(additions),
                    delta=delta,
                    delta_hash=digest(delta),
                )
            )
            row.payload, row.payload_hash = payload, receipt.payload_hash
            row.identity_hash, row.revision = receipt.identity_hash, receipt.revision
            row.state, row.activated_fencing = "prepared", None
            row.prepared_holder, row.prepared_fencing = self.fence.holder, self.fence.fencing
            row.updated_at = time.time()
            row.extension_count, row.extension_tip_hash = sequence, digest(delta)
            _reseal(row)
            await session.flush()
            await lock_authority(session)
            await self.enrollment(session, receipt.realm_id, new_record)
            await self.fence.lock(session)
            await self._fresh_head(session, successor)
            self.require_current(current, new_record)
            if decode_registration(row) != successor:
                raise Conflict("original_session_extension_changed_before_commit")
        return receipt

    async def requalify(
        self,
        expected: SavedSessionRegistration,
        new_record: SessionAdoptionRecord,
        *,
        lock_authority: LockedAuthority,
        current: CurrentProof,
    ) -> RegistrationReceipt:
        """CAS one unextended head to the same graph under the current qualification.

        v1 qualifications also digested the whole runtime manifest; a current
        head may be re-sealed only while its graph is just its root (a re-pinned
        lineage observation). The caller's factory has decided the old value is
        acceptable and freshly proved the identical live graph; only the
        qualification and format change here. Extended heads are refused: every
        delta header seals its qualification. Like a prepare, the result stays
        prepared until the caller activates it.
        """
        expected = self.expected(expected)
        try:
            new_record = SessionAdoptionRecord.model_validate(new_record.model_dump(mode="python"))
        except (ValueError, TypeError, AttributeError):
            raise Conflict("original_session_requalification_identity_changed") from None
        childless = (
            len(expected.record.nodes) == 1
            and expected.record.nodes[0].reference == expected.record.root
        )
        if (
            expected.record.format not in {LEGACY_RECORD_FORMAT, RECORD_FORMAT}
            or (expected.record.format == RECORD_FORMAT and not childless)
            or new_record.format != RECORD_FORMAT
            or expected.extension_count != 0
            or expected.extension_tip_hash is not None
            or new_record.qualification_sha256 == expected.record.qualification_sha256
            or not same_original_graph(expected.record, new_record)
        ):
            raise Conflict("original_session_requalification_identity_changed")
        payload = new_record.model_dump(mode="json")
        checked_json(payload)
        receipt = RegistrationReceipt(
            expected.receipt.key,
            expected.receipt.realm_id,
            expected.receipt.project_id,
            registration_identity(new_record),
            digest(payload),
            expected.receipt.revision + 1,
            self.fence.holder,
            self.fence.fencing,
        )
        intended = _saved(receipt, new_record, "prepared")
        await self.ready()
        self.require_current(current, new_record)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await self.enrollment(session, receipt.realm_id, new_record)
            await lock_authority(session)
            row = await session.scalar(
                select(SessionRegistration)
                .where(SessionRegistration.key == receipt.key)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if row is None or decode_registration(row) != expected:
                raise Conflict("original_session_requalification_predecessor_changed")
            if await self._verify_history(session, expected) != 0:
                raise Conflict("original_session_requalification_history_present")
            row.payload, row.payload_hash = payload, receipt.payload_hash
            row.identity_hash, row.revision = receipt.identity_hash, receipt.revision
            row.state, row.activated_fencing = "prepared", None
            row.prepared_holder, row.prepared_fencing = self.fence.holder, self.fence.fencing
            row.updated_at = time.time()
            _reseal(row)
            if decode_registration(row) != intended:
                raise Conflict("original_session_requalification_changed_before_commit")
            await session.flush()
            await self.enrollment(session, receipt.realm_id, new_record)
            await lock_authority(session)
            await self.fence.lock(session)
            await self._fresh_head(session, intended)
            self.require_current(current, new_record)
        return receipt

    async def prepare(
        self,
        realm_id: str,
        record: SessionAdoptionRecord,
        *,
        lock_authority: LockedAuthority,
        current: CurrentProof,
    ) -> RegistrationReceipt:
        """Persist before the factory's atomic registry commit; no Native effects."""
        record = SessionAdoptionRecord.model_validate(record.model_dump(mode="python"))
        payload = record.model_dump(mode="json")
        checked_json(payload)  # Bound plaintext before opening a write transaction.
        key = registration_key(realm_id, record.root)
        identity, checksum = registration_identity(record), digest(payload)
        await self.ready()
        self.require_current(current, record)
        async with self.db.sessions.begin() as session:
            # All cooperating consumers serialize here (also on PostgreSQL).
            await self.fence.lock(session)
            await self.enrollment(session, realm_id, record)
            await lock_authority(session)
            row = await session.scalar(
                select(SessionRegistration).where(SessionRegistration.key == key).with_for_update()
            )
            if row is not None:
                saved = decode_registration(row)
                if saved.receipt.identity_hash != identity:
                    raise Conflict("original_session_registration_identity_changed")
                await self._verify_history(session, saved)
                unchanged = (
                    saved.state == "prepared"
                    and row.payload_hash == checksum
                    and (row.prepared_holder, row.prepared_fencing)
                    == (self.fence.holder, self.fence.fencing)
                )
                if not unchanged:
                    row.revision += 1
                    row.payload, row.payload_hash = payload, checksum
                    row.state, row.activated_fencing = "prepared", None
                    row.prepared_holder, row.prepared_fencing = (
                        self.fence.holder,
                        self.fence.fencing,
                    )
                    row.updated_at = time.time()
            else:
                keys = list(
                    (
                        await session.scalars(
                            select(SessionRegistration.key)
                            .where(
                                SessionRegistration.realm_id == realm_id,
                                SessionRegistration.project_id == record.root.project_id,
                            )
                            .limit(MAX_REGISTRATIONS)
                        )
                    ).all()
                )
                if len(keys) >= MAX_REGISTRATIONS:
                    raise Conflict("original_session_registration_capacity")
                row = SessionRegistration(
                    key=key,
                    realm_id=realm_id,
                    project_id=record.root.project_id,
                    payload=payload,
                    payload_hash=checksum,
                    identity_hash=identity,
                    state="prepared",
                    revision=1,
                    prepared_holder=self.fence.holder,
                    prepared_fencing=self.fence.fencing,
                    activated_fencing=None,
                    created_at=time.time(),
                    updated_at=time.time(),
                    extension_count=0,
                    extension_tip_hash=None,
                )
                session.add(row)
            _reseal(row)
            intended = decode_registration(row)
            await session.flush()
            await self.enrollment(session, realm_id, record)
            await lock_authority(session)
            await self.fence.lock(session)
            await self._fresh_head(session, intended)
            self.require_current(current, record)
            receipt = decode_registration(row).receipt
        return receipt

    async def activate(
        self,
        receipt: RegistrationReceipt,
        *,
        lock_authority: LockedAuthority,
        current: CurrentProof,
    ) -> None:
        """Acknowledge local registration; cannot create a Binding or authorize a turn."""
        await self.ready()
        self.require_current(current)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            row = await session.scalar(
                select(SessionRegistration)
                .where(SessionRegistration.key == receipt.key)
                .with_for_update()
            )
            if row is None:
                raise Conflict("original_session_registration_missing")
            saved = decode_registration(row)
            if saved.receipt != receipt or (
                receipt.prepared_holder,
                receipt.prepared_fencing,
            ) != (self.fence.holder, self.fence.fencing):
                raise Conflict("original_session_registration_prepare_superseded")
            await self._verify_history(session, saved)
            await self.enrollment(session, receipt.realm_id, saved.record)
            await lock_authority(session)
            row.state, row.activated_fencing = "active", self.fence.fencing
            row.updated_at = time.time()
            _reseal(row)
            intended = decode_registration(row)
            await session.flush()
            await self.enrollment(session, receipt.realm_id, saved.record)
            await lock_authority(session)
            await self.fence.lock(session)
            await self._fresh_head(session, intended)
            self.require_current(current, saved.record)

    async def recovery_records(
        self,
        realm_id: str,
        project_id: str,
        *,
        lock_authority: LockedAuthority,
        current: CurrentProof,
    ) -> tuple[SavedSessionRegistration, ...]:
        """Bounded identities, including prepared crashes; never a dispatch queue.

        No TTL is imposed on historical identities. A caller must freshly prepare
        them through the factory, then journal that new observation before commit.
        """
        if not realm_id or not project_id or max(len(realm_id), len(project_id)) > 255:
            raise ValueError("registration_recovery_scope_required")
        await self.ready()
        self.require_current(current)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await lock_authority(session)
            rows = list(
                (
                    await session.scalars(
                        select(SessionRegistration)
                        .where(
                            SessionRegistration.realm_id == realm_id,
                            SessionRegistration.project_id == project_id,
                        )
                        .order_by(SessionRegistration.key)
                        .limit(MAX_REGISTRATIONS + 1)
                        .with_for_update()
                    )
                ).all()
            )
            if len(rows) > MAX_REGISTRATIONS:
                raise Conflict("original_session_registration_capacity")
            result = tuple(decode_registration(row) for row in rows)
            for saved in result:
                await self.enrollment(session, realm_id, saved.record)
                await self._verify_history(session, saved)
            await lock_authority(session)
            await self.fence.lock(session)
            for saved in result:
                await self._fresh_head(session, saved)
            self.require_current(current)
        return result
