"""Strict graph deltas with real encrypted ownSQLite; no Native qualification."""

import asyncio
import copy
import time
from dataclasses import asdict, replace

import pytest
from sqlalchemy import delete, select, text, update

from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.session_adoption import OriginalSessionNode, SessionAdoptionRecord
from jt_oz_bridge.domain.session_graph_extension import require_original_extension
from jt_oz_bridge.services.session_registration_journal import (
    RegistrationReceipt,
    SessionRegistrationJournal,
    _extension_delta,
    _saved,
    _scan_history,
    registration_identity,
)
from jt_oz_bridge.storage.cipher_types import checked_json
from jt_oz_bridge.storage.control_models import EnrolledProject
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.durable import Conflict, DurableStore, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Grant, WorkerLease
from jt_oz_bridge.storage.session_registration_models import (
    REGISTRATION_SEAL_FIELDS,
    SessionRegistration,
    SessionRegistrationExtension,
    registration_history_seal,
)
from tests.integration.test_session_registration_journal import record, recovery, setup
from tests.support import REF


def graph(nodes=None, **changes):
    """Construct internally coherent fixture records, including noncanonical order."""
    base = record()
    data = base.model_dump(mode="json") | changes
    selected = tuple(base.nodes if nodes is None else nodes)
    data["root"] = next(
        node.reference.model_dump(mode="json") for node in selected if node.parent_reference is None
    )
    data["nodes"] = [node.model_dump(mode="json") for node in selected]
    origins = {
        node.reference: {
            "reference": node.reference.model_dump(mode="json"),
            "native_project_id": data["native_project_id"],
            "created_at": node.native_created_at,
            "parent_id": node.parent_reference.upstream_session_id
            if node.parent_reference
            else None,
        }
        for node in selected
    }
    entries = []
    for node in sorted(selected, key=lambda node: node.reference.upstream_session_id):
        origin = dict(origins[node.reference])
        if node.parent_reference is not None:
            origin["parent_origin_sha256"] = digest(origins[node.parent_reference])
            origin["parent_created_at"] = node.parent_created_at
        entries.append(
            {
                "reference": node.reference.model_dump(mode="json"),
                "origin_sha256": digest(origin),
                "policy_sha256": node.policy_sha256,
            }
        )
    data["graph_sha256"] = digest({"nodes": entries})
    return SessionAdoptionRecord.model_validate(data)


def grow(previous, name="added-child", *, parent=None):
    parent = parent or previous.root
    ancestor = next(node for node in previous.nodes if node.reference == parent)
    child = OriginalSessionNode(
        reference=previous.root.model_copy(update={"upstream_session_id": name}),
        native_created_at=1000 + len(previous.nodes),
        parent_reference=parent,
        parent_created_at=ancestor.native_created_at,
        policy_sha256="e" * 64,
    )
    return graph((*previous.nodes, child), observed_owner_epoch="d" * 64)


def invalid_extension(previous, fault):
    new = grow(previous)
    if fault in {"native_project", "contract", "qualification"}:
        field = {
            "native_project": "native_project_id",
            "contract": "contract_sha256",
            "qualification": "qualification_sha256",
        }[fault]
        return graph(
            new.nodes, **{field: "other-project" if fault == "native_project" else "f" * 64}
        )
    if fault == "root":
        other = record(reference=REF.model_copy(update={"upstream_session_id": "another-root"}))
        return grow(other)
    if fault == "empty":
        return graph(previous.nodes)
    if fault == "forged":
        return new.model_copy(update={"graph_sha256": "f" * 64})
    if fault == "policy":
        return graph(
            (previous.nodes[0].model_copy(update={"policy_sha256": "f" * 64}), *new.nodes[1:])
        )
    if fault == "created":
        return graph(
            (
                previous.nodes[0].model_copy(update={"native_created_at": 999}),
                *(
                    node.model_copy(update={"parent_created_at": 999})
                    if node.parent_reference == previous.root
                    else node
                    for node in new.nodes[1:]
                ),
            )
        )
    if fault == "removed":
        return graph((previous.nodes[0], new.nodes[-1]))
    # Move an existing child under the newly added sibling: valid tree, wrong origin.
    assert fault == "parent"
    return graph(
        (
            new.nodes[0],
            new.nodes[1].model_copy(
                update={
                    "parent_reference": new.nodes[-1].reference,
                    "parent_created_at": new.nodes[-1].native_created_at,
                }
            ),
            *new.nodes[2:],
        )
    )


@pytest.mark.parametrize(
    "fault",
    [
        "root",
        "native_project",
        "contract",
        "qualification",
        "empty",
        "forged",
        "policy",
        "created",
        "removed",
        "parent",
    ],
)
def test_domain_rejects_replacement_and_nonextension_even_with_self_consistent_dtos(fault):
    old = grow(graph(), "existing-child")
    with pytest.raises(ValueError):
        require_original_extension(old, invalid_extension(old, fault))


def test_domain_preserves_every_old_node_and_accepts_added_grandchild_with_reordered_nodes():
    old = grow(graph(), "existing-child")
    new = grow(old, "grandchild", parent=old.nodes[-1].reference)
    new = graph(tuple(reversed(new.nodes)))
    added = require_original_extension(old, new)
    assert len(added) == 1 and added[0].parent_reference == old.nodes[-1].reference
    with pytest.raises(ValueError):
        require_original_extension(old.model_copy(update={"graph_sha256": "f" * 64}), new)


def test_original_graph_limit_is_1000_and_an_extension_must_add_a_node():
    old = graph()
    children = tuple(grow(old, "child-" + str(i)).nodes[-1] for i in range(999))
    full = graph((*old.nodes, *children))
    assert len(require_original_extension(old, full)) == 999
    with pytest.raises(ValueError):
        require_original_extension(full, full)
    with pytest.raises(ValueError):
        require_original_extension(
            old, full.model_copy(update={"nodes": (*full.nodes, children[0])})
        )


async def initialize(db, value=None, *, active=True):
    journal, authority = await setup(db)
    value = value or graph()
    receipt = await journal.prepare("realm", value, lock_authority=authority, current=lambda: True)
    if active:
        await journal.activate(receipt, lock_authority=authority, current=lambda: True)
    return journal, authority, (await recovery(journal, authority))[0]


async def extend(journal, authority, expected, new):
    return await journal.extend(expected, new, lock_authority=authority, current=lambda: True)


async def history(journal, authority, expected):
    return await journal.history(expected, lock_authority=authority, current=lambda: True)


async def raw_state(db):
    async with db.engine.connect() as connection:
        heads = (
            await connection.execute(text("SELECT * FROM session_registrations ORDER BY key"))
        ).all()
        deltas = (
            await connection.execute(
                text(
                    "SELECT * FROM session_registration_extensions ORDER BY registration_key, sequence"
                )
            )
        ).all()
    return heads, deltas


async def test_extension_cas_saves_encrypted_delta_and_reopens_exact_original_history(db):
    journal, authority, old = await initialize(db)
    new = grow(old.record)
    receipt = await extend(journal, authority, old, new)
    head = (await recovery(journal, authority))[0]
    assert head.record == new and head.receipt == receipt and head.state == "prepared"
    assert head.extension_count == 1 and head.extension_tip_hash
    restored = await history(journal, authority, head)
    assert len(restored) == 1 and restored[0].predecessor == old
    assert restored[0].successor == head
    assert restored[0].added_nodes == (new.nodes[-1],)
    assert receipt.revision == old.receipt.revision + 1
    raw = await raw_state(db)
    for table_rows in raw:
        for row in table_rows:
            for column in row:
                if isinstance(column, (bytes, str)):
                    body = column if isinstance(column, bytes) else column.encode()
                    assert REF.upstream_session_id.encode() not in body
                    assert b"added-child" not in body
    reopened = Database(str(db.engine.url), cipher=db.cipher)
    try:
        fresh = SessionRegistrationJournal(reopened, journal.fence)
        recovered = (await recovery(fresh, authority))[0]
        assert recovered == head
        assert await history(fresh, authority, recovered) == restored
        await fresh.activate(receipt, lock_authority=authority, current=lambda: True)
        assert (await recovery(fresh, authority))[0].state == "active"
    finally:
        await reopened.close()


async def test_header_order_and_revision_refresh_between_extensions_preserves_exact_predecessors(
    db,
):
    journal, authority, old = await initialize(db)
    first = grow(grow(old.record, "first-child"), "second-child")
    first = graph(tuple(reversed(first.nodes)))
    receipt = await extend(journal, authority, old, first)
    await journal.activate(receipt, lock_authority=authority, current=lambda: True)
    refreshed = graph(tuple(reversed(first.nodes)), observed_owner_epoch="f" * 64)
    refresh_receipt = await journal.prepare(
        "realm", refreshed, lock_authority=authority, current=lambda: True
    )
    await journal.activate(refresh_receipt, lock_authority=authority, current=lambda: True)
    current = (await recovery(journal, authority))[0]
    assert current.extension_count == 1 and current.receipt.revision > receipt.revision
    assert (await history(journal, authority, current))[0].successor.record == first
    second = grow(current.record, "grandchild", parent=first.nodes[0].reference)
    await extend(journal, authority, current, second)
    final = (await recovery(journal, authority))[0]
    ledger = await history(journal, authority, final)
    assert len(ledger) == 2
    assert ledger[0].predecessor == old
    assert ledger[0].successor.record == first
    assert ledger[1].predecessor == current
    assert ledger[1].successor.record == second
    with pytest.raises(Conflict):
        await extend(journal, authority, current, grow(current.record, "stale-child"))


async def test_delta_keeps_only_additions_and_header_order_instead_of_copying_full_graph(db):
    root = graph()
    initial = graph(
        (*root.nodes, *(grow(root, "existing-" + str(i)).nodes[-1] for i in range(100)))
    )
    journal, authority, old = await initialize(db, initial)
    new = grow(old.record)
    await extend(journal, authority, old, new)
    head = (await recovery(journal, authority))[0]
    async with db.sessions() as session:
        row = await session.scalar(select(SessionRegistrationExtension))
        delta = row.delta
    assert "nodes" not in delta["previous_header"] and "nodes" not in delta["next_header"]
    assert len(delta["added_nodes"]) == 1
    assert all(type(index) is int for index in delta["previous_order"] + delta["next_order"])
    assert len(checked_json(delta)) < len(checked_json(new.model_dump(mode="json"))) // 4
    assert (await history(journal, authority, head))[0].predecessor.record == initial


async def test_concurrent_candidates_have_one_sqlite_winner_and_stale_expected_cannot_overwrite(db):
    journal, authority, old = await initialize(db)
    candidates = [grow(old.record, "candidate-a"), grow(old.record, "candidate-b")]
    results = await asyncio.gather(
        *(extend(journal, authority, old, new) for new in candidates), return_exceptions=True
    )
    assert sum(not isinstance(result, BaseException) for result in results) == 1
    assert sum(isinstance(result, Conflict) for result in results) == 1
    head = (await recovery(journal, authority))[0]
    assert head.record in candidates and head.extension_count == 1
    assert len(await history(journal, authority, head)) == 1


@pytest.mark.parametrize("change", ["activate", "prepare", "extend"])
async def test_expected_includes_exact_state_payload_revision_and_history_tip(db, change):
    journal, authority, old = await initialize(db, active=False)
    if change == "activate":
        await journal.activate(old.receipt, lock_authority=authority, current=lambda: True)
    elif change == "prepare":
        await journal.prepare(
            "realm", graph(old.record.nodes), lock_authority=authority, current=lambda: True
        )
    else:
        await extend(journal, authority, old, grow(old.record))
    before = await raw_state(db)
    with pytest.raises(Conflict, match="predecessor_changed"):
        await extend(journal, authority, old, grow(old.record, "stale-candidate"))
    assert await raw_state(db) == before


@pytest.mark.parametrize(
    "fault",
    [
        "root",
        "native_project",
        "contract",
        "qualification",
        "empty",
        "forged",
        "policy",
        "created",
        "removed",
        "parent",
    ],
)
async def test_invalid_extension_never_changes_head_or_writes_history(db, fault):
    journal, authority, old = await initialize(db, grow(graph(), "existing-child"))
    before = await raw_state(db)
    with pytest.raises(Conflict, match="identity_changed"):
        await extend(journal, authority, old, invalid_extension(old.record, fault))
    assert await raw_state(db) == before


@pytest.mark.parametrize(
    "fault", ["revoke", "current", "fence", "enrollment", "cancel", "history_delete"]
)
async def test_late_authority_event_or_cancellation_rolls_back_head_and_delta_together(db, fault):
    journal, authority, old = await initialize(db)
    before = await raw_state(db)
    calls, live = 0, True

    async def during_flush(session):
        nonlocal calls, live
        calls += 1
        await authority(session)
        if calls == 2:
            if fault == "revoke":
                await session.execute(update(Grant).values(active=False))
                await authority(session)
            elif fault == "current":
                live = False
            elif fault == "fence":
                await session.execute(update(WorkerLease).values(fencing=999))
            elif fault == "enrollment":
                await session.execute(update(EnrolledProject).values(enabled=False))
            elif fault == "history_delete":
                await session.execute(delete(SessionRegistrationExtension))
            else:
                raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError if fault == "cancel" else Conflict):
        await journal.extend(
            old, grow(old.record), lock_authority=during_flush, current=lambda: live
        )
    assert calls == 2 and await raw_state(db) == before
    assert (await recovery(journal, authority))[0] == old


@pytest.mark.parametrize(
    "fault",
    [
        "delete_only",
        "delete_last",
        "replace_delta",
        "order",
        "added_policy",
        "added_reference_scope",
        "duplicate_addition",
        "projection",
        "unknown_header",
        "unknown_delta",
        "header_payload",
    ],
)
async def test_history_truncation_substitution_or_corruption_is_not_silently_accepted(db, fault):
    journal, authority, old = await initialize(db)
    await extend(journal, authority, old, grow(old.record))
    if fault == "delete_last":
        first = (await recovery(journal, authority))[0]
        await extend(journal, authority, first, grow(first.record, "second-child"))
    head = (await recovery(journal, authority))[0]
    async with db.sessions.begin() as session:
        row = await session.scalar(
            select(SessionRegistrationExtension).order_by(
                SessionRegistrationExtension.sequence.desc()
            )
        )
        if fault.startswith("delete"):
            await session.execute(
                delete(SessionRegistrationExtension).where(
                    SessionRegistrationExtension.sequence == row.sequence
                )
            )
        elif fault == "projection":
            row.predecessor_identity_hash = "f" * 64
        else:
            value = copy.deepcopy(row.delta)
            if fault == "replace_delta":
                value = {"format": "replacement"}
            elif fault == "order":
                value["previous_order"] = [False]
            elif fault == "unknown_header":
                value["previous_header"]["unknown"] = True
            elif fault == "unknown_delta":
                value["unknown"] = True
            elif fault == "header_payload":
                value["previous_header"]["observed_owner_epoch"] = "f" * 64
            elif fault == "added_reference_scope":
                # Same upstream ID is not the same full Native reference.
                value["added_nodes"][0]["reference"]["backend_identity"] = "foreign-installation"
            elif fault == "duplicate_addition":
                value["added_nodes"].append(copy.deepcopy(value["added_nodes"][0]))
            else:
                value["added_nodes"][0]["policy_sha256"] = "f" * 64
            row.delta, row.delta_hash = value, digest(value)
            # A deliberately invalid trusted fixture writer updates the authenticated
            # tip too: this exercises full delta semantics behind the head seal.
            stored = await session.get(SessionRegistration, head.receipt.key)
            stored.extension_tip_hash = row.delta_hash
            stored.history_seal = registration_history_seal(
                {field: getattr(stored, field) for field in REGISTRATION_SEAL_FIELDS}
            )
            head = replace(head, extension_tip_hash=row.delta_hash)
    for operation in (
        lambda: history(journal, authority, head),
        lambda: recovery(journal, authority),
        lambda: extend(journal, authority, head, grow(head.record, "must-not-publish")),
        lambda: journal.prepare(
            "realm", graph(head.record.nodes), lock_authority=authority, current=lambda: True
        ),
        lambda: journal.activate(head.receipt, lock_authority=authority, current=lambda: True),
    ):
        with pytest.raises(Conflict):
            await operation()


async def test_current_lease_takeover_can_extend_historic_identity_but_old_holder_cannot(db):
    old_journal, authority, old = await initialize(db)
    async with db.sessions.begin() as session:
        await session.execute(update(WorkerLease).values(expires_at=0))
    fencing = await DurableStore(db).acquire_lease("extension-restart", ttl=120)
    fresh = SessionRegistrationJournal(db, ConsumerFence("extension-restart", fencing))
    receipt = await extend(fresh, authority, old, grow(old.record))
    assert receipt.prepared_holder == "extension-restart" and receipt.prepared_fencing == fencing
    with pytest.raises(Conflict, match="consumer_lease"):
        await extend(old_journal, authority, old, grow(old.record, "old-holder-candidate"))
    current = (await recovery(fresh, authority))[0]
    assert (await history(fresh, authority, current))[0].predecessor == old


async def test_expired_new_observation_is_not_renewed_by_historical_registration(db):
    journal, authority, old = await initialize(db)
    before = await raw_state(db)
    stale = grow(old.record).model_copy(update={"observed_at": time.time() - 10})
    with pytest.raises(Conflict, match="proof_expired"):
        await extend(journal, authority, old, stale)
    assert await raw_state(db) == before


async def test_history_reads_require_current_authority_and_do_not_issue_native_work(db):
    journal, authority, old = await initialize(db)
    await extend(journal, authority, old, grow(old.record))
    head = (await recovery(journal, authority))[0]

    async def denied(session):
        raise Conflict("synthetic_current_authority_revoked")

    with pytest.raises(Conflict, match="revoked"):
        await journal.history(head, lock_authority=denied, current=lambda: True)
    with pytest.raises(Conflict, match="proof_expired"):
        await journal.history(head, lock_authority=authority, current=lambda: False)


@pytest.mark.parametrize("operation", ["recover", "prepare", "activate"])
async def test_plaintext_history_reset_cannot_erase_the_authenticated_ledger(db, operation):
    journal, authority, old = await initialize(db)
    receipt = await extend(journal, authority, old, grow(old.record))
    head = (await recovery(journal, authority))[0]
    before = (await raw_state(db))[0][0]
    async with db.engine.begin() as connection:
        await connection.execute(text("DELETE FROM session_registration_extensions"))
        await connection.execute(
            text("UPDATE session_registrations SET extension_count=0, extension_tip_hash=NULL")
        )
    after = (await raw_state(db))[0][0]
    assert before._mapping["payload"] == after._mapping["payload"]
    with pytest.raises(Conflict):
        if operation == "recover":
            await recovery(journal, authority)
        elif operation == "prepare":
            await journal.prepare(
                "realm", graph(head.record.nodes), lock_authority=authority, current=lambda: True
            )
        else:
            await journal.activate(receipt, lock_authority=authority, current=lambda: True)


@pytest.mark.parametrize("operation", ["prepare", "activate"])
async def test_late_history_delete_rolls_back_prepare_and_activate(db, operation):
    journal, authority, old = await initialize(db)
    receipt = await extend(journal, authority, old, grow(old.record))
    head = (await recovery(journal, authority))[0]
    before = await raw_state(db)
    calls = 0

    async def delete_after_flush(session):
        nonlocal calls
        calls += 1
        await authority(session)
        if calls == 2:
            await session.execute(delete(SessionRegistrationExtension))

    with pytest.raises(Conflict):
        if operation == "prepare":
            await journal.prepare(
                "realm",
                graph(head.record.nodes),
                lock_authority=delete_after_flush,
                current=lambda: True,
            )
        else:
            await journal.activate(receipt, lock_authority=delete_after_flush, current=lambda: True)
    assert calls == 2 and await raw_state(db) == before
    assert (await recovery(journal, authority))[0] == head


@pytest.mark.parametrize("node_count", [257, 999])
async def test_full_generation_chain_extends_under_original_five_second_proof(db, node_count):
    """Real encrypted SQL and every generation, including the 999-extension cap."""
    journal, authority, initial = await initialize(db, active=False)
    head = initial
    rows = []
    for sequence in range(1, node_count):
        new = grow(head.record, f"deadline-child-{sequence}")
        receipt = RegistrationReceipt(
            head.receipt.key,
            "realm",
            new.root.project_id,
            registration_identity(new),
            digest(new.model_dump(mode="json")),
            head.receipt.revision + 1,
            head.receipt.prepared_holder,
            head.receipt.prepared_fencing,
        )
        delta = _extension_delta(head, new, receipt, (new.nodes[-1],), sequence)
        checksum = digest(delta)
        rows.append(
            SessionRegistrationExtension(
                registration_key=receipt.key,
                sequence=sequence,
                predecessor_revision=head.receipt.revision,
                successor_revision=receipt.revision,
                predecessor_identity_hash=head.receipt.identity_hash,
                successor_identity_hash=receipt.identity_hash,
                predecessor_payload_hash=head.receipt.payload_hash,
                successor_payload_hash=receipt.payload_hash,
                added_count=1,
                delta=delta,
                delta_hash=checksum,
                created_at=time.time(),
            )
        )
        head = _saved(
            receipt, new, "prepared", extension_count=sequence, extension_tip_hash=checksum
        )
    # Seed genuine encrypted rows outside the live proof window. No Native state.
    async with db.sessions.begin() as session:
        stored = await session.get(SessionRegistration, head.receipt.key)
        for key, value in asdict(head.receipt).items():
            setattr(stored, key, value)
        stored.payload = head.record.model_dump(mode="json")
        stored.extension_count = head.extension_count
        stored.extension_tip_hash = head.extension_tip_hash
        stored.updated_at = time.time()
        stored.history_seal = registration_history_seal(
            {field: getattr(stored, field) for field in REGISTRATION_SEAL_FIELDS}
        )
        session.add_all(rows)
    assert (await recovery(journal, authority))[0] == head
    target = grow(head.record, "deadline-final-child")
    started = time.perf_counter()
    receipt = await extend(journal, authority, head, target)
    elapsed = time.perf_counter() - started
    assert elapsed < 5, f"full encrypted {node_count}-node chain took {elapsed:.3f}s"
    actual = (await recovery(journal, authority))[0]
    assert actual.receipt == receipt and actual.record == target
    assert actual.extension_count == node_count
    assert len(actual.record.nodes) == node_count + 1
    assert actual.record.nodes[:-1] == head.record.nodes
    print(f"full_history_deadline nodes={node_count}->{node_count + 1} seconds={elapsed:.6f}")


@pytest.mark.parametrize("materialize", [False, True])
async def test_complete_history_does_not_rehash_each_full_reference_per_generation(
    db, monkeypatch, materialize
):
    """Bound repeated DTO hashing, not wall time; all encrypted history is still read."""
    journal, authority, first = await initialize(db, active=False)
    head = first
    expected = []
    for sequence in range(32):
        await extend(journal, authority, head, grow(head.record, f"rank-child-{sequence}"))
        next_head = (await recovery(journal, authority))[0]
        expected.append((head, next_head))
        head = next_head
    async with db.sessions() as session:
        rows = tuple(
            (
                await session.scalars(
                    select(SessionRegistrationExtension).order_by(
                        SessionRegistrationExtension.sequence
                    )
                )
            ).all()
        )
    real_hash = SessionRef.__hash__
    calls = 0

    def counted(reference):
        nonlocal calls
        calls += 1
        return real_hash(reference)

    with monkeypatch.context() as patch:
        patch.setattr(SessionRef, "__hash__", counted)
        for _ in range(2):
            calls = 0
            result = _scan_history(rows, head, materialize=materialize)
            print(f"history_reference_hashes nodes={len(head.record.nodes)} calls={calls}")
            assert calls <= 64 * len(head.record.nodes)
            if materialize:
                assert [(item.predecessor, item.successor) for item in result] == expected
            else:
                assert result == ()
        # A later scan must revalidate every old delta rather than reuse a prior
        # successful verification. This is an isolated, detached ownDB fixture.
        changed = rows[len(rows) // 2]
        value = copy.deepcopy(changed.delta)
        value["previous_header"]["observed_owner_epoch"] = "f" * 64
        changed.delta = value
        with pytest.raises(Conflict, match="extension_history_invalid"):
            _scan_history(rows, head, materialize=materialize)
