"""Real isolated encrypted journal round trips; Native/owners are synthetic."""

import copy

import pytest

from jt_oz_bridge.domain.check_idle_anchor import (
    CheckHeadBoundary,
    CheckIdleAnchor,
    CheckPositiveIdle,
)
from jt_oz_bridge.services.check_dispatch_records import dispatch_preflight
from jt_oz_bridge.storage.check_dispatch_models import CheckDispatchRecord
from jt_oz_bridge.storage.durable import Conflict, digest
from tests.integration.test_check_dispatch_records import read, save, setup


async def test_legacy_original_encrypted_journal_without_anchor_stays_legacy(db):
    service, action, binding, proof = await setup(db)
    # Old stored payloads have no new optional key. Retain their actual hash,
    # owner and historical expiry; do not fabricate an Idle anchor at read time.
    payload = proof.model_dump(mode="json")
    payload.pop("idle_anchor")
    checksum = digest(payload)
    async with db.sessions.begin() as session:
        session.add(
            CheckDispatchRecord(action_id=action.id, payload=payload, payload_hash=checksum)
        )
    observed = await read(service, proof)
    assert observed.idle_anchor is None
    assert observed.owner_epoch == proof.owner_epoch
    assert observed.issued_at == proof.issued_at and observed.expires_at == proof.expires_at
    async with db.sessions() as session:
        original = await session.get(CheckDispatchRecord, action.id)
    assert original.payload == payload and original.payload_hash == checksum
    assert "idle_anchor" not in original.payload


async def test_positive_idle_anchor_is_immutable_and_bound_to_original_action_record(db):
    service, action, binding, proof = await setup(db)
    idle = CheckPositiveIdle(id="msg_idle", created_at=1, outcome="succeeded")
    wire = idle.wire()
    anchor = CheckIdleAnchor(
        reference=proof.reference,
        head=CheckHeadBoundary(
            id="msg_idle", type="idle", created_at=1, sha256=digest({"latest": wire})
        ),
        idle=idle,
        pristine=False,
    )
    anchored = proof.model_copy(update={"idle_anchor": anchor})
    assert await save(service, anchored) == anchored
    assert await read(service, anchored) == anchored
    # Neither a new positive boundary nor omission may replace this original
    # immutable pre-send proof even while the same local action remains claimed.
    with pytest.raises(Conflict, match="must_not_be_overwritten"):
        await save(service, proof)
    changed = anchor.model_copy(
        update={"head": anchor.head.model_copy(update={"sha256": "b" * 64})}
    )
    with pytest.raises(Conflict, match="must_not_be_overwritten"):
        await save(service, anchored.model_copy(update={"idle_anchor": changed}))
    assert await read(service, anchored) == anchored


async def test_cross_root_idle_anchor_in_legacy_row_cannot_be_accepted_as_original_proof(db):
    service, action, binding, proof = await setup(db)
    payload = proof.model_dump(mode="json")
    payload["idle_anchor"] = {
        "reference": proof.reference.model_copy(
            update={"upstream_session_id": "ses_foreign"}
        ).model_dump(mode="json"),
        "head": None,
        "idle": None,
        "pristine": True,
    }
    row = CheckDispatchRecord(
        action_id=action.id, payload=copy.deepcopy(payload), payload_hash=digest(payload)
    )
    with pytest.raises(Conflict, match="record_invalid"):
        dispatch_preflight(row, action)
