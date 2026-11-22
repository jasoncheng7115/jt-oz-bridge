import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select, text, update

from jt_oz_bridge.domain.control import FieldAnswer, InteractionSnapshot, QuestionField
from jt_oz_bridge.security.cipher import EnvelopeCipher
from jt_oz_bridge.services.interactions import InteractionService
from jt_oz_bridge.storage.cipher_types import checked_json, payload_scope
from jt_oz_bridge.storage.control_models import FormDraft
from jt_oz_bridge.storage.database import Database, migrate
from jt_oz_bridge.storage.durable import Conflict
from tests.support import REF, bound


async def test_legacy_draft_migration_preserves_encrypted_answers_and_pins_snapshot(tmp_path):
    cipher = EnvelopeCipher({"test": os.urandom(32)}, "test")
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'legacy.db'}", cipher=cipher)

    def legacy(connection):
        config = Config()
        config.set_main_option(
            "script_location", str(Path("src/jt_oz_bridge/storage/migrations").resolve())
        )
        config.attributes["connection"] = connection
        command.upgrade(config, "0008_delivery_batches")

    try:
        async with db.engine.begin() as connection:
            await connection.run_sync(legacy)
            snapshot = cipher.seal(
                checked_json({}), payload_scope("pending_interactions", "snapshot")
            )
            answers = cipher.seal(
                checked_json({"note": {"text": "PRIVATE_OLD_ANSWER"}}),
                payload_scope("form_drafts", "answers"),
            )
            await connection.execute(
                text(
                    "INSERT INTO pending_interactions (id,identity_key,binding_id,binding_revision,snapshot,snapshot_hash,state,expires_at,version) VALUES ('request','identity','binding',1,:snapshot,:hash,'pending',9999999999,1)"
                ),
                {"snapshot": snapshot, "hash": "a" * 64},
            )
            await connection.execute(
                text(
                    "INSERT INTO form_drafts (key,interaction_id,user_id,answers,revision) VALUES ('draft','request',7,:answers,3)"
                ),
                {"answers": answers},
            )
            await connection.execute(
                text(
                    "INSERT INTO form_drafts (key,interaction_id,user_id,answers,revision) VALUES ('orphan','missing-request',7,:answers,2)"
                ),
                {"answers": answers},
            )
        await migrate(db.engine)
        assert await db.ready()
        async with db.sessions() as session:
            draft = await session.get(FormDraft, "draft")
            assert draft.answers == {"note": {"text": "PRIVATE_OLD_ANSWER"}} and draft.revision == 3
            assert draft.progress == {"skipped": []} and draft.snapshot_hash == "a" * 64
            assert (await session.get(FormDraft, "orphan")).snapshot_hash is None
        async with db.engine.connect() as connection:
            assert (
                await connection.scalar(
                    text("SELECT typeof(progress) FROM form_drafts WHERE key='draft'")
                )
                == "blob"
            )
    finally:
        await db.close()


async def test_draft_schema_mismatch_cannot_reuse_or_submit_saved_answers(db):
    bindings, binding, control, _audience = await bound(db)
    service = InteractionService(bindings)
    snapshot = InteractionSnapshot(
        reference=REF,
        upstream_request_id="form",
        generation="g1",
        kind="form",
        pending=True,
        description="Question",
        fields=(QuestionField(id="note", label="Note", kind="text"),),
    )
    control.requests["form"] = snapshot
    identity = await service.observe(binding, snapshot)
    token = await service.issue(identity, "realm", 7)
    revision = await service.save_answer(
        token, "realm", 7, "note", FieldAnswer(text="Original answer")
    )
    async with db.sessions.begin() as session:
        await session.execute(update(FormDraft).values(snapshot_hash="b" * 64))
    with pytest.raises(Conflict, match="snapshot"):
        await service.save_answer(token, "realm", 7, "note", FieldAnswer(text="new"), revision)
    with pytest.raises(Conflict, match="snapshot"):
        await service.reply(token, "realm", 7)
    async with db.sessions() as session:
        assert (await session.scalar(select(FormDraft))).answers["note"][
            "text"
        ] == "Original answer"


async def test_token_consumption_is_atomic_with_draft_transaction_and_context_hash(db):
    from jt_oz_bridge.security.admin import token_hash
    from jt_oz_bridge.services.tokens import TokenService
    from jt_oz_bridge.storage.control_models import ControlToken
    from jt_oz_bridge.storage.durable import digest

    tokens = TokenService(db)
    token = await tokens.issue("form-step", "realm", 7, {"draft_revision": 1})
    saved = await tokens.inspect(token, "form-step", "realm", 7)
    with pytest.raises(RuntimeError, match="rollback"):
        async with db.sessions.begin() as session:
            await tokens.consume_in_session(session, saved)
            raise RuntimeError("rollback draft and token together")
    assert not (await tokens.inspect(token, "form-step", "realm", 7)).used
    async with db.sessions.begin() as session:
        await session.execute(
            update(ControlToken)
            .where(ControlToken.token_hash == token_hash(token))
            .values(context={"draft_revision": 2}, context_hash=digest({"draft_revision": 2}))
        )
    with pytest.raises(Conflict, match="context_changed"):
        async with db.sessions.begin() as session:
            await tokens.consume_in_session(session, saved)
    assert (await tokens.consume(token, "form-step", "realm", 7)) == {"draft_revision": 2}
