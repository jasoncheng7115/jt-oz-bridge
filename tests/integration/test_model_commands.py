"""Local encrypted DB + synthetic Native catalog; no production accounts or mail."""

import asyncio
import re
from html import unescape

import pytest
from sqlalchemy import select, update

from jt_oz_bridge.domain.model_catalog import NativeModelCatalog, NativeModelOption, NativeModelRef
from jt_oz_bridge.domain.models import Capability
from jt_oz_bridge.domain.operations import current_operation
from jt_oz_bridge.security.policy import Permission
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.dispatch import Dispatcher
from jt_oz_bridge.services.model_commands import CHOICE_KIND, ModelCommands
from jt_oz_bridge.services.queue import QueueService
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.models import Action, Grant
from tests.integration.test_dispatch import SyntheticExecution
from tests.integration.test_router import Source, message, send
from tests.support import bound


class Catalog:
    def __init__(self, ref, contract):
        self.calls = []
        self.hook = None
        self.snapshot = NativeModelCatalog(
            reference=ref,
            contract_sha256=contract,
            selected=NativeModelRef(
                provider_id="synthetic-provider", model_id="Case/Alias", variant="none"
            ),
            default=NativeModelRef(provider_id="synthetic-provider", model_id="Case/Alias"),
            items=(
                NativeModelOption(
                    reference=NativeModelRef(
                        provider_id="synthetic-provider", model_id="Case/Alias"
                    ),
                    upstream_model_id="upstream-synthetic-id",
                    name="Synthetic model",
                    status="active",
                    variant_ids=("none", "low", "medium", "high"),
                ),
                *(
                    NativeModelOption(
                        reference=NativeModelRef(
                            provider_id="ollama", model_id=f"hf.co/Team/Model-{i:02d}:Q4"
                        ),
                        upstream_model_id=f"native-ollama-{i}",
                        name=f"Ollama model {i}",
                        status="active",
                        variant_ids=(),
                    )
                    for i in range(12)
                ),
            ),
        )

    def contract_for(self, ref):
        assert ref == self.snapshot.reference
        return self.snapshot.contract_sha256

    async def read(self, ref):
        self.calls.append(ref)
        if self.hook:
            await self.hook()
        return self.snapshot


class ModelExecution(SyntheticExecution):
    def __init__(self):
        super().__init__()
        self.model_supported = True

    def capabilities(self, ref):
        return {
            **super().capabilities(ref),
            "model.switch": Capability(
                supported=self.model_supported,
                scope="session",
                reason="synthetic",
                verification="synthetic",
            ),
        }


async def setup(db, execution=None):
    execution = execution or ModelExecution()
    bindings, binding, _control, audience = await bound(db, control=execution)
    fencing = await DurableStore(db).acquire_lease("models", ttl=120)
    inbox, source = CommandInbox(db, "models", fencing), Source()
    tokens = TokenService(db, fence=inbox.fence)
    catalog = Catalog(reference(binding), execution.contract_hash)
    commands = ModelCommands(
        bindings, {binding.backend_id: catalog}, tokens, source, capabilities=execution.capabilities
    )
    router = CommandRouter(
        bindings, source, inbox, capabilities=execution.capabilities, models=commands
    )
    worker = Dispatcher(bindings, execution, source, "models", fencing)
    return router, binding, source, catalog, execution, commands, worker, audience


def tokens(text, command):
    return re.findall(r"!oz " + re.escape(command) + r" ([A-Za-z0-9_-]+)`", text)


async def rows(db, model):
    async with db.sessions() as session:
        return list((await session.scalars(select(model))).all())


async def model_menu(router, source, start=101):
    providers = await send(router, source, message("!oz models", start))
    provider = tokens(providers.text, "models")[0]  # ollama sorts first
    menu = await send(router, source, message(f"!oz models {provider}", start + 1))
    return menu, tokens(menu.text, "model")


async def test_provider_first_native_models_page_is_bounded_and_preserves_aliases(db):
    router, binding, source, catalog, _execution, _commands, _worker, _audience = await setup(db)
    menu, choices = await model_menu(router, source)
    assert len(choices) == 9 and "ollama / hf.co/Team/Model" in unescape(menu.text)
    more = tokens(menu.text, "models")
    assert len(more) == 1
    next_page = await send(router, source, message(f"!oz models {more[0]}", 103))
    assert len(tokens(next_page.text, "model")) == 3 and not tokens(next_page.text, "models")
    assert all(ref == reference(binding) for ref in catalog.calls)
    assert not await rows(db, Action)


async def test_model_choice_consumes_once_and_creates_one_encrypted_durable_action(db):
    router, binding, source, _catalog, execution, _commands, worker, _audience = await setup(db)
    _menu, choices = await model_menu(router, source)
    chosen = message(f"!oz model {choices[0]}", 103)
    reply = await send(router, source, chosen)
    assert "Received and queued" in reply.text
    assert await router.route(chosen) == reply
    actions = await rows(db, Action)
    assert len(actions) == 1
    action = actions[0]
    assert action.operation == current_operation(action.payload) == "model.switch"
    assert action.payload["selection"]["target"] == {
        "provider_id": "ollama",
        "model_id": "hf.co/Team/Model-00:Q4",
        "variant": None,
    }
    assert action.binding_id == binding.id and action.state == "queued"
    assert await worker.advance(action.id) == "completed"
    assert await worker.advance(action.id) == "completed" and len(execution.submitted) == 1
    replay = await send(router, source, message(f"!oz model {choices[0]}", 104))
    assert "expired" in replay.text and len(await rows(db, Action)) == 1


async def test_variants_keep_native_default_separate_from_none_and_only_change_current_model(db):
    router, _binding, source, _catalog, _execution, _commands, _worker, _audience = await setup(db)
    menu = await send(router, source, message("!oz variants"))
    choices = tokens(menu.text, "variant")
    assert len(choices) == 5
    assert "none (current)" in menu.text and "OpenCode default variant" in menu.text
    await send(router, source, message(f"!oz variant {choices[-1]}", 102))
    action = (await rows(db, Action))[0]
    target = action.payload["selection"]["target"]
    assert target == {
        "provider_id": "synthetic-provider",
        "model_id": "Case/Alias",
        "variant": "high",
    }


async def test_viewer_can_read_models_without_receiving_mutation_tokens(db):
    router, _binding, source, _catalog, _execution, _commands, _worker, _audience = await setup(db)
    async with db.sessions.begin() as session:
        await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
        session.add(Grant(realm_id="realm", user_id=7, project_id="project", role="viewer"))
    menu, choices = await model_menu(router, source)
    assert not choices and "operator access" in menu.text
    assert not await rows(db, Action)


async def test_unqualified_backend_exposes_readonly_catalog_without_model_choice_tokens(db):
    router, _binding, source, _catalog, execution, _commands, _worker, _audience = await setup(db)
    execution.model_supported = False
    menu, choices = await model_menu(router, source)
    assert not choices and "backend support" in menu.text
    assert not await rows(db, Action)


@pytest.mark.parametrize("change", ["actor", "binding", "catalog", "expired", "wrong-command"])
async def test_stolen_stale_or_wrong_kind_choice_never_queues_an_action(db, change):
    router, binding, source, catalog, _execution, _commands, _worker, _audience = await setup(db)
    _menu, choices = await model_menu(router, source)
    item = message(f"!oz model {choices[0]}", 103)
    if change == "actor":
        item = item.model_copy(update={"author_id": 8})
    elif change == "binding":
        async with db.sessions.begin() as session:
            await session.execute(
                update(Binding).where(Binding.id == binding.id).values(revision=2)
            )
    elif change == "catalog":
        catalog.snapshot = catalog.snapshot.model_copy(
            update={"items": catalog.snapshot.items[:-1]}
        )
    elif change == "expired":
        async with db.sessions.begin() as session:
            await session.execute(
                update(ControlToken).where(ControlToken.kind == CHOICE_KIND).values(expires_at=0)
            )
    else:
        item = item.model_copy(update={"text": f"!oz variant {choices[0]}"})
    await send(router, source, item)
    assert not await rows(db, Action)


async def test_concurrent_replies_to_one_choice_have_one_winner(db):
    router, _binding, source, _catalog, _execution, _commands, _worker, _audience = await setup(db)
    _menu, choices = await model_menu(router, source)
    items = [message(f"!oz model {choices[0]}", identity) for identity in (103, 104)]
    source.messages.update({item.message_id: item for item in items})
    await asyncio.gather(*(router.route(item) for item in items))
    actions = await rows(db, Action)
    assert len(actions) == 1 and actions[0].state == "queued"


async def test_source_edit_during_catalog_read_is_rejected_before_choice_is_committed(db):
    router, _binding, source, catalog, _execution, _commands, _worker, _audience = await setup(db)
    _menu, choices = await model_menu(router, source)
    item = message(f"!oz model {choices[0]}", 103)

    async def edited():
        source.messages[103] = item.model_copy(update={"revision": 1, "text": "changed control"})

    catalog.hook = edited
    await send(router, source, item)
    assert not await rows(db, Action)


async def test_final_sql_transaction_rechecks_operate_grant_before_consuming_token(db):
    router, _binding, source, _catalog, _execution, commands, _worker, _audience = await setup(db)
    _menu, choices = await model_menu(router, source)
    original = commands.current
    operate_reads = 0

    async def revoked(binding, item, permission=Permission.VIEW):
        nonlocal operate_reads
        current = await original(binding, item, permission)
        if permission == Permission.OPERATE:
            operate_reads += 1
            if operate_reads == 2:
                async with db.sessions.begin() as session:
                    await session.execute(
                        update(Grant).where(Grant.user_id == 7).values(active=False)
                    )
                    session.add(
                        Grant(realm_id="realm", user_id=7, project_id="project", role="viewer")
                    )
        return current

    commands.current = revoked
    await send(router, source, message(f"!oz model {choices[0]}", 103))
    assert not await rows(db, Action)
    assert all(not row.used for row in await rows(db, ControlToken) if row.kind == CHOICE_KIND)


@pytest.mark.parametrize("change", ["token-reset", "token-expired", "source-edit"])
async def test_dispatch_rechecks_consumed_choice_and_original_human_source(db, change):
    router, _binding, source, _catalog, execution, _commands, worker, _audience = await setup(db)
    _menu, choices = await model_menu(router, source)
    item = message(f"!oz model {choices[0]}", 103)
    await send(router, source, item)
    action = (await rows(db, Action))[0]
    if change == "source-edit":
        source.messages[103] = item.model_copy(update={"revision": 1})
    else:
        async with db.sessions.begin() as session:
            await session.execute(
                update(ControlToken)
                .where(ControlToken.token_hash == action.payload["selection_token_sha256"])
                .values(**({"used": False} if change == "token-reset" else {"expires_at": 0}))
            )
    assert await worker.advance(action.id) == "held"
    assert not execution.submitted


async def test_paused_binding_holds_new_setting_without_resuming_other_work(db):
    router, binding, source, _catalog, execution, _commands, worker, _audience = await setup(db)
    _menu, choices = await model_menu(router, source)
    await QueueService(worker.bindings).pause(binding.id, "realm", 7, binding.revision)
    await send(router, source, message(f"!oz model {choices[0]}", 103))
    action = (await rows(db, Action))[0]
    assert action.state == "held" and await worker.advance(action.id) == "held"
    assert not execution.submitted


async def test_ambiguous_model_request_blocks_subsequent_settings_and_prompts_without_retry(db):
    router, binding, source, _catalog, execution, _commands, worker, _audience = await setup(db)
    _menu, choices = await model_menu(router, source)
    await send(router, source, message(f"!oz model {choices[0]}", 103))
    first = (await rows(db, Action))[0]
    execution.mode = "timeout"
    assert await worker.advance(first.id) == "ambiguous"
    execution.mode = "success"
    await send(router, source, message(f"!oz model {choices[1]}", 104))
    second = next(a for a in await rows(db, Action) if a.id != first.id)
    item = message("a new prompt", 105)
    source.messages[105] = item
    prompt = await QueueService(worker.bindings).receive(binding.id, item)
    assert await worker.advance(second.id) == "queued"
    assert await worker.advance(prompt.action_id) == "queued"
    assert await worker.advance(first.id) == "ambiguous"
    assert len(execution.submitted) == 1


async def test_settings_are_serialized_in_their_original_queue_order(db):
    router, _binding, source, _catalog, execution, _commands, worker, _audience = await setup(db)
    _menu, choices = await model_menu(router, source)
    await send(router, source, message(f"!oz model {choices[0]}", 103))
    await send(router, source, message(f"!oz model {choices[1]}", 104))
    actions = sorted(await rows(db, Action), key=lambda x: (x.created_at, x.id))
    assert await worker.advance(actions[1].id) == "queued" and not execution.submitted
    assert await worker.advance(actions[0].id) == "completed" and len(execution.submitted) == 1
