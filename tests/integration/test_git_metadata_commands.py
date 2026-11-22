"""Git command routing with real own transactions and synthetic Human/Native gateways."""

import asyncio
import hashlib
from dataclasses import replace
from html import unescape

import pytest
from sqlalchemy import update

from jt_oz_bridge.domain.git import NativeGitContext
from jt_oz_bridge.domain.native_metadata import GitFileMetadata, NativeMetadataSnapshot
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Action, Grant
from tests.integration.test_native_metadata_commands import Catalog, rows, setup, token
from tests.integration.test_router import message, send


def report(ref, contract, *, count=23, branch="feature/original", prefix="src/file"):
    items = tuple(
        GitFileMetadata(
            native_id=hashlib.sha256((prefix + str(i)).encode()).hexdigest(),
            name=prefix + str(i),
            change="modified",
            additions=i,
            deletions=1,
        )
        for i in range(count)
    )
    return NativeMetadataSnapshot(
        reference=ref,
        contract_sha256=contract,
        kind="git",
        items=items,
        git=NativeGitContext(
            provider="git",
            branch=branch,
            default_branch="main",
            reported_files=count,
            native_project_root_sha256="a" * 64,
        ),
    )


async def configured(db, maximum=10000, **kwargs):
    router, binding, source, catalog, commands, audience = await setup(db, maximum)
    catalog.snapshots["git"] = report(catalog.ref, catalog.contract, **kwargs)
    catalog.kinds = frozenset(catalog.snapshots)
    return router, binding, source, catalog, commands, audience


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
@pytest.mark.parametrize("command", ["!oz git", "!oz git status"])
async def test_git_uses_original_binding_and_reported_data_without_verified_index_or_actions(
    db, locale, command
):
    router, binding, source, catalog, commands, audience = await configured(db, count=2)
    async with db.sessions.begin() as session:
        from jt_oz_bridge.storage.models import Preference

        session.add(Preference(principal="user:realm:7", locale=locale))
    reply = await send(router, source, message(command))
    assert ("Git 狀態" if locale == "zh-TW" else "Git status") in reply.text
    assert "feature/original" in unescape(reply.text) and "src/file0" in unescape(reply.text)
    assert "HEAD" in unescape(reply.text) and (
        "暫存區" if locale == "zh-TW" else "index"
    ) in unescape(reply.text)
    assert await router.route(source.messages[101]) == reply and catalog.calls == ["git"]
    assert not await rows(db, Action)


async def test_zero_report_does_not_claim_a_clean_repository(db):
    router, binding, source, catalog, commands, audience = await configured(
        db, count=0, branch=None
    )
    reply = await send(router, source, message("!oz git"))
    assert "not reported" in reply.text and "may still not be clean" in reply.text
    assert "repository is clean" not in reply.text and not await rows(db, Action)


@pytest.mark.parametrize("changed_context", ["branch", "root"])
async def test_git_page_is_bound_to_actor_kind_branch_and_whole_snapshot(db, changed_context):
    router, binding, source, catalog, commands, audience = await configured(db)
    first = await send(router, source, message("!oz git status"))
    page = token(first.text, "git")
    for mid, command, actor in [(102, "!oz git " + page, 8), (103, "!oz agents " + page, 7)]:
        result = await send(router, source, message(command, mid, author_id=actor))
        assert "expired" in result.text
    next_page = await send(router, source, message("!oz git status " + page, 104))
    assert "src/file9" in unescape(next_page.text)
    second = token(next_page.text, "git")
    current = catalog.snapshots["git"]
    catalog.snapshots["git"] = current.model_copy(
        update={
            "git": current.git.model_copy(
                update={"branch": "different-branch"}
                if changed_context == "branch"
                else {"native_project_root_sha256": "b" * 64}
            )
        }
    )
    stale = await send(router, source, message("!oz git " + second, 105))
    assert "expired" in stale.text
    assert not await rows(db, Action)


async def test_same_git_page_race_consumes_only_one_preview(db):
    router, binding, source, catalog, commands, audience = await configured(db)
    page = token((await send(router, source, message("!oz git"))).text, "git")
    results = await asyncio.gather(
        *(send(router, source, message("!oz git " + page, mid)) for mid in (102, 103))
    )
    assert sum("src/file9" in unescape(item.text) for item in results) == 1
    assert sum("expired" in item.text for item in results) == 1
    assert not await rows(db, Action)


@pytest.mark.parametrize(
    "failure", ["grant", "source-edit", "source-delete", "audience", "binding"]
)
async def test_git_rechecks_source_audience_and_role_after_native_read(db, failure):
    router, binding, source, catalog, commands, audience = await configured(db)
    item = message("!oz git")
    source.messages[101] = item

    async def change():
        if failure == "source-edit":
            source.messages[101] = item.model_copy(update={"revision": 1})
        elif failure == "source-delete":
            source.messages[101] = item.model_copy(update={"deleted": True})
        elif failure == "audience":
            audience.private = False
        else:
            async with db.sessions.begin() as session:
                if failure == "grant":
                    await session.execute(
                        update(Grant).where(Grant.user_id == 7).values(active=False)
                    )
                else:
                    await session.execute(
                        update(Binding)
                        .where(Binding.id == binding.id)
                        .values(revision=Binding.revision + 1)
                    )

    catalog.hook = change
    with pytest.raises((Conflict, AccessDenied)):
        await commands.route(binding, item, "en", "git", "")
    assert not await rows(db, Action) and not await rows(db, ControlToken)


@pytest.mark.parametrize(
    "failure",
    [
        "missing-context",
        "verified-claim",
        "wrong-count",
        "foreign-kind",
        "foreign-reference",
        "expired",
    ],
)
async def test_invalid_git_report_is_not_rendered(db, failure):
    router, binding, source, catalog, commands, audience = await configured(db)
    current = catalog.snapshots["git"]
    if failure == "missing-context":
        current = current.model_copy(update={"git": None})
    elif failure == "verified-claim":
        current = current.model_copy(
            update={"git": current.git.model_copy(update={"checks_verified": True})}
        )
    elif failure == "wrong-count":
        current = current.model_copy(
            update={"git": current.git.model_copy(update={"reported_files": 999})}
        )
    elif failure == "foreign-kind":
        current = current.model_copy(update={"kind": "commands"})
    elif failure == "foreign-reference":
        current = current.model_copy(
            update={
                "reference": current.reference.model_copy(update={"canonical_directory": "/other"})
            }
        )
    else:
        catalog.live = False
    catalog.snapshots["git"] = current
    result = await send(router, source, message("!oz git"))
    assert "expired" in result.text and "feature/original" not in result.text
    assert not await rows(db, Action)


@pytest.mark.parametrize("maximum", [512, 700, 1200, 10000])
async def test_git_hostile_names_branches_and_punctuation_stay_inert_and_bounded(db, maximum):
    router, binding, source, catalog, commands, audience = await configured(
        db,
        maximum,
        prefix="@**all** !oz stop " + ("[*()#|]" * 20 + "/") * 5,
        branch="@**all** !oz stop " + "[*()#|]" * 100,
    )
    result = await send(router, source, message("!oz git"))
    assert len(result.text) <= maximum - 100 and "@**all**" not in result.text
    assert "!oz git " in result.text and "expired" not in result.text
    assert not await rows(db, Action)


async def test_git_unqualified_and_mutating_verbs_never_call_native(db):
    router, binding, source, catalog, commands, audience = await configured(db)
    catalog.kinds = frozenset({"usage"})
    result = await send(router, source, message("!oz git"))
    assert "available for this conversation" in result.text
    for mid, verb in enumerate(
        ["commit", "push", "diff", "reset", "clean", "checkout", "worktree", "check", "checks"], 102
    ):
        result = await send(router, source, message("!oz git " + verb + " anything", mid))
        assert "can't be run" in result.text
    assert not catalog.calls and not await rows(db, Action) and not await rows(db, ControlToken)


async def test_consumer_pipeline_delivers_git_to_same_topic_and_does_not_execute_agent(db):
    from tests.integration.test_consumer_runtime import post_containing
    from tests.integration.test_consumer_runtime import setup as graph_setup

    previous, server, native, results, binding, pulse = await graph_setup(db)
    ref = reference(binding)
    backend = previous.backends[ref.backend_id]
    catalog = Catalog(ref, backend.registered.contract_sha256)
    catalog.snapshots["git"] = report(ref, catalog.contract, count=2)
    catalog.kinds = frozenset(catalog.snapshots)
    backend = replace(backend, metadata={ref: catalog})
    pipeline = ConsumerPipeline(
        db,
        previous.fence,
        previous.scope,
        {ref.backend_id: backend},
        interval=0.02,
        delivery_interval=0,
    )
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("!oz git status", 101)
        reply = await post_containing(server, "Git status")
        assert reply["sender_id"] == 11 and reply["subject"] == binding.topic
        await asyncio.sleep(0.1)
        assert runtime.healthy and not native.submitted and catalog.calls == ["git"]
        assert not await rows(db, Action)
    finally:
        await runtime.close()


@pytest.mark.parametrize("maximum", [512, 700, 1200])
@pytest.mark.parametrize("all_hidden", [False, True])
async def test_git_disclosure_policy_is_applied_to_snapshot_validation_and_visible_output(
    db, maximum, all_hidden
):
    from jt_oz_bridge.adapters.opencode.native_metadata import project_git

    router, binding, source, catalog, commands, audience = await configured(db, maximum, count=0)
    raw = [
        {
            "file": ".jt-oz-incoming-service/SYNTHETIC_PRIVATE_FILENAME",
            "status": "added",
            "additions": 1,
            "deletions": 0,
        }
    ]
    if not all_hidden:
        raw.append({"file": "src/public.py", "status": "modified", "additions": 1, "deletions": 0})
    context, items = project_git(
        {"branch": {"current": "@**all** " + "[x]" * 100}}, raw, root_sha256="a" * 64
    )
    catalog.snapshots["git"] = NativeMetadataSnapshot(
        reference=catalog.ref,
        contract_sha256=catalog.contract,
        kind="git",
        git=context,
        items=items,
    )
    reply = await send(router, source, message("!oz git"))
    text = unescape(reply.text)
    assert "SYNTHETIC_PRIVATE_FILENAME" not in text and ".jt-oz-incoming-" not in text
    assert "1 protected paths hidden" in text and len(reply.text) <= maximum - 100
    assert ("Nothing to show" in text) if all_hidden else ("src/public.py" in text)
    assert "No changes reported" not in text and not await rows(db, Action)


async def test_forged_sensitive_git_item_cannot_bypass_the_shared_policy_on_revalidation(db):
    router, binding, source, catalog, commands, audience = await configured(db, count=1)
    current = catalog.snapshots["git"]
    name = ".env"
    forged = current.items[0].model_copy(
        update={"name": name, "native_id": hashlib.sha256(name.encode()).hexdigest()}
    )
    catalog.snapshots["git"] = current.model_copy(update={"items": (forged,)})
    result = await send(router, source, message("!oz git"))
    assert "expired" in result.text and ".env" not in result.text and not await rows(db, Action)
