import pytest
from pydantic import ValidationError
from sqlalchemy import update

from jt_oz_bridge.domain.catalog import CatalogPage, CatalogSession
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.discovery import DiscoveryService, RegisteredCatalog
from jt_oz_bridge.storage.control_models import EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Action, Grant
from tests.integration.test_backend_registry import OTHER, registered
from tests.integration.test_router import count, message
from tests.support import REF


class SyntheticCatalog:
    def __init__(self, contract, size=25):
        self.contract, self.size, self.calls = contract, size, []
        self.change = None

    def contract_for_project(self, scope):
        return self.contract

    async def list_sessions(self, scope, *, search, cursor, limit):
        self.calls.append((scope, search, cursor, limit))
        offset = int(cursor.split(":")[1]) if cursor else 0
        items = tuple(
            CatalogSession(
                reference=SessionRef(**scope.model_dump(), upstream_session_id=f"session:{index}"),
                title=f"Work {index}",
            )
            for index in range(offset, min(offset + limit, self.size))
        )
        page = CatalogPage(
            scope=scope,
            contract_sha256=self.contract,
            search=search,
            cursor=cursor,
            items=items,
            next_cursor=f"position:{offset + limit}" if offset + limit < self.size else None,
        )
        return self.change(page) if self.change else page


async def discovery(db):
    _registry, bindings, first, second = await registered(db)
    catalogs = {
        REF.backend_id: SyntheticCatalog(first.contract_hash),
        OTHER.backend_id: SyntheticCatalog(second.contract_hash),
    }
    return DiscoveryService(
        bindings,
        {
            ref.backend_id: RegisteredCatalog(
                ref.backend_identity,
                catalogs[ref.backend_id].contract,
                {ref.project_id: ref.canonical_directory},
                catalogs[ref.backend_id],
            )
            for ref in (REF, OTHER)
        },
    ), catalogs


async def test_authorized_backends_projects_and_session_pages_use_exact_project_and_query(db):
    service, clients = await discovery(db)
    backends = await service.backends(message())
    assert [item.backend_id for item in backends.items] == ["backend", "second"]
    projects = await service.projects(message(), backend_id="second")
    assert [item.scope.project_id for item in projects.items] == ["second-project"]
    page = await service.sessions(message(), "second-project", search="!oz literal search")
    assert len(page.items) == 10 and page.next_cursor == "position:10"
    next_page = await service.sessions(
        message(), "second-project", search="!oz literal search", cursor=page.next_cursor
    )
    final = await service.sessions(
        message(), "second-project", search="!oz literal search", cursor=next_page.next_cursor
    )
    assert len(final.items) == 5 and final.next_cursor is None
    assert clients["backend"].calls == []
    assert clients["second"].calls[0][1:] == ("!oz literal search", None, 10)
    assert await count(db, Action) == 0


async def test_one_unprivileged_channel_member_blocks_project_and_all_native_catalog_reads(db):
    service, clients = await discovery(db)
    service.bindings.audience.users = frozenset({7, 8, 999})
    assert (await service.projects(message())).items == ()
    assert (await service.backends(message())).items == ()
    with pytest.raises(AccessDenied):
        await service.sessions(message(), "project")
    assert all(not client.calls for client in clients.values())


@pytest.mark.parametrize(
    "changes",
    [
        {"is_bot": True},
        {"deleted": True},
        {"revision": 1},
        {"author_id": 999},
        {"realm_id": "foreign"},
    ],
)
async def test_nonoriginal_or_unauthorized_subject_never_reads_a_native_catalog(db, changes):
    service, clients = await discovery(db)
    with pytest.raises(AccessDenied):
        await service.sessions(message(**changes), "project")
    assert all(not client.calls for client in clients.values())


@pytest.mark.parametrize("change", ["private", "topic", "bot"])
async def test_unverified_output_target_is_refused_before_read(db, change):
    service, clients = await discovery(db)
    audience = service.bindings.audience
    if change == "private":
        audience.private = False
    else:
        original = audience.inspect

        async def changed(realm, channel, topic):
            current = await original(realm, channel, topic)
            return current.model_copy(
                update={"canonical_topic": "different"}
                if change == "topic"
                else {"untrusted_bot_ids": frozenset({999})}
            )

        audience.inspect = changed
    with pytest.raises((AccessDenied, Conflict)):
        await service.sessions(message(), "project")
    assert not clients["backend"].calls


@pytest.mark.parametrize("change", ["disabled", "unverified", "identity", "contract"])
async def test_changed_or_disabled_enrollment_does_not_fallback_to_other_backend(db, change):
    service, clients = await discovery(db)
    if change in {"disabled", "unverified"}:
        async with db.sessions.begin() as session:
            await session.execute(
                update(EnrolledBackend)
                .where(EnrolledBackend.id == "backend")
                .values(**({"enabled": False} if change == "disabled" else {"verified": False}))
            )
        expected = AccessDenied
    elif change == "identity":
        async with db.sessions.begin() as session:
            await session.execute(
                update(EnrolledBackend)
                .where(EnrolledBackend.id == "backend")
                .values(identity="replacement")
            )
        expected = Conflict
    else:
        clients["backend"].contract = "c" * 64
        expected = Conflict
    with pytest.raises(expected):
        await service.sessions(message(), "project")
    assert all(not client.calls for client in clients.values())
    assert len((await service.sessions(message(), "second-project")).items) == 10


@pytest.mark.parametrize(
    "change", ["query", "cursor", "scope", "contract", "duplicate", "foreign_item", "repeat_cursor"]
)
async def test_native_catalog_reply_must_match_frozen_request_and_typed_bounds(db, change):
    service, clients = await discovery(db)

    def tamper(page):
        if change == "query":
            return page.model_copy(update={"search": "different"})
        if change == "cursor":
            return page.model_copy(update={"cursor": "position:0"})
        if change == "scope":
            return page.model_copy(
                update={"scope": page.scope.model_copy(update={"project_id": "foreign"})}
            )
        if change == "contract":
            return page.model_copy(update={"contract_sha256": "c" * 64})
        if change == "duplicate":
            return page.model_copy(update={"items": (page.items[0], page.items[0])})
        if change == "foreign_item":
            return page.model_copy(
                update={"items": (page.items[0].model_copy(update={"reference": OTHER}),)}
            )
        return page.model_copy(update={"cursor": "repeat", "next_cursor": "repeat"})

    clients["backend"].change = tamper
    with pytest.raises((Conflict, ValidationError)):
        await service.sessions(message(), "project")
    assert not clients["second"].calls


@pytest.mark.parametrize("change", ["role", "audience", "project"])
async def test_revocation_during_catalog_read_prevents_export_of_received_items(db, change):
    service, clients = await discovery(db)
    client = clients["backend"]
    original = client.list_sessions

    async def changing(scope, **options):
        page = await original(scope, **options)
        if change == "audience":
            service.bindings.audience.users = frozenset({7, 8, 999})
        else:
            async with db.sessions.begin() as session:
                if change == "role":
                    await session.execute(
                        update(Grant)
                        .where(Grant.user_id == 8, Grant.project_id == "project")
                        .values(active=False)
                    )
                else:
                    await session.execute(
                        update(EnrolledProject)
                        .where(EnrolledProject.id == "project")
                        .values(enabled=False)
                    )
        return page

    client.list_sessions = changing
    with pytest.raises((Conflict, AccessDenied)):
        await service.sessions(message(), "project")


async def test_project_pages_are_deduplicated_despite_multiple_grants_and_progress_over_ten(db):
    service, clients = await discovery(db)
    async with db.sessions.begin() as session:
        for index in range(15):
            identity = f"project:{index:02}"
            session.add(
                EnrolledProject(
                    id=identity,
                    backend_id="backend",
                    realm_id="realm",
                    canonical_directory=f"/workspace/{index}",
                    enabled=True,
                )
            )
            for user in (7, 8):
                for role in ("viewer", "operator"):
                    session.add(
                        Grant(realm_id="realm", user_id=user, project_id=identity, role=role)
                    )
    registrations = dict(service.catalogs)
    registrations["backend"] = RegisteredCatalog(
        REF.backend_identity,
        "a" * 64,
        {
            REF.project_id: REF.canonical_directory,
            **{f"project:{index:02}": f"/workspace/{index}" for index in range(15)},
        },
        clients["backend"],
    )
    service = DiscoveryService(service.bindings, registrations)
    first = await service.projects(message(), backend_id="backend")
    second = await service.projects(message(), backend_id="backend", after=first.next_after)
    assert len(first.items) == 10 and len(second.items) == 6 and second.next_after is None
    ids = [item.scope.project_id for item in first.items + second.items]
    assert len(set(ids)) == 16 and all(not client.calls for client in clients.values())


async def test_recent_means_own_recent_bindings_and_rechecks_current_audience_and_identity(db):
    service, clients = await discovery(db)
    binding = await service.bindings.bind("realm", 7, 10, "Original work", REF)
    assert (await service.recent(message(author_id=8))) == ()
    recent = await service.recent(message())
    assert (
        len(recent) == 1
        and recent[0].reference == REF
        and recent[0].title_at_binding == binding.title
    )
    service.bindings.audience.users = frozenset({7, 8, 999})
    assert (await service.recent(message())) == ()
    assert all(not client.calls for client in clients.values())


async def test_backend_pages_never_invent_a_final_page_or_repeat_an_entry(db):
    service, clients = await discovery(db)
    registrations = dict(service.catalogs)
    async with db.sessions.begin() as session:
        for index in range(11):
            backend, project = f"extra:{index:02}", f"extra-project:{index:02}"
            identity, directory = f"test-instance:{index}", f"/workspace/extra/{index}"
            session.add(
                EnrolledBackend(
                    id=backend,
                    identity=identity,
                    contract_hash="c" * 64,
                    enabled=True,
                    verified=True,
                    version="synthetic",
                )
            )
            session.add(
                EnrolledProject(
                    id=project,
                    backend_id=backend,
                    realm_id="realm",
                    canonical_directory=directory,
                    enabled=True,
                )
            )
            for user in (7, 8):
                session.add(
                    Grant(realm_id="realm", user_id=user, project_id=project, role="viewer")
                )
            client = SyntheticCatalog("c" * 64)
            registrations[backend] = RegisteredCatalog(
                identity, "c" * 64, {project: directory}, client
            )
    service = DiscoveryService(service.bindings, registrations)
    first = await service.backends(message())
    second = await service.backends(message(), after=first.next_after)
    assert len(first.items) == 10 and len(second.items) == 3 and second.next_after is None
    assert len({item.backend_id for item in first.items + second.items}) == 13
    assert all(not registered.client.calls for registered in registrations.values())


async def test_project_directory_change_requires_explicit_catalog_registration_reload(db):
    service, clients = await discovery(db)
    async with db.sessions.begin() as session:
        await session.execute(
            update(EnrolledProject)
            .where(EnrolledProject.id == "project")
            .values(canonical_directory="/workspace/changed")
        )
    with pytest.raises(Conflict, match="contract_unavailable"):
        await service.sessions(message(), "project")
    assert not clients["backend"].calls


async def test_replaced_backend_does_not_inherit_old_recent_binding_titles(db):
    service, clients = await discovery(db)
    await service.bindings.bind("realm", 7, 10, "Original work", REF)
    async with db.sessions.begin() as session:
        await session.execute(
            update(EnrolledBackend)
            .where(EnrolledBackend.id == "backend")
            .values(identity="replacement")
        )
    registrations = dict(service.catalogs)
    registrations["backend"] = RegisteredCatalog(
        "replacement", "a" * 64, {REF.project_id: REF.canonical_directory}, clients["backend"]
    )
    service = DiscoveryService(service.bindings, registrations)
    assert await service.recent(message()) == ()


async def test_oversized_native_page_is_revalidated_even_if_adapter_bypasses_model_constructor(db):
    service, clients = await discovery(db)
    clients["backend"].change = lambda page: page.model_copy(
        update={"items": page.items + (page.items[0],)}
    )
    with pytest.raises(ValidationError):
        await service.sessions(message(), "project")


async def test_public_project_page_retains_two_independent_audience_observations(db):
    service, _clients = await discovery(db)
    original, calls = service.bindings.audience.inspect, []

    async def inspect(*args):
        calls.append(args)
        return await original(*args)

    service.bindings.audience.inspect = inspect
    page = await service.projects(message())
    assert len(page.items) == 2 and len(calls) == 2
    assert not isinstance(page, tuple)
