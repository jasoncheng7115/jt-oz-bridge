"""One private channel per project: a listed channel only offers its own projects.

Real ownDB and discovery with synthetic catalogs; no Zulip channel is created here.
"""

from html import unescape
from types import MappingProxyType

import pytest
from pydantic import ValidationError

from jt_oz_bridge.config import Realm
from jt_oz_bridge.security.policy import AccessDenied
from tests.integration.test_backend_registry import OTHER
from tests.integration.test_discovery import discovery
from tests.integration.test_router import message
from tests.integration.test_unbound_router import pipeline, send
from tests.support import REF


def realm(**changes):
    return Realm.model_validate(
        {
            "id": "realm",
            "url": "https://z.invalid/",
            "bot_email": "b@z.invalid",
            "api_key_ref": "env:PRIVATE_TEST_KEY",
            "allowed_channel_ids": [10, 11],
            **changes,
        }
    )


def test_channel_projects_must_name_allowed_channels_once():
    assert realm().channel_projects == []
    ok = realm(channel_projects=[{"channel_id": 11, "projects": ["second-project"]}])
    assert ok.channel_projects[0].projects == ["second-project"]
    for bad in (
        [{"channel_id": 12, "projects": ["project"]}],
        [{"channel_id": 11, "projects": ["a"]}, {"channel_id": 11, "projects": ["b"]}],
        [{"channel_id": 11, "projects": []}],
    ):
        with pytest.raises(ValidationError):
            realm(channel_projects=bad)


async def test_a_listed_channel_offers_only_its_projects(db):
    service, _catalogs = await discovery(db)
    assert {p.scope.project_id for p in (await service.projects(message())).items} == {
        REF.project_id,
        OTHER.project_id,
    }
    service.channel_projects = MappingProxyType({10: frozenset({OTHER.project_id})})
    page = await service.projects(message())
    assert [p.scope.project_id for p in page.items] == [OTHER.project_id]
    with pytest.raises(AccessDenied):
        await service.project(message(), REF.project_id)
    await service.project(message(), OTHER.project_id)


async def test_an_unlisted_channel_keeps_every_project(db):
    service, _catalogs = await discovery(db)
    service.channel_projects = MappingProxyType({99: frozenset({OTHER.project_id})})
    page = await service.projects(message())
    assert {p.scope.project_id for p in page.items} == {REF.project_id, OTHER.project_id}


async def test_new_topic_menu_in_a_project_channel_lists_only_that_project(db):
    router, source, *_ = await pipeline(db)
    everything = await send(router, source, message("!go", 201))
    assert f"   {REF.project_id}\n" in unescape(everything.text)
    router.unbound.discovery.channel_projects = MappingProxyType(
        {10: frozenset({OTHER.project_id})}
    )
    narrowed = await send(router, source, message("!go", 202, topic="Another topic"))
    assert f"   {OTHER.project_id}\n" in unescape(narrowed.text)
    assert f"   {REF.project_id}\n" not in unescape(narrowed.text)
