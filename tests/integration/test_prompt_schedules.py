"""Synthetic Humans, clock and Native with a real isolated encrypted DB and outbox.

Nothing here is live Native, Zulip or Human evidence.
"""

import json
from datetime import datetime
from html import unescape
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import select, update

from jt_oz_bridge.config import Runtime
from jt_oz_bridge.domain.schedules import SCHEDULE_TOKEN, ScheduleFire
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.dispatch import Dispatcher
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.services.prompt_schedules import PromptSchedules
from jt_oz_bridge.services.routed_output import RoutedOutbox
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.models import Action, Delivery, Grant
from jt_oz_bridge.storage.schedule_models import PromptSchedule
from tests.integration.test_dispatch import SyntheticExecution
from tests.integration.test_router import Source, message, send
from tests.support import bound

TAIPEI = ZoneInfo("Asia/Taipei")
START = datetime(2026, 1, 15, 9, 7, tzinfo=TAIPEI).timestamp()
ASK = "每半小時檢查一下建置佇列的狀態, 直到 13:00 為止"
TASK = "檢查一下建置佇列的狀態"


async def rows(db, model):
    async with db.sessions() as session:
        return list((await session.scalars(select(model))).all())


class Clock:
    def __init__(self):
        self.now = START

    def __call__(self):
        return self.now


class Harness:
    def __init__(self, db):
        self.db, self.next_id, self.clock = db, 100, Clock()

    async def start(self):
        self.execution = SyntheticExecution()
        self.bindings, self.binding, _, self.audience = await bound(self.db, control=self.execution)
        self.lease = await DurableStore(self.db).acquire_lease("schedules", ttl=120)
        self.inbox, self.source = CommandInbox(self.db, "schedules", self.lease), Source()
        tokens = TokenService(self.db, fence=self.inbox.fence)
        self.router = CommandRouter(self.bindings, self.source, self.inbox)
        self.schedules = PromptSchedules(
            self.bindings,
            tokens,
            self.source,
            self.router.queue,
            timezone="Asia/Taipei",
            clock=self.clock,
        )
        self.schedules.replies = RoutedOutbox(
            Outbox(self.bindings, 77, fence=self.inbox.fence),
            realm_id="realm",
            message_limit=4000,
            topic_limit=60,
        )
        self.router.schedules = self.schedules
        self.worker = Dispatcher(
            self.bindings, self.execution, self.source, "schedules", self.lease
        )
        self.worker.schedules = self.schedules
        return self

    async def say(self, text, **changes):
        self.next_id += 1
        item = message(text, self.next_id, **changes)
        routed = await send(self.router, self.source, item)
        return item, SimpleNamespace(text=unescape(routed.text or ""), raw=routed)

    async def scheduled(self, text=ASK):
        source, proposal = await self.say(text)
        assert "!ok" in proposal.text, proposal.text
        reply = (await self.say("!ok"))[1].text
        assert "Schedule set" in reply, reply
        return source, (await rows(self.db, PromptSchedule))[-1]

    async def fires(self):
        return [a for a in await rows(self.db, Action) if a.dedupe_key.startswith("schedule:")]

    async def notices(self):
        return [unescape(d.payload["content"]) for d in await rows(self.db, Delivery)]

    async def finish(self, action_id):
        async with self.db.sessions.begin() as session:
            await session.execute(
                update(Action).where(Action.id == action_id).values(state="completed")
            )


async def harness(db):
    return await Harness(db).start()


async def test_a_repeat_is_shown_back_and_never_sent_before_confirm(db):
    h = await harness(db)
    _, proposal = await h.say(ASK)
    assert f"“{TASK}”" in proposal.text and "every 30 min" in proposal.text.lower()
    assert "until 13:00" in proposal.text and "about 8 times" in proposal.text
    assert "!send" in proposal.text and "!no" in proposal.text
    widget = json.loads(proposal.raw.widget)
    assert [c["reply"] for c in widget["extra_data"]["choices"]] == ["!ok", "!send", "!no"]
    assert not await rows(db, Action) and not h.execution.submitted
    tokens = [t for t in await rows(db, ControlToken) if t.kind == SCHEDULE_TOKEN]
    assert len(tokens) == 1 and not tokens[0].used


async def test_confirm_records_one_schedule_and_each_due_time_one_prompt(db):
    h = await harness(db)
    _, schedule = await h.scheduled()
    assert schedule.state == "active" and schedule.total == 8 and schedule.next_at == START
    assert await h.schedules.fire_once() == 1
    (first,) = await h.fires()
    assert first.operation == "prompt" and first.state == "queued" and first.actor_id == 7
    assert first.payload["text"] == TASK
    assert ScheduleFire.model_validate(first.payload["schedule"]).index == 1
    assert await h.worker.advance(first.id) == "admitted"
    (sent,) = h.execution.submitted
    assert sent[1]["text"] == TASK and sent[1]["operation"] == "prompt"
    assert any("Schedule 1/8" in n and TASK in n for n in await h.notices())
    # Nothing more is due until the next half hour.
    assert await h.schedules.fire_once() == 0
    await h.finish(first.id)
    h.clock.now += 1800
    assert await h.schedules.fire_once() == 1
    second = (await h.fires())[-1]
    assert ScheduleFire.model_validate(second.payload["schedule"]).index == 2
    assert await h.worker.advance(second.id) == "admitted"
    assert len(h.execution.submitted) == 2


async def test_a_time_that_comes_while_the_last_send_runs_is_skipped_not_piled_up(db):
    h = await harness(db)
    await h.scheduled()
    await h.schedules.fire_once()
    (first,) = await h.fires()
    await h.worker.advance(first.id)
    h.clock.now += 1800
    assert await h.schedules.fire_once() == 1
    assert len(await h.fires()) == 1
    (schedule,) = await rows(db, PromptSchedule)
    assert (schedule.sent, schedule.skipped) == (1, 1)
    assert schedule.next_at == START + 3600


async def test_times_missed_while_down_are_skipped_and_the_last_one_ends_it(db):
    h = await harness(db)
    await h.scheduled()
    await h.schedules.fire_once()
    await h.finish((await h.fires())[0].id)
    h.clock.now = START + 7 * 1800 + 5
    assert await h.schedules.fire_once() == 1
    (schedule,) = await rows(db, PromptSchedule)
    assert schedule.state == "completed" and (schedule.sent, schedule.skipped) == (2, 6)
    assert any("Schedule 8/8 (last)" in n for n in await h.notices())
    h.clock.now += 3600
    assert await h.schedules.fire_once() == 0


async def test_editing_the_original_message_stops_the_schedule_and_its_queued_send(db):
    h = await harness(db)
    source, _ = await h.scheduled()
    await h.schedules.fire_once()
    (first,) = await h.fires()
    edited = source.model_copy(update={"text": ASK.replace("13:00", "12:00"), "revision": 1})
    h.source.messages[source.message_id] = edited
    assert await h.worker.advance(first.id) == "cancelled"
    assert not h.execution.submitted
    (schedule,) = await rows(db, PromptSchedule)
    assert schedule.state == "cancelled" and schedule.status_reason == "source_changed"
    assert any("edited or deleted" in n for n in await h.notices())


async def test_the_edit_itself_is_shown_back_again_and_not_sent(db):
    h = await harness(db)
    source, _ = await h.scheduled()
    edited = source.model_copy(update={"text": ASK.replace("13:00", "12:00"), "revision": 1})
    reply = unescape((await send(h.router, h.source, edited)).text)
    assert "has stopped" in reply and "until 12:00" in reply and "!ok" in reply
    plain = source.model_copy(update={"text": "只是想問一下建置佇列", "revision": 2})
    reply = unescape((await send(h.router, h.source, plain)).text)
    assert "not sent to OpenCode" in reply
    assert not await h.fires() and not [a for a in await rows(db, Action)]


async def test_deleting_the_original_message_stops_it_at_the_next_time(db):
    h = await harness(db)
    source, _ = await h.scheduled()
    h.source.messages[source.message_id] = source.model_copy(update={"deleted": True})
    assert await h.schedules.fire_once() == 1
    assert not await h.fires()
    (schedule,) = await rows(db, PromptSchedule)
    assert schedule.state == "cancelled" and schedule.status_reason == "source_changed"


async def test_losing_the_grant_stops_it(db):
    h = await harness(db)
    await h.scheduled()
    async with db.sessions.begin() as session:
        await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
    assert await h.schedules.fire_once() == 1
    assert not await h.fires()
    (schedule,) = await rows(db, PromptSchedule)
    assert schedule.state == "cancelled" and schedule.status_reason == "authorization_revoked"


async def test_a_changed_channel_audience_sends_nothing_that_time(db):
    h = await harness(db)
    await h.scheduled()
    h.audience.users = frozenset({8})
    assert await h.schedules.fire_once() == 1
    assert not await h.fires()
    (schedule,) = await rows(db, PromptSchedule)
    assert schedule.state == "active" and (schedule.sent, schedule.skipped) == (0, 1)
    assert schedule.next_at == START + 1800


async def test_unbinding_the_topic_stops_it_without_posting(db):
    h = await harness(db)
    await h.scheduled()
    before = len(await rows(db, Delivery))
    async with db.sessions.begin() as session:
        await session.execute(
            update(Binding)
            .where(Binding.id == h.binding.id)
            .values(state="unbound", revision=Binding.revision + 1, topic_key=None)
        )
    assert await h.schedules.fire_once() == 1
    (schedule,) = await rows(db, PromptSchedule)
    assert schedule.state == "cancelled" and schedule.status_reason == "binding_changed"
    assert len(await rows(db, Delivery)) == before and not await h.fires()


async def test_a_paused_queue_skips_times_and_refuses_new_schedules(db):
    h = await harness(db)
    await h.scheduled()
    async with db.sessions.begin() as session:
        await session.execute(
            update(Binding).where(Binding.id == h.binding.id).values(dispatch_paused=True)
        )
    assert await h.schedules.fire_once() == 1
    assert not await h.fires()
    (schedule,) = await rows(db, PromptSchedule)
    assert (schedule.sent, schedule.skipped) == (0, 1)
    reply = (await h.say(ASK.replace("13:00", "12:00")))[1].text
    assert "is paused" in reply and "!go" in reply


async def test_list_and_stop_cancel_the_schedule_and_any_unsent_prompt(db):
    h = await harness(db)
    await h.scheduled()
    await h.schedules.fire_once()
    listing = (await h.say("!oz schedule"))[1].text
    assert "Every 30 min" in listing and "sent 1/8" in listing and "next 09:37" in listing
    stopped = (await h.say("!oz schedule stop"))[1].text
    assert "Stopped 1 schedule" in stopped
    (fire,) = await h.fires()
    assert fire.state == "cancelled" and fire.status_reason == "schedule_stopped"
    assert "no running schedule" in (await h.say("!oz schedule"))[1].text
    assert "no schedule of yours" in (await h.say("!oz schedule stop"))[1].text
    h.clock.now += 1800
    assert await h.schedules.fire_once() == 0


async def test_once_sends_the_message_as_written_and_sets_nothing(db):
    h = await harness(db)
    source, _ = await h.say(ASK)
    reply = (await h.say("!once"))[1].text
    assert "Sent once as written" in reply
    (action,) = await rows(db, Action)
    assert action.dedupe_key == f"human:realm:{source.message_id}" and action.payload["text"] == ASK
    assert "schedule" not in action.payload and not await rows(db, PromptSchedule)
    assert await h.worker.advance(action.id) == "admitted"
    assert h.execution.submitted[0][1]["text"] == ASK
    # The offer was spent: a later `!confirm` sets nothing.
    assert "Schedule set" not in (await h.say("!ok"))[1].text
    assert not await rows(db, PromptSchedule)
    assert "No schedule is waiting" in (await h.say("!once"))[1].text


async def test_send_and_stop_are_the_everyday_words_for_once_and_stop(db):
    h = await harness(db)
    source, _ = await h.say(ASK)
    assert "Sent once as written" in (await h.say("!send"))[1].text
    (action,) = await rows(db, Action)
    assert action.payload["text"] == ASK and not await rows(db, PromptSchedule)
    await h.finish(action.id)
    await h.scheduled(ASK.replace("13:00", "12:00"))
    stopped = (await h.say("!stop"))[1].text
    assert "Stopped 1 schedule" in stopped
    (schedule,) = await rows(db, PromptSchedule)
    assert schedule.state == "cancelled" and schedule.status_reason == "stopped"


async def test_no_drops_the_offer_and_sends_nothing(db):
    h = await harness(db)
    await h.say(ASK)
    assert "Nothing was sent" in (await h.say("!no"))[1].text
    assert "Schedule set" not in (await h.say("!ok"))[1].text
    assert not await rows(db, PromptSchedule) and not await rows(db, Action)
    assert "Nothing is waiting" in (await h.say("!no"))[1].text


async def test_confirm_is_for_the_proposer_only_and_only_once(db):
    h = await harness(db)
    await h.say(ASK)
    other = (await h.say("!confirm", author_id=8))[1].text
    assert "Schedule set" not in other and not await rows(db, PromptSchedule)
    assert "Schedule set" in (await h.say("!ok"))[1].text
    assert "Schedule set" not in (await h.say("!ok"))[1].text
    assert len(await rows(db, PromptSchedule)) == 1


async def test_refused_repeats_explain_and_send_nothing(db):
    h = await harness(db)
    assert "at most every 5 minutes" in (await h.say("每分鐘檢查一下建置佇列"))[1].text
    assert "at most 96 times" in (await h.say("每 5 分鐘檢查一下建置佇列"))[1].text
    assert not await rows(db, Action) and not await rows(db, PromptSchedule)


async def test_ordinary_prompts_still_go_straight_to_the_session(db):
    h = await harness(db)
    await h.say("這個 cron 每 5 分鐘跑一次，幫我看為什麼失敗")
    await h.say("!oz send -- 每半小時檢查一下建置佇列，到 13:00")
    texts = [a.payload["text"] for a in await rows(db, Action)]
    assert texts == [
        "這個 cron 每 5 分鐘跑一次，幫我看為什麼失敗",
        "每半小時檢查一下建置佇列，到 13:00",
    ]
    assert not await rows(db, PromptSchedule)


async def test_without_composition_a_repeat_is_an_ordinary_prompt_and_a_timed_one_is_refused(db):
    h = await harness(db)
    await h.scheduled()
    await h.schedules.fire_once()
    (fire,) = await h.fires()
    h.worker.schedules = None
    assert await h.worker.advance(fire.id) == "rejected"
    assert not h.execution.submitted
    h.router.schedules = None
    await h.say(ASK.replace("13:00", "12:00"))
    assert (await rows(db, Action))[-1].payload["text"] == ASK.replace("13:00", "12:00")


def test_schedules_need_the_enrolled_runtime():
    assert Runtime().prompt_schedules_enabled is False
    with pytest.raises(ValueError, match="prompt_schedules_require_enabled_enrolled_runtime"):
        Runtime(prompt_schedules_enabled=True)


async def test_migration38_adds_only_the_empty_table_and_refuses_downgrade(tmp_path):
    import os

    from alembic import command
    from alembic.config import Config
    from sqlalchemy import inspect, text

    from jt_oz_bridge.security.cipher import EnvelopeCipher
    from jt_oz_bridge.storage.database import CURRENT_REVISION, Database, migrate

    assert CURRENT_REVISION == "0038_prompt_schedules"
    value = Database(
        "sqlite+aiosqlite:///" + str(tmp_path / "schema37.db"),
        cipher=EnvelopeCipher({"test": os.urandom(32)}, "test"),
    )

    def config(connection):
        cfg = Config()
        cfg.set_main_option("script_location", "src/jt_oz_bridge/storage/migrations")
        cfg.attributes["connection"] = connection
        return cfg

    async def tables():
        async with value.engine.connect() as connection:
            return await connection.run_sync(lambda c: set(inspect(c).get_table_names()))

    try:
        async with value.engine.begin() as connection:
            await connection.run_sync(
                lambda c: command.upgrade(config(c), "0037_live_source_retention")
            )
        before = await tables()
        await migrate(value.engine)
        assert await value.ready()
        assert await tables() - before == {"prompt_schedules"}
        async with value.engine.connect() as connection:
            assert await connection.scalar(text("SELECT COUNT(*) FROM prompt_schedules")) == 0
        with pytest.raises(ValueError, match="prompt_schedules_must_be_preserved"):
            async with value.engine.begin() as connection:
                await connection.run_sync(
                    lambda c: command.downgrade(config(c), "0037_live_source_retention")
                )
        assert await value.ready()
    finally:
        await value.close()
