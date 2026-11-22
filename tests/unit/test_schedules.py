"""Pure reading of repeat requests; no clock, database or Native."""

from datetime import datetime
from zoneinfo import ZoneInfo

import pytest
from pydantic import ValidationError

from jt_oz_bridge.domain.schedules import (
    MAX_FIRES,
    EndClock,
    ScheduleAsk,
    ScheduleFire,
    ScheduleRefused,
    detect,
    ends_at,
    fire_count,
    looks_scheduled,
    scheduled_text,
)

TAIPEI = ZoneInfo("Asia/Taipei")
NOW = datetime(2026, 11, 5, 14, 7, tzinfo=TAIPEI)


@pytest.mark.parametrize(
    ("text", "seconds", "task", "end"),
    [
        (
            "每半小時看一下建置有沒有新結果, 直到 18:00 為止",
            1800,
            "看一下建置有沒有新結果",
            "18:00",
        ),
        ("幫我每半小時看一下建置，到 6 點", 1800, "幫我看一下建置", "18:00"),
        ("每隔15分鐘檢查 CI 狀態到下午五點半", 900, "檢查 CI 狀態", "17:30"),
        ("每一個半小時看一下進度直到晚上十點", 5400, "看一下進度", "22:00"),
        ("每兩個小時提醒我喝水", 7200, "提醒我喝水", "23:59"),
        ("請每小時整理一次新的 issue", 3600, "請整理一次新的 issue", "23:59"),
        ("every 30 minutes check the build until 6pm", 1800, "check the build", "18:00"),
        ("Check the build every half hour until 18:30.", 1800, "Check the build", "18:30"),
        ("every 2 hours run the smoke tests", 7200, "run the smoke tests", "23:59"),
        ("Every ten minutes, look at the build until noon tomorrow", 600, None, None),
    ],
)
def test_plain_repeats_give_interval_task_and_end(text, seconds, task, end):
    ask = detect(text)
    assert ask is not None and ask.interval_seconds == seconds
    if task is not None:
        assert ask.text == task
        assert ends_at(ask, NOW).strftime("%H:%M") == end


@pytest.mark.parametrize(
    "text",
    [
        "這個 cron 每 5 分鐘跑一次，幫我看為什麼失敗",
        "看一下 log，裡面每小時都有一筆錯誤",
        "!oz send -- 每半小時看一下建置，到 18:00",
        "!oz steer -- 每半小時看一下建置，到 18:00",
        "每半小時看一下 /user_uploads/2/ab/report.txt 到 18:00",
        "每半小時看一下建置，到 18:00 " + "很長" * 300,
        "!oz schedule",
        "every day check the backups",
        "the job runs every 5 minutes, why does it fail?",
        "",
    ],
)
def test_ordinary_text_is_never_a_repeat(text):
    assert detect(text) is None
    assert looks_scheduled(text) is False


@pytest.mark.parametrize(
    ("text", "key"),
    [
        ("每分鐘看一下建置", "schedule.too_often"),
        ("每 3 分鐘看一下建置", "schedule.too_often"),
        ("每 13 小時看一下建置", "schedule.too_rare"),
        ("每半小時，直到 18:00", "schedule.empty"),
        ("every minute check the queue", "schedule.too_often"),
    ],
)
def test_recognized_repeats_the_bridge_will_not_run_are_refused(text, key):
    with pytest.raises(ScheduleRefused) as error:
        detect(text)
    assert error.value.key == key
    assert looks_scheduled(text) is True


def test_the_same_text_always_gives_the_same_ask():
    text = "每半小時看一下建置有沒有新結果, 直到 18:00 為止"
    assert detect(text) == detect(text)
    assert detect("@**jt-oz-bridge** " + text) is not None


@pytest.mark.parametrize(
    ("clock", "now", "expected"),
    [
        (EndClock(hour=18, minute=0), NOW, "2026-11-05 18:00"),
        # Without am/pm a morning hour already past means this evening.
        (EndClock(hour=6, minute=0), NOW, "2026-11-05 18:00"),
        (EndClock(hour=9, minute=0), NOW.replace(hour=22), "2026-11-06 09:00"),
        (EndClock(hour=2, minute=0), NOW.replace(hour=23), "2026-11-06 02:00"),
        (EndClock(hour=5, minute=30, meridiem="pm"), NOW, "2026-11-05 17:30"),
        (EndClock(hour=12, minute=0, meridiem="noon"), NOW.replace(hour=9), "2026-11-05 12:00"),
        (EndClock(hour=12, minute=0, meridiem="am"), NOW, "2026-11-06 00:00"),
        (EndClock(hour=24, minute=0), NOW, "2026-11-06 00:00"),
    ],
)
def test_end_is_the_next_matching_wall_clock_time(clock, now, expected):
    ask = ScheduleAsk(interval_seconds=1800, end=clock, text="x")
    assert ends_at(ask, now).strftime("%Y-%m-%d %H:%M") == expected


def test_end_must_be_aware_and_within_a_day():
    ask = ScheduleAsk(
        interval_seconds=1800, end=EndClock(hour=2, minute=0, meridiem="pm"), text="x"
    )
    with pytest.raises(ValueError, match="aware"):
        ends_at(ask, NOW.replace(tzinfo=None))
    # 14:00 just passed: the next 14:00 is almost a day away, still within the horizon.
    assert ends_at(ask, NOW).day == 6
    with pytest.raises(ValidationError):
        EndClock(hour=24, minute=30)
    with pytest.raises(ValidationError):
        EndClock(hour=18, minute=0, meridiem="pm")


def test_fire_count_includes_the_first_send_and_is_bounded():
    ask = ScheduleAsk(interval_seconds=1800, text="x")
    start = NOW.timestamp()
    end = NOW.replace(hour=18, minute=0).timestamp()
    assert fire_count(ask, start, end) == 8
    assert fire_count(ask, start, start + 1) == 1
    with pytest.raises(ScheduleRefused, match="schedule.ended"):
        fire_count(ask, start, start)
    many = ScheduleAsk(interval_seconds=300, text="x")
    with pytest.raises(ScheduleRefused, match="schedule.too_many"):
        fire_count(many, start, start + 300 * MAX_FIRES)


def test_a_timed_send_may_only_carry_the_task_its_source_still_asks_for():
    text = "每半小時看一下建置有沒有新結果, 直到 18:00 為止"
    ask = detect(text)
    fire = ScheduleFire(id="s", index=1, total=8, ask=ask).model_dump(mode="json")
    assert scheduled_text(text, fire) == "看一下建置有沒有新結果"
    with pytest.raises(ValueError, match="source_changed"):
        scheduled_text(text.replace("18:00", "17:00"), fire)
    with pytest.raises(ValueError, match="source_changed"):
        scheduled_text("看一下建置", fire)
    with pytest.raises(ValidationError):
        ScheduleFire(id="s", index=0, total=8, ask=ask)
    with pytest.raises(ValueError, match="source_changed"):
        scheduled_text(text, fire | {"index": 9})
