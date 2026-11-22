"""Repeating prompts from chat: "every 30 minutes check my mail until 18:00".

OpenCode 2.0.32 has no scheduler. The bridge recognizes a plainly worded repeat in a
bound topic, shows what it understood, and after `!confirm` sends the same short task
to the original session at each time, as the person who asked. It never guesses a
repeat from text in the middle of a long request: the repeat must lead the message or
name an end time. Everything here is pure; time comes from the caller.
"""

import math
import re
from datetime import datetime, timedelta
from typing import Literal, Self

from pydantic import Field, StrictInt, model_validator

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.presentation.commands import control_text, parse_input

SCHEDULE_TOKEN = "prompt-schedule-confirm"
MIN_INTERVAL = 5 * 60
MAX_INTERVAL = 12 * 3600
MAX_FIRES = 96
HORIZON = 24 * 3600
MAX_SOURCE = 500
MAX_TASK = 400
# The repeat must start within this many characters (after a polite prefix), or the
# message must name an end time. "This cron runs every 5 minutes, why…" stays a prompt.
LEAD = 2

DIGITS = {"零": 0, "一": 1, "二": 2, "兩": 2, "三": 3, "四": 4, "五": 5}
DIGITS |= {"六": 6, "七": 7, "八": 8, "九": 9}
WORDS = {"a": 1, "an": 1, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6}
WORDS |= {"ten": 10, "twelve": 12, "fifteen": 15, "twenty": 20, "thirty": 30}
ZH_NUMBER = r"\d{1,3}|[零一二兩三四五六七八九十]{1,3}"

INTERVAL_ZH = re.compile(
    r"每(?:隔)?\s*(?:(?P<n>" + ZH_NUMBER + r")\s*(?:個)?\s*(?P<more>半)?\s*"
    r"(?P<unit>分鐘|分|小時|鐘頭)|(?P<bare>半)?\s*(?:個)?\s*(?P<bare_unit>小時|鐘頭|分鐘))"
)
INTERVAL_EN = re.compile(
    r"\bevery\s+(?:(?P<half>half\s+(?:an\s+)?hour)|(?:(?P<n>\d{1,3}|[a-z]+)\s+)?"
    r"(?P<unit>minutes?|mins?|hours?|hrs?)\b)",
    re.IGNORECASE,
)
UNTIL_ZH = re.compile(
    r"(?:[,，、]\s*)?(?:一直到|直到|到|至)\s*(?:今天|今晚)?\s*"
    r"(?P<mer>上午|早上|中午|下午|傍晚|晚上)?\s*(?P<h>\d{1,2}|[零一二兩三四五六七八九十]{1,3})\s*"
    r"(?:[:：]\s*(?P<m>\d{2})|點\s*(?:(?P<half>半)|(?P<m2>\d{1,2}|[一二三四五六七八九十]{1,3})\s*分?)?|時)"
    r"\s*(?:為止|結束|止|前)?"
)
UNTIL_EN = re.compile(
    r"(?:,\s*)?\b(?:until|till|til)\s+(?:(?P<word>noon|midnight)|(?P<h>\d{1,2})"
    r"(?::(?P<m>\d{2}))?\s*(?P<mer>am|pm|a\.m\.|p\.m\.)?)(?![\w:])",
    re.IGNORECASE,
)
POLITE = re.compile(r"^(?:請|麻煩|幫我|請幫我|麻煩你|please|can you|could you)\s*", re.IGNORECASE)
EDGES = " \t\r\n,，、。.;；:：!！"


class ScheduleRefused(Exception):
    """A recognized repeat the bridge answers with a fixed explanation and no token."""

    def __init__(self, key: str, **values: str) -> None:
        super().__init__(key)
        self.key, self.values = key, values


class EndClock(ControlModel):
    hour: StrictInt = Field(ge=0, le=24)
    minute: StrictInt = Field(ge=0, le=59)
    # "pm"/"下午": afternoon; "am"/"上午": morning; None: the next such time on a clock.
    meridiem: Literal["am", "noon", "pm"] | None = None

    @model_validator(mode="after")
    def real_time(self) -> Self:
        if self.hour == 24 and self.minute:
            raise ValueError("schedule_end_after_midnight")
        if self.meridiem is not None and self.hour > 12:
            raise ValueError("schedule_end_meridiem_with_24_hour_clock")
        return self


class ScheduleAsk(ControlModel):
    """What one message asks for; the same text always gives the same ask."""

    interval_seconds: StrictInt = Field(gt=0)
    end: EndClock | None = None
    text: str = Field(min_length=1, max_length=MAX_TASK)


def _number(value: str) -> int:
    if value.isdigit():
        return int(value)
    lowered = value.lower()
    if lowered in WORDS:
        return WORDS[lowered]
    if not value or any(c not in DIGITS and c != "十" for c in value):
        raise ValueError("schedule_number_unrecognized")
    if "十" in value:
        tens, _, ones = value.partition("十")
        if "十" in ones:
            raise ValueError("schedule_number_unrecognized")
        return (DIGITS[tens] if tens else 1) * 10 + (DIGITS[ones] if ones else 0)
    if len(value) != 1:
        raise ValueError("schedule_number_unrecognized")
    return DIGITS[value]


def _interval(match: re.Match[str], english: bool) -> int:
    if english:
        if match["half"]:
            return 1800
        count = _number(match["n"]) if match["n"] else 1
        unit = 3600 if match["unit"].lower().startswith("h") else 60
        return count * unit
    if match["bare_unit"]:
        unit = 60 if match["bare_unit"] == "分鐘" else 3600
        return unit // 2 if match["bare"] else unit
    count = _number(match["n"])
    unit = 60 if match["unit"] in {"分鐘", "分"} else 3600
    seconds = count * unit
    return seconds + unit // 2 if match["more"] else seconds


def _end(match: re.Match[str], english: bool) -> EndClock:
    if english:
        if match["word"]:
            word = match["word"].lower()
            return (
                EndClock(hour=12, minute=0, meridiem="noon")
                if word == "noon"
                else EndClock(hour=24, minute=0)
            )
        mer = (match["mer"] or "").lower().replace(".", "")
        return EndClock(
            hour=int(match["h"]),
            minute=int(match["m"] or 0),
            meridiem="pm" if mer == "pm" else "am" if mer == "am" else None,
        )
    minute = 30 if match["half"] else _number(match["m"] or match["m2"] or "0")
    mer = match["mer"]
    meridiem: Literal["am", "noon", "pm"] | None = (
        "am"
        if mer in {"上午", "早上"}
        else "noon"
        if mer == "中午"
        else "pm"
        if mer in {"下午", "傍晚", "晚上"}
        else None
    )
    return EndClock(hour=_number(match["h"]), minute=minute, meridiem=meridiem)


def _cut(text: str, span: tuple[int, int]) -> str:
    """Remove one phrase; a space is kept only between two ASCII words."""
    before, after = text[: span[0]], text[span[1] :]
    joined = before.rstrip(" \t") and after.lstrip(" \t")
    ascii_words = (
        joined and before.rstrip(" \t")[-1:].isascii() and after.lstrip(" \t")[:1].isascii()
    )
    gap = " " if ascii_words else ""
    return before.rstrip(" \t") + gap + after.lstrip(" \t")


def detect(text: str) -> ScheduleAsk | None:
    """The repeat a plain bound prompt asks for, or None when it is ordinary text.

    Raises ScheduleRefused for a recognized repeat the bridge will not run (too
    often, nothing left to send). `!oz send -- …` and attachments are never repeats.
    """
    parsed = parse_input(text, bound=True)
    if (
        parsed.kind != "prompt"
        or parsed.command
        or parsed.arguments != text
        or len(text) > MAX_SOURCE
        or "/user_uploads/" in text
    ):
        return None
    body = control_text(text)
    english = False
    interval = INTERVAL_ZH.search(body)
    if interval is None:
        interval, english = INTERVAL_EN.search(body), True
    if interval is None:
        return None
    rest = _cut(body, interval.span())
    until = (UNTIL_EN if english else UNTIL_ZH).search(rest)
    if until is None and english is False:
        until = UNTIL_EN.search(rest)
    lead = POLITE.match(body)
    leading = interval.start() <= (lead.end() if lead else 0) + LEAD
    if until is None and not leading:
        return None
    try:
        seconds = _interval(interval, english)
        end = _end(until, until.re is UNTIL_EN) if until else None
    except ValueError:
        return None
    task = re.sub(r"[ \t]{2,}", " ", _cut(rest, until.span()) if until else rest).strip(EDGES)
    if not task:
        raise ScheduleRefused("schedule.empty")
    if len(task) > MAX_TASK:
        return None
    if seconds < MIN_INTERVAL:
        raise ScheduleRefused("schedule.too_often", minutes=str(MIN_INTERVAL // 60))
    if seconds > MAX_INTERVAL:
        raise ScheduleRefused("schedule.too_rare", hours=str(MAX_INTERVAL // 3600))
    return ScheduleAsk(interval_seconds=seconds, end=end, text=task)


def ends_at(ask: ScheduleAsk, now: datetime) -> datetime:
    """The first matching wall-clock time after now (aware), or the end of today."""
    if now.tzinfo is None:
        raise ValueError("schedule_requires_aware_time")
    if ask.end is None:
        return now.replace(hour=23, minute=59, second=59, microsecond=0)
    clock = ask.end
    hour = clock.hour
    if clock.meridiem == "pm" and hour < 12:
        hour += 12
    elif clock.meridiem == "am" and hour == 12:
        hour = 0
    elif clock.meridiem == "noon" and hour < 6:
        hour += 12
    day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    candidates = [day + timedelta(hours=hour, minutes=clock.minute)]
    if clock.meridiem is None and hour < 12:
        # "到 6 點" at 15:00 means 18:00 today.
        candidates.append(day + timedelta(hours=hour + 12, minutes=clock.minute))
    candidates.append(candidates[0] + timedelta(days=1))
    for candidate in candidates:
        if candidate > now:
            if (candidate - now).total_seconds() > HORIZON:
                break
            return candidate
    raise ScheduleRefused("schedule.too_far", hours=str(HORIZON // 3600))


def fire_count(ask: ScheduleAsk, start: float, end: float) -> int:
    """Sends from start (inclusive, the first one) every interval up to end."""
    if end <= start:
        raise ScheduleRefused("schedule.ended")
    count = math.floor((end - start) / ask.interval_seconds) + 1
    if count > MAX_FIRES:
        raise ScheduleRefused("schedule.too_many", limit=str(MAX_FIRES))
    return count


class ScheduleFire(ControlModel):
    """The `schedule` part of a timed prompt Action's payload."""

    id: str = Field(min_length=1, max_length=36)
    index: StrictInt = Field(ge=1, le=MAX_FIRES)
    total: StrictInt = Field(ge=1, le=MAX_FIRES)
    ask: ScheduleAsk


def scheduled_text(source_text: str, raw: object) -> str:
    """The text a timed prompt may carry: the task its own source still asks for."""
    fire = ScheduleFire.model_validate(raw)
    try:
        ask = detect(source_text)
    except ScheduleRefused:
        ask = None
    if ask is None or ask != fire.ask or not 1 <= fire.index <= fire.total:
        raise ValueError("scheduled_prompt_source_changed")
    return ask.text


def looks_scheduled(text: str) -> bool:
    """A repeat (or a refused one): never taken by a shortcut that sends at once."""
    try:
        return detect(text) is not None
    except ScheduleRefused:
        return True
