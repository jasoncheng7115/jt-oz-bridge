#!/usr/bin/env python3
"""While Bridge is stopped, answer each topic once so a message never meets silence.

Started by `OnFailure=` next to the stop notice, and it exits by itself as soon as Bridge
answers ready. It sends one fixed sentence into a topic where someone wrote, and only in
the configured private channels. It never reads message content, never sends anything to
OpenCode and keeps nothing on disk. Bridge's own restart catch-up later handles the
messages themselves. Standard library only, like the stop notice.
"""

import argparse
import base64
import json
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

BRIDGE_CONFIG = Path("/etc/jt-oz-bridge/config.toml")
READY_URL = "http://127.0.0.1:8765/readyz"
TEXT = (
    "⚠️ Bridge 目前停止，這則訊息沒有送到 OpenCode。原因和恢復的消息請看「Bridge 狀態」話題；"
    "恢復後，最近 10 分鐘內的訊息會自動送出，更早的請再送一次。\n"
    "Bridge is stopped, so this message did not reach OpenCode. The topic “Bridge 狀態” "
    "says why and when it is back; messages from the last 10 minutes then go out by "
    "themselves, so send older ones again."
)
# In the status topic itself the reason is the notice just above.
STATUS_TOPIC = "Bridge 狀態"
STATUS_TEXT = (
    "⚠️ Bridge 目前停止，原因在上面的通知；恢復時這裡會再發一則 ✅。\n"
    "Bridge is stopped; the notice above says why, and a ✅ follows here once it is back."
)
# One answer per topic per this long, and at most this many per outage.
TOPIC_QUIET_SECONDS = 1800
MAX_REPLIES = 30


def secret(reference: str) -> str:
    if not reference.startswith("file:"):
        raise ValueError("bridge_standby_file_secret_required")
    return Path(reference.removeprefix("file:")).read_text().strip()


def realm_settings(config: dict[str, Any]) -> dict[str, Any]:
    enabled = [realm for realm in config["zulip_realms"] if realm.get("enabled", True)]
    if len(enabled) != 1:
        raise ValueError("bridge_standby_exactly_one_realm_required")
    return enabled[0]


class Zulip:
    def __init__(self, zulip: dict[str, Any]) -> None:
        self.base = str(zulip["url"]).rstrip("/") + "/api/v1/"
        pair = f"{zulip['bot_email']}:{secret(str(zulip['api_key_ref']))}"
        self.auth = "Basic " + base64.b64encode(pair.encode()).decode()

    def call(
        self, method: str, path: str, values: dict[str, Any] | None = None, timeout: float = 20
    ) -> dict[str, Any]:
        data = urllib.parse.urlencode(values or {})
        url = self.base + path + ("?" + data if method == "GET" and data else "")
        request = urllib.request.Request(
            url,
            data=data.encode() if method != "GET" else None,
            headers={"Authorization": self.auth},
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = json.load(response)
        except urllib.error.HTTPError as error:
            body = json.load(error)
        if not isinstance(body, dict):
            raise ValueError("bridge_standby_unexpected_reply")
        return body


def ready(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return json.load(response).get("ready") is True
    except (OSError, ValueError):
        return False


def private_channels(api: Zulip, channel_ids: list[int]) -> set[int]:
    """Only channels that are invite-only and not web-public right now."""
    kept = set()
    for channel in channel_ids:
        stream = api.call("GET", f"streams/{int(channel)}").get("stream")
        if (
            isinstance(stream, dict)
            and stream.get("invite_only") is True
            and stream.get("is_web_public") is False
        ):
            kept.add(int(channel))
    return kept


class Standby:
    """Which messages get the sentence; pure, so tests drive it without a server."""

    def __init__(self, bot_id: int, channels: set[int], now: Callable[[], float]) -> None:
        self.bot_id, self.channels, self.now = bot_id, channels, now
        self.answered: dict[tuple[int, str], float] = {}
        self.replies = 0

    def target(self, event: dict[str, Any]) -> tuple[int, str] | None:
        message = event.get("message") if event.get("type") == "message" else None
        if not isinstance(message, dict) or message.get("type") != "stream":
            return None
        channel, topic = message.get("stream_id"), message.get("subject")
        sender = message.get("sender_id")
        if (
            type(channel) is not int
            or channel not in self.channels
            or not isinstance(topic, str)
            or not topic
            or type(sender) is not int
            or sender == self.bot_id
            or self.replies >= MAX_REPLIES
        ):
            return None
        key = (channel, topic)
        last = self.answered.get(key)
        if last is not None and self.now() - last < TOPIC_QUIET_SECONDS:
            return None
        self.answered[key] = self.now()
        self.replies += 1
        return key


def bridge_down() -> bool:
    """True only while systemd reports Bridge failed or stopped, never while it starts."""
    try:
        state = subprocess.run(
            ["systemctl", "is-active", "jt-oz-bridge.service"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return False
    return state in {"failed", "inactive"}


def serve(
    api: Zulip,
    ready_url: str,
    sleep: Callable[[float], None] = time.sleep,
    down: Callable[[], bool] = bridge_down,
) -> int:
    """Answer until Bridge is ready. Every Zulip error waits and retries in this
    process, so what was already answered is never answered again."""
    standby: Standby | None = None
    queue = None
    last_event = -1
    backoff = 5.0
    while not ready(ready_url):
        try:
            if standby is None:
                me = api.call("GET", "users/me")
                if me.get("result") != "success" or me.get("is_bot") is not True:
                    raise ValueError("bridge_standby_bot_identity_required")
                zulip = realm_settings(tomllib.loads(BRIDGE_CONFIG.read_text()))
                channels = private_channels(api, list(zulip["allowed_channel_ids"]))
                standby = Standby(int(me["user_id"]), channels, time.time)
            if queue is None:
                registered = api.call(
                    "POST",
                    "register",
                    {"event_types": json.dumps(["message"]), "apply_markdown": "false"},
                )
                if registered.get("result") != "success":
                    raise ValueError("bridge_standby_register_refused")
                queue, last_event = registered["queue_id"], int(registered["last_event_id"])
            polled = api.call(
                "GET", "events", {"queue_id": queue, "last_event_id": last_event}, timeout=70
            )
            if polled.get("result") != "success":
                queue = None  # Registers again; Bridge itself catches up what it missed.
                raise ValueError("bridge_standby_queue_lost")
            for event in polled.get("events", []):
                last_event = max(last_event, int(event.get("id", last_event)))
                if not down():
                    continue  # Starting again or back: Bridge answers for itself.
                key = standby.target(event)
                if key is None:
                    continue
                if ready(ready_url):
                    break
                text = STATUS_TEXT if key[1] == STATUS_TOPIC else TEXT
                api.call(
                    "POST",
                    "messages",
                    {"type": "stream", "to": key[0], "topic": key[1], "content": text},
                )
            backoff = 5.0
        except (OSError, ValueError, KeyError, TypeError):
            sleep(backoff)
            backoff = min(300.0, backoff * 2)
    if queue is not None:
        try:
            api.call("DELETE", "events", {"queue_id": queue})
        except (OSError, ValueError):
            pass
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ready-url", default=READY_URL)
    args = parser.parse_args(argv)
    if ready(args.ready_url):
        return 0  # Bridge is already back; nothing to answer for.
    zulip = realm_settings(tomllib.loads(BRIDGE_CONFIG.read_text()))
    return serve(Zulip(zulip), args.ready_url)


if __name__ == "__main__":
    sys.exit(main())
