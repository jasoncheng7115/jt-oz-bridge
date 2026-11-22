#!/usr/bin/env python3
"""Tell the Zulip channel once when Bridge has stopped and why, and once when it is back.

Run by `OnFailure=`, which systemd triggers on every failed start, including one it is
about to retry. A failure that the next try fixes (OpenCode still warming up after a
reboot) is not announced: the notice waits until Bridge is ready again or has really
stopped. Bridge may never have reached its Zulip consumer, so this stays
standard-library only. A timer
runs it again with `--recovered`: once Bridge answers ready, the stop notice that is
still open gets one "back" notice, so the channel never shows a stale stop.
"""

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
import time
import tomllib
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

OWNER_CONFIG = Path("/etc/opencode-owner-probe.json")
BRIDGE_CONFIG = Path("/etc/jt-oz-bridge/config.toml")
STATE = Path("/var/lib/jt-oz-bridge-notice/last")
READY_URL = "http://127.0.0.1:8765/readyz"
UNIT = "jt-oz-bridge.service"
# How long a failure may take to fix itself before it is announced anyway.
SETTLE_SECONDS = 240
TOPIC = "Bridge 狀態"
TEXT = {
    "stopped": (
        "⚠️ Bridge 已停止，訊息暫時不會處理也不會回覆。管理員處理好後，這裡會再通知。\n"
        "Bridge has stopped; messages are paused. This topic says so again once it is back."
    ),
    "native_changed": (
        "⚠️ OpenCode 版本已變更，Bridge 已暫停送出。"
        "請先執行 `check_native_upgrade.py` 確認相容性。\n"
        "OpenCode changed, so sending is paused. Run `check_native_upgrade.py` first."
    ),
    "policy_changed": (
        "⚠️ Bridge 已停止：OpenCode 的設定或外掛變了（例如稽核外掛更新），"
        "要管理員確認後才能恢復。期間訊息不會處理。恢復後這裡會再通知。\n"
        "Bridge stopped because OpenCode's settings or a plugin changed. An administrator "
        "must review the change first. This topic says so again once it is back."
    ),
    "plugin_changed": (
        "⚠️ Bridge 已停止：OpenCode 的外掛剛更新（例如稽核外掛），"
        "要管理員全文重新審核後才能恢復。期間訊息不會處理；恢復後這裡會再通知。\n"
        "Bridge stopped because an OpenCode plugin was just updated (for example an audit "
        "plugin). An administrator must review it in full first. This topic says so "
        "again once it is back."
    ),
    "zulip_changed": (
        "⚠️ Bridge 已停止：Zulip 已升級成這一版 Bridge 還沒確認過的版本。"
        "同一大版的維護更新（例如 12.3 → 12.5）會自動接受；換大版（例如 13.0）要管理員先執行 "
        "`check_zulip_upgrade.py`，確認相容並更新 Bridge 後才能恢復，或把 Zulip 退回原版。"
        "期間訊息不會處理；恢復後這裡會再通知。\n"
        "Bridge stopped because Zulip now runs a release this Bridge has not been qualified "
        "on. Maintenance releases of the same series (12.3 to 12.5) are accepted by "
        "themselves; a new major release (13.0) needs an administrator to run "
        "`check_zulip_upgrade.py` and update Bridge first, or to roll Zulip back. This topic "
        "says so again once it is back."
    ),
    "recovered": (
        "✅ Bridge 已恢復。最近 10 分鐘內送的訊息會自動送出；"
        "更早的訊息請到原話題看提示（`!go` 送出、`!no` 丟掉）。\n"
        "Bridge is back. Messages from the last 10 minutes go out by themselves; for older "
        "ones, the topic says what to do (`!go` sends, `!no` drops)."
    ),
}
# The fixed reason Bridge logs when a startup part refuses; never free text.
CAUSE = re.compile(r"runtime_component_failed .*\bcode=([a-z0-9_]{1,100})(?:\s|$)")
# A conversation that could not be restored names its own reason the same way.
DEFERRED = re.compile(r"creation_restore_deferred .*\bcode=([a-z0-9_]{1,100})(?:\s|$)")
# Bridge names a Zulip release it refuses once per start; versions are public, not secret.
RELEASE = re.compile(
    r"zulip_release_not_qualified version=([0-9A-Za-z.+-]{1,32}) feature_level=([0-9]{1,6}|-)"
    r" qualified=([0-9A-Za-z.+-]{1,32})/([0-9]{1,6})(?:\s|$)"
)
ZULIP_RELEASE = "zulip_release_not_qualified"
# Refusals that mean OpenCode's approved settings or plugins no longer match.
POLICY_WORDS = ("drift", "fingerprint", "approval", "observer_plugin", "policy_changed")


def file_sha256(path: str) -> str | None:
    try:
        with open(path, "rb") as source:
            return hashlib.file_digest(source, "sha256").hexdigest()
    except OSError:
        return None


def last_cause(log: str) -> str | None:
    """The code of the last refused startup part in Bridge's journal, if any.

    A settings or plugin refusal anywhere in the last attempt wins over a later
    knock-on failure, which says less about what to do. So does a refused Zulip
    release: the Zulip error it causes carries no code of its own.
    """
    found = policy = release = None
    for line in log.splitlines():
        if line.startswith("Started ") or "Started jt-oz-bridge" in line:
            found = policy = release = None  # Only the latest attempt counts.
        if RELEASE.search(line):
            release = ZULIP_RELEASE
        match = CAUSE.search(line) or DEFERRED.search(line)
        if match:
            found = match[1]
            if any(word in found for word in POLICY_WORDS):
                policy = found
    return policy or release or found


def last_release(log: str) -> tuple[str, str, str] | None:
    """The refused Zulip release, its feature level and the qualified one, from the last start."""
    found = None
    for line in log.splitlines():
        if line.startswith("Started ") or "Started jt-oz-bridge" in line:
            found = None
        if match := RELEASE.search(line):
            found = (match[1], match[2], f"{match[3]}/{match[4]}")
    return found


def journal() -> str:
    try:
        return subprocess.run(
            ["journalctl", "-u", "jt-oz-bridge", "-n", "400", "-o", "cat", "--no-pager"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def journal_cause() -> str | None:
    return last_cause(journal())


def changed_plugins(config: dict[str, Any]) -> list[str]:
    """Approved observer plugins whose file no longer has the approved sha256."""
    changed = []
    for backend in config.get("opencode_backends", []):
        for plugin in backend.get("observer_plugins", []):
            if file_sha256(str(plugin.get("path"))) != plugin.get("sha256"):
                changed.append(str(plugin.get("id")))
    return changed


def classify(
    owner: dict[str, str], cause: str | None = None, plugins: list[str] | None = None
) -> str:
    """Only a pinned hash that no longer matches may be reported as an OpenCode change."""
    pins = (("unit_path", "unit_sha256"), ("executable_path", "executable_sha256"))
    for path, expected in pins:
        if file_sha256(owner[path]) != owner[expected]:
            return "native_changed"
    if plugins:
        return "plugin_changed"
    if cause == ZULIP_RELEASE:
        return "zulip_changed"
    if cause is not None and any(word in cause for word in POLICY_WORDS):
        return "policy_changed"
    return "stopped"


def notice(kind: str, cause: str | None, release: tuple[str, str, str] | None = None) -> str:
    if cause is None or kind == "recovered":
        return TEXT[kind]
    text = TEXT[kind] + f"\n原因代碼 / Reason code: `{cause}`"
    if kind == "zulip_changed" and release is not None:
        live, level, qualified = release
        text += (
            f"\nZulip 現在 / now: `{live}`（feature level {level}）；"
            f"Bridge 確認過 / qualified: `{qualified}`"
        )
    return text


def already_sent(state: Path, key: str) -> bool:
    try:
        return state.read_text().strip() == key
    except OSError:
        return False


def open_notice(state: Path) -> bool:
    try:
        return bool(state.read_text().strip())
    except OSError:
        return False


def remember(state: Path, key: str) -> None:
    state.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    state.write_text(key + "\n")


def forget(state: Path) -> None:
    state.unlink(missing_ok=True)


def ready(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return json.load(response).get("ready") is True
    except (OSError, ValueError):
        return False


def unit_state() -> str:
    """Bridge's systemd sub-state; `failed` or `dead` once nothing will start it again."""
    try:
        return subprocess.run(
            ["systemctl", "show", "-P", "SubState", UNIT],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def came_back(url: str, wait: float = SETTLE_SECONDS) -> bool:
    """Bridge got ready again by itself before it stopped for good or the wait ran out."""
    deadline = time.monotonic() + wait
    while True:
        if ready(url):
            return True
        if unit_state() in ("failed", "dead") or time.monotonic() >= deadline:
            return False
        time.sleep(5)


def secret(reference: str) -> str:
    if not reference.startswith("file:"):
        raise ValueError("bridge_notice_file_secret_required")
    return Path(reference.removeprefix("file:")).read_text().strip()


def post(zulip: dict[str, object], channel: int, topic: str, text: str) -> None:
    pair = f"{zulip['bot_email']}:{secret(str(zulip['api_key_ref']))}"
    request = urllib.request.Request(
        str(zulip["url"]).rstrip("/") + "/api/v1/messages",
        data=urllib.parse.urlencode(
            {"type": "stream", "to": channel, "topic": topic, "content": text}
        ).encode(),
        headers={"Authorization": "Basic " + base64.b64encode(pair.encode()).decode()},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        if json.load(response).get("result") != "success":
            raise ValueError("bridge_notice_post_refused")


def realm_settings(config: dict[str, Any]) -> dict[str, Any]:
    enabled = [realm for realm in config["zulip_realms"] if realm.get("enabled", True)]
    if len(enabled) != 1:
        raise ValueError("bridge_notice_exactly_one_realm_required")
    return enabled[0]


def private(zulip: dict[str, object], channel: int) -> bool:
    """The channel is invite-only and not web-public right now."""
    pair = f"{zulip['bot_email']}:{secret(str(zulip['api_key_ref']))}"
    request = urllib.request.Request(
        str(zulip["url"]).rstrip("/") + f"/api/v1/streams/{int(channel)}",
        headers={"Authorization": "Basic " + base64.b64encode(pair.encode()).decode()},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        stream = json.load(response).get("stream")
    return (
        isinstance(stream, dict)
        and stream.get("invite_only") is True
        and stream.get("is_web_public") is False
    )


def send(topic: str, text: str) -> None:
    zulip = realm_settings(tomllib.loads(BRIDGE_CONFIG.read_text()))
    channel = zulip["allowed_channel_ids"][0]
    if not private(zulip, channel):
        raise ValueError("bridge_notice_channel_not_private")
    post(zulip, channel, topic, text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="print, send nothing")
    parser.add_argument(
        "--recovered", action="store_true", help="say Bridge is back if a stop notice is open"
    )
    parser.add_argument("--topic", default=TOPIC)
    parser.add_argument("--state", type=Path, default=STATE)
    parser.add_argument("--ready-url", default=READY_URL)
    args = parser.parse_args(argv)
    if args.recovered:
        # Nothing to take back unless a stop was announced, and only once Bridge is ready.
        if not open_notice(args.state) or not ready(args.ready_url):
            return 0
        if args.dry_run:
            print("recovered")
            print(TEXT["recovered"])
            return 0
        send(args.topic, TEXT["recovered"])
        forget(args.state)
        return 0
    if not args.dry_run and came_back(args.ready_url):
        return 0
    cause = journal_cause()
    try:
        plugins = changed_plugins(tomllib.loads(BRIDGE_CONFIG.read_text()))
    except (OSError, ValueError):
        plugins = []
    kind = classify(json.loads(OWNER_CONFIG.read_text()), cause, plugins)
    release = last_release(journal()) if kind == "zulip_changed" else None
    if args.dry_run:
        print(kind)
        print(notice(kind, cause, release))
        return 0
    if already_sent(args.state, kind):
        return 0
    send(args.topic, notice(kind, cause, release))
    remember(args.state, kind)
    return 0


if __name__ == "__main__":
    sys.exit(main())
