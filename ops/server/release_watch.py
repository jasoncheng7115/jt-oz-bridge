#!/usr/bin/env python3
"""Once a day, tell the Zulip channel when Zulip or OpenCode has a newer release.

Zulip ships security fixes as maintenance releases, and Bridge refuses to run on a
Zulip release it has not been qualified on. This says ahead of time whether Bridge would
keep running on each newer release, so an upgrade is planned instead of found out. It uses GET only:
the public Zulip `server_settings`, GitHub's public release list for zulip/zulip and
OpenCode's own update metadata. It never downloads or installs anything, never touches
OpenCode, and posts only release numbers into the status topic of the private channel,
once per new release. Standard library only, like the stop notice.
"""

import argparse
import base64
import json
import re
import sys
import tomllib
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

BRIDGE_CONFIG = Path("/etc/jt-oz-bridge/config.toml")
OWNER_CONFIG = Path("/etc/opencode-owner-probe.json")
STATE = Path("/var/lib/jt-oz-release-watch/announced.json")
ZULIP_RELEASES = "https://api.github.com/repos/zulip/zulip/releases?per_page=30"
# Where the OpenCode installer itself asks for the latest version.
OPENCODE_LATEST = "https://opencode.ai/update/api/latest/cli/npm"
TOPIC = "Bridge 狀態"
MAX_BYTES = 2 * 1024 * 1024
RELEASE = re.compile(r"^([0-9]{1,4})\.([0-9]{1,4})$")
OPENCODE_VERSION = re.compile(r"^v?([0-9]{1,4})\.([0-9]{1,4})\.([0-9]{1,5})$")


def get_json(url: str, headers: dict[str, str] | None = None) -> Any:
    # opencode.ai refuses Python's default agent; say plainly what is asking.
    base = {"Accept": "application/json", "User-Agent": "jt-oz-bridge-release-watch"}
    request = urllib.request.Request(url, headers={**base, **(headers or {})})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read(MAX_BYTES + 1)[:MAX_BYTES])


def release(text: object) -> tuple[int, int] | None:
    """(12, 5) for a plain Zulip release such as 12.5; None for anything else."""
    match = RELEASE.fullmatch(text) if isinstance(text, str) else None
    return (int(match[1]), int(match[2])) if match else None


def opencode_release(text: object) -> tuple[int, int, int] | None:
    match = OPENCODE_VERSION.fullmatch(text) if isinstance(text, str) else None
    return (int(match[1]), int(match[2]), int(match[3])) if match else None


def bridge_accepts(qualified: tuple[int, int], candidate: tuple[int, int]) -> bool:
    """Bridge's own rule (`server_release.same_release_line`) without a feature level.

    Maintenance releases keep their series' API and never lower the feature level, so
    the series and minor number decide. `check_zulip_upgrade.py --sources` on the
    release tarball is the full check before upgrading.
    """
    return candidate[0] == qualified[0] and candidate[1] >= qualified[1]


def qualified_release(config: dict[str, Any]) -> tuple[int, int]:
    manifest = Path(config["runtime"]["enrollment_file"])
    value = release(json.loads(manifest.read_text())["realm"]["zulip_version"])
    if value is None:
        raise ValueError("release_watch_qualified_release_unrecognized")
    return value


def installed_opencode(owner: dict[str, Any]) -> tuple[int, int, int] | None:
    # Installs live in a directory named after their version: /opt/opencode/2.0.32/opencode.
    return opencode_release(Path(str(owner.get("executable_path", ""))).parent.name)


def unavailable(name: str, error: Exception) -> None:
    # One source down must not hide the other; the journal names which and why.
    print(
        f"release_watch_source_unavailable source={name} error={type(error).__name__}",
        file=sys.stderr,
    )


def zulip_releases() -> list[tuple[int, int]]:
    try:
        items = get_json(ZULIP_RELEASES, {"X-GitHub-Api-Version": "2022-11-28"})
    except (OSError, ValueError) as error:
        unavailable("zulip", error)
        return []
    found = []
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and not item.get("draft") and not item.get("prerelease"):
            if (value := release(item.get("tag_name"))) is not None:
                found.append(value)
    return found


def latest_opencode() -> tuple[int, int, int] | None:
    try:
        body = get_json(OPENCODE_LATEST)
    except (OSError, ValueError) as error:
        unavailable("opencode", error)
        return None
    return opencode_release(body.get("version")) if isinstance(body, dict) else None


def dotted(value: tuple[int, ...]) -> str:
    return ".".join(map(str, value))


def findings(
    live: tuple[int, int],
    releases: list[tuple[int, int]],
    opencode: tuple[int, int, int] | None,
    opencode_latest: tuple[int, int, int] | None,
) -> dict[str, str]:
    """The newest release worth naming in each line, keyed so each is announced once."""
    found = {}
    series = [r for r in releases if r[0] == live[0] and r > live]
    if series:
        found["zulip_series"] = dotted(max(series))
    major = [r for r in releases if r[0] > live[0]]
    if major:
        found["zulip_major"] = dotted(max(major))
    if opencode and opencode_latest and opencode_latest > opencode:
        found["opencode"] = dotted(opencode_latest)
    return found


def message(
    found: dict[str, str],
    live: tuple[int, int],
    qualified: tuple[int, int],
    opencode: tuple[int, int, int] | None,
) -> str:
    now, q = dotted(live), dotted(qualified)
    lines = ["🔔 有新版本 / New releases"]
    for key in ("zulip_series", "zulip_major"):
        if key not in found:
            continue
        name = found[key]
        candidate = release(name)
        if candidate is not None and bridge_accepts(qualified, candidate):
            lines.append(
                f"- Zulip {name} 已發布（目前 {now}）：同一大版的維護更新，Bridge 會自動接受。"
                "維護版通常含安全修正，建議安排升級；升級前跑 `check_zulip_upgrade.py`，"
                "避開 Bridge 切換時段。\n"
                f"  Zulip {name} is out (running {now}): a maintenance release Bridge accepts "
                "by itself. Plan the upgrade; run `check_zulip_upgrade.py` first."
            )
        else:
            lines.append(
                f"- Zulip {name} 已發布（目前 {now}）：換大版，這一版 Bridge 不接受"
                f"（只接受 {q} 以上的 {qualified[0]}.x）。升級前要先完成 Bridge 的相容性確認，否則 Bridge 會停止。\n"
                f"  Zulip {name} is out (running {now}): a new major release this Bridge "
                f"refuses (it takes {qualified[0]}.x from {q} on). Qualify Bridge before upgrading, or it stops."
            )
    if "opencode" in found and opencode is not None:
        name, now = found["opencode"], dotted(opencode)
        lines.append(
            f"- OpenCode {name} 已發布（目前 {now}）：Bridge 綁定目前版本，升級前要先跑 "
            "`check_native_upgrade.py`。OpenCode 自動更新已關閉，不會自己升級。\n"
            f"  OpenCode {name} is out (running {now}): Bridge pins the installed version, "
            "so run `check_native_upgrade.py` first. Auto-update is off."
        )
    return "\n".join(lines)


def unannounced(found: dict[str, str], state: Path) -> dict[str, str]:
    try:
        seen = json.loads(state.read_text())
    except (OSError, ValueError):
        seen = {}
    return {key: value for key, value in found.items() if seen.get(key) != value}


def remember(found: dict[str, str], state: Path) -> None:
    state.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    state.write_text(json.dumps(found, sort_keys=True) + "\n")


def secret(reference: str) -> str:
    if not reference.startswith("file:"):
        raise ValueError("release_watch_file_secret_required")
    return Path(reference.removeprefix("file:")).read_text().strip()


def realm_settings(config: dict[str, Any]) -> dict[str, Any]:
    enabled = [realm for realm in config["zulip_realms"] if realm.get("enabled", True)]
    if len(enabled) != 1:
        raise ValueError("release_watch_exactly_one_realm_required")
    return enabled[0]


def live_release(zulip: dict[str, Any]) -> tuple[int, int]:
    body = get_json(str(zulip["url"]).rstrip("/") + "/api/v1/server_settings")
    value = release(body.get("zulip_version")) if isinstance(body, dict) else None
    if value is None:
        raise ValueError("release_watch_live_release_unrecognized")
    return value


def call(zulip: dict[str, Any], method: str, path: str, values: dict[str, Any]) -> Any:
    pair = f"{zulip['bot_email']}:{secret(str(zulip['api_key_ref']))}"
    data = urllib.parse.urlencode(values).encode() if method == "POST" else None
    request = urllib.request.Request(
        str(zulip["url"]).rstrip("/") + "/api/v1/" + path,
        data=data,
        headers={"Authorization": "Basic " + base64.b64encode(pair.encode()).decode()},
        method=method,
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)


def send(zulip: dict[str, Any], topic: str, text: str) -> None:
    channel = int(zulip["allowed_channel_ids"][0])
    stream = call(zulip, "GET", f"streams/{channel}", {}).get("stream")
    if not (
        isinstance(stream, dict)
        and stream.get("invite_only") is True
        and stream.get("is_web_public") is False
    ):
        raise ValueError("release_watch_channel_not_private")
    body = call(
        zulip,
        "POST",
        "messages",
        {"type": "stream", "to": channel, "topic": topic, "content": text},
    )
    if body.get("result") != "success":
        raise ValueError("release_watch_post_refused")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dry-run", action="store_true", help="print, send nothing")
    parser.add_argument("--state", type=Path, default=STATE)
    parser.add_argument("--topic", default=TOPIC)
    args = parser.parse_args(argv)
    config = tomllib.loads(BRIDGE_CONFIG.read_text())
    zulip = realm_settings(config)
    live, qualified = live_release(zulip), qualified_release(config)
    owner = json.loads(OWNER_CONFIG.read_text())
    found = findings(live, zulip_releases(), installed_opencode(owner), latest_opencode())
    new = unannounced(found, args.state)
    if args.dry_run:
        print(json.dumps(found, sort_keys=True))
        if new:
            print(message(new, live, qualified, installed_opencode(owner)))
        return 0
    if new:
        send(zulip, args.topic, message(new, live, qualified, installed_opencode(owner)))
    # What is no longer newer (installed since) drops out, so a later release is new again.
    remember(found, args.state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
