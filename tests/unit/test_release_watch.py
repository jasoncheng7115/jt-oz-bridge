"""Daily release watch: Bridge's own Zulip rule, announced once per release, GET only."""

import importlib.util
import json
from pathlib import Path

import pytest

from jt_oz_bridge.adapters.zulip.server_release import same_release_line

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("release_watch", ROOT / "ops/server/release_watch.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

# Made-up versions: qualified on Zulip 7.1, running 7.3, a new major 8.2 is out;
# OpenCode 1.2.3 is installed and 1.4.0 is out.
LIVE, QUALIFIED, OPENCODE = (7, 3), (7, 1), (1, 2, 3)
RELEASES = [(8, 2), (7, 3), (8, 1), (8, 0), (7, 2), (7, 1)]


@pytest.mark.parametrize("candidate", ["7.0", "7.1", "7.3", "7.10", "8.0", "6.9", "8.2"])
def test_the_watch_says_what_the_running_bridge_would_do(candidate):
    """Maintenance releases never lower the feature level, so give it one above."""
    value = module.release(candidate)
    assert module.bridge_accepts(QUALIFIED, value) is same_release_line("7.1", 500, candidate, 501)


def test_only_plain_releases_are_read():
    assert module.release("7.3") == (7, 3)
    assert [module.release(x) for x in ("7.3-dev+git", "v7.3", "7", 7.3, None)] == [None] * 5
    assert module.opencode_release("v1.19.6") == (1, 19, 6)
    assert module.opencode_release("0.0.0-beta-17236") is None
    assert module.installed_opencode({"executable_path": "/opt/example/1.2.3/opencode"}) == OPENCODE
    assert module.installed_opencode({}) is None


def test_a_new_major_zulip_is_named_as_refused_and_opencode_as_needing_the_check():
    found = module.findings(LIVE, RELEASES, OPENCODE, (1, 4, 0))
    assert found == {"zulip_major": "8.2", "opencode": "1.4.0"}
    text = module.message(found, LIVE, QUALIFIED, OPENCODE)
    assert "Zulip 8.2 已發布（目前 7.3）：換大版，這一版 Bridge 不接受" in text
    assert "OpenCode 1.4.0 已發布（目前 1.2.3）" in text and "check_native_upgrade.py" in text


def test_a_newer_maintenance_release_is_named_as_accepted():
    found = module.findings((7, 1), RELEASES, OPENCODE, OPENCODE)
    assert found == {"zulip_series": "7.3", "zulip_major": "8.2"}
    text = module.message({"zulip_series": "7.3"}, (7, 1), QUALIFIED, OPENCODE)
    assert "Bridge 會自動接受" in text and "check_zulip_upgrade.py" in text
    # Nothing newer: nothing to say.
    assert module.findings((8, 2), RELEASES, OPENCODE, OPENCODE) == {}


def test_each_release_is_announced_once_and_a_later_one_again(tmp_path):
    state = tmp_path / "watch" / "announced.json"
    found = {"zulip_major": "8.2", "opencode": "1.4.0"}
    assert module.unannounced(found, state) == found
    module.remember(found, state)
    assert module.unannounced(found, state) == {}
    assert module.unannounced({**found, "opencode": "1.4.1"}, state) == {"opencode": "1.4.1"}


def test_one_source_down_does_not_hide_the_other(monkeypatch, capsys):
    def down(url, headers=None):
        raise OSError("synthetic")

    monkeypatch.setattr(module, "get_json", down)
    assert module.zulip_releases() == [] and module.latest_opencode() is None
    err = capsys.readouterr().err
    assert "source=zulip error=OSError" in err and "source=opencode error=OSError" in err


def test_requests_are_gets_with_a_named_agent_and_only_the_post_carries_the_key(
    tmp_path, monkeypatch
):
    seen = []

    class Response:
        def __init__(self, body):
            self.body = json.dumps(body).encode()

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self, limit=None):
            return self.body

    def urlopen(request, timeout):
        seen.append(request)
        if request.full_url.endswith("/streams/4"):
            return Response({"stream": {"invite_only": True, "is_web_public": False}})
        return Response({"result": "success", "version": "1.4.0"})

    key = tmp_path / "key"
    key.write_text("SYNTHETIC-KEY\n")
    monkeypatch.setattr(module.urllib.request, "urlopen", urlopen)
    assert module.latest_opencode() == (1, 4, 0)
    assert seen[0].get_method() == "GET" and seen[0].get_header("User-agent")
    assert "Authorization" not in seen[0].headers
    zulip = {
        "url": "https://z.invalid/",
        "bot_email": "b@z.invalid",
        "api_key_ref": f"file:{key}",
        "allowed_channel_ids": [4],
    }
    module.send(zulip, "Bridge 狀態", "🔔")
    assert [r.get_method() for r in seen[1:]] == ["GET", "POST"]
    assert seen[2].full_url == "https://z.invalid/api/v1/messages"
    assert b"to=4" in seen[2].data and b"SYNTHETIC-KEY" not in seen[2].data


def test_a_channel_that_stopped_being_private_gets_nothing(monkeypatch):
    posted = []

    def call(zulip, method, path, values):
        posted.append(method)
        return {"stream": {"invite_only": False, "is_web_public": False}}

    monkeypatch.setattr(module, "call", call)
    with pytest.raises(ValueError, match="release_watch_channel_not_private"):
        module.send({"allowed_channel_ids": [4]}, "Bridge 狀態", "🔔")
    assert posted == ["GET"]


def test_units_run_the_watch_daily_with_its_own_state():
    service = (ROOT / "ops/server/jt-oz-release-watch.service").read_text()
    assert "ExecStart=/usr/bin/python3 -I /opt/jt-oz-bridge/release-watch.py" in service
    assert "StateDirectory=jt-oz-release-watch" in service and "ProtectSystem=strict" in service
    timer = (ROOT / "ops/server/jt-oz-release-watch.timer").read_text()
    assert "OnCalendar=*-*-* 09:30" in timer and "Persistent=true" in timer
