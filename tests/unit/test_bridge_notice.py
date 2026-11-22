import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("bridge_notice", ROOT / "ops/server/bridge_notice.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def owner(tmp_path, *, unit=b"unit", binary=b"binary"):
    unit_path, binary_path = tmp_path / "unit", tmp_path / "binary"
    unit_path.write_bytes(unit)
    binary_path.write_bytes(binary)
    return {
        "unit_path": str(unit_path),
        "unit_sha256": module.file_sha256(str(unit_path)),
        "executable_path": str(binary_path),
        "executable_sha256": module.file_sha256(str(binary_path)),
    }


def test_matching_pins_report_only_a_stop(tmp_path):
    assert module.classify(owner(tmp_path)) == "stopped"


def test_changed_or_missing_pins_report_an_opencode_change(tmp_path):
    pins = owner(tmp_path)
    Path(pins["executable_path"]).write_bytes(b"upgraded")
    assert module.classify(pins) == "native_changed"
    pins = owner(tmp_path)
    Path(pins["unit_path"]).unlink()
    assert module.classify(pins) == "native_changed"


def test_same_kind_is_sent_once_and_a_new_kind_is_sent_again(tmp_path):
    state = tmp_path / "state" / "last"
    assert not module.already_sent(state, "stopped")
    module.remember(state, "stopped")
    assert module.already_sent(state, "stopped")
    assert not module.already_sent(state, "native_changed")


def test_message_goes_to_the_bridge_channel_and_no_secret_is_in_the_text(tmp_path, monkeypatch):
    sent = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self):
            return json.dumps({"result": "success"}).encode()

    def urlopen(request, timeout):
        sent.append(request)
        return Response()

    key = tmp_path / "key"
    key.write_text("SYNTHETIC-KEY\n")
    monkeypatch.setattr(module.urllib.request, "urlopen", urlopen)
    zulip = {"url": "https://z.invalid/", "bot_email": "b@z.invalid", "api_key_ref": f"file:{key}"}
    module.post(zulip, 4, "Bridge 狀態", module.TEXT["stopped"])
    assert sent[0].full_url == "https://z.invalid/api/v1/messages"
    assert b"to=4" in sent[0].data and b"SYNTHETIC-KEY" not in sent[0].data
    assert all("KEY" not in text for text in module.TEXT.values())


def test_settings_come_from_the_one_enabled_realm_in_the_real_config_shape():
    realm = {"enabled": True, "url": "https://z.invalid", "allowed_channel_ids": [4]}
    assert module.realm_settings({"zulip_realms": [realm, {"enabled": False}]}) is realm
    with pytest.raises(ValueError):
        module.realm_settings({"zulip_realms": [realm, dict(realm)]})


def test_a_refused_policy_check_is_named_and_a_plain_stop_stays_plain(tmp_path):
    log = (
        "INFO: started\n"
        "runtime_component_failed stage=worker component=native-owner-feed index=2"
        " kind=raised error_type=ContractError code=public_feed_not_running\n"
        "runtime_component_failed stage=startup component=session-restoration index=4"
        " kind=raised error_type=ContractError"
        " code=creation_policy_source_drifted_from_operator_approval\n"
        "RuntimeError: runtime_start_failed\n"
    )
    cause = module.last_cause(log)
    assert cause == "creation_policy_source_drifted_from_operator_approval"
    assert module.classify(owner(tmp_path), cause) == "policy_changed"
    assert module.classify(owner(tmp_path), "public_feed_not_running") == "stopped"
    assert module.last_cause("code=Not A Code\nTraceback") is None
    assert module.last_cause("runtime_component_failed code=-") is None
    text = module.notice("policy_changed", cause)
    assert text.startswith(module.TEXT["policy_changed"]) and f"`{cause}`" in text
    assert module.notice("stopped", None) == module.TEXT["stopped"]


def test_a_stop_is_announced_once_per_outage_and_taken_back_once_ready(tmp_path, monkeypatch):
    state = tmp_path / "state" / "last"
    pins = tmp_path / "owner.json"
    pins.write_text(json.dumps(owner(tmp_path)))
    posts, up = [], {"ready": False}
    monkeypatch.setattr(module, "OWNER_CONFIG", pins)
    monkeypatch.setattr(module, "journal_cause", lambda: None)
    monkeypatch.setattr(module, "send", lambda topic, text: posts.append(text))
    monkeypatch.setattr(module, "ready", lambda url: up["ready"])
    # systemd has given up, so the stop is announced without waiting for a retry.
    monkeypatch.setattr(module, "unit_state", lambda: "failed")
    args = ["--state", str(state)]
    # Nothing was announced, so a ready Bridge needs no "back" notice.
    up["ready"] = True
    assert module.main([*args, "--recovered"]) == 0 and posts == []
    up["ready"] = False
    module.main(args)
    module.main(args)
    assert posts == [module.TEXT["stopped"]]
    module.main([*args, "--recovered"])
    assert len(posts) == 1 and state.exists()
    up["ready"] = True
    module.main([*args, "--recovered"])
    module.main([*args, "--recovered"])
    assert posts[1:] == [module.TEXT["recovered"]] and not state.exists()
    # The next outage is announced again instead of being taken as already said.
    up["ready"] = False
    module.main(args)
    assert posts[2:] == [module.TEXT["stopped"]]


def test_a_failure_the_next_try_fixes_is_never_announced(tmp_path, monkeypatch):
    """A first start that runs before OpenCode is up, followed by a retry that works."""
    state = tmp_path / "state" / "last"
    pins = tmp_path / "owner.json"
    pins.write_text(json.dumps(owner(tmp_path)))
    posts = []
    states = iter(["auto-restart", "auto-restart", "start-pre", "running"])
    readiness = iter([False, False, False, False, True])
    monkeypatch.setattr(module, "OWNER_CONFIG", pins)
    monkeypatch.setattr(module, "journal_cause", lambda: "upstream_rejected_request")
    monkeypatch.setattr(module, "send", lambda topic, text: posts.append(text))
    monkeypatch.setattr(module, "ready", lambda url: next(readiness))
    monkeypatch.setattr(module, "unit_state", lambda: next(states))
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
    assert module.main(["--state", str(state)]) == 0
    assert posts == [] and not state.exists()


def test_a_stop_is_announced_once_systemd_gives_up_or_the_wait_runs_out(monkeypatch):
    monkeypatch.setattr(module, "ready", lambda url: False)
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
    states = iter(["auto-restart", "start", "failed"])
    monkeypatch.setattr(module, "unit_state", lambda: next(states))
    assert module.came_back("http://127.0.0.1:8765/readyz") is False
    # Still trying when the wait is over: announce rather than stay silent.
    monkeypatch.setattr(module, "unit_state", lambda: "start-pre")
    assert module.came_back("http://127.0.0.1:8765/readyz", wait=0) is False


def test_readiness_needs_bridge_to_say_ready(monkeypatch):
    class Response:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self):
            return self.body

    bodies = [b'{"ready":true,"mode":"managed"}', b'{"ready":false}', b"not json"]
    monkeypatch.setattr(
        module.urllib.request, "urlopen", lambda url, timeout: Response(bodies.pop(0))
    )
    assert module.ready("http://127.0.0.1:8765/readyz") is True
    assert module.ready("http://127.0.0.1:8765/readyz") is False
    assert module.ready("http://127.0.0.1:8765/readyz") is False

    def refused(url, timeout):
        raise OSError("refused")

    monkeypatch.setattr(module.urllib.request, "urlopen", refused)
    assert module.ready("http://127.0.0.1:8765/readyz") is False


def test_units_wire_the_stop_notice_and_the_recovery_timer():
    bridge = (ROOT / "ops/server/jt-oz-bridge.service").read_text()
    assert "OnFailure=jt-oz-bridge-notice.service" in bridge
    recovered = (ROOT / "ops/server/jt-oz-bridge-recovered.service").read_text()
    assert "bridge-notice.py --recovered" in recovered
    assert "StateDirectory=jt-oz-bridge-notice" in recovered
    timer = (ROOT / "ops/server/jt-oz-bridge-recovered.timer").read_text()
    assert "OnUnitActiveSec=2min" in timer


def test_bridge_waits_for_opencode_at_boot_without_ever_starting_it():
    bridge = (ROOT / "ops/server/jt-oz-bridge.service").read_text()
    after = next(line for line in bridge.splitlines() if line.startswith("After="))
    wants = next(line for line in bridge.splitlines() if line.startswith("Wants="))
    assert "opencode.service" in after and "opencode.service" not in wants
    assert "/dev/tcp/127.0.0.1/4096" in bridge and "$$(seq 60)" in bridge
    assert "TimeoutStartSec=180" in bridge
    timer = (ROOT / "ops/server/jt-oz-bridge-retry.timer").read_text()
    assert "OnUnitActiveSec=5min" in timer and "WantedBy=timers.target" in timer
    retry = (ROOT / "ops/server/jt-oz-bridge-retry.service").read_text()
    assert "/opt/jt-oz-bridge/bridge-retry.sh" in retry
    assert "ConditionPathExists=!/etc/jt-oz-bridge/promotion-active" in retry
    # The observer waits for Bridge instead of spending its three starts too early.
    observer = (ROOT / "ops/server/jt-oz-observer.service").read_text()
    assert "http://127.0.0.1:8765/readyz" in observer and "$$(seq 90)" in observer
    assert "TimeoutStartSec=240" in observer
    notice = (ROOT / "ops/server/jt-oz-bridge-notice.service").read_text()
    assert "TimeoutStartSec=300" in notice


def retry_run(tmp_path, *, state, failed_ago, observer="active"):
    import subprocess
    import time

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls"
    since = f"@{int(time.time() - failed_ago)}"
    fake = bin_dir / "systemctl"
    fake.write_text(
        "#!/bin/bash\n"
        f'echo "$*" >> {calls}\n'
        'case "$1" in\n'
        '  is-failed) case "$3" in\n'
        f'    jt-oz-bridge.service) [ "{state}" = failed ];;\n'
        f'    *) [ "{observer}" = failed ];;\n'
        "  esac;;\n"
        f'  show) [ "$2" = --timestamp=unix ] && echo "{since}";;\n'
        "esac\n"
    )
    fake.chmod(0o755)
    result = subprocess.run(
        ["bash", str(ROOT / "ops/server/bridge_retry.sh")],
        env={"PATH": f"{bin_dir}:/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    return result.stdout, calls.read_text().splitlines() if calls.exists() else []


def test_retry_starts_bridge_only_after_five_minutes_failed(tmp_path):
    out, calls = retry_run(tmp_path, state="failed", failed_ago=400)
    assert out.startswith("bridge_retry start after=")
    assert out.strip().endswith("unit=jt-oz-bridge.service")
    assert [c for c in calls if c.startswith(("start", "reset-failed"))] == [
        "reset-failed jt-oz-bridge.service",
        "start --no-block jt-oz-bridge.service",
    ]


def test_retry_also_starts_an_observer_that_gave_up_waiting_for_bridge(tmp_path):
    out, calls = retry_run(tmp_path, state="active", failed_ago=400, observer="failed")
    assert out.strip().endswith("unit=jt-oz-observer.service")
    started = [c for c in calls if c.startswith(("start", "reset-failed"))]
    assert started == [
        "reset-failed jt-oz-observer.service",
        "start --no-block jt-oz-observer.service",
    ]


@pytest.mark.parametrize(("state", "failed_ago"), [("failed", 60), ("inactive", 4000)])
def test_retry_leaves_a_fresh_failure_and_a_deliberate_stop_alone(tmp_path, state, failed_ago):
    out, calls = retry_run(tmp_path, state=state, failed_ago=failed_ago)
    assert out == ""
    assert not any(c.startswith(("start", "reset-failed")) for c in calls)


def test_a_plugin_update_is_named_and_its_policy_refusal_wins(tmp_path):
    """A changed plugin is named, not reported as only `public_feed_not_running`."""
    log = (
        "runtime_component_failed stage=worker component=native-session-graphs index=9"
        " kind=raised error_type=ContractError code=public_feed_not_running\n"
        "Started jt-oz-bridge.service - jt-oz-bridge qualified Zulip and OpenCode consumer.\n"
        "creation_restore_deferred action=a session=s kind=ContractError"
        " code=creation_policy_source_drifted_from_operator_approval\n"
        "runtime_component_failed stage=startup component=other index=5 kind=raised"
        " error_type=ContractError code=existing_session_original_observation_changed\n"
        "RuntimeError: runtime_start_failed\n"
    )
    assert module.last_cause(log) == "creation_policy_source_drifted_from_operator_approval"
    # Only the latest attempt counts: the first exit alone names its own code.
    assert module.last_cause(log.split("Started")[0]) == "public_feed_not_running"
    plugin = tmp_path / "audit-plugin.js"
    plugin.write_text("approved bytes")
    approved = module.file_sha256(str(plugin))
    config = {
        "opencode_backends": [
            {"observer_plugins": [{"id": "audit-plugin", "path": str(plugin), "sha256": approved}]}
        ]
    }
    assert module.changed_plugins(config) == []
    plugin.write_text("updated bytes")
    assert module.changed_plugins(config) == ["audit-plugin"]
    plugin.unlink()
    assert module.changed_plugins(config) == ["audit-plugin"]
    assert module.changed_plugins({}) == []
    pins = owner(tmp_path)
    assert module.classify(pins, "public_feed_not_running", ["audit-plugin"]) == "plugin_changed"
    assert module.classify(pins, None, []) == "stopped"
    text = module.notice("plugin_changed", "creation_policy_source_drifted_from_operator_approval")
    assert text.startswith(module.TEXT["plugin_changed"])
    assert "稽核外掛" in text and "audit plugin" in text


standby_spec = importlib.util.spec_from_file_location(
    "bridge_standby", ROOT / "ops/server/bridge_standby.py"
)
standby = importlib.util.module_from_spec(standby_spec)
standby_spec.loader.exec_module(standby)


def event(mid, *, channel=4, topic="範例", sender=9, kind="stream"):
    return {
        "id": mid,
        "type": "message",
        "message": {"type": kind, "stream_id": channel, "subject": topic, "sender_id": sender},
    }


def test_standby_answers_each_topic_once_and_only_people_in_private_channels():
    clock = [1000.0]
    s = standby.Standby(11, {4}, lambda: clock[0])
    assert s.target(event(1)) == (4, "範例")
    assert s.target(event(2)) is None  # Once per topic.
    assert s.target(event(3, topic="工作")) == (4, "工作")
    assert s.target(event(4, channel=99)) is None  # Not a configured private channel.
    assert s.target(event(5, sender=11, topic="x")) is None  # Bridge's own Bot.
    assert s.target(event(6, topic="")) is None  # "general chat" has no topic.
    assert s.target(event(7, kind="private", topic="y")) is None
    assert s.target({"id": 8, "type": "heartbeat"}) is None
    clock[0] += standby.TOPIC_QUIET_SECONDS
    assert s.target(event(9)) == (4, "範例")  # A long outage reminds once more.
    s.replies = standby.MAX_REPLIES
    assert s.target(event(10, topic="z")) is None


def test_standby_posts_the_fixed_sentence_and_exits_once_bridge_is_ready(tmp_path, monkeypatch):
    key = tmp_path / "key"
    key.write_text("SYNTHETIC-KEY\n")
    config = tmp_path / "config.toml"
    config.write_text(
        '[[zulip_realms]]\nurl = "https://z.invalid"\nbot_email = "b@z.invalid"\n'
        f'api_key_ref = "file:{key}"\nallowed_channel_ids = [4, 5]\n'
    )
    monkeypatch.setattr(standby, "BRIDGE_CONFIG", config)
    calls = []

    class Api:
        def call(self, method, path, values=None, timeout=20):
            calls.append((method, path, values))
            if path == "users/me":
                return {"result": "success", "is_bot": True, "user_id": 11}
            if path.startswith("streams/"):
                private = path == "streams/4"
                return {"stream": {"invite_only": private, "is_web_public": False}}
            if path == "register":
                return {"result": "success", "queue_id": "q", "last_event_id": -1}
            if method == "GET" and path == "events":
                return {
                    "result": "success",
                    "events": [
                        event(1),
                        event(2),
                        event(3, channel=5),
                        event(4, sender=11),
                        event(5, topic="Bridge 狀態"),
                    ],
                }
            return {"result": "success"}

    polls = [0]
    original = Api.call

    def counted(self, method, path, values=None, timeout=20):
        if method == "GET" and path == "events":
            polls[0] += 1
        return original(self, method, path, values, timeout)

    Api.call = counted
    # Ready once two polls are done; each check before a reply until then says "not yet".
    monkeypatch.setattr(standby, "ready", lambda url: polls[0] > 2)
    assert (
        standby.serve(
            Api(), "http://127.0.0.1:8765/readyz", sleep=lambda s: None, down=lambda: True
        )
        == 0
    )
    posts = [values for method, path, values in calls if path == "messages"]
    # Two polls of the same events, one topic: one sentence; channel 5 is not private.
    assert posts == [
        {"type": "stream", "to": 4, "topic": "範例", "content": standby.TEXT},
        # In the status topic the reason is the notice right above it.
        {"type": "stream", "to": 4, "topic": "Bridge 狀態", "content": standby.STATUS_TEXT},
    ]
    assert ("DELETE", "events", {"queue_id": "q"}) in calls
    assert "KEY" not in standby.TEXT


def test_standby_unit_is_started_with_the_notice_and_never_needs_a_bridge_stop():
    bridge = (ROOT / "ops/server/jt-oz-bridge.service").read_text()
    assert "OnFailure=jt-oz-bridge-notice.service jt-oz-bridge-standby.service" in bridge
    unit = (ROOT / "ops/server/jt-oz-bridge-standby.service").read_text()
    assert "/opt/jt-oz-bridge/bridge-standby.py" in unit and "Conflicts=" not in unit


def test_standby_waits_out_zulip_errors_and_is_quiet_while_bridge_starts(monkeypatch, tmp_path):
    key = tmp_path / "key"
    key.write_text("K\n")
    config = tmp_path / "config.toml"
    config.write_text(
        '[[zulip_realms]]\nurl = "https://z.invalid"\nbot_email = "b@z.invalid"\n'
        f'api_key_ref = "file:{key}"\nallowed_channel_ids = [4]\n'
    )
    monkeypatch.setattr(standby, "BRIDGE_CONFIG", config)
    posts, sleeps, step = [], [], [0]

    class Api:
        def call(self, method, path, values=None, timeout=20):
            if path == "users/me":
                step[0] += 1
                if step[0] == 1:
                    raise OSError("zulip down")  # Waited out, not a crash.
                return {"result": "success", "is_bot": True, "user_id": 11}
            if path.startswith("streams/"):
                return {"stream": {"invite_only": True, "is_web_public": False}}
            if path == "register":
                return {"result": "success", "queue_id": "q", "last_event_id": -1}
            if method == "GET" and path == "events":
                step[0] += 1
                return {"result": "success", "events": [event(step[0])]}
            if path == "messages":
                posts.append(values["topic"])
                raise ValueError("502 page")  # A refused post does not end the standby.
            return {"result": "success"}

    states = iter([False, True, True])  # Bridge starting, then failed again.
    monkeypatch.setattr(standby, "ready", lambda url: step[0] >= 5)
    standby.serve(Api(), "u", sleep=sleeps.append, down=lambda: next(states, True))
    # The first poll came while Bridge was starting: no reply. Later ones: one, once.
    assert posts == ["範例"]
    assert sleeps and sleeps[0] == 5.0 and all(s <= 300 for s in sleeps)


def test_notice_refuses_a_channel_that_stopped_being_private(monkeypatch, tmp_path):
    key = tmp_path / "key"
    key.write_text("K\n")
    config = tmp_path / "config.toml"
    config.write_text(
        '[[zulip_realms]]\nurl = "https://z.invalid"\nbot_email = "b@z.invalid"\n'
        f'api_key_ref = "file:{key}"\nallowed_channel_ids = [4]\n'
    )
    monkeypatch.setattr(module, "BRIDGE_CONFIG", config)
    posted = []
    monkeypatch.setattr(module, "post", lambda *args: posted.append(args))
    monkeypatch.setattr(module, "private", lambda zulip, channel: False)
    with pytest.raises(ValueError, match="not_private"):
        module.send("Bridge 狀態", module.TEXT["stopped"])
    monkeypatch.setattr(module, "private", lambda zulip, channel: True)
    module.send("Bridge 狀態", module.TEXT["stopped"])
    assert posted and posted == [posted[0]] and posted[0][1] == 4


def test_a_refused_zulip_release_is_named_with_both_versions(tmp_path, monkeypatch):
    """A Zulip release that is not accepted is named, not left as an uncoded Zulip error."""
    log = (
        "Started jt-oz-bridge.service - jt-oz-bridge\n"
        "zulip_release_not_qualified version=13.0 feature_level=510 qualified=12.3/500\n"
        "runtime_component_failed stage=startup component=other index=5"
        " kind=raised error_type=TransportError code=upstream_rejected_request\n"
        "runtime_component_failed stage=startup component=zulip-consumer index=7"
        " kind=raised error_type=ZulipError code=-\n"
    )
    cause = module.last_cause(log)
    assert cause == "zulip_release_not_qualified"
    assert module.last_release(log) == ("13.0", "510", "12.3/500")
    assert module.classify(owner(tmp_path), cause) == "zulip_changed"
    text = module.notice("zulip_changed", cause, module.last_release(log))
    assert text.startswith(module.TEXT["zulip_changed"])
    assert "`13.0`（feature level 510）" in text and "`12.3/500`" in text
    # Only the latest start counts: once Zulip is rolled back the old refusal is gone.
    later = log + "Started jt-oz-bridge.service - jt-oz-bridge\nruntime_component_failed code=-\n"
    assert module.last_cause(later) is None and module.last_release(later) is None
    # A changed OpenCode or plugin is still named first.
    pins = owner(tmp_path)
    Path(pins["executable_path"]).write_bytes(b"upgraded")
    assert module.classify(pins, cause) == "native_changed"
    assert module.classify(owner(tmp_path), cause, ["audit-plugin"]) == "plugin_changed"
    # Free text in the version never reaches the notice.
    assert (
        module.last_release("zulip_release_not_qualified version=<b>x</b> feature_level=1") is None
    )


def test_a_zulip_stop_is_announced_with_the_versions_from_the_journal(tmp_path, monkeypatch):
    state = tmp_path / "state" / "last"
    pins = tmp_path / "owner.json"
    pins.write_text(json.dumps(owner(tmp_path)))
    log = "zulip_release_not_qualified version=13.0 feature_level=510 qualified=12.3/500\n"
    posts = []
    monkeypatch.setattr(module, "OWNER_CONFIG", pins)
    monkeypatch.setattr(module, "BRIDGE_CONFIG", tmp_path / "missing.toml")
    monkeypatch.setattr(module, "journal", lambda: log)
    monkeypatch.setattr(module, "send", lambda topic, text: posts.append(text))
    monkeypatch.setattr(module, "ready", lambda url: False)
    monkeypatch.setattr(module, "unit_state", lambda: "failed")
    module.main(["--state", str(state)])
    module.main(["--state", str(state)])
    assert len(posts) == 1 and "`13.0`" in posts[0] and state.read_text() == "zulip_changed\n"
