"""CLI exit semantics, without starting sockets or reading live credentials."""

import os

import pytest

from jt_oz_bridge import cli
from jt_oz_bridge.config import Settings


@pytest.mark.parametrize("outcome", ["normal", "worker_failure", "startup_failure"])
def test_server_failure_exits_nonzero_for_supervisor_without_restarting_native(
    monkeypatch, outcome
):
    callback = None
    config_seen = {}
    server_seen = []
    monkeypatch.setattr(cli.sys, "argv", ["jt-oz-bridge", "serve"])
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(cli, "load_settings", lambda path: Settings())
    monkeypatch.setattr(cli, "configured_database", lambda settings: object())

    def app(settings, database, **kwargs):
        nonlocal callback
        callback = kwargs["on_runtime_failure"]
        assert kwargs["runtime_factory"] is None
        return object()

    def config(application, **kwargs):
        config_seen.update(kwargs)
        return object()

    class Server:
        def __init__(self, config):
            self.started = outcome != "startup_failure"
            self.should_exit = False
            server_seen.append(self)

        def run(self):
            if outcome == "worker_failure":
                callback()

    monkeypatch.setattr(cli, "create_app", app)
    monkeypatch.setattr(cli.uvicorn, "Config", config)
    monkeypatch.setattr(cli.uvicorn, "Server", Server)
    prior_umask = os.umask(0o077)
    try:
        if outcome == "normal":
            cli.main()
        else:
            with pytest.raises(SystemExit) as error:
                cli.main()
            assert error.value.code == 1
        assert server_seen[0].should_exit is (outcome == "worker_failure")
        assert config_seen["workers"] == 1 and config_seen["proxy_headers"] is False
    finally:
        os.umask(prior_umask)
