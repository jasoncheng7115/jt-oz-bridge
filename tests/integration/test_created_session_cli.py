"""Synthetic creation -> independent read-only observer -> real local CLI process.

Native HTTP is a loopback fixture, not the installed backend or Human acceptance.
Linux uses actual SO_PEERCRED; other platforms use explicitly synthetic peers.
"""

import asyncio
import copy
import inspect
import json
import os
import sys
import tempfile
from pathlib import Path

import httpx
import pytest
from sqlalchemy import update

from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.models import Grant
from tests.integration.test_creation_commands import close, environment, reserve, used_root

PROFILE = Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json").resolve()

OBSERVER = r"""
import asyncio,json,os,signal,socket,sys,time
from pathlib import Path
from types import SimpleNamespace
from sqlalchemy import event
from jt_oz_bridge.adapters.opencode.contracts import OpenAPIProfile
from jt_oz_bridge.adapters.opencode.inspection import INSPECTION_READS,V2SessionInspection
from jt_oz_bridge.adapters.opencode.transport import ContractAttestation,V2HTTPTransport
from jt_oz_bridge.services.inspection_runtime import ReadOnlyInspectionDatabase
from jt_oz_bridge.services.inspection_socket import InspectionSocketServer,peer_uid
from jt_oz_bridge.services.local_inspection import LocalSessionInspector
async def main():
 config=json.loads(Path(sys.argv[1]).read_text());ref=config['ref']
 db=ReadOnlyInspectionDatabase(config['db']);assert db.cipher is None
 statements=[]
 event.listen(db.engine.sync_engine,'before_cursor_execute',lambda conn,cursor,statement,params,context,many:statements.append(statement))
 async def owner():return SimpleNamespace(backend_id=ref['backend_id'],backend_identity=ref['backend_identity'],version='2.0.32',owner_epoch=config['owner_epoch'],observed_at=time.time(),pid=123)
 async def identity():await owner();return True
 async def ready():return True
 profile=OpenAPIProfile.from_file(Path(config['profile']))
 transport=V2HTTPTransport(config['url'],profile,attestation=ContractAttestation(profile.sha256,ref['backend_identity'],'2.0.32',INSPECTION_READS),verify_identity=identity)
 backend=V2SessionInspection(transport,SimpleNamespace(read=owner),ref['backend_id'],ref['backend_identity'])
 observer=LocalSessionInspector(db,{ref['backend_id']:backend},{ref['project_id']:(ref['backend_id'],config['native_project'],ref['canonical_directory'])},frozenset({(ref['backend_id'],ref['backend_identity'],ref['upstream_session_id'],ref['canonical_directory'])}),{'realm':'https://zulip.invalid'},ready)
 peers=peer_uid if sys.platform=='linux' else lambda sock:os.geteuid()
 server=InspectionSocketServer(Path(config['socket']),os.getegid(),frozenset({os.geteuid()}),observer.query,peer_reader=peers)
 stop=asyncio.Event();loop=asyncio.get_running_loop();loop.add_signal_handler(signal.SIGTERM,stop.set)
 try:
  assert await db.schema_ready();await server.start();print('READY',flush=True);await stop.wait()
 finally:
  await server.close();await transport.close();await db.close()
  Path(config['sql']).write_text(json.dumps(statements))
asyncio.run(main())
"""

CLIENT = r"""
import functools,os,sys
from jt_oz_bridge import cli,local_cli
from jt_oz_bridge.services.inspection_socket import inspect_query
from jt_oz_bridge.security import secrets
local_cli.expected_observer_uid=lambda:os.geteuid()
if sys.platform!='linux':local_cli.inspect_query=functools.partial(inspect_query,peer_reader=lambda sock:os.geteuid())
def forbidden(*args,**kwargs):raise AssertionError('CLI must not read service configuration or credentials')
cli.load_settings=forbidden;secrets.resolve_secret=forbidden
sys.argv=['jt-oz-bridge',*sys.argv[1:]];cli.main()
"""


class InspectionProcesses:
    def __init__(self, e, directory):
        self.e, self.directory = e, directory
        self.socket = directory / "observer.sock"
        self.process = None
        self.http = None
        self.tasks = set()
        self.requests = []
        self.errors = []
        self.native_unavailable = False
        self.env = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONUTF8": "1",
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    async def connection(self, reader, writer):
        try:
            header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            method, target, _ = header.split(b"\r\n", 1)[0].decode().split()
            self.requests.append((method, target))
            assert method == "GET"  # The child only has read-qualified operations.
            request = httpx.Request(method, "http://native.invalid" + target)
            if request.url.path == "/api/session" and "parentID" not in request.url.params:
                values = [
                    copy.deepcopy(self.e["state"]["info"]),
                    copy.deepcopy(self.e["d"]["session.get"]["data"]),
                ]
                rows = {item["id"]: item for item in values}
                response = httpx.Response(200, json={"data": list(rows.values()), "cursor": {}})
            elif self.native_unavailable:
                response = httpx.Response(503, json={"error": "synthetic unavailable"})
            else:
                response = self.e["t"].client._transport.handler(request)
                if inspect.isawaitable(response):
                    response = await response
            body = await response.aread()
            writer.write(
                (
                    f"HTTP/1.1 {response.status_code} OK\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                ).encode()
                + body
            )
            await writer.drain()
        except Exception as exc:
            self.errors.append(type(exc).__name__)
        finally:
            writer.close()
            await writer.wait_closed()

    def accept(self, reader, writer):
        task = asyncio.create_task(self.connection(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def start(self, db):
        self.http = await asyncio.start_server(self.accept, "127.0.0.1", 0, limit=16384)
        url = "http://127.0.0.1:" + str(self.http.sockets[0].getsockname()[1])
        ref = self.e["anchor"].reference
        config = {
            "ref": ref.model_dump(mode="json"),
            "owner_epoch": self.e["live_intent"].owner_epoch,
            "db": str(db.engine.url),
            "url": url,
            "native_project": "global",
            "socket": str(self.socket),
            "sql": str(self.directory / "queries.json"),
            "profile": str(PROFILE),
        }
        file = self.directory / "observer.json"
        file.write_text(json.dumps(config))
        self.process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            OBSERVER,
            str(file),
            env=self.env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert await asyncio.wait_for(self.process.stdout.readline(), 15) == b"READY\n"
        assert self.process.pid != os.getpid()

    async def launch(self, *arguments):
        return await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            CLIENT,
            "--socket",
            str(self.socket),
            *arguments,
            env=self.env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def command(self, *arguments):
        process = await self.launch(*arguments)
        try:
            out, err = await asyncio.wait_for(process.communicate(), 40)
        except BaseException:
            process.kill()
            await process.communicate()
            raise
        assert not err, err.decode()
        return process.returncode, out.decode()

    async def stop(self):
        if self.process is None and self.http is None:
            return
        code, out, err = 0, b"", b""
        if self.process is not None:
            if self.process.returncode is None:
                self.process.terminate()
            try:
                out, err = await asyncio.wait_for(self.process.communicate(), 10)
            except TimeoutError:
                self.process.kill()
                out, err = await self.process.communicate()
            code = self.process.returncode
            self.process = None
        if self.http is not None:
            self.http.close()
            await self.http.wait_closed()
            self.http = None
        if self.tasks:
            await asyncio.gather(*self.tasks)
        assert code == 0, (out.decode(), err.decode())
        assert not self.errors
        queries = json.loads((self.directory / "queries.json").read_text())
        assert queries and not any(
            q.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE")) for q in queries
        )
        assert not any(
            "actions.payload" in q or "actions.native_result" in q or "deliveries.payload" in q
            for q in queries
        )
        assert not self.socket.exists()


@pytest.mark.parametrize("state", ["idle", "running", "queued", "waiting", "waiting-input"])
async def test_created_root_is_visible_to_independent_secretless_observer_and_cli(db, state):
    e = await environment(db)
    processes = None
    try:
        item, _, action, _ = await reserve(e)
        await e["pipe"].creation_commands.once()
        action, binding = await e["pipe"].creation.journal.load(action.id)
        assert action.state == "completed"
        if state != "idle":
            used_root(e, state)
        with tempfile.TemporaryDirectory(prefix="jtoz-cli-", dir="/tmp") as path:
            processes = InspectionProcesses(e, await asyncio.to_thread(Path(path).resolve))
            try:
                await processes.start(db)
                code, out = await processes.command("--json", "sessions", "--bound")
                result = json.loads(out)
                assert code == 0 and result["status"] == "ok"
                assert len(result["rows"]) == 1
                row = result["rows"][0]
                assert row["session_id"] == binding.session_id
                assert (
                    row["state"]
                    == {
                        "idle": "idle",
                        "running": "running",
                        "queued": "queued",
                        "waiting": "waiting_permission",
                        "waiting-input": "waiting_input",
                    }[state]
                )
                assert (
                    row["bindings"][0]["binding_id"] == binding.id
                    and row["bindings"][0]["topic"] == item.topic
                )
                assert (
                    row["bindings"][0]["state"] == "active_record"
                    and row["bindings"][0]["access_verified"] is False
                )
                assert (
                    row["execution_registration"] == "catalog_only"
                )  # Static operator list, not a live execution certificate.
                code, out = await processes.command("--json", "sessions", "--bound", "--active")
                assert code == 0
                assert len(json.loads(out)["rows"]) == (0 if state == "idle" else 1)
                for locale in ("en", "zh-TW"):
                    code, text = await processes.command(
                        "--locale", locale, "session", binding.session_id
                    )
                    assert code == 0 and binding.session_id in text and item.topic in text
                assert all(method == "GET" for method, _ in processes.requests)
                assert not any(
                    secret in out for secret in ("jt_oz_bridge", "creation_id", "intent_sha256")
                )
            finally:
                await processes.stop()
                processes = None
        assert e["wire"].count(("POST", "/api/session")) == 1
        assert (await e["pipe"].creation.journal.load(action.id))[
            0
        ].native_result == action.native_result
    finally:
        if processes is not None:
            await processes.stop()
        await close(e)


async def test_fresh_observer_follows_real_created_binding_move_pause_and_unbind(db):
    e = await environment(db)
    processes = None
    try:
        _, _, action, _ = await reserve(e)
        await e["pipe"].creation_commands.once()
        _, binding = await e["pipe"].creation.journal.load(action.id)
        async with db.sessions.begin() as session:
            session.add(
                Grant(
                    realm_id="realm", user_id=7, project_id=binding.project_id, role="administrator"
                )
            )
        with tempfile.TemporaryDirectory(prefix="jtoz-cli-", dir="/tmp") as path:
            processes = InspectionProcesses(e, await asyncio.to_thread(Path(path).resolve))
            try:
                await processes.start(db)
                code, before = await processes.command("--json", "sessions", "--bound")
                assert (
                    code == 0 and json.loads(before)["rows"][0]["session_id"] == binding.session_id
                )
                await e["pipe"].bindings.move(
                    binding.id,
                    "realm",
                    7,
                    binding.revision,
                    10,
                    "Moved current topic",
                    whole_topic=True,
                )
                code, after = await processes.command("--json", "session", binding.session_id)
                observed = json.loads(after)["rows"][0]["bindings"][0]
                assert (
                    code == 0
                    and observed["topic"] == "Moved current topic"
                    and observed["revision"] == binding.revision + 1
                    and observed["paused"]
                )
                await processes.stop()
                await processes.start(db)  # No creation registry, key or reenrollment.
                code, after = await processes.command("--json", "session", binding.session_id)
                assert code == 0 and json.loads(after)["rows"][0]["bindings"][0] == observed
                await e["pipe"].bindings.unbind(binding.id, "realm", 7, observed["revision"])
                code, after = await processes.command("--json", "sessions", "--bound")
                assert code == 0 and not json.loads(after)["rows"]
                code, after = await processes.command("--json", "session", binding.session_id)
                assert (
                    code == 0 and json.loads(after)["rows"][0]["bindings"][0]["state"] == "inactive"
                )
                assert e["wire"].count(("POST", "/api/session")) == 1
            finally:
                await processes.stop()
                processes = None
    finally:
        if processes is not None:
            await processes.stop()
        await close(e)


@pytest.mark.parametrize(
    "fault",
    ["contract", "project_disabled", "backend_disabled", "backend_identity", "foreign_directory"],
)
async def test_independent_observer_rechecks_created_root_metadata_without_cached_binding(
    db, fault
):
    e = await environment(db)
    processes = None
    try:
        _, _, action, _ = await reserve(e)
        await e["pipe"].creation_commands.once()
        _, binding = await e["pipe"].creation.journal.load(action.id)
        with tempfile.TemporaryDirectory(prefix="jtoz-cli-", dir="/tmp") as path:
            processes = InspectionProcesses(e, await asyncio.to_thread(Path(path).resolve))
            try:
                await processes.start(db)
                code, before = await processes.command("--json", "sessions", "--bound")
                assert code == 0 and len(json.loads(before)["rows"]) == 1
                async with db.sessions.begin() as session:
                    if fault == "contract":
                        await session.execute(
                            update(EnrolledBackend).values(contract_hash="f" * 64)
                        )
                    elif fault == "project_disabled":
                        await session.execute(update(EnrolledProject).values(enabled=False))
                    elif fault == "backend_disabled":
                        await session.execute(update(EnrolledBackend).values(enabled=False))
                    elif fault == "backend_identity":
                        await session.execute(update(EnrolledBackend).values(identity="foreign"))
                    else:
                        await session.execute(
                            update(Binding).values(canonical_directory="/foreign")
                        )
                code, after = await processes.command("--json", "sessions", "--bound")
                assert code == 0 and not json.loads(after)["rows"]
                code, detail = await processes.command("--json", "session", binding.session_id)
                row = json.loads(detail)["rows"][0]
                assert code == 0 and row["session_id"] == binding.session_id
                assert (
                    not row["bindings"]
                    if fault == "foreign_directory"
                    else row["bindings"][0]["state"] == "stale"
                )
                assert e["wire"].count(("POST", "/api/session")) == 1
            finally:
                await processes.stop()
                processes = None
    finally:
        if processes is not None:
            await processes.stop()
        await close(e)


async def test_created_root_native_outage_is_unknown_and_partial_not_idle_or_active(db):
    e = await environment(db)
    processes = None
    try:
        _, _, action, _ = await reserve(e)
        await e["pipe"].creation_commands.once()
        _, binding = await e["pipe"].creation.journal.load(action.id)
        used_root(e, "running")
        with tempfile.TemporaryDirectory(prefix="jtoz-cli-", dir="/tmp") as path:
            processes = InspectionProcesses(e, await asyncio.to_thread(Path(path).resolve))
            try:
                await processes.start(db)
                processes.native_unavailable = True
                code, out = await processes.command("--json", "sessions", "--bound")
                row = json.loads(out)["rows"][0]
                assert (
                    code == 3
                    and row["session_id"] == binding.session_id
                    and row["state"] == "unknown"
                    and row["owner_epoch"] is None
                )
                code, out = await processes.command("--json", "sessions", "--bound", "--active")
                assert (
                    code == 3
                    and json.loads(out)["status"] == "partial"
                    and not json.loads(out)["rows"]
                )
                assert e["wire"].count(("POST", "/api/session")) == 1
            finally:
                await processes.stop()
                processes = None
    finally:
        if processes is not None:
            await processes.stop()
        await close(e)


async def test_created_root_watch_observes_new_native_work_without_restarting_observer(db):
    e = await environment(db)
    processes = None
    watch = None
    try:
        _, _, action, _ = await reserve(e)
        await e["pipe"].creation_commands.once()
        _, binding = await e["pipe"].creation.journal.load(action.id)
        with tempfile.TemporaryDirectory(prefix="jtoz-cli-", dir="/tmp") as path:
            processes = InspectionProcesses(e, await asyncio.to_thread(Path(path).resolve))
            try:
                await processes.start(db)
                observer_pid = processes.process.pid
                watch = await processes.launch(
                    "--json", "sessions", "--bound", "--watch", "2", "--count", "2"
                )
                first = json.loads(await asyncio.wait_for(watch.stdout.readline(), 40))
                assert (
                    first["rows"][0]["session_id"] == binding.session_id
                    and first["rows"][0]["state"] == "idle"
                )
                used_root(e, "running")
                second = json.loads(await asyncio.wait_for(watch.stdout.readline(), 40))
                assert (
                    second["rows"][0]["session_id"] == binding.session_id
                    and second["rows"][0]["state"] == "running"
                )
                out, err = await asyncio.wait_for(watch.communicate(), 10)
                assert watch.returncode == 0 and not out and not err
                assert processes.process.pid == observer_pid
                assert e["wire"].count(("POST", "/api/session")) == 1
            finally:
                if watch is not None and watch.returncode is None:
                    watch.terminate()
                    await asyncio.wait_for(watch.communicate(), 10)
                await processes.stop()
                processes = None
    finally:
        if processes is not None:
            await processes.stop()
        await close(e)
