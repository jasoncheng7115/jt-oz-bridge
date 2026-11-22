"""Test the built wheel outside its source tree, with a temporary loopback server."""

import argparse
import hashlib
import json
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

CHILD = r"""
import asyncio, json, os, socket, sys, uuid
from importlib.metadata import distribution
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import jt_oz_bridge
assert Path(jt_oz_bridge.__file__).is_relative_to(Path(sys.argv[1]))
package_metadata = distribution('jt-oz-bridge')
assert package_metadata.metadata['License-Expression'] == 'GPL-3.0-only'
license_path = next(Path(sys.argv[1]).glob('jt_oz_bridge-*.dist-info/licenses/LICENSE'))
assert b'GNU GENERAL PUBLIC LICENSE' in license_path.read_bytes()
from sqlalchemy import text
from jt_oz_bridge.config import Settings
from jt_oz_bridge.storage.database import CURRENT_REVISION, Database, migrate
from jt_oz_bridge.storage.artifact_files import LocalArtifactFiles
from jt_oz_bridge.security.cipher import EnvelopeCipher
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.services.runtime_enrollment import RuntimeEnrollment
from jt_oz_bridge.services.session_registry import SessionRegistry
from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline
from jt_oz_bridge.services.runtime import SupervisedRuntime
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.services.backend_registry import BackendRegistry
from jt_oz_bridge.services.discovery import DiscoveryService
from jt_oz_bridge.services.binding_confirmation import BindingConfirmation
from jt_oz_bridge.services.output_destinations import OutputDestinations
from jt_oz_bridge.services.discovery_delivery import DiscoveryDeliveryWorker
from jt_oz_bridge.services.reply_publisher import ReplyPublisher
from jt_oz_bridge.adapters.opencode.catalog import V2SessionCatalog
from jt_oz_bridge.adapters.opencode.project_policy import V2ProjectPolicyGuard
from jt_oz_bridge.adapters.opencode.turn_resources import V2TurnResourceReader
from jt_oz_bridge.adapters.opencode.transcript import V2TranscriptReader
from jt_oz_bridge.services.transcript_commands import NativeTranscriptCommands
from jt_oz_bridge.services.transcript_collector import TranscriptCollector
from jt_oz_bridge.services.transcript_publisher import TranscriptPublisher
from jt_oz_bridge.services.transcript_drafts import TranscriptDraftPublisher
from jt_oz_bridge.services.live_capture import LiveEventJournal, LiveTextCollector
from jt_oz_bridge.services.live_draft_sources import LiveDraftCollector
from jt_oz_bridge.services.draft_records import LiveDraftHeader
from jt_oz_bridge.adapters.opencode.live_text import VisibleTextCapture
from jt_oz_bridge.adapters.opencode.model_catalog import V2ModelCatalog
from jt_oz_bridge.adapters.opencode.model_settings import ModelSettingsAttestation
from jt_oz_bridge.services.model_commands import ModelCommands
from jt_oz_bridge.services.model_setting_publisher import ModelSettingPublisher
from jt_oz_bridge.services.resource_execution_results import ResourceResultCollector
from jt_oz_bridge.services.resource_publisher import ResourcePublisher
from jt_oz_bridge.services.resource_history import ResourceHistory
from jt_oz_bridge.services.zulip_events import ZulipEventJournal
from jt_oz_bridge.services.zulip_consumer import ZulipCommandConsumer
from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.services.routed_output import RoutedOutbox
from jt_oz_bridge.services.execution_receipts import ExecutionReceipt
from jt_oz_bridge.services.native_log_reader import V2LogReader
from jt_oz_bridge.services.native_projection import NativeProjector
from jt_oz_bridge.services.native_publisher import NativePublisher
from jt_oz_bridge.services.native_history import NativeHistory
from jt_oz_bridge.services.history_commands import HistoryCommands
from jt_oz_bridge.adapters.opencode.event_semantics import SEMANTICS_SHA256
from jt_oz_bridge.web.app import create_app
import uvicorn

async def main():
    state = Path(sys.argv[2])
    cipher = EnvelopeCipher({'smoke': os.urandom(32)}, 'smoke')
    database = Database('sqlite+aiosqlite:///' + str(state / 'test.db'), cipher=cipher)
    await migrate(database.engine)
    assert await database.ready()
    await DurableStore(database).enqueue('smoke', 'binding', 1, 7, {'text': 'PACKAGED_PRIVATE_PAYLOAD'})
    async with database.engine.connect() as connection:
        assert all(item is not None for item in (V2TranscriptReader, NativeTranscriptCommands, TranscriptCollector, TranscriptPublisher, TranscriptDraftPublisher, LiveEventJournal, LiveTextCollector, VisibleTextCapture, LiveDraftCollector, LiveDraftHeader))
        for name in ('transcript_streams', 'transcript_candidates', 'transcript_messages', 'transcript_versions', 'transcript_publications', 'transcript_drafts', 'transcript_draft_publications', 'native_feed_receipts', 'native_live_captures', 'transcript_live_draft_publications', 'zulip_receipt_retries'):
            assert (await connection.execute(text('SELECT count(*) FROM ' + name))).scalar() == 0
        assert (await connection.execute(text('SELECT count(*) FROM artifacts'))).scalar() == 0
        assert (await connection.execute(text('SELECT count(*) FROM delivery_batches'))).scalar() == 0
        assert (await connection.execute(text('SELECT count(*) FROM output_destinations'))).scalar() == 0
        assert all(item is not None for item in (SessionRegistry, RuntimeEnrollment, ConsumerPipeline, SupervisedRuntime, CommandRouter, RoutedOutbox, BackendRegistry, DiscoveryService, BindingConfirmation, OutputDestinations, DiscoveryDeliveryWorker, ReplyPublisher, V2SessionCatalog, V2ExecutionClient, ExecutionReceipt, V2LogReader, NativeProjector, NativePublisher, NativeHistory, HistoryCommands, SEMANTICS_SHA256, V2ProjectPolicyGuard, V2TurnResourceReader, ZulipEventJournal, ZulipCommandConsumer, V2ModelCatalog, ModelSettingsAttestation, ModelCommands, ModelSettingPublisher, ResourceResultCollector, ResourcePublisher, ResourceHistory))
        assert (await connection.execute(text('SELECT count(*) FROM model_setting_publications'))).scalar() == 0
        for name in ('resource_result_records', 'resource_text_records', 'resource_publications'):
            assert (await connection.execute(text('SELECT count(*) FROM ' + name))).scalar() == 0
        native_result = await connection.scalar(text('SELECT native_result FROM actions'))
        assert isinstance(native_result, bytes)
        assert (await connection.execute(text('SELECT count(*) FROM native_log_index'))).scalar() == 0
        payload = await connection.scalar(text('SELECT payload FROM actions'))
        assert isinstance(payload, bytes) and b'PACKAGED_PRIVATE_PAYLOAD' not in payload
    files = LocalArtifactFiles(state / 'artifacts')
    identity, scope = str(uuid.uuid4()), {'purpose': 'packaging-test'}
    encrypted = cipher.seal(b'packaged crypto and file check', scope)
    files.write(identity, encrypted)
    assert cipher.open(files.read(identity, 1000), scope, max_plaintext_bytes=100) == b'packaged crypto and file check'
    files.remove(identity)
    files.close()
    settings = Settings.model_validate({'app': {'state_dir': str(state)}, 'database': {'url': str(database.engine.url)}})
    application = create_app(settings, database)
    listener = socket.socket(fileno=int(sys.argv[3]))
    print(json.dumps({'isolated_wheel_import': True, 'migration_revision': CURRENT_REVISION, 'packaged_crypto_and_files': True, 'packaged_payload_encryption': True, 'packaged_gpl_license': True}), flush=True)
    server = uvicorn.Server(uvicorn.Config(application, access_log=False, log_level='error', proxy_headers=False))
    await server.serve(sockets=[listener])

asyncio.run(main())
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    wheel = arguments.wheel.resolve(strict=True)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    evidence: dict[str, object] = {
        "wheel": wheel.name,
        "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
    }
    with tempfile.TemporaryDirectory(prefix="jt-oz-wheel-") as directory:
        root, state = Path(directory) / "package", Path(directory) / "state"
        root.mkdir()
        state.mkdir(mode=0o700)
        with zipfile.ZipFile(wheel) as archive:
            for name in archive.namelist():
                if Path(name).is_absolute() or ".." in Path(name).parts:
                    raise ValueError("unsafe wheel member")
            archive.extractall(root)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            process = subprocess.Popen(
                [sys.executable, "-I", "-c", CHILD, str(root), str(state), str(listener.fileno())],
                cwd=directory,
                pass_fds=(listener.fileno(),),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        try:
            deadline = time.monotonic() + 15
            while True:
                if process.poll() is not None:
                    raise RuntimeError("packaged application exited before readiness")
                try:
                    with opener.open(f"http://127.0.0.1:{port}/readyz", timeout=1) as response:
                        ready = json.load(response)
                    break
                except (urllib.error.URLError, TimeoutError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("packaged application readiness timeout") from None
                    time.sleep(0.05)
            assert ready["agent_consumers"] is False
            for route, expected in [("/", b"jt-oz-bridge"), ("/static/app.css", b"body")]:
                with opener.open(f"http://127.0.0.1:{port}{route}", timeout=2) as response:
                    assert expected in response.read()
            evidence.update(
                real_uvicorn_loopback_readiness=True,
                local_assets_and_login_page=True,
                agent_consumers=False,
            )
        finally:
            process.terminate()
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate(timeout=5)
            if process.returncode not in {0, -15}:
                raise RuntimeError("packaged application smoke failed: " + stderr[-2000:])
        evidence.update(json.loads(stdout.splitlines()[0]))
    evidence.update(
        process_stopped_and_temporary_state_removed=True,
        scope="Local packaging/HTTP smoke only; not installed-backend, authenticated browser or phone acceptance.",
    )
    report = json.dumps(evidence, indent=2) + "\n"
    if arguments.report:
        arguments.report.write_text(report)
    print(report, end="")


if __name__ == "__main__":
    main()
