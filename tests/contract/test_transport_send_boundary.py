"""Controlled localhost HTTP1 peer, never Native or a live qualification."""

import asyncio
import json
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.contracts import OpenAPIProfile
from jt_oz_bridge.adapters.opencode.transport import (
    ContractAttestation,
    TransportNotSent,
    V2HTTPTransport,
)


@asynccontextmanager
async def localhost_peer():
    state = SimpleNamespace(
        held=asyncio.Event(),
        release=asyncio.Event(),
        post_headers=[],
        post_bodies=[],
        header_received=asyncio.Event(),
        drop_ack=False,
        writers=set(),
        tasks=set(),
    )

    async def handle(reader, writer):
        state.writers.add(writer)
        try:
            while True:
                raw = await reader.readuntil(b"\r\n\r\n")
                first, *lines = raw[:-4].split(b"\r\n")
                method, target, _ = first.split(b" ", 2)
                headers = dict(line.split(b": ", 1) for line in lines)
                if method == b"POST":
                    state.post_headers.append((target, dict(headers)))
                    state.header_received.set()
                body = await reader.readexactly(int(headers.get(b"Content-Length", b"0")))
                if method == b"GET" and target == b"/hold":
                    state.held.set()
                    await state.release.wait()
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                elif method == b"POST":
                    state.post_bodies.append(body)
                    if state.drop_ack:
                        return
                    writer.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                else:
                    raise AssertionError("unexpected controlled localhost request")
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            state.writers.discard(writer)
            writer.close()
            await writer.wait_closed()

    def connected(reader, writer):
        task = asyncio.create_task(handle(reader, writer))
        state.tasks.add(task)
        task.add_done_callback(state.tasks.discard)

    server = await asyncio.start_server(connected, "127.0.0.1", 0)
    state.url = "http://127.0.0.1:" + str(server.sockets[0].getsockname()[1])
    try:
        yield state
    finally:
        state.release.set()
        server.close()
        await server.wait_closed()
        for writer in list(state.writers):
            writer.close()
        if state.tasks:
            await asyncio.wait_for(asyncio.gather(*list(state.tasks)), timeout=2)


def controlled_client(url, operations=frozenset({"session.shell"})):
    profile = OpenAPIProfile.from_file(
        Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json")
    )

    async def verify():
        return True

    client = V2HTTPTransport(
        url,
        profile,
        attestation=ContractAttestation(profile.sha256, "localhost-only", "fixture", operations),
        verify_identity=verify,
        transport=httpx.AsyncHTTPTransport(
            http1=True,
            http2=False,
            retries=0,
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
        ),
    )
    return client


@pytest.mark.parametrize("change", ["proof-expired", "authority-revoked", "attestation-drift"])
async def test_pool_wait_cannot_send_after_original_authority_expires(change):
    async with localhost_peer() as peer:
        client = controlled_client(peer.url)
        clock = {"now": 0.0, "allowed": True}
        queued = asyncio.Event()

        async def request_started(request):
            if request.method == "POST":
                queued.set()

        client.client.event_hooks["request"].append(request_started)

        async def authorize():
            if not clock["allowed"]:
                raise ValueError("PRIVATE_AUTHORITY_REVOKED")

        def ready():
            if clock["now"] >= 5:
                raise ValueError("PRIVATE_ORIGINAL_PROOF_EXPIRED")

        try:
            hold = asyncio.create_task(client.client.get("/hold"))
            await asyncio.wait_for(peer.held.wait(), timeout=2)
            mutation = asyncio.create_task(
                client.request(
                    "session.shell",
                    path={"sessionID": "ses_original"},
                    body={"id": "msg_" + "a" * 64, "command": "printf localhost-fixture"},
                    authorize_send=authorize,
                    before_send=ready,
                )
            )
            await asyncio.wait_for(queued.wait(), timeout=2)
            if change == "proof-expired":
                clock["now"] = 6.0
            elif change == "authority-revoked":
                clock["allowed"] = False
            else:
                client.attestation = replace(client.attestation)
            peer.release.set()
            with pytest.raises(TransportNotSent) as error:
                await asyncio.wait_for(mutation, timeout=2)
            assert "PRIVATE" not in str(error.value)
            await asyncio.wait_for(hold, timeout=2)
            assert peer.post_headers == [] and peer.post_bodies == []
        finally:
            await client.close()


async def test_connect_wait_cannot_renew_original_five_second_proof():
    async with localhost_peer() as peer:
        client = controlled_client(peer.url)
        pool = client.client._transport._pool
        backend = pool._network_backend
        connecting, release = asyncio.Event(), asyncio.Event()
        clock = {"now": 0}

        async def connect_tcp(*args, **kwargs):
            connecting.set()
            await release.wait()
            return await backend.connect_tcp(*args, **kwargs)

        pool._network_backend = SimpleNamespace(
            connect_tcp=connect_tcp,
            connect_unix_socket=backend.connect_unix_socket,
            sleep=backend.sleep,
        )

        async def authorize():
            return None

        def ready():
            if clock["now"] >= 5:
                raise ValueError("PRIVATE_EXPIRED_DURING_CONNECT")

        try:
            mutation = asyncio.create_task(
                client.request(
                    "session.shell",
                    path={"sessionID": "ses_original"},
                    body={"command": "printf localhost-fixture"},
                    authorize_send=authorize,
                    before_send=ready,
                )
            )
            await asyncio.wait_for(connecting.wait(), timeout=2)
            clock["now"] = 6
            release.set()
            with pytest.raises(TransportNotSent):
                await asyncio.wait_for(mutation, timeout=2)
            assert not peer.post_headers and not peer.post_bodies
        finally:
            release.set()
            await client.close()


@pytest.mark.parametrize("failure", ["body-guard", "lost-ack"])
async def test_after_headers_a_withheld_body_is_unsent_a_lost_ack_uncertain_neither_replayed(
    failure,
):
    from jt_oz_bridge.adapters.opencode.transport import TransportError

    async with localhost_peer() as peer:
        client = controlled_client(peer.url)
        peer.drop_ack = failure == "lost-ack"
        calls = []

        async def authorize():
            calls.append("authority")
            if failure == "body-guard" and len(calls) == 3:
                raise PermissionError("PRIVATE_REVOKED_AFTER_HEADERS")

        try:
            with pytest.raises(TransportError) as error:
                await client.request(
                    "session.shell",
                    path={"sessionID": "ses_original"},
                    body={"command": "printf localhost-fixture"},
                    authorize_send=authorize,
                )
            # Revoked before any body byte: Native cannot act on headers alone.
            assert isinstance(error.value, TransportNotSent) is (failure == "body-guard")
            assert "PRIVATE" not in str(error.value) and error.value.__suppress_context__
            await asyncio.wait_for(peer.header_received.wait(), timeout=2)
            assert len(calls) == 3 and len(peer.post_headers) == 1
            assert len(peer.post_bodies) == (1 if failure == "lost-ack" else 0)
        finally:
            await client.close()


async def test_repeated_real_wire_guards_keep_one_original_encrypted_journal_and_action(db):
    from sqlalchemy import select

    from jt_oz_bridge.storage.control_models import ControlToken
    from jt_oz_bridge.storage.models import Action
    from tests.integration.test_check_dispatch_records import count, read, save, setup

    journal, action, _, preflight = await setup(db)
    async with db.sessions() as session:
        original_action = await session.get(Action, action.id)
        original = (
            original_action.state,
            original_action.version,
            original_action.payload,
            original_action.operation_digest,
        )
        token = await session.scalar(select(ControlToken))
        token_before = token.used, token.context_hash, token.expires_at
    async with localhost_peer() as peer:
        client = controlled_client(peer.url)
        calls = []

        async def authorize():
            calls.append(preflight)
            assert await save(journal, preflight) == preflight

        body = {"id": preflight.message_id, "command": "printf localhost-fixture"}
        try:
            await client.request(
                "session.shell",
                path={"sessionID": "ses_original"},
                body=body,
                authorize_send=authorize,
            )
            assert len(calls) == 3 and all(value is preflight for value in calls)
            assert await count(db) == 1 and await read(journal, preflight) == preflight
            assert len(peer.post_headers) == len(peer.post_bodies) == 1
            assert peer.post_bodies[0] == json.dumps(body, ensure_ascii=False).encode()
            assert int(peer.post_headers[0][1][b"Content-Length"]) == len(peer.post_bodies[0])
            async with db.sessions() as session:
                saved = await session.get(Action, action.id)
                assert (
                    saved.state,
                    saved.version,
                    saved.payload,
                    saved.operation_digest,
                ) == original
                assert not saved.admission and not saved.native_result and saved.upstream_id is None
                token = await session.scalar(select(ControlToken))
                assert (token.used, token.context_hash, token.expires_at) == token_before
        finally:
            await client.close()


async def test_mock_auth_retry_cannot_drop_gate_extensions_and_send_a_second_post():
    from jt_oz_bridge.adapters.opencode.transport import TransportError

    attempts = []

    def handle(request):
        attempts.append(request)
        return httpx.Response(401)

    class RetryingAuth(httpx.Auth):
        def auth_flow(self, request):
            response = yield request
            assert response.status_code == 401
            # Deliberately omit all extensions, as a custom Auth flow may do.
            yield httpx.Request(request.method, request.url, content=request.content)

    client = controlled_client("http://127.0.0.1:1")
    await client.client._transport.aclose()
    client.client._transport = httpx.MockTransport(handle)
    client.client.auth = RetryingAuth()

    async def authority():
        return None

    try:
        with pytest.raises(TransportError) as error:
            await client.request(
                "session.shell",
                path={"sessionID": "ses_original"},
                body={"command": "printf localhost-fixture"},
                authorize_send=authority,
            )
        assert not isinstance(error.value, TransportNotSent) and len(attempts) == 1
    finally:
        await client.close()


@pytest.mark.parametrize("configuration", ["unknown-transport", "http2", "dependency-drift"])
async def test_unqualified_write_boundaries_reject_before_any_localhost_headers(
    configuration, monkeypatch
):
    async with localhost_peer() as peer:
        client = controlled_client(peer.url)
        delegate = client.client._transport
        calls = []

        class Unqualified(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request):
                calls.append(request)
                return await delegate.handle_async_request(request)

            async def aclose(self):
                await delegate.aclose()

        if configuration == "unknown-transport":
            client.client._transport = Unqualified()
        elif configuration == "http2":
            delegate._pool._http2 = True
        else:
            monkeypatch.setattr(httpx, "__version__", "unqualified")

        async def authority():
            return None

        try:
            with pytest.raises(TransportNotSent):
                await client.request(
                    "session.shell",
                    path={"sessionID": "ses_original"},
                    body={"command": "printf localhost-fixture"},
                    authorize_send=authority,
                )
            assert not calls and not peer.post_headers and not peer.post_bodies
        finally:
            await client.close()


async def test_non_check_mutation_also_rechecks_ready_after_pool_wait():
    async with localhost_peer() as peer:
        client = controlled_client(peer.url)
        client.attestation = replace(
            client.attestation, verified_operations=frozenset({"session.interrupt"})
        )
        queued = asyncio.Event()
        allowed = {"value": True}

        async def request_started(request):
            if request.method == "POST":
                queued.set()

        client.client.event_hooks["request"].append(request_started)

        def ready():
            if not allowed["value"]:
                raise PermissionError("PRIVATE_NON_CHECK_REVOKED")

        try:
            hold = asyncio.create_task(client.client.get("/hold"))
            await asyncio.wait_for(peer.held.wait(), timeout=2)
            mutation = asyncio.create_task(
                client.request(
                    "session.interrupt", path={"sessionID": "ses_original"}, before_send=ready
                )
            )
            await asyncio.wait_for(queued.wait(), timeout=2)
            allowed["value"] = False
            peer.release.set()
            with pytest.raises(TransportNotSent):
                await asyncio.wait_for(mutation, timeout=2)
            await asyncio.wait_for(hold, timeout=2)
            assert not peer.post_headers and not peer.post_bodies
        finally:
            await client.close()


@pytest.mark.parametrize(
    ("operation", "request_args", "withheld"),
    [
        (
            "session.shell",
            {
                "path": {"sessionID": "ses_original"},
                "body": {"command": "printf localhost-fixture"},
            },
            True,
        ),
        # Without a body the headers are the whole request: Native may act on them.
        ("session.interrupt", {"path": {"sessionID": "ses_original"}}, False),
    ],
)
async def test_expiry_during_actual_header_write_cannot_send_json_body(
    operation, request_args, withheld
):
    import httpcore

    from jt_oz_bridge.adapters.opencode.transport import TransportError

    async with localhost_peer() as peer:
        client = controlled_client(peer.url, frozenset({operation}))
        pool = client.client._transport._pool
        backend = pool._network_backend
        clock = {"now": 0}

        class HeaderWrite(httpcore.AsyncNetworkStream):
            def __init__(self, stream):
                self.stream = stream

            async def read(self, max_bytes, *args, **kwargs):
                return await self.stream.read(max_bytes, *args, **kwargs)

            async def write(self, buffer, *args, **kwargs):
                await self.stream.write(buffer, *args, **kwargs)
                if buffer.startswith(b"POST "):
                    clock["now"] = 6

            async def aclose(self):
                await self.stream.aclose()

            def get_extra_info(self, name):
                return self.stream.get_extra_info(name)

        async def connect_tcp(*args, **kwargs):
            return HeaderWrite(await backend.connect_tcp(*args, **kwargs))

        pool._network_backend = SimpleNamespace(
            connect_tcp=connect_tcp,
            connect_unix_socket=backend.connect_unix_socket,
            sleep=backend.sleep,
        )

        async def authorize():
            return None

        def ready():
            if clock["now"] >= 5:
                raise ValueError("PRIVATE_HEADER_WRITE_EXPIRED")

        try:
            with pytest.raises(TransportError) as error:
                await client.request(
                    operation,
                    **request_args,
                    before_send=ready,
                    authorize_send=authorize if operation == "session.shell" else None,
                )
            # Refused at the body's start: no body byte left, so a request that needs
            # one is known unsent; a bodiless one was complete with its headers.
            assert isinstance(error.value, TransportNotSent) is withheld
            assert str(error.value) == (
                "native_mutation_body_withheld"
                if withheld
                else "native_mutation_write_outcome_unknown"
            )
            await asyncio.wait_for(peer.header_received.wait(), timeout=2)
            assert len(peer.post_headers) == 1
            assert peer.post_bodies == ([] if withheld else [b""])
        finally:
            await client.close()


async def test_auth_cannot_replace_original_target_or_body_before_first_attempt():
    attempts = []

    class ChangingAuth(httpx.Auth):
        def auth_flow(self, request):
            yield httpx.Request(
                request.method, request.url.copy_with(path="/foreign"), content=b"PRIVATE_CHANGED"
            )

    client = controlled_client("http://127.0.0.1:1")
    await client.client._transport.aclose()
    client.client._transport = httpx.MockTransport(
        lambda request: attempts.append(request) or httpx.Response(204)
    )
    client.client.auth = ChangingAuth()

    async def authorize():
        return None

    try:
        with pytest.raises(TransportNotSent) as error:
            await client.request(
                "session.shell",
                path={"sessionID": "ses_original"},
                body={"command": "printf localhost-fixture"},
                authorize_send=authorize,
            )
        assert "PRIVATE" not in str(error.value) and attempts == []
    finally:
        await client.close()
