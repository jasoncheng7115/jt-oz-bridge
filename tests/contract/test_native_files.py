"""Original-root/policy graph and binary HTTP mocks; not live qualification."""

import asyncio
import copy
import gc
import json
import time
import weakref
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.files import (
    FILE_FEATURES,
    FILE_SEMANTICS,
    BinaryReadAttestation,
    V2NativeFileReader,
    relative_file,
)
from tests.contract.test_leaf_resources import REF, finish
from tests.contract.test_native_project_policy import setup as policy_setup


async def setup(body=b"exact\x00\xff\r\n", mime="application/octet-stream", hook=None):
    p, t, d, g, client, policy_calls, writes = await policy_setup()
    t.attestation = replace(
        t.attestation, verified_operations=t.attestation.verified_operations | {"fs.read"}
    )
    attestation = BinaryReadAttestation(
        REF,
        t.profile.sha256,
        FILE_SEMANTICS,
        "a" * 64,
        g.enrollments[REF].fingerprint_sha256,
        FILE_FEATURES,
    )
    reader = V2NativeFileReader(client, attestation=attestation)
    original = t.client._transport
    reads = []

    def handler(request):
        if request.url.path.startswith("/api/fs/read/"):
            reads.append(request)
            assert (
                request.method == "GET"
                and request.url.params["location[directory]"] == REF.canonical_directory
            )
            assert (
                request.headers["accept-encoding"] == "identity" and "range" not in request.headers
            )
            if hook:
                response = hook(len(reads), d, p, t, reader)
                if response is not None:
                    return response
            return httpx.Response(
                200,
                headers={
                    "content-type": mime,
                    "content-length": str(len(body)),
                    "etag": 'W/"original"',
                },
                content=body,
            )
        return original.handler(request)

    t.client._transport = httpx.MockTransport(handler)
    # Compose the complete fixture contract before qualifying this generation.
    # A replaced transport attestation cannot borrow the earlier policy watch.
    await p.watch(REF)
    return p, t, d, reader, reads, writes


@pytest.mark.parametrize(
    "body,mime",
    [
        (b"", "application/octet-stream"),
        (b"\x00\xff\x7f\r\n", "application/octet-stream"),
        ("繁體中文".encode(), "text/plain"),
        (b"<!doctype html><html>PRIVATE_HTML_CONTENT</html>", "text/html"),
        (b'{"normal":"json file"}', "application/json"),
    ],
)
async def test_exact_binary_empty_html_utf8_json_bytes_are_not_json_transport_or_error_pages(
    body, mime
):
    p, t, d, reader, reads, writes = await setup(body, mime)
    try:
        result = await reader.read(REF, "dir/繁體#?%.txt")
        assert result.content == body and result.evidence.projection.mime_type == mime
        assert reader.current(result) and len(reads) == 2 and not writes
        assert b"%23%3F%25.txt" in reads[0].url.raw_path
        assert (
            "PRIVATE_HTML_CONTENT" not in repr(result)
            and "PRIVATE_HTML_CONTENT" not in result.evidence.model_dump_json()
        )
        assert not reader.current(replace(result))
        held = weakref.ref(result)
        del result
        gc.collect()
        assert held() is None
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "../escape",
        "a/../escape",
        "a//b",
        "a/./b",
        "a\\b",
        "https://outside/file",
        "file\x00name",
        "a\r\nheader",
        "a/",
        "a" * 256,
    ],
)
async def test_noncanonical_paths_are_rejected_before_any_file_request(path):
    p, t, d, reader, reads, writes = await setup()
    try:
        with pytest.raises(ContractError):
            await reader.read(REF, path)
        assert not reads and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "change",
    [
        {"reference": REF.model_copy(update={"upstream_session_id": "other"})},
        {"semantics_sha256": "0" * 64},
        {"installed_evidence_sha256": "wrong"},
        {"native_policy_sha256": "0" * 64},
        {"verified_features": frozenset()},
    ],
)
async def test_independent_file_qualification_cannot_be_inferred_from_text_execution(change):
    p, t, d, reader, reads, writes = await setup()
    reader.attestation = replace(reader.attestation, **change)
    try:
        with pytest.raises(ContractError, match="not_qualified"):
            await reader.read(REF, "file.bin")
        assert not reads and not writes
    finally:
        await finish(p, t)


async def test_unqualified_file_operation_and_missing_file_attestation_default_deny():
    p, t, d, reader, reads, writes = await setup()
    try:
        saved = reader.attestation
        reader.attestation = None
        with pytest.raises(ContractError):
            await reader.read(REF, "file.bin")
        reader.attestation = saved
        t.attestation = replace(
            t.attestation, verified_operations=t.attestation.verified_operations - {"fs.read"}
        )
        with pytest.raises(ContractError):
            await reader.read(REF, "file.bin")
        assert not reads and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("kind", ["size", "body", "etag", "policy", "qualification"])
async def test_two_reads_and_fresh_policy_must_match_before_file_can_be_returned(kind):
    def change(index, data, p, t, reader):
        if index != 2:
            return None
        if kind == "policy":
            data["session.get"]["data"]["permissions"] = [
                {"action": "*", "resource": "*", "effect": "allow"}
            ]
        if kind == "qualification":
            reader.attestation = replace(reader.attestation, installed_evidence_sha256="b" * 64)
        if kind in {"size", "body", "etag"}:
            body = {"size": b"other size", "body": b"CHANGED\r\n", "etag": b"exact\x00\xff\r\n"}[
                kind
            ]
            return httpx.Response(
                200,
                headers={
                    "content-type": "application/octet-stream",
                    "content-length": str(len(body)),
                    "etag": 'W/"changed"' if kind == "etag" else 'W/"original"',
                },
                content=body,
            )

    p, t, d, reader, reads, writes = await setup(hook=change)
    try:
        with pytest.raises(ContractError):
            await reader.read(REF, "file.bin")
        assert len(reads) == 2 and not reader._witnesses and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "kind",
    [
        "over-limit",
        "short",
        "long",
        "gzip",
        "partial",
        "no-etag",
        "no-length",
        "duplicate-length",
        "redirect",
        "not-found",
    ],
)
async def test_invalid_or_error_http_response_is_never_file_content(kind):
    def response(index, d, p, t, reader):
        headers = {
            "content-type": "application/octet-stream",
            "content-length": "3",
            "etag": 'W/"fixed"',
        }
        body = b"abc"
        status = 200
        if kind == "over-limit":
            headers["content-length"] = "20971521"
        elif kind == "short":
            headers["content-length"] = "4"
        elif kind == "long":
            headers["content-length"] = "2"
        elif kind == "gzip":
            headers["content-encoding"] = "gzip"
            body = b"not gzip"
        elif kind == "partial":
            headers["content-range"] = "bytes 0-2/6"
            status = 206
        elif kind == "no-etag":
            headers.pop("etag")
        elif kind == "duplicate-length":
            headers["content-length"] = "3, 3"
        elif kind == "redirect":
            status = 302
            headers["location"] = "https://other.invalid/secret"
        elif kind == "not-found":
            status = 404
            body = json.dumps(
                {"_tag": "FileNotFoundError", "path": "missing", "message": "not found"}
            ).encode()
            headers["content-length"] = str(len(body))
        result = httpx.Response(status, headers=headers, content=body)
        if kind == "no-length":
            result.headers.pop("content-length")
        return result

    p, t, d, reader, reads, writes = await setup(hook=response)
    try:
        with pytest.raises(ValueError):
            await reader.read(REF, "file.bin")
        assert len(reads) == 1 and not reader._witnesses and not writes
    finally:
        await finish(p, t)


async def test_object_witness_revokes_when_owner_feed_closes_or_qualification_changes():
    p, t, d, reader, reads, writes = await setup()
    try:
        result = await reader.read(REF, "file.bin")
        assert reader.current(result)
        att = reader.attestation
        reader.attestation = replace(att, installed_evidence_sha256="b" * 64)
        assert not reader.current(result)
        reader.attestation = att
        assert reader.current(result)
        await p.feed.close()
        assert not reader.current(result)
    finally:
        await finish(p, t)


def test_encoded_percent_names_are_literal_names_not_decoded_paths():
    assert relative_file("%2e%2e/ordinary.txt") == "%2e%2e/ordinary.txt"


async def test_twenty_mib_file_has_bounded_exact_hash_receipt_and_no_plaintext_cache():
    from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES

    content = b"x" * MAX_ATTACHMENT_BYTES
    p, t, d, reader, reads, writes = await setup(content)
    try:
        result = await reader.read(REF, "large.bin")
        assert len(result.content) == MAX_ATTACHMENT_BYTES and reader.current(result)
        assert len(reads) == 2 and not writes
        held = weakref.ref(result)
        del result
        gc.collect()
        assert held() is None
    finally:
        await finish(p, t)


async def test_file_witness_expiry_does_not_authorize_later_publication(monkeypatch):
    p, t, d, reader, reads, writes = await setup()
    try:
        result = await reader.read(REF, "file.bin")
        assert reader.current(result)
        monkeypatch.setattr(
            "jt_oz_bridge.adapters.opencode.files.time.time", lambda: result.evidence.expires_at + 1
        )
        assert not reader.current(result)
    finally:
        await finish(p, t)


async def test_read_scope_file_bytes_do_not_require_or_restore_mutation_watch(monkeypatch):
    p, t, data, reader, reads, writes = await setup()
    p.revoke_watch(REF)
    monkeypatch.setattr(reader.client, "qualified_snapshot", AsyncMock(side_effect=AssertionError))
    monkeypatch.setattr(p, "watch", AsyncMock(side_effect=AssertionError))
    try:
        result = await reader.read(REF, "file.bin")
        assert reader.current(result) and result.content == b"exact\x00\xff\r\n"
        assert result.evidence.expires_at - result.evidence.observed_at == 5
        assert p.certified_epoch(REF, t.profile.sha256) is None and not p._watched
        assert len(reads) == 2 and not writes
        assert not reader.current(replace(result))
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "drift",
    ["owner", "feed", "index", "task", "attestation", "generation", "fence", "policy", "scope"],
)
async def test_read_scope_binary_read_preserves_every_original_boundary(drift):
    tasks = []

    def hook(index, data, proofs, transport, reader):
        if index != 2:
            return
        if drift == "owner":
            proofs.feed.owner.read.return_value = SimpleNamespace(owner_epoch="f" * 64)
        elif drift == "feed":
            proofs.feed = copy.copy(proofs.feed)
        elif drift == "index":
            proofs.feed.index = copy.copy(proofs.feed.index)
        elif drift == "task":
            tasks.append(proofs.feed.task)
            proofs.feed.task = asyncio.create_task(asyncio.Event().wait())
        elif drift == "attestation":
            transport.attestation = replace(transport.attestation)
        elif drift == "generation":
            proofs.feed.index.connection_epoch = "f" * 64
        elif drift == "fence":
            from tests.contract.test_public_live_feed import REAL

            proofs.feed.index._notice_arrival(REAL[0])
        elif drift == "policy":
            data["session.get"]["data"]["permissions"] = []
        else:
            data["session.get"]["data"]["location"]["directory"] = "/other"

    p, t, data, reader, reads, writes = await setup(hook=hook)
    p.revoke_watch(REF)
    try:
        with pytest.raises((ValueError, KeyError)):
            await reader.read(REF, "file.bin")
        assert not reader._witnesses and len(reads) == 2 and not writes
        assert p.certified_epoch(REF, t.profile.sha256) is None
    finally:
        await finish(p, t)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.parametrize("elapsed", [2, 6])
async def test_read_scope_binary_deadline_starts_before_first_file_read(monkeypatch, elapsed):
    clock = [0.0]

    def hook(index, *_):
        if index == 2:
            clock[0] += elapsed

    p, t, data, reader, reads, writes = await setup(hook=hook)
    p.revoke_watch(REF)
    clock[0] = time.time()
    start = clock[0]
    monkeypatch.setattr("jt_oz_bridge.adapters.opencode.files.time.time", lambda: clock[0])
    try:
        if elapsed > 5:
            with pytest.raises(ContractError):
                await reader.read(REF, "file.bin")
            assert not reader._witnesses
        else:
            file = await reader.read(REF, "file.bin")
            assert file.evidence.observed_at == start and file.evidence.expires_at == start + 5
            assert reader.current(file)
            clock[0] = start + 5
            assert not reader.current(file)
        assert len(reads) == 2 and not writes and not p._watched
    finally:
        await finish(p, t)


@pytest.mark.parametrize("changed", ["feed", "index", "task", "attestation"])
async def test_new_read_epoch_cannot_resurrect_binary_witness_from_replaced_context(changed):
    p, t, data, reader, reads, writes = await setup()
    old_task = None
    p.revoke_watch(REF)
    try:
        previous = await reader.read(REF, "report.bin")
        if changed == "feed":
            p.feed = copy.copy(p.feed)
        elif changed == "index":
            p.feed.index = copy.copy(p.feed.index)
        elif changed == "task":
            old_task = p.feed.task
            p.feed.task = asyncio.create_task(asyncio.Event().wait())
        else:
            t.attestation = replace(t.attestation)
        # A different path keeps the first path's original-object memo alive.
        fresh = await reader.read(REF, "other.bin")
        assert reader.current(fresh) and not reader.current(previous)
        assert len(reads) == 4 and not writes and not p._watched
        assert p.certified_epoch(REF, t.profile.sha256) is None
    finally:
        await finish(p, t)
        if old_task is not None:
            old_task.cancel()
            await asyncio.gather(old_task, return_exceptions=True)


async def test_binary_read_elapsed_limit_cannot_be_reset_by_wall_clock_rollback(monkeypatch):
    p, t, data, reader, reads, writes = await setup()
    p.revoke_watch(REF)
    try:
        file = await reader.read(REF, "report.bin")
        now = time.monotonic()
        monkeypatch.setattr(
            "jt_oz_bridge.adapters.opencode.files.time.time",
            lambda: file.evidence.observed_at + 1,
        )
        monkeypatch.setattr("jt_oz_bridge.adapters.opencode.files.time.monotonic", lambda: now + 6)
        assert not reader.current(file)
        assert len(reads) == 2 and not writes and not p._watched
    finally:
        await finish(p, t)
