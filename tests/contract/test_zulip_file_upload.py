"""Synthetic multipart/budget/uncertain tests; not installed upload qualification."""

import hashlib
from dataclasses import replace
from email import policy
from email.parser import BytesParser

import httpx
import pytest

from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget
from jt_oz_bridge.adapters.zulip.client import ZulipAttestation, ZulipClient, ZulipError
from jt_oz_bridge.adapters.zulip.file_upload import (
    UPLOAD_SEMANTICS,
    FileUploadAttestation,
    ZulipFileUploader,
)
from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES, NativeAttachmentProjection
from jt_oz_bridge.domain.delivery import (
    DeliveryNotSent,
    DeliveryRateLimited,
    DeliveryRejected,
    original_write_witness,
)


def setup(response=None, *, budget=None):
    seen = []

    def handler(request):
        seen.append(request)
        assert request.method == "POST" and request.url.path == "/api/v1/user_uploads"
        assert request.headers["authorization"].startswith("Basic ")
        if callable(response):
            return response(request)
        return response or httpx.Response(
            200,
            json={
                "result": "success",
                "msg": "",
                "url": "/user_uploads/2/random/file.bin",
                "uri": "/user_uploads/2/random/file.bin",
                "filename": "file.bin",
            },
        )

    async def identity():
        return True

    client = ZulipClient(
        "https://chat.example",
        "fixture@example",
        "synthetic-key",
        attestation=ZulipAttestation(
            "https://chat.example",
            "realm",
            11,
            500,
            10000,
            60,
            verified_file_operations=frozenset({"upload"}),
        ),
        verify_identity=identity,
        transport=httpx.MockTransport(handler),
        budget=budget,
    )
    uploader = ZulipFileUploader(
        client, attestation=FileUploadAttestation("realm", 2, 11, 500, UPLOAD_SEMANTICS, "a" * 64)
    )
    return client, uploader, seen


def source(
    content=b"\x00\xffexact bytes\r\n", filename="file.bin", mime="application/octet-stream"
):
    return NativeAttachmentProjection(
        filename=filename,
        mime_type=mime,
        size=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )


@pytest.mark.parametrize(
    "content,mime",
    [
        (b"\x00\xffexact bytes\r\n", "application/octet-stream"),
        (b"", "application/octet-stream"),
        (b"<!doctype html><html>private file</html>", "text/html"),
        ("中文內容".encode(), "text/plain"),
    ],
)
async def test_multipart_preserves_exact_bytes_and_receipt_does_not_claim_download_or_sharing(
    content, mime
):
    client, uploader, seen = setup()
    called = []
    try:
        result = await uploader.upload(
            source(content, mime=mime), content, before_send=lambda: called.append(True)
        )
        assert (
            called == [True]
            and len(seen) == 1
            and not result.bytes_verified
            and not result.shared_in_message
        )
        assert result.source.sha256 == hashlib.sha256(content).hexdigest()
        message = BytesParser(policy=policy.default).parsebytes(
            b"Content-Type: "
            + seen[0].headers["content-type"].encode()
            + b"\r\nMIME-Version: 1.0\r\n\r\n"
            + seen[0].content
        )
        parts = list(message.iter_parts())
        assert len(parts) == 1
        assert parts[0].get_param("name", header="content-disposition") == "filename"
        assert parts[0].get_payload(decode=True) == content and parts[0].get_content_type() == mime
        assert "private file" not in result.model_dump_json()
    finally:
        await client.close()


async def test_unicode_server_url_is_canonicalized_and_stored_name_kept_separate_from_path():
    name = "繁體 [board].html"
    content = b"<html>data</html>"
    url = "/user_uploads/2/random/繁體-board.html"
    client, uploader, seen = setup(
        httpx.Response(200, json={"result": "success", "url": url, "uri": url, "filename": name})
    )
    try:
        result = await uploader.upload(
            source(content, filename=name, mime="text/html"), content, before_send=lambda: None
        )
        assert result.upload_url == "/user_uploads/2/random/%E7%B9%81%E9%AB%94-board.html"
        assert result.filename_stored == name and result.source.filename == name
    finally:
        await client.close()


@pytest.mark.parametrize(
    "kind",
    [
        "no-qualification",
        "no-upload-op",
        "no-identity",
        "false-identity",
        "changed-identity",
        "source-bytes",
        "source-size",
        "oversize",
        "maximum",
        "witness",
        "original-witness",
    ],
)
async def test_known_pre_send_refusals_do_not_open_an_http_request(kind):
    content = b"\x00\xffexact bytes\r\n"
    file = source(content)
    client, uploader, seen = setup()
    if kind == "no-qualification":
        uploader.attestation = None
    elif kind == "no-upload-op":
        client.attestation = replace(client.attestation, verified_file_operations=frozenset())
    elif kind == "no-identity":
        client.verify_identity = None
    elif kind == "false-identity":

        async def identity():
            return False

        client.verify_identity = identity
    elif kind == "changed-identity":

        async def identity():
            uploader.attestation = replace(uploader.attestation, installed_evidence_sha256="b" * 64)
            return True

        client.verify_identity = identity
    elif kind == "source-bytes":
        content = b"wrong"
    elif kind == "source-size":
        file = file.model_copy(update={"size": 0})
    elif kind == "oversize":
        file = file.model_copy(update={"size": MAX_ATTACHMENT_BYTES + 1})
    elif kind == "maximum":
        uploader.attestation = replace(uploader.attestation, maximum_file_bytes=1)

    def witness():
        if kind == "witness":
            raise ValueError("revoked synthetic original")

    try:
        with original_write_witness(lambda: kind != "original-witness"):
            with pytest.raises(DeliveryNotSent):
                await uploader.upload(file, content, before_send=witness)
        assert not seen
    finally:
        await client.close()


@pytest.mark.parametrize(
    "changes",
    [
        {"realm_id": "other"},
        {"upload_realm_id": True},
        {"bot_user_id": 99},
        {"feature_level": 501},
        {"semantics_sha256": "f" * 64},
        {"installed_evidence_sha256": "bad"},
        {"maximum_file_bytes": MAX_ATTACHMENT_BYTES + 1},
    ],
)
async def test_upload_qualification_is_explicitly_scoped_to_installed_contract(changes):
    client, uploader, seen = setup()
    uploader.attestation = replace(uploader.attestation, **changes)
    try:
        with pytest.raises(DeliveryNotSent):
            await uploader.upload(source(), b"\x00\xffexact bytes\r\n", before_send=lambda: None)
        assert not seen
    finally:
        await client.close()


@pytest.mark.parametrize(
    "kind",
    [
        "foreign",
        "other-realm",
        "alias",
        "missing-name",
        "unsafe-name",
        "ignored",
        "duplicate-json",
        "server-error",
        "redirect",
        "timeout",
    ],
)
async def test_unknown_post_send_outcome_is_single_attempt_and_never_retry_permission(kind):
    data = {"result": "success", "url": "/user_uploads/2/random/file.bin", "filename": "file.bin"}
    status = 200
    if kind == "foreign":
        data["url"] = "https://foreign.invalid/user_uploads/2/random/file.bin"
    elif kind == "other-realm":
        data["url"] = "/user_uploads/3/random/file.bin"
    elif kind == "alias":
        data["uri"] = "/user_uploads/2/random/other.bin"
    elif kind == "missing-name":
        data.pop("filename")
    elif kind == "unsafe-name":
        data["filename"] = "../secret"
    elif kind == "ignored":
        data["ignored_parameters_unsupported"] = ["filename"]
    elif kind == "server-error":
        status = 500
        data = {"result": "error", "msg": "private upstream diagnostic"}
    elif kind == "redirect":
        status = 302

    def reply(request):
        if kind == "timeout":
            raise httpx.ReadTimeout("synthetic timeout after request", request=request)
        if kind == "duplicate-json":
            return httpx.Response(200, content=b'{"result":"success","result":"error"}')
        return httpx.Response(status, json=data)

    client, uploader, seen = setup(reply)
    try:
        with pytest.raises(ZulipError, match="do_not_retry"):
            await uploader.upload(source(), b"\x00\xffexact bytes\r\n", before_send=lambda: None)
        assert len(seen) == 1
    finally:
        await client.close()


@pytest.mark.parametrize("status", [400, 401, 403, 404, 413])
async def test_verified_rejection_is_distinct_from_uncertain_upload(status):
    client, uploader, seen = setup(
        httpx.Response(status, json={"result": "error", "msg": "not stored"})
    )
    try:
        with pytest.raises(DeliveryRejected):
            await uploader.upload(source(), b"\x00\xffexact bytes\r\n", before_send=lambda: None)
        assert len(seen) == 1
    finally:
        await client.close()


async def test_upload_uses_same_bot_budget_and_honors_verified_rate_limit_cooldown():
    budget = ZulipRequestBudget(requests=4, reserved=1)
    client, uploader, seen = setup(
        httpx.Response(
            429, headers={"retry-after": "12"}, json={"result": "error", "code": "RATE_LIMIT_HIT"}
        ),
        budget=budget,
    )
    try:
        with pytest.raises(DeliveryRateLimited) as error:
            await uploader.upload(source(), b"\x00\xffexact bytes\r\n", before_send=lambda: None)
        assert error.value.retry_after == 12 and len(seen) == 1
        with pytest.raises(DeliveryRateLimited):
            await uploader.upload(source(), b"\x00\xffexact bytes\r\n", before_send=lambda: None)
        assert len(seen) == 1
    finally:
        await client.close()


async def test_full_twenty_mib_per_file_uses_real_multipart_bytes_not_base64_or_local_path():
    content = b"x" * MAX_ATTACHMENT_BYTES
    client, uploader, seen = setup()
    try:
        result = await uploader.upload(source(content), content, before_send=lambda: None)
        assert result.source.size == MAX_ATTACHMENT_BYTES and len(seen) == 1
        assert (
            content in seen[0].content
            and b"Content-Transfer-Encoding: base64" not in seen[0].content
        )
    finally:
        await client.close()


async def test_false_guard_is_a_known_unsent_result_instead_of_silent_success():
    client, uploader, seen = setup()
    try:
        with pytest.raises(DeliveryNotSent):
            await uploader.upload(source(), b"\x00\xffexact bytes\r\n", before_send=lambda: False)
        assert not seen
    finally:
        await client.close()


@pytest.mark.parametrize(
    "filename",
    [
        "literal%20file &amp;.txt",
        'quote"file.txt',
        "圖 [x].txt",
        "plain&copy;name%2F.txt",
        "%" * 85,
    ],
    ids=("percent-entity", "quote", "unicode", "entity-path-looking", "wire-boundary"),
)
async def test_multipart_name_survives_installed_django_html_unescape_and_zulip_unquote(filename):
    from html import unescape
    from urllib.parse import unquote

    def accept(request):
        parsed = BytesParser(policy=policy.default).parsebytes(
            b"Content-Type: "
            + request.headers["content-type"].encode()
            + b"\r\nMIME-Version: 1.0\r\n\r\n"
            + request.content
        )
        part = tuple(parsed.iter_parts())[0]
        wire = unescape(part.get_filename())
        assert len(wire) <= 255  # The installed UploadedFile pre-unquote cap.
        stored = unquote(wire)
        assert stored == filename
        return httpx.Response(
            200,
            json={
                "result": "success",
                "url": "/user_uploads/2/random/file.txt",
                "filename": stored,
            },
        )

    client, uploader, seen = setup(accept)
    try:
        value = b"unchanged bytes"
        receipt = await uploader.upload(
            source(value, filename=filename), value, before_send=lambda: None
        )
        assert receipt.filename_stored == filename and len(seen) == 1
    finally:
        await client.close()


@pytest.mark.parametrize(
    "filename",
    ["%" * 86, "&" * 86, '"' * 86, "non\u200bprintable.txt"],
    ids=("percent", "entity", "quote", "nonprintable"),
)
async def test_unrepresentable_multipart_names_stop_before_post_instead_of_silent_truncation(
    filename,
):
    client, uploader, seen = setup()
    try:
        value = b"unchanged bytes"
        with pytest.raises(DeliveryNotSent):
            await uploader.upload(source(value, filename=filename), value, before_send=lambda: None)
        assert not seen
    finally:
        await client.close()


async def test_success_response_with_changed_stored_filename_is_uncertain_not_retryable():
    client, uploader, seen = setup(
        httpx.Response(
            200,
            json={
                "result": "success",
                "url": "/user_uploads/2/random/file.bin",
                "filename": "renamed.bin",
            },
        )
    )
    try:
        value = b"unchanged bytes"
        with pytest.raises(ZulipError, match="do_not_retry"):
            await uploader.upload(source(value), value, before_send=lambda: None)
        assert len(seen) == 1
    finally:
        await client.close()
