"""Synthetic exact V2 inline-byte admission; never installed/model certification."""

import base64
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from pydantic import ValidationError

from jt_oz_bridge.adapters.opencode.attachments import (
    ATTACHMENT_SCHEMA,
    ATTACHMENT_SEMANTICS,
    InlineAttachmentAttestation,
    inline_files,
    native_mime,
    projected_files,
    verify_admitted_files,
)
from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile
from jt_oz_bridge.domain.attachments import (
    MAX_ATTACHMENT_BYTES,
    PreparedPromptAttachments,
    PromptAttachmentManifest,
    PromptAttachmentReceipt,
    ResolvedPromptAttachment,
)
from jt_oz_bridge.domain.execution import MutationNotSent
from jt_oz_bridge.storage.durable import digest
from tests.contract.test_v2_execution import REF, payload, setup


def sample(content=b"exact file \x00\xff\r\n"):
    frozen = payload()
    manifest = PromptAttachmentManifest(
        files=(
            PromptAttachmentReceipt(
                artifact_id=str(uuid4()),
                source_upload="/user_uploads/2/random/original.bin",
                source_message_id=frozen["source"]["message_id"],
                source_sha256=digest(frozen["source"]),
                filename="original.bin",
                mime_type="application/octet-stream",
                size=len(content),
                sha256=hashlib.sha256(content).hexdigest(),
            ),
        )
    )
    prepared = PreparedPromptAttachments((ResolvedPromptAttachment(manifest.files[0], content),))
    frozen["attachments"] = manifest.model_dump(mode="json")
    return frozen, manifest, prepared


def ack_files(prepared):
    return [
        dict(
            data=base64.b64encode(f.content).decode(),
            mime=native_mime(f.content),
            source={"type": "inline"},
            name=f.receipt.filename,
        )
        for f in prepared.files
    ]


class SyntheticFiles:
    def __init__(self, prepared):
        self.prepared = prepared
        self.enabled = True
        self.valid = True
        self.calls = []
        self.attestation = InlineAttachmentAttestation(
            REF,
            ATTACHMENT_SCHEMA,
            ATTACHMENT_SEMANTICS,
            "a" * 64,
            verified_mime_types=frozenset(
                {"text/plain", "application/octet-stream", "application/pdf"}
            ),
        )

    def qualified(self, ref, sha):
        if not self.enabled:
            return False
        self.attestation.require(ref, sha)
        return True

    async def prepare(self, ref, action, source, manifest):
        self.calls.append((ref, action, source, manifest))
        return self.prepared

    def current(self, ref, action, prepared):
        return self.valid and prepared is self.prepared and ref == REF


def client_for(prepared, change_ack=None, *, corrupt_metadata=False):
    def change(request, data, provider):
        if request.method == "POST" and request.url.path.endswith("/prompt"):
            body = json.loads(request.content)
            files = ack_files(prepared)
            if change_ack:
                files = change_ack(files)
            return httpx.Response(
                200,
                json={
                    "data": {
                        "id": "msg_original",
                        "sessionID": REF.upstream_session_id,
                        "time": {"created": 0},
                        "type": "user",
                        "payload": {
                            "text": body["text"],
                            "files": files,
                            "metadata": {} if corrupt_metadata else body["metadata"],
                        },
                        "delivery": body["delivery"],
                    }
                },
            )

    profile = OpenAPIProfile.from_file(
        Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json")
    )
    client, transport, provider, data, seen = setup(profile, change=change)
    files = SyntheticFiles(prepared)
    client.attachments = files
    return client, transport, files, provider, seen


async def test_exact_original_prompt_inline_bytes_and_receipt_not_model_understanding():
    frozen, manifest, prepared = sample()
    client, transport, files, proofs, seen = client_for(prepared)
    try:
        admitted = await client.submit(REF, frozen, "action-original")
        requests = [r for r in seen if r.method == "POST"]
        assert len(requests) == 1
        body = json.loads(requests[0].content)
        assert requests[0].url.path.endswith("/" + REF.upstream_session_id + "/prompt")
        assert body["files"] == inline_files(manifest, prepared)
        assert body["metadata"]["jt_oz_bridge"]["operation_digest"] == digest(frozen)
        assert admitted.status == "admitted"
        projection = admitted.details["attachments"][0]
        assert projection["source"]["sha256"] == manifest.files[0].sha256
        assert projection["native"] == {
            "filename": "original.bin",
            "mime_type": "application/octet-stream",
            "size": len(prepared.files[0].content),
            "sha256": manifest.files[0].sha256,
        }
        assert projection["normalization"] == "none"
        assert (
            admitted.details["model_visibility"] == "unverified"
            and admitted.details["turn_completed"] is False
        )
        assert files.calls[0][0:2] == (REF, "action-original")
        assert "exact file" not in repr(prepared)
    finally:
        await transport.close()


async def test_twenty_mib_decoded_attachment_survives_bounded_base64_ack_response():
    frozen, manifest, prepared = sample(b"x" * MAX_ATTACHMENT_BYTES)
    client, transport, files, proofs, seen = client_for(prepared)
    try:
        admitted = await client.submit(REF, frozen, "large-file")
        assert admitted.details["attachments"][0]["native"]["size"] == MAX_ATTACHMENT_BYTES
        assert len([r for r in seen if r.method == "POST"]) == 1
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "kind",
    [
        "missing-provider",
        "unqualified",
        "expired",
        "bytes",
        "order",
        "source",
        "total",
        "unknown-field",
        "foreign-ref",
    ],
)
async def test_invalid_file_authority_or_bytes_never_sends_native_mutation(kind):
    frozen, manifest, prepared = sample()
    client, transport, files, proofs, seen = client_for(prepared)
    if kind == "missing-provider":
        client.attachments = None
    if kind == "unqualified":
        files.enabled = False
    if kind == "expired":
        files.valid = False
    if kind == "bytes":
        files.prepared = PreparedPromptAttachments(
            (replace(prepared.files[0], content=b"altered"),)
        )
    if kind == "order":
        files.prepared = PreparedPromptAttachments(())
    if kind == "source":
        frozen["source"]["revision"] += 1
    if kind == "total":
        frozen["attachments"]["files"] *= 2
    if kind == "unknown-field":
        frozen["attachments"]["files"][0]["uri"] = "file:///etc/passwd"
    if kind == "foreign-ref":
        frozen["reference"]["upstream_session_id"] = "ses_other"
    try:
        with pytest.raises(MutationNotSent):
            await client.submit(REF, frozen, "original")
        assert not [r for r in seen if r.method != "GET"]
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "kind", ["bytes", "mime", "filename", "source", "missing", "duplicate", "noncanonical", "extra"]
)
async def test_bad_attachment_ack_is_uncertain_and_never_reposted(kind):
    frozen, manifest, prepared = sample()

    def change(files):
        if kind == "bytes":
            files[0]["data"] = base64.b64encode(b"changed").decode()
        if kind == "mime":
            files[0]["mime"] = "text/plain"
        if kind == "filename":
            files[0]["name"] = "other.txt"
        if kind == "source":
            files[0]["source"] = {"type": "uri", "uri": "file:///server/file"}
        if kind == "missing":
            files = []
        if kind == "duplicate":
            files *= 2
        if kind == "noncanonical":
            files[0]["data"] = "Zh=="
        if kind == "extra":
            files[0]["unexpected"] = "PRIVATE"
        return files

    client, transport, files, proofs, seen = client_for(prepared, change)
    try:
        with pytest.raises((ContractError, ValueError)) as exc:
            await client.submit(REF, frozen, "same-action")
        assert not isinstance(exc.value, MutationNotSent)
        assert len([r for r in seen if r.method == "POST"]) == 1
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "changes",
    [
        {"contract_sha256": "b" * 64},
        {"semantics_sha256": "b" * 64},
        {"installed_evidence_sha256": "not-proof"},
        {"qualification_scope": "other"},
    ],
)
def test_file_qualification_requires_exact_schema_semantics_and_installed_evidence(changes):
    attestation = InlineAttachmentAttestation(
        REF,
        ATTACHMENT_SCHEMA,
        ATTACHMENT_SEMANTICS,
        "a" * 64,
        verified_mime_types=frozenset(
            {"text/plain", "application/octet-stream", "application/pdf"}
        ),
    )
    with pytest.raises(ContractError):
        replace(attestation, **changes).require(REF, ATTACHMENT_SCHEMA)


def test_session_scope_not_implicitly_promoted_to_other_native_root():
    attestation = InlineAttachmentAttestation(
        REF,
        ATTACHMENT_SCHEMA,
        ATTACHMENT_SEMANTICS,
        "a" * 64,
        verified_mime_types=frozenset(
            {"text/plain", "application/octet-stream", "application/pdf"}
        ),
    )
    other = REF.model_copy(update={"upstream_session_id": "ses_other"})
    with pytest.raises(ContractError):
        attestation.require(other, ATTACHMENT_SCHEMA)
    replace(attestation, qualification_scope="backend").require(other, ATTACHMENT_SCHEMA)
    with pytest.raises(ContractError):
        replace(attestation, qualification_scope="backend").require(
            other.model_copy(update={"backend_identity": "different-install"}), ATTACHMENT_SCHEMA
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"artifact_id": "../../etc/passwd"},
        {"filename": "../bad"},
        {"filename": "line\nname"},
        {"mime_type": "text/plain; secret=x"},
        {"size": True},
        {"source_upload": "https://outside/user_uploads/2/a/b"},
        {"source_upload": "/user_uploads/2/a/b?token=x"},
    ],
)
def test_receipt_rejects_paths_credentials_and_coercive_metadata(changes):
    frozen, manifest, prepared = sample()
    raw = {**manifest.files[0].model_dump(), **changes}
    with pytest.raises((ValidationError, ValueError)):
        PromptAttachmentReceipt.model_validate(raw)


def test_empty_binary_and_utf8_text_are_exact_not_interpreted_or_executed():
    for content in (b"", "繁體中文\r\n<script>alert(1)</script>".encode()):
        frozen, manifest, prepared = sample(content)
        verify_admitted_files(ack_files(prepared), manifest, prepared)
        assert (
            projected_files(ack_files(prepared))[0]["sha256"] == hashlib.sha256(content).hexdigest()
        )


def test_projected_receipts_never_retain_content_or_attachment_uri():
    frozen, manifest, prepared = sample(b"PRIVATE-MARKER")
    encoded = json.dumps(projected_files(ack_files(prepared)))
    assert "PRIVATE-MARKER" not in encoded and "UFJJVkFURS1NQVJLRVI=" not in encoded
    assert "uri" not in encoded


def test_multiple_files_preserve_order_and_total_bound_without_raw_paths():
    frozen, manifest, prepared = sample(b"first")
    receipt = manifest.files[0].model_copy(
        update={
            "artifact_id": str(uuid4()),
            "source_upload": "/user_uploads/2/random/second.txt",
            "filename": "second.txt",
            "mime_type": "text/plain",
            "size": 6,
            "sha256": hashlib.sha256(b"second").hexdigest(),
        }
    )
    manifest = PromptAttachmentManifest(files=(*manifest.files, receipt))
    prepared = PreparedPromptAttachments(
        (*prepared.files, ResolvedPromptAttachment(receipt, b"second"))
    )
    verify_admitted_files(ack_files(prepared), manifest, prepared)
    assert [f["name"] for f in inline_files(manifest, prepared)] == ["original.bin", "second.txt"]
    with pytest.raises(ValidationError):
        PromptAttachmentManifest(
            files=(manifest.files[0].model_copy(update={"size": MAX_ATTACHMENT_BYTES}), receipt)
        )


async def test_unexpected_files_without_a_frozen_manifest_are_not_silently_accepted():
    frozen, manifest, prepared = sample()
    frozen.pop("attachments")
    client, transport, files, proofs, seen = client_for(prepared)
    client.attachments = None
    try:
        with pytest.raises(ContractError, match="unexpected_attachment"):
            await client.submit(REF, frozen, "no-files-were-authorized")
        assert len([r for r in seen if r.method == "POST"]) == 1
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "content,expected",
    [
        (b"", "text/plain"),
        (b"plain\r\n", "text/plain"),
        ("繁體中文".encode(), "text/plain"),
        (b"\xef\xbb\xbfplain", "text/plain"),
        (b"\xe2\x82", "text/plain"),
        (b"\xff", "application/octet-stream"),
        (b"\x00text", "application/octet-stream"),
        (b"\xed\xa0\x80", "application/octet-stream"),
        (b"\x01" * 3 + b"a" * 7, "text/plain"),
        (b"\x01" * 4 + b"a" * 6, "application/octet-stream"),
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff", "image/jpeg"),
        (b"GIF89a", "image/gif"),
        (b"BM\x00\x00", "image/bmp"),
        (b"%PDF-1.7", "application/pdf"),
        (b"RIFF0000WEBP", "image/webp"),
        (b"0000ftypavif", "image/avif"),
        (b"0000ftypavis", "image/avif"),
        (b"<svg>not raster media</svg>", "text/plain"),
    ],
)
def test_classifier_matches_pinned_native_magic_and_streaming_utf8_behavior(content, expected):
    assert native_mime(content) == expected


def png(width=1, height=1):
    import struct
    import zlib

    def chunk(kind, body):
        return (
            struct.pack("!I", len(body)) + kind + body + struct.pack("!I", zlib.crc32(kind + body))
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack("!IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress((b"\x00" + b"\xff\x00\x00" * width) * height))
        + chunk(b"IEND", b"")
    )


def test_native_mime_correction_preserves_original_descriptor_and_exact_bytes():
    frozen, manifest, prepared = sample(b"UTF-8 text")
    # Zulip supplied octet-stream; the actual V2 engine detects text/plain.
    projection = verify_admitted_files(ack_files(prepared), manifest, prepared)[0]
    assert projection["source"]["mime_type"] == "application/octet-stream"
    assert projection["native"]["mime_type"] == "text/plain"
    assert projection["normalization"] == "none"
    assert projection["source"]["sha256"] == projection["native"]["sha256"]


@pytest.mark.parametrize("normalized", [False, True])
def test_qualified_image_preserves_original_hash_and_separates_normalized_native_projection(
    normalized,
):
    original = png(2100, 1)
    frozen, manifest, prepared = sample(original)
    prepared = replace(prepared, allow_image_normalization=True)
    actual = png(2000, 1) if normalized else original
    raw = [
        {
            "data": base64.b64encode(actual).decode(),
            "mime": "image/png",
            "source": {"type": "inline"},
            "name": "original.bin",
        }
    ]
    projection = verify_admitted_files(raw, manifest, prepared)[0]
    assert projection["source"]["sha256"] == hashlib.sha256(original).hexdigest()
    assert projection["native"]["sha256"] == hashlib.sha256(actual).hexdigest()
    assert projection["normalization"] == ("native-image-normalized" if normalized else "none")
    assert projection["source"]["mime_type"] == "application/octet-stream"
    assert projection["native"]["mime_type"] == "image/png"


async def test_sniffed_image_without_normalization_qualification_is_rejected_before_native_post():
    frozen, manifest, prepared = sample(png())
    client, transport, files, proofs, seen = client_for(prepared)
    try:
        with pytest.raises(MutationNotSent):
            await client.submit(REF, frozen, "image-unqualified")
        assert not [r for r in seen if r.method == "POST"]
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "kind",
    [
        "no-normalization-authority",
        "nonimage-source",
        "wrong-projection-mime",
        "wrong-name",
        "source-url",
        "description",
        "mention",
    ],
)
def test_image_normalization_does_not_relax_nonimage_integrity_or_provenance(kind):
    frozen, manifest, prepared = sample(b"plain" if kind == "nonimage-source" else png(2100, 1))
    prepared = replace(prepared, allow_image_normalization=(kind != "no-normalization-authority"))
    actual = png(2000, 1)
    raw = [
        {
            "data": base64.b64encode(actual).decode(),
            "mime": "image/png",
            "source": {"type": "inline"},
            "name": "original.bin",
        }
    ]
    if kind == "wrong-projection-mime":
        raw[0]["mime"] = "image/jpeg"
    if kind == "wrong-name":
        raw[0]["name"] = "other.png"
    if kind == "source-url":
        raw[0]["source"] = {"type": "uri", "uri": "file:///etc/secret"}
    if kind == "description":
        raw[0]["description"] = "unexpected instruction"
    if kind == "mention":
        raw[0]["mention"] = {"text": "unexpected", "start": 0, "end": 10}
    with pytest.raises(ContractError):
        verify_admitted_files(raw, manifest, prepared)


@pytest.mark.parametrize(
    "changes",
    [
        {"verified_mime_types": frozenset()},
        {"verified_mime_types": frozenset({"*/*"})},
        {"verified_mime_types": frozenset({"image/png"})},
        {"image_normalization_evidence_sha256": "invalid"},
    ],
)
def test_text_file_evidence_does_not_promote_to_unqualified_media(changes):
    attestation = InlineAttachmentAttestation(
        REF,
        ATTACHMENT_SCHEMA,
        ATTACHMENT_SEMANTICS,
        "a" * 64,
        verified_mime_types=frozenset({"text/plain"}),
    )
    with pytest.raises(ContractError):
        replace(attestation, **changes).require(REF, ATTACHMENT_SCHEMA)
    with pytest.raises(ContractError):
        attestation.require(REF, ATTACHMENT_SCHEMA, mime_type="application/pdf")


def test_separate_image_source_evidence_is_required_with_scoped_media_types():
    attestation = InlineAttachmentAttestation(
        REF,
        ATTACHMENT_SCHEMA,
        ATTACHMENT_SEMANTICS,
        "a" * 64,
        verified_mime_types=frozenset({"image/png"}),
        image_normalization_evidence_sha256="b" * 64,
    )
    attestation.require(REF, ATTACHMENT_SCHEMA, mime_type="image/png")
    with pytest.raises(ContractError):
        attestation.require(REF, ATTACHMENT_SCHEMA, mime_type="image/jpeg")


async def test_attachment_ack_must_preserve_exact_original_action_metadata_after_native_hooks():
    frozen, manifest, prepared = sample()
    client, transport, files, proofs, seen = client_for(prepared, corrupt_metadata=True)
    try:
        with pytest.raises(ContractError, match="correlation_changed"):
            await client.submit(REF, frozen, "original-action")
        assert len([r for r in seen if r.method == "POST"]) == 1
    finally:
        await transport.close()
