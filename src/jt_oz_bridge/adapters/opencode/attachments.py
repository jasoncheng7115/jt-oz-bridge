"""V2 inline attachment bytes, independently qualified from text-only prompts."""

import base64
import binascii
import codecs
import hashlib
from dataclasses import dataclass
from typing import Any, Literal

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.domain.attachments import (
    MAX_ATTACHMENT_BYTES,
    MAX_ATTACHMENTS,
    PreparedPromptAttachments,
    PromptAttachmentManifest,
)
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.storage.durable import digest

ATTACHMENT_SCHEMA = "1c42291edfab54761b7f6cf0f490a262be277d45d1daa926ab3b8de15e658bce"
ATTACHMENT_SOURCES = {
    "prompt.ts": "4a453f9e57d3cc48fc7d6ea23504d1437c751620d7b97bff795c090f2941fc99",
    "mime.ts": "2898fc0a471236438177823763b1ee58fd92f871fe5ca19e23036c5d075ad57d",
    "image.ts": "d7f81a06fd941d0b45998a8d65da597bd3e3b53f4b9f996707b5abf6c4a204f9",
    "image/photon.ts": "074a05b55294f9940c3bcd6a8997f56da4be2c7d9b65c878b983c5522513646e",
}
ATTACHMENT_SEMANTICS = digest({"version": "2.0.32", "sources": ATTACHMENT_SOURCES})
NATIVE_MIMES = frozenset(
    {
        "text/plain",
        "application/octet-stream",
        "application/pdf",
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/bmp",
        "image/webp",
        "image/avif",
    }
)


def native_mime(content: bytes) -> str:
    """Match pinned V2 Mime.detect, including streaming UTF-8 validation."""
    for prefix, mime in (
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff", "image/jpeg"),
        (b"GIF8", "image/gif"),
        (b"BM", "image/bmp"),
        (b"%PDF-", "application/pdf"),
    ):
        if content.startswith(prefix):
            return mime
    if content[:4] == b"RIFF" and content[8:12] == b"WEBP":
        return "image/webp"
    if content[4:8] == b"ftyp" and content[8:12] in {b"avif", b"avis"}:
        return "image/avif"
    if not content:
        return "text/plain"
    if b"\x00" in content:
        return "application/octet-stream"
    try:
        codecs.getincrementaldecoder("utf-8")("strict").decode(content, final=False)
    except UnicodeError:
        return "application/octet-stream"
    ordinary = bytes(b for b in range(256) if not (b < 9 or 13 < b < 32))
    controls = len(content.translate(None, ordinary))
    return "text/plain" if controls / len(content) <= 0.3 else "application/octet-stream"


@dataclass(frozen=True)
class InlineAttachmentAttestation:
    reference: SessionRef
    contract_sha256: str
    semantics_sha256: str
    installed_evidence_sha256: str
    qualification_scope: Literal["session", "backend"] = "session"
    verified_mime_types: frozenset[str] = frozenset()
    image_normalization_evidence_sha256: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "verified_mime_types", frozenset(self.verified_mime_types))

    def require(
        self, reference: SessionRef, schema_sha256: str, *, mime_type: str | None = None
    ) -> None:
        scoped = reference == self.reference
        if self.qualification_scope == "backend":
            scoped = (
                reference.backend_id == self.reference.backend_id
                and reference.backend_identity == self.reference.backend_identity
            )
        if (
            not self.verified_mime_types
            or not self.verified_mime_types <= NATIVE_MIMES
            or mime_type is not None
            and mime_type not in self.verified_mime_types
            or any(m.startswith("image/") for m in self.verified_mime_types)
            and self.image_normalization_evidence_sha256 is None
            or self.image_normalization_evidence_sha256 is not None
            and (
                len(self.image_normalization_evidence_sha256) != 64
                or any(
                    c not in "0123456789abcdef" for c in self.image_normalization_evidence_sha256
                )
            )
            or self.qualification_scope not in {"session", "backend"}
            or not scoped
            or schema_sha256 != ATTACHMENT_SCHEMA
            or self.contract_sha256 != schema_sha256
            or self.semantics_sha256 != ATTACHMENT_SEMANTICS
            or len(self.installed_evidence_sha256) != 64
            or any(c not in "0123456789abcdef" for c in self.installed_evidence_sha256)
        ):
            raise ContractError("native_inline_attachment_semantics_unqualified")


def inline_files(
    manifest: PromptAttachmentManifest, prepared: PreparedPromptAttachments
) -> list[dict[str, str]]:
    prepared.checked(manifest)
    if not prepared.allow_image_normalization and any(
        native_mime(file.content).startswith("image/") for file in prepared.files
    ):
        raise ContractError("native_image_normalization_qualification_required_before_send")
    return [
        {
            "uri": "data:"
            + f.receipt.mime_type
            + ";base64,"
            + base64.b64encode(f.content).decode(),
            "name": f.receipt.filename,
        }
        for f in prepared.files
    ]


def projected_files(raw: Any, *, verify_detected_mime: bool = False) -> tuple[dict[str, Any], ...]:
    """Exact bytes-only receipt projection, never retain data URIs or content."""
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_ATTACHMENTS:
        raise ContractError("native_attachment_count_or_shape_changed")
    selected = []
    total = 0
    for item in raw:
        if (
            not isinstance(item, dict)
            or not {"data", "mime", "source", "name"} <= item.keys()
            or item.keys() - {"data", "mime", "source", "name"}
            or item["source"] != {"type": "inline"}
            or not isinstance(item["data"], str)
            or len(item["data"]) > 4 * ((MAX_ATTACHMENT_BYTES + 2) // 3)
            or not isinstance(item["name"], str)
            or not isinstance(item["mime"], str)
        ):
            raise ContractError("native_attachment_inline_projection_changed")
        try:
            encoded = item["data"].encode("ascii")
            content = base64.b64decode(encoded, validate=True)
        except (UnicodeError, ValueError, binascii.Error):
            raise ContractError("native_attachment_encoding_invalid") from None
        if verify_detected_mime and native_mime(content) != item["mime"]:
            raise ContractError("native_attachment_detected_mime_changed")
        total += len(content)
        if total > MAX_ATTACHMENT_BYTES or base64.b64encode(content) != encoded:
            raise ContractError("native_attachment_size_or_canonical_encoding_changed")
        selected.append(
            {
                "filename": item["name"],
                "mime_type": item["mime"],
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    return tuple(selected)


def verify_admitted_files(
    raw: Any,
    manifest: PromptAttachmentManifest,
    prepared: PreparedPromptAttachments,
) -> tuple[dict[str, Any], ...]:
    """Preserve originals, verify non-image bytes and separately qualified normalization.

    This verifies the Native admission representation, not model comprehension.
    The caller has already frozen the single original request and checked its
    owner/policy/qualification. No new capability is inferred from an ACK.
    """
    prepared.checked(manifest)
    selected = projected_files(raw, verify_detected_mime=True)
    if len(selected) != len(prepared.files):
        raise ContractError("native_attachment_acknowledgement_count_changed")
    results = []
    for actual, original in zip(selected, prepared.files, strict=True):
        detected = native_mime(original.content)
        unchanged = (actual["sha256"], actual["size"]) == (
            original.receipt.sha256,
            original.receipt.size,
        )
        if actual["filename"] != original.receipt.filename or (
            unchanged and actual["mime_type"] != detected
        ):
            raise ContractError("native_attachment_name_or_mime_changed")
        if not unchanged and not (
            detected.startswith("image/")
            and prepared.allow_image_normalization
            and actual["mime_type"] in {"image/png", "image/jpeg"}
        ):
            raise ContractError("native_attachment_unqualified_bytes_transformation")
        results.append(
            {
                "source": original.receipt.model_dump(
                    include={"artifact_id", "filename", "mime_type", "size", "sha256"}
                ),
                "native": actual,
                "normalization": "none" if unchanged else "native-image-normalized",
                "mime_detected_from_bytes": True,
            }
        )
    return tuple(results)
