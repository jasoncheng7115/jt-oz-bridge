"""Qualified one-attempt multipart upload; sharing and byte verification are separate."""

import hashlib
import math
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

import httpx
from pydantic import Field, StrictInt

from jt_oz_bridge.adapters.zulip.client import ZulipClient, ZulipError
from jt_oz_bridge.adapters.zulip.uploads import upload_reference
from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES, NativeAttachmentProjection
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.delivery import (
    DeliveryNotSent,
    DeliveryRateLimited,
    DeliveryRejected,
    check_original_write_witness,
)
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.storage.durable import digest

UPLOAD_SOURCES = {
    "zulip-12.3-upload.py": "9d7b8aec1f85c04fc3d5ec884918fed65c905436060cd0c1bcc6972ec8a7de77",
    "zulip-12.3-upload-views.py": "8ff6f886d799ebee31a2d84879cb947dc898c8cd3a1e837455f8ed6733a88b11",
}
UPLOAD_SEMANTICS = digest({"version": "12.3", "sources": UPLOAD_SOURCES})


def multipart_filename(filename: str) -> str:
    """Preserve names through pinned Django sanitizing + Zulip unquote().

    Django HTML-unescapes the multipart name and limits it to 255 characters
    before Zulip URL-decodes it. Protect literal percent/entity syntax without
    expanding Unicode characters. HTTPX additionally escapes each quote as %22.
    A name that cannot fit this wire representation is rejected before POST.
    """
    wire = filename.replace("%", "%25").replace("&", "%26")
    if any(not char.isprintable() for char in filename) or len(wire) + 2 * wire.count('"') > 255:
        raise DeliveryNotSent("zulip_file_filename_not_representable_without_changes")
    return wire


@dataclass(frozen=True)
class FileUploadAttestation:
    realm_id: str
    upload_realm_id: int
    bot_user_id: int
    feature_level: int
    semantics_sha256: str
    installed_evidence_sha256: str
    maximum_file_bytes: int = MAX_ATTACHMENT_BYTES


class UploadedFileReceipt(ControlModel):
    format: Literal["zulip-file-upload-admission-v1"] = "zulip-file-upload-admission-v1"
    realm_id: str
    bot_user_id: StrictInt = Field(gt=0)
    source: NativeAttachmentProjection
    upload_url: str
    filename_stored: str
    semantics_sha256: str
    installed_evidence_sha256: str
    bytes_verified: Literal[False] = False
    shared_in_message: Literal[False] = False


class ZulipFileUploader:
    def __init__(
        self, client: ZulipClient, *, attestation: FileUploadAttestation | None = None
    ) -> None:
        self.client, self.attestation = client, attestation

    def require(self) -> FileUploadAttestation:
        a = self.attestation
        e = self.client.attestation
        if (
            a is None
            or e is None
            or self.client.verify_identity is None
            or (a.realm_id, a.bot_user_id, a.feature_level)
            != (e.realm_id, e.bot_user_id, e.feature_level)
            or type(a.upload_realm_id) is not int
            or a.upload_realm_id <= 0
            or a.feature_level != 500
            or "upload" not in e.verified_file_operations
            or a.semantics_sha256 != UPLOAD_SEMANTICS
            or len(a.installed_evidence_sha256) != 64
            or any(c not in "0123456789abcdef" for c in a.installed_evidence_sha256)
            or type(a.maximum_file_bytes) is not int
            or not 0 < a.maximum_file_bytes <= MAX_ATTACHMENT_BYTES
        ):
            raise DeliveryNotSent("zulip_file_upload_not_qualified")
        return a

    async def upload(
        self,
        source: NativeAttachmentProjection,
        content: bytes,
        *,
        before_send: Callable[[], object],
    ) -> UploadedFileReceipt:
        # Bytes are immutable and never interpreted as a local path/file object.
        a = self.require()
        enrolled = self.client.attestation
        identity = self.client.verify_identity
        try:
            source = NativeAttachmentProjection.model_validate(source.model_dump(mode="json"))
            wire_filename = multipart_filename(source.filename)
            if (
                not isinstance(content, bytes)
                or len(content) != source.size
                or len(content) > a.maximum_file_bytes
                or hashlib.sha256(content).hexdigest() != source.sha256
            ):
                raise ValueError("mismatched upload bytes")
            if not callable(before_send) or identity is None or await identity() is not True:
                raise ValueError("missing current upload identity or witness")
            if (
                self.require() is not a
                or self.client.attestation is not enrolled
                or self.client.verify_identity is not identity
            ):
                raise ValueError("upload qualification changed")
        except Exception:
            raise DeliveryNotSent("zulip_file_upload_preflight_rejected") from None
        # Shared Bot/realm quota, including this non-message mutation. No awaits
        # between the final original/fencing checks and starting the HTTP call.
        sequence = self.client.budget.acquire() if self.client.budget is not None else 0
        try:
            if before_send() is not None:
                raise ValueError("upload_guard_must_complete_without_a_return_value")
            check_original_write_witness()
        except Exception:
            raise DeliveryNotSent("zulip_file_upload_original_witness_rejected") from None
        try:
            async with self.client.client.stream(
                "POST",
                "user_uploads",
                files={"filename": (wire_filename, content, source.mime_type)},
            ) as response:
                raw = bytearray()
                async for part in response.aiter_bytes():
                    if len(raw) + len(part) > 65536:
                        raise ZulipError("zulip_file_upload_response_too_large")
                    raw.extend(part)
                value = strict_loads(raw)
            if not isinstance(value, dict):
                raise ZulipError("zulip_file_upload_schema_changed")
            if (
                response.status_code == 429
                and value.get("result") == "error"
                and value.get("code") == "RATE_LIMIT_HIT"
            ):
                try:
                    retry = float(response.headers.get("retry-after", value.get("retry-after", 60)))
                except (TypeError, ValueError):
                    retry = 60
                if not math.isfinite(retry):
                    retry = 60
                retry = max(1, min(3600, retry))
                if self.client.budget is not None:
                    self.client.budget.rate_limited(retry)
                raise DeliveryRateLimited(retry)
            if response.status_code in {400, 401, 403, 404, 413} and value.get("result") == "error":
                raise DeliveryRejected("zulip_file_upload_rejected")
            if (
                response.status_code != 200
                or value.get("result") != "success"
                or value.get("ignored_parameters_unsupported")
            ):
                raise ZulipError("zulip_file_upload_outcome_requires_reconciliation")
            url = value.get("url")
            filename = value.get("filename")
            if (
                not isinstance(url, str)
                or not isinstance(filename, str)
                or not 1 <= len(filename) <= 255
                or filename != source.filename
            ):
                raise ZulipError("zulip_file_upload_receipt_changed")
            if "uri" in value and value["uri"] != url:
                raise ZulipError("zulip_file_upload_alias_changed")
            link = upload_reference(url, self.client.url)
            if link.path_id.split("/", 1)[0] != str(a.upload_realm_id):
                raise ZulipError("zulip_file_upload_realm_changed")
            # Keep a relative canonical URL; never persist a signed/foreign URL.
            canonical = "/user_uploads/" + link.path_id
            if not url.startswith("/user_uploads/"):
                raise ZulipError("zulip_file_upload_relative_url_required")
            NativeAttachmentProjection(
                filename=filename,
                mime_type=source.mime_type,
                size=source.size,
                sha256=source.sha256,
            )
            if self.client.budget is not None:
                self.client.budget.observe(response.headers, sequence)
            return UploadedFileReceipt(
                realm_id=a.realm_id,
                bot_user_id=a.bot_user_id,
                source=source,
                upload_url=canonical,
                filename_stored=filename,
                semantics_sha256=UPLOAD_SEMANTICS,
                installed_evidence_sha256=a.installed_evidence_sha256,
            )
        except (DeliveryRateLimited, DeliveryRejected):
            raise
        except (httpx.HTTPError, ValueError, TypeError, RecursionError):
            # An unknown post-send result is never retry authorization.
            raise ZulipError("zulip_file_upload_result_unverified_do_not_retry") from None
