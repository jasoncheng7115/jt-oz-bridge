"""Normalize root-reviewed file evidence; never derive authority from chat data."""

import hashlib
import ipaddress
from pathlib import Path
from types import ModuleType
from typing import Any

from jt_oz_bridge.adapters.opencode import files as native_module
from jt_oz_bridge.adapters.opencode.files import (
    FILE_FEATURES,
    FILE_SEMANTICS,
    BinaryReadAttestation,
)
from jt_oz_bridge.adapters.zulip import file_upload as upload_module
from jt_oz_bridge.adapters.zulip.file_upload import (
    UPLOAD_SEMANTICS,
    FileUploadAttestation,
    UploadedFileReceipt,
)
from jt_oz_bridge.adapters.zulip.uploads import upload_reference
from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES, NativeAttachmentProjection
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.downloads import DownloadOrigin
from jt_oz_bridge.security.json_data import strict_loads


def component_sha(module: ModuleType) -> str:
    if not isinstance(module.__file__, str):
        raise ValueError("file_component_source_required")
    return hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()


def object_data(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("file_evidence_object_required")
    return value


def zero(value: Any) -> bool:
    return type(value) is int and value == 0


def native_file_qualification(
    raw: bytes,
    *,
    reference: SessionRef,
    contract_sha256: str,
    native_policy_sha256: str,
    executable_sha256: str,
    evidence_sha256: str,
) -> BinaryReadAttestation:
    bundle = object_data(strict_loads(raw))
    host, read = object_data(bundle.get("host_check")), object_data(bundle.get("native_read"))
    before, after = object_data(host.get("native_before")), object_data(host.get("native_after"))
    if (
        bundle.get("format") != "qualified-native-file-read-v2"
        or bundle.get("operator_review") != "installed-evidence-reviewed-for-development-runtime"
        or host.get("passed") is not True
        or host.get("native_restart") is not False
        or not zero(host.get("native_mutations"))
        or host.get("native_database_bytes_read") is not False
        or host.get("native_process_unchanged") is not True
        or host.get("controlled_probe_cleanup_complete") is not True
        or before != after
        or before.get("binary_sha256") != executable_sha256
        or not zero(before.get("nrestarts"))
        or read.get("passed") is not True
        or read.get("native_database_bytes_read") is not False
        or not zero(read.get("native_http_mutations"))
        or not zero(read.get("zulip_requests"))
        or read.get("reference") != reference.model_dump(mode="json")
        or read.get("contract_sha256") != contract_sha256
        or read.get("native_policy_sha256") != native_policy_sha256
        or read.get("candidate_module_sha256") != component_sha(native_module)
        or read.get("file_semantics_sha256") != FILE_SEMANTICS
        or read.get("verified_features") != sorted(FILE_FEATURES)
        or read.get("readonly_without_mutation_watch") is not True
        or read.get("first_scope_deadline_preserved") is not True
    ):
        raise ValueError("native_file_evidence_scope_or_component_changed")
    cases = read.get("cases")
    if not isinstance(cases, list) or len(cases) != 7:
        raise ValueError("native_file_evidence_complete_cases_required")
    cases = [object_data(case) for case in cases]
    expected = {
        "empty.bin": (0, "application/octet-stream"),
        "binary.bin": (24, "application/octet-stream"),
        "繁體 #?%.txt": (26, "text/plain"),
        "board.html": (71, "text/html"),
        "large.bin": (MAX_ATTACHMENT_BYTES, "application/octet-stream"),
    }
    if {c.get("case") for c in cases} != set(expected) | {"outside.bin", "missing.bin"}:
        raise ValueError("native_file_evidence_case_set_changed")
    for case in cases:
        if case["case"] in expected:
            size, mime = expected[case["case"]]
            if (
                type(case.get("size")) is not int
                or (case["size"], case.get("mime_type")) != (size, mime)
                or case.get("two_exact_native_reads") is not True
                or case.get("original_object_current") is not True
                or case.get("direct_local_read_not_permitted") is not True
            ):
                raise ValueError("native_file_evidence_exact_read_required")
            NativeAttachmentProjection(
                filename=case["case"], mime_type=mime, size=size, sha256=case.get("sha256")
            )
        elif (
            type(case.get("status")) is not int
            or case["status"] != 404
            or case.get("error_not_file") is not True
        ):
            raise ValueError("native_file_evidence_actual_boundary_rejection_required")
    return BinaryReadAttestation(
        reference,
        contract_sha256,
        FILE_SEMANTICS,
        evidence_sha256,
        native_policy_sha256,
        FILE_FEATURES,
    )


def upload_qualification(
    raw: bytes,
    *,
    realm_id: str,
    realm_url: str,
    numeric_realm_id: int,
    bot_user_id: int,
    zulip_version: str,
    feature_level: int,
    evidence_sha256: str,
) -> FileUploadAttestation:
    bundle = object_data(strict_loads(raw))
    upload = object_data(bundle.get("upload"))
    required = (
        "passed",
        "one_attempt_claimed",
        "upload_acknowledged",
        "exact_bytes_readback",
        "original_download_filename_preserved",
        "original_percent_entity_quote_filename_preserved",
        "signed_url_not_persisted",
        "auth_free_dns_pinned_readback",
        "live_bridge_counts_unchanged",
        "runtime_manifest_unchanged",
    )
    if (
        bundle.get("format") != "qualified-zulip-file-upload-v1"
        or bundle.get("operator_review") != "installed-evidence-reviewed-for-development-runtime"
        or bundle.get("realm_url") != realm_url
        or bundle.get("realm_id") != realm_id
        or type(bundle.get("upload_realm_id")) is not int
        or bundle["upload_realm_id"] != numeric_realm_id
        or bundle.get("bot_user_id") != bot_user_id
        or bundle.get("zulip_version") != zulip_version
        or bundle.get("feature_level") != feature_level
        or zulip_version != "12.3"
        or feature_level != 500
        or any(upload.get(flag) is not True for flag in required)
        or type(upload.get("upload_attempts")) is not int
        or upload["upload_attempts"] != 1
        or not zero(upload.get("message_posts"))
        or not zero(upload.get("native_requests"))
        or upload.get("native_database_bytes_read") is not False
        or upload.get("uploader_module_sha256") != component_sha(upload_module)
    ):
        raise ValueError("zulip_file_evidence_scope_or_component_changed")
    receipt = UploadedFileReceipt.model_validate(upload.get("receipt"))
    source = NativeAttachmentProjection.model_validate(upload.get("source"))
    if (
        receipt.realm_id != realm_id
        or receipt.bot_user_id != bot_user_id
        or receipt.semantics_sha256 != UPLOAD_SEMANTICS
        or receipt.source != source
        or receipt.filename_stored != source.filename
        or source.size != MAX_ATTACHMENT_BYTES
        or source.mime_type != "application/octet-stream"
        or not all(part in source.filename for part in ("%", "&", '"'))
        or source.filename.isascii()
    ):
        raise ValueError("zulip_file_evidence_exact_original_descriptor_required")
    uploaded = upload_reference(receipt.upload_url, realm_url)
    if uploaded.path_id.split("/", 1)[0] != str(numeric_realm_id):
        raise ValueError("zulip_file_evidence_numeric_realm_changed")
    return FileUploadAttestation(
        realm_id,
        int(uploaded.path_id.split("/", 1)[0]),
        bot_user_id,
        feature_level,
        UPLOAD_SEMANTICS,
        evidence_sha256,
    )


def download_origin(url: str, networks: tuple[str, ...]) -> DownloadOrigin:
    if len(networks) > 8 or len(set(networks)) != len(networks):
        raise ValueError("file_download_pins_must_be_unique_and_bounded")
    for value in networks:
        network = ipaddress.ip_network(value, strict=True)
        if network.prefixlen != network.max_prefixlen:
            raise ValueError("file_download_private_pin_must_be_single_host")
    return DownloadOrigin(url, private_networks=networks, path_prefixes=("/user_uploads/",))
