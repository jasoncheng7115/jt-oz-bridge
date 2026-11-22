"""Synthetic root-pinned evidence and composition; not installed certification."""

import copy
import json
from pathlib import Path

import pytest

from jt_oz_bridge.adapters.opencode import files as native_module
from jt_oz_bridge.adapters.opencode.files import FILE_FEATURES, FILE_SEMANTICS
from jt_oz_bridge.adapters.zulip import file_upload as upload_module
from jt_oz_bridge.adapters.zulip.file_upload import UPLOAD_SEMANTICS
from jt_oz_bridge.services import runtime_enrollment as runtime
from jt_oz_bridge.services.file_enrollment import component_sha, download_origin
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from tests.integration.test_runtime_enrollment import enrolled as enrolled

REVIEW = "installed-evidence-reviewed-for-development-runtime"


def native_document(enrolled):
    b = enrolled.manifest["backends"][0]
    owner = json.loads(enrolled.documents[Path(b["owner"]["path"])])
    host = {
        "pid": 42,
        "start_ticks": 123,
        "binary_sha256": owner["executable_sha256"],
        "nrestarts": 0,
    }
    cases = []
    for name, size, mime in [
        ("empty.bin", 0, "application/octet-stream"),
        ("binary.bin", 24, "application/octet-stream"),
        ("繁體 #?%.txt", 26, "text/plain"),
        ("board.html", 71, "text/html"),
        ("large.bin", 20 * 1024**2, "application/octet-stream"),
    ]:
        cases.append(
            {
                "case": name,
                "size": size,
                "mime_type": mime,
                "sha256": "c" * 64,
                "two_exact_native_reads": True,
                "original_object_current": True,
                "direct_local_read_not_permitted": True,
            }
        )
    cases += [
        {"case": name, "status": 404, "error_not_file": True}
        for name in ("outside.bin", "missing.bin")
    ]
    return {
        "format": "qualified-native-file-read-v2",
        "operator_review": REVIEW,
        "host_check": {
            "passed": True,
            "native_restart": False,
            "native_mutations": 0,
            "native_database_bytes_read": False,
            "native_process_unchanged": True,
            "controlled_probe_cleanup_complete": True,
            "native_before": host,
            "native_after": copy.deepcopy(host),
        },
        "native_read": {
            "passed": True,
            "native_database_bytes_read": False,
            "native_http_mutations": 0,
            "zulip_requests": 0,
            "reference": copy.deepcopy(enrolled.ref),
            "contract_sha256": b["schema_file"]["sha256"],
            "native_policy_sha256": "b" * 64,
            "candidate_module_sha256": component_sha(native_module),
            "file_semantics_sha256": FILE_SEMANTICS,
            "verified_features": sorted(FILE_FEATURES),
            "readonly_without_mutation_watch": True,
            "first_scope_deadline_preserved": True,
            "cases": cases,
        },
    }


def upload_document():
    source = {
        "filename": '測試%20&amp;".bin',
        "mime_type": "application/octet-stream",
        "size": 20 * 1024**2,
        "sha256": "d" * 64,
    }
    receipt = {
        "format": "zulip-file-upload-admission-v1",
        "realm_id": "2",
        "bot_user_id": 11,
        "source": source,
        "upload_url": "/user_uploads/2/synthetic/file.bin",
        "filename_stored": source["filename"],
        "semantics_sha256": UPLOAD_SEMANTICS,
        "installed_evidence_sha256": "e" * 64,
        "bytes_verified": False,
        "shared_in_message": False,
    }
    data = {
        k: True
        for k in (
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
    }
    data.update(
        upload_attempts=1,
        message_posts=0,
        native_requests=0,
        native_database_bytes_read=False,
        uploader_module_sha256=component_sha(upload_module),
        source=source,
        receipt=receipt,
    )
    return {
        "format": "qualified-zulip-file-upload-v1",
        "operator_review": REVIEW,
        "realm_url": "https://chat.invalid",
        "realm_id": "2",
        "upload_realm_id": 2,
        "bot_user_id": 11,
        "zulip_version": "12.3",
        "feature_level": 500,
        "upload": data,
    }


@pytest.fixture
def files(enrolled, tmp_path):
    enrolled.native = native_document(enrolled)
    enrolled.upload = upload_document()
    enrolled.manifest["format"] = "qualified-consumer-runtime-v3"
    b = enrolled.manifest["backends"][0]
    b["verified_operations"].append("fs.read")
    enrolled.settings.runtime.file_returns_enabled = True
    enrolled.settings.attachments.allowed_download_origins = ["https://chat.invalid"]
    enrolled.settings.app.state_dir = tmp_path / "runtime-state"

    def save_files():
        b["file_read"] = enrolled.pin("file-read.json", enrolled.native)
        enrolled.manifest["realm"]["file_upload"] = enrolled.pin(
            "file-upload.json", enrolled.upload
        )
        enrolled.manifest["realm"]["upload_realm_id"] = 2
        enrolled.manifest["realm"]["file_private_networks"] = ["10.0.0.25/32"]
        enrolled.save()

    enrolled.save_files = save_files
    save_files()
    return enrolled


def test_explicit_v3_file_evidence_load_is_inert(files, monkeypatch):
    monkeypatch.setattr(
        runtime, "resolve_secret", lambda _: pytest.fail("not resolved during read")
    )
    value, sha = runtime.read_enrollment(files.settings)
    assert value.format.endswith("v3") and len(sha) == 64
    assert not files.settings.app.state_dir.exists()


@pytest.mark.parametrize(
    "path,value",
    [
        (("native_read", "reference", "upstream_session_id"), "wrong"),
        (("native_read", "candidate_module_sha256"), "0" * 64),
        (("native_read", "native_policy_sha256"), "0" * 64),
        (("native_read", "contract_sha256"), "0" * 64),
        (("native_read", "file_semantics_sha256"), "0" * 64),
        (("native_read", "native_http_mutations"), 1),
        (("native_read", "native_database_bytes_read"), True),
        (("native_read", "verified_features"), []),
        (("native_read", "cases", 4, "size"), 1024),
        (("native_read", "cases", 5, "status"), 200),
        (("native_read", "cases", 0, "two_exact_native_reads"), False),
        (("host_check", "controlled_probe_cleanup_complete"), False),
        (("host_check", "native_after", "binary_sha256"), "0" * 64),
        (("operator_review",), "automatic-response-certificate"),
    ],
)
def test_native_evidence_drift_rejected_even_when_operator_rehashes_pin(files, path, value):
    target = files.native
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    files.save_files()
    with pytest.raises(ValueError):
        runtime.read_enrollment(files.settings)


@pytest.mark.parametrize(
    "path,value",
    [
        (("realm_url",), "https://different.invalid"),
        (("realm_id",), "foreign"),
        (("upload_realm_id",), 3),
        (("bot_user_id",), 12),
        (("zulip_version",), "different"),
        (("upload", "uploader_module_sha256"), "0" * 64),
        (("upload", "upload_attempts"), 2),
        (("upload", "original_download_filename_preserved"), False),
        (("upload", "source", "size"), 10),
        (("upload", "receipt", "bot_user_id"), 12),
        (("upload", "receipt", "semantics_sha256"), "0" * 64),
        (("upload", "receipt", "upload_url"), "/user_uploads/99/synthetic/file.bin"),
        (("upload", "receipt", "upload_url"), "https://foreign.invalid/user_uploads/2/x/y.bin"),
        (("upload", "message_posts"), True),
    ],
)
def test_upload_evidence_drift_rejected_even_with_matching_file_hash(files, path, value):
    target = files.upload
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    files.save_files()
    with pytest.raises(ValueError):
        runtime.read_enrollment(files.settings)


@pytest.mark.parametrize(
    "change",
    ["v2", "missing-read", "missing-upload", "missing-fs", "origin", "hash", "private-range"],
)
def test_incomplete_or_misconfigured_file_optin_fails_closed(files, change):
    if change == "v2":
        files.manifest["format"] = "qualified-consumer-runtime-v2"
    elif change == "missing-read":
        files.manifest["backends"][0].pop("file_read")
    elif change == "missing-upload":
        files.manifest["realm"].pop("file_upload")
    elif change == "missing-fs":
        files.manifest["backends"][0]["verified_operations"].remove("fs.read")
    elif change == "origin":
        files.settings.attachments.allowed_download_origins = []
    elif change == "private-range":
        files.manifest["realm"]["file_private_networks"] = ["10.0.0.0/24"]
    else:
        pin = files.manifest["realm"]["file_upload"]
        files.documents[Path(pin["path"])] += b" "
    files.save()
    with pytest.raises(ValueError):
        runtime.read_enrollment(files.settings)


@pytest.mark.parametrize("days", [2, 7])
async def test_enabled_pipeline_uses_original_clients_and_scoped_files_without_network(
    files, db, days
):
    files.settings.retention.temporary_artifact_days = days
    value, sha = runtime.read_enrollment(files.settings)
    lease = await DurableStore(db).acquire_lease("file-enrollment")
    pipeline = runtime.build_pipeline(
        files.settings, value, sha, db, ConsumerFence("file-enrollment", lease)
    )
    try:
        assert pipeline.files is not None
        journal = pipeline.files.journal
        assert journal.uploader.client is pipeline.scope.client
        assert pipeline.scope.enrolled is pipeline.scope.client.attestation
        assert (
            journal.outbox is pipeline.bound_outbox
            and pipeline.bound_delivery.file_returns is journal
        )
        for ref, reader in pipeline.files.readers.items():
            assert reader.client is pipeline.backends[ref.backend_id].metadata[ref].client
        assert pipeline.files.artifact_ttl_seconds == days * 86400
        assert pipeline.files.journal.artifacts.files._fd >= 0
    finally:
        await pipeline.close_files()
        await pipeline.scope.client.close()
        for backend in pipeline.backends.values():
            for resource in backend.resources:
                await resource.close()
    assert journal.artifacts.files._fd == -1 and journal.downloader.client.is_closed


async def test_disabled_flag_does_not_enable_even_preloaded_valid_file_proofs(files, db):
    files.settings.runtime.file_returns_enabled = False
    value, sha = runtime.read_enrollment(files.settings)
    lease = await DurableStore(db).acquire_lease("files-disabled")
    pipeline = runtime.build_pipeline(
        files.settings, value, sha, db, ConsumerFence("files-disabled", lease)
    )
    try:
        assert (
            pipeline.files is None
            and not pipeline.scope.client.attestation.verified_file_operations
        )
        assert not files.settings.app.state_dir.exists()
    finally:
        await pipeline.scope.client.close()
        for backend in pipeline.backends.values():
            for resource in backend.resources:
                await resource.close()


@pytest.mark.parametrize(
    "network", ["10.0.0.0/24", "0.0.0.0/0", "127.0.0.1/32", "169.254.169.254/32"]
)
def test_private_download_pins_are_specific_hosts_and_never_metadata_or_loopback(network):
    with pytest.raises(ValueError):
        download_origin("https://chat.invalid", (network,))


@pytest.mark.parametrize("changed", ["legacy-format", "readonly", "deadline"])
def test_old_mutation_watch_file_certificate_cannot_silently_authorize_read_scope(files, changed):
    if changed == "legacy-format":
        files.native["format"] = "qualified-native-file-read-v1"
    else:
        key = {
            "readonly": "readonly_without_mutation_watch",
            "deadline": "first_scope_deadline_preserved",
        }[changed]
        files.native["native_read"].pop(key)
    files.save_files()
    with pytest.raises(ValueError):
        runtime.read_enrollment(files.settings)
