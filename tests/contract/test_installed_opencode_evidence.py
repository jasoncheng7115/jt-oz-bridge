"""Regression decoding of benign installed captures; never enables live writes."""

import hashlib
import json
from pathlib import Path

import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile
from jt_oz_bridge.adapters.opencode.event_semantics import ProjectionState, normalize, reduce
from jt_oz_bridge.adapters.opencode.log import DurableLogItem, LogRead, decode_log
from jt_oz_bridge.adapters.opencode.sse import SSEFrame
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.native_events import LogProvenance, QualifiedLogRecord

ROOT = Path("tests/fixtures/installed/opencode-v2.0.32")
CAPTURE = json.loads((ROOT / "parsed-feed.json").read_text())
REF = SessionRef(
    backend_id="captured-fixture-only",
    backend_identity="not-an-owner-certificate",
    project_id="fixture-project",
    canonical_directory="/home/opencode/workspaces/example-project",
    upstream_session_id=CAPTURE["session_id"],
)
PROFILE = OpenAPIProfile.from_file(Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json"))


def test_installed_schema_scoped_capture_and_static_source_hashes_are_distinct_evidence():
    manifest = json.loads((ROOT / "manifest.json").read_text())
    assert PROFILE.sha256 == manifest["installed_openapi_sha256"]
    assert (
        hashlib.sha256((ROOT / "parsed-feed.json").read_bytes()).hexdigest()
        == manifest["parsed_feed_sha256"]
    )
    assert not manifest["qualified_bridge_mutation_enabled"]
    assert manifest["normal_original_followup_primitive"]
    assert manifest["durable_replay"] == "NOT_SUPPORTED_BY_DEFAULT_CLI"
    for row in manifest["source_tag_comparison"]:
        b = (ROOT / row["preserved_identical_file"]).read_bytes()
        assert len(b) == row["bytes"] and hashlib.sha256(b).hexdigest() == row["sha256"]
    for row in manifest["persistence_source_files"]:
        b = (ROOT / row["path"]).read_bytes()
        assert len(b) == row["bytes"] and hashlib.sha256(b).hexdigest() == row["sha256"]
    assert b"MIT License" in (ROOT / manifest["persistence_source_license"]).read_bytes()


@pytest.mark.parametrize("event", CAPTURE["events"], ids=lambda e: e["type"])
def test_real_filtered_public_feed_objects_match_installed_schema(event):
    PROFILE.sse_frame("event.subscribe", event="message", data=json.dumps(event), event_id=None)
    if "durable" in event:
        item = decode_log(SSEFrame(event="message", data=json.dumps(event)), REF)
        assert isinstance(item, DurableLogItem)
        assert item.durable.aggregateID == CAPTURE["session_id"]
    else:
        with pytest.raises(ContractError):
            decode_log(SSEFrame(event="message", data=json.dumps(event)), REF)


def test_actual_native_sequences_and_final_text_decode_without_inventing_ephemeral_positions():
    # This local synthetic provenance is explicitly not an enrollment certificate.
    context = LogProvenance(
        binding_id="fixture-binding",
        binding_revision=1,
        realm_id="fixture-realm",
        reference=REF,
        contract_sha256=PROFILE.sha256,
        execution_epoch="fixture-epoch",
        ownership_evidence_sha256="0" * 64,
        session_info_sha256="1" * 64,
    )
    state = ProjectionState(provenance=context)
    changes = []
    read = LogRead(REF)
    for raw in CAPTURE["events"]:
        if "durable" not in raw:
            continue
        read.accept(SSEFrame(event="message", data=json.dumps(raw)))
        event = normalize(
            QualifiedLogRecord(provenance=context, capture_epoch="fixture-stream", native=raw)
        )
        change = reduce(state, event)
        state = change.state
        changes.append(change)
    assert read.position == 19 and not read.synced
    texts = [c.text for c in changes if c.text is not None]
    assert len(texts) == 1 and texts[0].text == "JT_OZ_SAME_SESSION_OK"
    delivered = [c.delivery for c in changes if c.delivery is not None]
    assert len(delivered) == 1 and delivered[0].native_inbox_id == CAPTURE["inbox_id"]
    assert any(c.terminal is not None for c in changes)


def test_marker_only_actual_log_read_is_not_a_replay_of_observed_live_events():
    raw = (ROOT / "model-server-log-from-zero.sse").read_text()
    payload = raw.removeprefix("data: ").strip()
    read = LogRead(REF)
    marker = read.accept(SSEFrame(event="message", data=payload))
    assert marker.type == "log.synced" and read.synced and read.position == 10
    assert "durable" not in json.loads(payload)


@pytest.mark.parametrize("change", ["aggregate", "location", "session"])
def test_captured_event_cannot_be_reassigned_to_another_native_scope(change):
    raw = json.loads(
        json.dumps(next(e for e in CAPTURE["events"] if e["type"] == "session.text.ended"))
    )
    if change == "aggregate":
        raw["durable"]["aggregateID"] = "ses_other"
    elif change == "location":
        raw["location"]["directory"] = "/another/workspace"
    else:
        raw["data"]["sessionID"] = "ses_other"
    with pytest.raises(ContractError):
        decode_log(SSEFrame(event="message", data=json.dumps(raw)), REF)
