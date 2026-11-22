"""Runtime readiness file and DTO checks; no live service or Native calls."""

import json
import os

import pytest
from pydantic import ValidationError

from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.runtime_readiness import (
    ConsumerLeaseObservation,
    RootModeFact,
    RuntimeModeSnapshot,
    canonical_digest,
    lease_fingerprint,
    scope_key,
)
from jt_oz_bridge.services import runtime_status as status

KEY = lease_fingerprint("private-main-holder", 7)
REF = SessionRef(
    backend_id="backend-private",
    backend_identity="installation-private",
    upstream_session_id="ses_private_original",
    project_id="private-project",
    canonical_directory="/private/original/root",
)


@pytest.fixture
def private(tmp_path):
    path = tmp_path / "status"
    path.mkdir(mode=0o700)
    return path


def fact(**changes):
    return RootModeFact(
        scope_key=scope_key(REF), mode="strict", reason="strict-observation", transition_at=1.0
    ).model_copy(update=changes)


def snapshot(*, generated=100.0, roots=None, key=KEY):
    return RuntimeModeSnapshot.create(
        generated_at=generated, lease_fingerprint=key, roots=(fact(),) if roots is None else roots
    )


def lease(*, observed=100.0, expires=200.0, key=KEY):
    return ConsumerLeaseObservation(lease_fingerprint=key, observed_at=observed, expires_at=expires)


def seed(private, value=None):
    path = private / status.FILENAME
    path.write_text((value or snapshot()).model_dump_json() + "\n")
    path.chmod(0o600)
    return path


def test_actual_atomic_create_replace_and_old_transition_without_authority(private):
    writer = status.RuntimeStatusWriter(private, KEY, clock=lambda: 100.0)
    reader = status.RuntimeStatusReader(private, clock=lambda: 100.0)
    try:
        original = snapshot()
        writer.publish(original)
        first_inode = (private / status.FILENAME).stat().st_ino
        assert reader.read(lease(), bridge_healthy=True) == original
        updated = snapshot(
            roots=(fact(mode="readonly-owned-check", reason="owned-check-recovery"),)
        )
        writer.publish(updated)
        assert reader.read(lease(), bridge_healthy=True) == updated
        assert updated.roots[0].transition_at == 1.0  # old transition is not expired Native proof
        assert (private / status.FILENAME).stat().st_ino != first_inode
        assert sorted(p.name for p in private.iterdir()) == [status.BUFFER, status.FILENAME]
        raw = (private / status.FILENAME).read_text()
        for forbidden in (
            REF.upstream_session_id,
            REF.canonical_directory,
            REF.project_id,
            "private-main-holder",
            "owner_epoch",
            "connection_epoch",
            "proof",
            "cursor",
            "token",
        ):
            assert forbidden not in raw
        assert updated.roots[0].authority == "diagnostic_only"
        assert not hasattr(updated.roots[0], "writable")
    finally:
        writer.close()
        reader.close()


@pytest.mark.parametrize(
    "change",
    [
        "mode",
        "reason",
        "authority",
        "root",
        "duplicate",
        "unordered",
        "transition",
        "hash",
        "extra",
        "nan",
        "bool",
    ],
)
def test_dto_rejects_forged_or_noncanonical_fact_and_snapshot(change):
    value = snapshot().model_dump(mode="json")
    if change == "mode":
        value["roots"][0]["mode"] = "idle"
    elif change == "reason":
        value["roots"][0]["reason"] = "positive-idle-required"
    elif change == "authority":
        value["roots"][0]["authority"] = "mutation"
    elif change == "root":
        value["roots"][0]["scope_key"] = REF.upstream_session_id
    elif change == "duplicate":
        value["roots"] *= 2
    elif change == "unordered":
        value["roots"] = [
            value["roots"][0] | {"scope_key": "f" * 64},
            value["roots"][0] | {"scope_key": "0" * 64},
        ]
    elif change == "transition":
        value["roots"][0]["transition_at"] = 101.0
    elif change == "hash":
        value["content_sha256"] = "0" * 64
    elif change == "extra":
        value["token"] = "PRIVATE_FORBIDDEN"
    elif change == "nan":
        value["generated_at"] = float("nan")
    elif change == "bool":
        value["generated_at"] = True
    if change != "hash":
        value["content_sha256"] = (
            canonical_digest({k: v for k, v in value.items() if k != "content_sha256"})
            if change != "nan"
            else "0" * 64
        )
    with pytest.raises((ValidationError, ValueError)):
        RuntimeModeSnapshot.model_validate(value)


def test_scope_and_lease_keys_bind_all_identity_fields_without_serializing_them():
    baseline = scope_key(REF)
    for field in SessionRef.model_fields:
        assert (
            scope_key(REF.model_copy(update={field: str(getattr(REF, field)) + "-other"}))
            != baseline
        )
    assert lease_fingerprint("private-main-holder", 8) != KEY
    assert lease_fingerprint("other-holder", 7) != KEY
    with pytest.raises(ValueError):
        lease_fingerprint("private-main-holder", True)
    with pytest.raises(ValueError):
        lease_fingerprint("private\nsecret", 1)


@pytest.mark.parametrize(
    "case",
    [
        "future",
        "stale",
        "lease-stale",
        "lease-future",
        "lease-expired",
        "wrong-lease",
        "unhealthy",
        "coerced-health",
    ],
)
def test_reader_requires_fresh_matching_current_lease_and_process_observation(private, case):
    seed(
        private,
        snapshot(generated=101.0 if case == "future" else 95.0 if case == "stale" else 100.0),
    )
    expected = lease(
        observed=95.0 if case == "lease-stale" else 101.0 if case == "lease-future" else 100.0,
        expires=100.0 if case == "lease-expired" else 200.0,
        key="a" * 64 if case == "wrong-lease" else KEY,
    )
    reader = status.RuntimeStatusReader(private, clock=lambda: 100.0)
    try:
        with pytest.raises(status.RuntimeStatusError):
            reader.read(
                expected,
                bridge_healthy=False
                if case == "unhealthy"
                else 1
                if case == "coerced-health"
                else True,
            )
    finally:
        reader.close()


@pytest.mark.parametrize(
    "kind",
    [
        "symlink",
        "hardlink",
        "permissions",
        "directory",
        "large",
        "malformed",
        "duplicate-json",
        "wrong-hash",
        "secret-extra",
    ],
)
def test_untrusted_file_never_becomes_a_snapshot_or_gets_overwritten(private, kind):
    target = private / status.FILENAME
    if kind == "directory":
        target.mkdir(mode=0o700)
    elif kind == "symlink":
        original = private / "foreign"
        original.write_text("PRIVATE_ORIGINAL")
        target.symlink_to(original)
    else:
        seed(private)
        if kind == "hardlink":
            os.link(target, private / "second-link")
        elif kind == "permissions":
            target.chmod(0o640)
        elif kind == "large":
            target.write_bytes(b" " * (status.MAX_BYTES + 1))
        elif kind == "malformed":
            target.write_bytes(b'{"PRIVATE":"never show this"')
        elif kind == "duplicate-json":
            target.write_bytes(b'{"format":"PRIVATE","format":"second"}')
        elif kind == "wrong-hash":
            target.write_text(target.read_text().replace(KEY, "0" * 64))
        elif kind == "secret-extra":
            value = json.loads(target.read_text())
            value["token"] = "PRIVATE_SECRET"
            target.write_text(json.dumps(value))
    before = target.lstat()
    reader = status.RuntimeStatusReader(private, clock=lambda: 100.0)
    try:
        with pytest.raises(status.RuntimeStatusError) as failure:
            reader.read(lease(), bridge_healthy=True)
        assert "PRIVATE" not in str(failure.value)
    finally:
        reader.close()
    with pytest.raises(status.RuntimeStatusError):
        status.RuntimeStatusWriter(private, KEY, clock=lambda: 100.0)
    assert target.lstat().st_ino == before.st_ino
    if kind == "symlink":
        assert (private / "foreign").read_text() == "PRIVATE_ORIGINAL"


@pytest.mark.parametrize("mode", [0o750, 0o770, 0o755])
def test_reader_and_writer_reject_nonprivate_directory(private, mode):
    private.chmod(mode)
    for constructor in (
        lambda: status.RuntimeStatusReader(private),
        lambda: status.RuntimeStatusWriter(private, KEY),
    ):
        with pytest.raises(status.RuntimeStatusError):
            constructor()


def test_symlink_parent_rejected_and_replaced_directory_not_used(private):
    seed(private)
    link = private.parent / "alias"
    link.symlink_to(private, target_is_directory=True)
    with pytest.raises(status.RuntimeStatusError):
        status.RuntimeStatusReader(link)
    reader = status.RuntimeStatusReader(private, clock=lambda: 100.0)
    moved = private.with_name("original-directory")
    private.rename(moved)
    private.mkdir(mode=0o700)
    seed(private)
    try:
        with pytest.raises(status.RuntimeStatusError):
            reader.read(lease(), bridge_healthy=True)
    finally:
        reader.close()


def test_read_replacement_during_parse_is_rejected(private, monkeypatch):
    seed(private)
    reader = status.RuntimeStatusReader(private, clock=lambda: 100.0)
    parse = status._parse

    def replaced(raw):
        result = parse(raw)
        other = private / "replacement"
        other.write_bytes(raw)
        other.chmod(0o600)
        other.replace(private / status.FILENAME)
        return result

    monkeypatch.setattr(status, "_parse", replaced)
    try:
        with pytest.raises(status.RuntimeStatusError, match="file_changed"):
            reader.read(lease(), bridge_healthy=True)
    finally:
        reader.close()


@pytest.mark.parametrize("after_existing", [False, True])
def test_publish_raced_foreign_replacement_is_retained_not_unlinked(
    private, monkeypatch, after_existing
):
    if after_existing:
        seed(private)
    writer = status.RuntimeStatusWriter(private, KEY, clock=lambda: 100.0)
    rename = status._atomic_rename
    fired = False

    def raced(fd, source, target, *, exchange):
        nonlocal fired
        if not fired:
            fired = True
            foreign = private / "foreign"
            foreign.write_text("PRIVATE_FOREIGN_KEEP")
            foreign.chmod(0o600)
            foreign.replace(private / status.FILENAME)
        return rename(fd, source, target, exchange=exchange)

    monkeypatch.setattr(status, "_atomic_rename", raced)
    try:
        with pytest.raises(status.RuntimeStatusError):
            writer.publish(snapshot())
        preserved = [p for p in private.iterdir() if p.read_text() == "PRIVATE_FOREIGN_KEEP"]
        assert len(preserved) == 1
        assert sorted(p.name for p in private.iterdir()) == [status.BUFFER, status.FILENAME]
        with pytest.raises(status.RuntimeStatusError, match="invalidated"):
            writer.publish(snapshot())
    finally:
        writer.close()


def test_reader_lease_expiry_after_file_read_is_not_accepted(private):
    seed(private)
    values = iter((100.0, 101.0))
    reader = status.RuntimeStatusReader(private, clock=lambda: next(values))
    try:
        with pytest.raises(status.RuntimeStatusError, match="lease_not_current"):
            reader.read(lease(expires=100.5), bridge_healthy=True)
    finally:
        reader.close()


def test_writer_expiry_and_io_failure_leave_no_partial_or_unknown_cleanup(private, monkeypatch):
    writer = status.RuntimeStatusWriter(private, KEY, clock=lambda: 100.0)

    def fail(fd, data):
        raise OSError("PRIVATE_DISK_ERROR")

    monkeypatch.setattr(os, "write", fail)
    try:
        with pytest.raises(status.RuntimeStatusError) as failure:
            writer.publish(snapshot())
        assert "PRIVATE" not in str(failure.value)
        assert sorted(p.name for p in private.iterdir()) == [status.BUFFER]
        assert (private / status.BUFFER).stat().st_size == 0
        with pytest.raises(status.RuntimeStatusError, match="existing_file_untrusted"):
            status.RuntimeStatusWriter(private, KEY)
    finally:
        writer.close()


def test_snapshot_is_still_fresh_after_read_but_cannot_extend_transition_or_hash(private):
    seed(private)
    reader = status.RuntimeStatusReader(private, clock=lambda: 104.99)
    try:
        actual = reader.read(lease(observed=104.0), bridge_healthy=True)
        assert actual.roots[0].transition_at == 1.0 and actual.generated_at == 100.0
    finally:
        reader.close()


def test_root_count_and_serialized_capacity_are_bounded():
    roots = tuple(fact(scope_key=f"{i:064x}") for i in range(1001))
    with pytest.raises(ValueError, match="capacity"):
        snapshot(roots=roots)


def test_writer_revalidates_model_copy_and_wrong_lease_without_creating_files(private):
    original = snapshot()
    for forged in (
        original.model_copy(update={"content_sha256": "0" * 64}),
        original.model_copy(update={"generated_at": float("nan")}),
        snapshot(key="a" * 64),
    ):
        writer = status.RuntimeStatusWriter(private, KEY, clock=lambda: 100.0)
        try:
            with pytest.raises(status.RuntimeStatusError):
                writer.publish(forged)
            assert not list(private.iterdir())
        finally:
            writer.close()


@pytest.mark.parametrize("failure", ["expired-after-write", "zero-write", "unsupported-atomic"])
def test_failed_initial_publication_is_bounded_and_never_uses_plain_replace(
    private, monkeypatch, failure
):
    values = iter((100.0, 100.0, 105.0))
    writer = status.RuntimeStatusWriter(
        private,
        KEY,
        clock=(lambda: next(values)) if failure == "expired-after-write" else lambda: 100.0,
    )
    if failure == "zero-write":
        monkeypatch.setattr(os, "write", lambda fd, value: 0)
    if failure == "unsupported-atomic":
        monkeypatch.setattr(status.sys, "platform", "unsupported")
    try:
        with pytest.raises(status.RuntimeStatusError):
            writer.publish(snapshot())
        assert sorted(p.name for p in private.iterdir()) == [status.BUFFER]
        assert (private / status.BUFFER).stat().st_size <= status.MAX_BYTES
    finally:
        writer.close()


def test_writer_detects_replaced_existing_file_before_publication(private):
    seed(private)
    writer = status.RuntimeStatusWriter(private, KEY, clock=lambda: 100.0)
    foreign = private / "foreign"
    foreign.write_text("PRIVATE_DIFFERENT_SNAPSHOT")
    foreign.chmod(0o600)
    foreign.replace(private / status.FILENAME)
    try:
        with pytest.raises(status.RuntimeStatusError):
            writer.publish(snapshot())
        assert (private / status.FILENAME).read_text() == "PRIVATE_DIFFERENT_SNAPSHOT"
        assert sorted(p.name for p in private.iterdir()) == [status.FILENAME]
    finally:
        writer.close()


def test_current_file_wrong_owner_is_rejected_without_changing_it(private, monkeypatch):
    from types import SimpleNamespace

    seed(private)
    original = os.fstat

    def changed(fd):
        info = original(fd)
        if status.stat.S_ISREG(info.st_mode):
            values = {
                field: getattr(info, field)
                for field in (
                    "st_dev",
                    "st_ino",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                    "st_uid",
                    "st_mode",
                    "st_nlink",
                )
            }
            values["st_uid"] += 1
            return SimpleNamespace(**values)
        return info

    monkeypatch.setattr(os, "fstat", changed)
    reader = status.RuntimeStatusReader(private, clock=lambda: 100.0)
    try:
        with pytest.raises(status.RuntimeStatusError, match="private_regular_file"):
            reader.read(lease(), bridge_healthy=True)
    finally:
        reader.close()
    assert (private / status.FILENAME).read_text() == snapshot().model_dump_json() + "\n"


def test_directory_permissions_changed_after_open_are_not_accepted(private):
    seed(private)
    reader = status.RuntimeStatusReader(private, clock=lambda: 100.0)
    private.chmod(0o750)
    try:
        with pytest.raises(status.RuntimeStatusError, match="private_directory"):
            reader.read(lease(), bridge_healthy=True)
    finally:
        reader.close()


def test_reader_detects_in_place_file_change_during_read(private, monkeypatch):
    seed(private)
    reader = status.RuntimeStatusReader(private, clock=lambda: 100.0)
    read = os.read
    changed = False

    def mutate(fd, size):
        nonlocal changed
        result = read(fd, size)
        if not changed:
            changed = True
            with (private / status.FILENAME).open("a") as target:
                target.write(" ")
        return result

    monkeypatch.setattr(os, "read", mutate)
    try:
        with pytest.raises(status.RuntimeStatusError, match="file_changed"):
            reader.read(lease(), bridge_healthy=True)
    finally:
        reader.close()


@pytest.mark.parametrize(
    "kind", ["missing", "unsupported-version", "infinite-clock", "future-lease"]
)
def test_unavailable_observations_have_fixed_codes_and_no_epoch_or_state_fallback(private, kind):
    if kind != "missing":
        seed(private)
    if kind == "unsupported-version":
        path = private / status.FILENAME
        path.write_text(path.read_text().replace("snapshot-v1", "snapshot-v999"))
    reader = status.RuntimeStatusReader(
        private, clock=lambda: float("inf") if kind == "infinite-clock" else 100.0
    )
    try:
        with pytest.raises(status.RuntimeStatusError):
            reader.read(
                lease(observed=101.0 if kind == "future-lease" else 100.0), bridge_healthy=True
            )
    finally:
        reader.close()


def test_hours_old_controller_transition_is_not_a_five_second_native_proof(private):
    value = snapshot(generated=36001.0)
    writer = status.RuntimeStatusWriter(private, KEY, clock=lambda: 36001.0)
    reader = status.RuntimeStatusReader(private, clock=lambda: 36002.0)
    try:
        writer.publish(value)
        observed = reader.read(lease(observed=36002.0, expires=36010.0), bridge_healthy=True)
        assert observed.roots[0].transition_at == 1.0
        assert observed.generated_at == 36001.0
        assert observed.roots[0].authority == "diagnostic_only"
    finally:
        writer.close()
        reader.close()


def test_exact_maximum_root_snapshot_is_bounded_and_roundtrips(private):
    value = snapshot(roots=tuple(fact(scope_key=f"{i:064x}") for i in range(1000)))
    writer = status.RuntimeStatusWriter(private, KEY, clock=lambda: 100.0)
    reader = status.RuntimeStatusReader(private, clock=lambda: 100.0)
    try:
        writer.publish(value)
        assert (private / status.FILENAME).stat().st_size <= status.MAX_BYTES
        assert reader.read(lease(), bridge_healthy=True) == value
    finally:
        writer.close()
        reader.close()


@pytest.mark.parametrize("expiry", ["snapshot", "lease"])
def test_reader_rechecks_expiry_after_final_path_stat(private, monkeypatch, expiry):
    seed(private)
    clock = [104.0 if expiry == "snapshot" else 100.0]
    reader = status.RuntimeStatusReader(private, clock=lambda: clock[0])
    original = os.stat
    count = 0

    def delayed(path, *args, **kwargs):
        nonlocal count
        result = original(path, *args, **kwargs)
        if path == status.FILENAME and kwargs.get("dir_fd") == reader.directory.fd:
            count += 1
            if count == 2:
                clock[0] = 105.0 if expiry == "snapshot" else 101.0
        return result

    monkeypatch.setattr(os, "stat", delayed)
    try:
        with pytest.raises(status.RuntimeStatusError, match="not_current"):
            reader.read(
                lease(
                    observed=104.0 if expiry == "snapshot" else 100.0,
                    expires=200.0 if expiry == "snapshot" else 100.5,
                ),
                bridge_healthy=True,
            )
    finally:
        reader.close()


def test_publication_never_uses_pathname_unlink_cleanup(private, monkeypatch):
    writer = status.RuntimeStatusWriter(private, KEY, clock=lambda: 100.0)
    try:
        writer.publish(snapshot())

        def forbidden(*args, **kwargs):
            raise AssertionError("pathname unlink cannot preserve raced unknown entries")

        monkeypatch.setattr(os, "unlink", forbidden)
        writer.publish(snapshot(roots=()))
        assert len(list(private.iterdir())) <= 2
    finally:
        writer.close()


@pytest.mark.parametrize("corruption", ["partial", "hash", "symlink", "hardlink", "mode"])
def test_restart_refuses_untrusted_buffer_and_preserves_every_entry(private, corruption):
    seed(private)
    buffer = private / status.BUFFER
    buffer.write_text(snapshot().model_dump_json())
    buffer.chmod(0o600)
    if corruption == "partial":
        buffer.write_text('{"format":')
    elif corruption == "hash":
        buffer.write_text(buffer.read_text().replace(KEY, "0" * 64))
    elif corruption == "mode":
        buffer.chmod(0o640)
    elif corruption in ("symlink", "hardlink"):
        original = private / "external-original"
        buffer.rename(original)
        if corruption == "symlink":
            buffer.symlink_to(original)
        else:
            os.link(original, buffer)
    before = {p.name: p.lstat().st_ino for p in private.iterdir()}
    with pytest.raises(status.RuntimeStatusError, match="existing_file_untrusted"):
        status.RuntimeStatusWriter(private, KEY)
    assert {p.name: p.lstat().st_ino for p in private.iterdir()} == before


def test_restart_adopts_only_complete_managed_slots_and_reuses_two_inodes(private):
    writer = status.RuntimeStatusWriter(private, KEY, clock=lambda: 100.0)
    writer.publish(snapshot())
    writer.publish(snapshot(roots=()))
    writer.close()
    original = {p.stat().st_ino for p in private.iterdir()}
    writer = status.RuntimeStatusWriter(private, KEY, clock=lambda: 100.0)
    reader = status.RuntimeStatusReader(private, clock=lambda: 100.0)
    try:
        for i in range(100):
            expected = snapshot(roots=() if i % 2 else (fact(),))
            writer.publish(expected)
            assert reader.read(lease(), bridge_healthy=True) == expected
            assert {p.stat().st_ino for p in private.iterdir()} == original
            assert all(p.stat().st_size <= status.MAX_BYTES for p in private.iterdir())
    finally:
        writer.close()
        reader.close()


def test_replaced_buffer_is_opened_without_truncation_and_unknown_bytes_survive(
    private, monkeypatch
):
    writer = status.RuntimeStatusWriter(private, KEY, clock=lambda: 100.0)
    writer.publish(snapshot())
    writer.publish(snapshot())
    original = os.open
    fired = False

    def replaced(name, flags, *args, **kwargs):
        nonlocal fired
        if name == status.BUFFER and flags & os.O_RDWR:
            assert not flags & os.O_TRUNC
            fired = True
            replacement = private / "replacement"
            replacement.write_text("UNKNOWN_DO_NOT_TRUNCATE")
            replacement.chmod(0o600)
            replacement.replace(private / status.BUFFER)
        return original(name, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", replaced)
    try:
        with pytest.raises(status.RuntimeStatusError, match="file_changed"):
            writer.publish(snapshot())
        assert fired
        assert (private / status.BUFFER).read_text() == "UNKNOWN_DO_NOT_TRUNCATE"
        assert len(list(private.iterdir())) == 2
    finally:
        writer.close()


def test_model_copy_capacity_rejected_before_dump_or_sort(private, monkeypatch):
    huge = (fact(),) * 1001

    def forbidden(*args, **kwargs):
        raise AssertionError("capacity must be rejected before serialization")

    monkeypatch.setattr(RootModeFact, "model_dump", forbidden)
    with pytest.raises(ValueError, match="capacity"):
        snapshot(roots=huge)
    forged = RuntimeModeSnapshot.model_construct(roots=huge)
    writer = status.RuntimeStatusWriter(private, KEY, clock=lambda: 100.0)
    try:
        with pytest.raises(status.RuntimeStatusError, match="invalid_snapshot"):
            writer.publish(forged)
        assert not list(private.iterdir())
    finally:
        writer.close()


def test_wrong_dto_types_are_fixed_diagnostic_errors_without_public_fallback(private):
    reader = status.RuntimeStatusReader(private, clock=lambda: 100.0)
    writer = status.RuntimeStatusWriter(private, KEY, clock=lambda: 100.0)
    try:
        with pytest.raises(status.RuntimeStatusError, match="lease_invalid"):
            reader.read(None, bridge_healthy=True)
        with pytest.raises(status.RuntimeStatusError, match="invalid_snapshot"):
            writer.publish(None)
        assert not list(private.iterdir())
    finally:
        reader.close()
        writer.close()
