"""Synthetic helper qualification only: no Native/Human/Git/network proof.

The helper is imported without running its CLI. Index/tree/config fixtures are
local bytes. Child tests use harmless Python children, never a Git repository.
These tests do not enroll a scope or establish current mutation authority.
"""

import ast
import errno
import hashlib
import importlib.util
import json
import os
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

HELPER = Path(__file__).parents[2] / "ops" / "git-inspect225.py"
SPEC = importlib.util.spec_from_file_location("git_inspect225_helper", HELPER)
h = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(h)


def index_bytes(entries=(), algorithm="sha1", version=2, extension=b"", flags=None, extended=0):
    """Independent binary fixture encoder; never calls helper parsing/Merkle."""
    body = bytearray(b"DIRC" + struct.pack("!II", version, len(entries)))
    for path, mode, oid in entries:
        start = len(body)
        body.extend(struct.pack("!10I", 1, 0, 1, 0, 0, 1, int(mode, 8), 1000, 1000, 1))
        body.extend(bytes.fromhex(oid))
        bits = min(len(path), 0xFFF) if flags is None else flags
        body.extend(struct.pack("!H", bits))
        if bits & 0x4000:
            body.extend(struct.pack("!H", extended))
        body.extend(path + b"\0")
        body.extend(b"\0" * ((-(len(body) - start)) % 8))
    body.extend(extension)
    return bytes(body) + hashlib.new(algorithm, body).digest()


def reseal(raw, algorithm="sha1"):
    size = hashlib.new(algorithm).digest_size
    return raw[:-size] + hashlib.new(algorithm, raw[:-size]).digest()


def oid(algorithm="sha1", byte="11"):
    return byte * hashlib.new(algorithm).digest_size


def leaf_tree(name, mode="100644", value=None, algorithm="sha1"):
    raw = mode.encode() + b" " + name + b"\0" + bytes.fromhex(value or oid(algorithm))
    return hashlib.new(algorithm, b"tree " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


@pytest.mark.parametrize("algorithm", ["sha1", "sha256"])
@pytest.mark.parametrize("version", [2, 3])
def test_complete_index_supported_formats(algorithm, version):
    rows = [(b"a.txt", "100644", oid(algorithm)), (b"z/link", "120000", oid(algorithm, "22"))]
    entries, root, semantic = h.parse_index(
        index_bytes(rows, algorithm, version), algorithm, h.Deadline()
    )
    child = leaf_tree(b"link", "120000", oid(algorithm, "22"), algorithm)
    expected_body = (
        b"100644 a.txt\0" + bytes.fromhex(oid(algorithm)) + b"40000 z\0" + bytes.fromhex(child)
    )
    expected = hashlib.new(
        algorithm, b"tree " + str(len(expected_body)).encode() + b"\0" + expected_body
    ).hexdigest()
    assert entries == {p: (m, o) for p, m, o in rows}
    assert root == expected
    assert (
        semantic
        == hashlib.sha256(
            json.dumps([[m, p.decode(), o] for p, m, o in rows], separators=(",", ":")).encode()
        ).hexdigest()
    )


@pytest.mark.parametrize("count", [0, 51, 1001, 4096])
def test_complete_index_not_first_page(count):
    rows = [(f"p{i:04d}".encode(), "100644", oid()) for i in range(count)]
    entries, root, _ = h.parse_index(index_bytes(rows), "sha1", h.Deadline())
    assert len(entries) == count
    assert len(root) == 40
    if count == 0:
        assert root == "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


@pytest.mark.parametrize("mode", ["100644", "100755", "120000", "160000"])
def test_all_leaf_modes_have_exact_ls_files_crosscheck(mode):
    raw = index_bytes([(b"f", mode, oid())])
    entries, _, _ = h.parse_index(raw, "sha1", h.Deadline())
    assert entries == h.parse_ls_files(f"{mode} {oid()} 0\tf\0".encode(), "sha1", h.Deadline())


@pytest.mark.parametrize("flags", [0x1001, 0x2001, 0x3001, 0x8001])
def test_unmerged_and_assume_valid_refused(flags):
    with pytest.raises(h.Unavailable, match="index_flags"):
        h.parse_index(index_bytes([(b"f", "100644", oid())], flags=flags), "sha1", h.Deadline())


@pytest.mark.parametrize("extended", [0x2000, 0x4000, 0x8000, 1])
def test_ita_skip_worktree_and_reserved_extended_flags_refused(extended):
    raw = index_bytes([(b"f", "100644", oid())], version=3, flags=0x4001, extended=extended)
    with pytest.raises(h.Unavailable, match="index_flags"):
        h.parse_index(raw, "sha1", h.Deadline())


def test_v3_zero_extended_is_supported_but_v2_extended_is_not():
    row = [(b"f", "100644", oid())]
    assert (
        len(h.parse_index(index_bytes(row, version=3, flags=0x4001), "sha1", h.Deadline())[0]) == 1
    )
    with pytest.raises(h.Unavailable, match="index_flags"):
        h.parse_index(index_bytes(row, version=2, flags=0x4001), "sha1", h.Deadline())


@pytest.mark.parametrize("signature", [b"link", b"sdir", b"REUC", b"UNKN", b"EOIE", b"IEOT"])
def test_unsupported_split_sparse_optional_and_mandatory_extensions_refused(signature):
    raw = index_bytes(extension=signature + struct.pack("!I", 0))
    with pytest.raises(h.Unavailable, match="index_extension"):
        h.parse_index(raw, "sha1", h.Deadline())


@pytest.mark.parametrize("algorithm", ["sha1", "sha256"])
def test_tree_cache_never_supplies_tree_authority(algorithm):
    payload = b"\0" + b"0 0\n" + bytes.fromhex(oid(algorithm, "ff"))
    raw = index_bytes(
        algorithm=algorithm, extension=b"TREE" + struct.pack("!I", len(payload)) + payload
    )
    entries, root, _ = h.parse_index(raw, algorithm, h.Deadline())
    assert entries == {}
    assert root == hashlib.new(algorithm, b"tree 0\0").hexdigest()
    assert root != oid(algorithm, "ff")


@pytest.mark.parametrize(
    "payload", [b"", b"bad", b"x\0-1 0\n", b"\0-2 0\n", b"\0-1 1\n", b"\0-1 0\ntrailing"]
)
def test_malformed_cache_tree_refused(payload):
    with pytest.raises(h.Unavailable, match="index_extension"):
        h.parse_index(
            index_bytes(extension=b"TREE" + struct.pack("!I", len(payload)) + payload),
            "sha1",
            h.Deadline(),
        )


def test_checksum_padding_name_length_and_truncation_independent():
    original = index_bytes([(b"ff", "100644", oid())])
    corrupt = bytearray(original)
    corrupt[-1] ^= 1
    with pytest.raises(h.Unavailable, match="index_checksum"):
        h.parse_index(bytes(corrupt), "sha1", h.Deadline())
    corrupt = bytearray(original)
    corrupt[12 + 71] = 1  # final v2 entry padding byte, not path terminator
    with pytest.raises(h.Unavailable, match="index_padding"):
        h.parse_index(reseal(bytes(corrupt)), "sha1", h.Deadline())
    with pytest.raises(h.Unavailable, match="index_name_length"):
        h.parse_index(index_bytes([(b"f", "100644", oid())], flags=2), "sha1", h.Deadline())
    with pytest.raises(h.Unavailable):
        h.parse_index(original[:50], "sha1", h.Deadline())


@pytest.mark.parametrize(
    "rows",
    [
        [(b"a", "100644", "11" * 20), (b"a", "100644", "22" * 20)],
        [(b"z", "100644", "11" * 20), (b"a", "100644", "22" * 20)],
        [(b"a", "100644", "11" * 20), (b"a/b", "100644", "22" * 20)],
    ],
)
def test_duplicate_order_and_file_directory_collision_refused(rows):
    with pytest.raises(h.Unavailable):
        h.parse_index(index_bytes(rows), "sha1", h.Deadline())


@pytest.mark.parametrize(
    "path", [b"../bad", b"/abs", b"a//b", b"a\\b", b"a\nb", b"\xff", b"a" * 256]
)
def test_unsafe_binary_path_refused(path):
    with pytest.raises(h.Unavailable):
        h.parse_index(index_bytes([(path, "100644", oid())]), "sha1", h.Deadline())


def test_index_capacity_format_and_null_oid_fail_closed(monkeypatch):
    for raw in [
        index_bytes([(b"f", "100644", "00" * 20)]),
        index_bytes(version=4),
        b"x" * (h.INDEX_BYTES + 1),
    ]:
        with pytest.raises(h.Unavailable):
            h.parse_index(raw, "sha1", h.Deadline())
    raw = bytearray(index_bytes())
    raw[8:12] = struct.pack("!I", 4097)
    with pytest.raises(h.Unavailable, match="index_format"):
        h.parse_index(reseal(bytes(raw)), "sha1", h.Deadline())


def test_git_tree_sort_uses_directory_slash_not_plain_name_order():
    # Git sorts a.c before directory a/, despite ordinary byte sorting of names.
    entries = {b"a/z": ("100644", oid()), b"a.c": ("100644", oid(byte="22"))}
    root, hashes = h.tree_oids(entries, "sha1")
    body = (
        b"100644 a.c\0" + bytes.fromhex(oid(byte="22")) + b"40000 a\0" + bytes.fromhex(hashes[b"a"])
    )
    assert root == hashlib.sha1(b"tree " + str(len(body)).encode() + b"\0" + body).hexdigest()


@pytest.mark.parametrize("algorithm", ["sha1", "sha256"])
def test_full_head_tree_keeps_empty_directories_and_verifies_every_tree(algorithm):
    empty = hashlib.new(algorithm, b"tree 0\0").hexdigest()
    leaf = leaf_tree(b"f", algorithm=algorithm)
    body = b"40000 d\0" + bytes.fromhex(leaf) + b"40000 empty\0" + bytes.fromhex(empty)
    expected = hashlib.new(algorithm, b"tree " + str(len(body)).encode() + b"\0" + body).hexdigest()
    raw = (
        f"040000 tree {leaf}\td\0".encode()
        + f"100644 blob {oid(algorithm)}\td/f\0".encode()
        + f"040000 tree {empty}\tempty\0".encode()
    )
    assert h.parse_head(raw, algorithm, expected, h.Deadline()) == {
        b"d/f": ("100644", oid(algorithm))
    }
    with pytest.raises(h.Unavailable, match="head_tree_invalid"):
        h.parse_head(
            raw.replace(leaf.encode(), oid(algorithm, "ff").encode(), 1),
            algorithm,
            expected,
            h.Deadline(),
        )


def test_incomplete_head_directory_and_truncation_refused():
    raw = f"100644 blob {oid()}\td/f\0".encode()
    with pytest.raises(h.Unavailable, match="head_tree_incomplete"):
        h.parse_head(raw, "sha1", oid(), h.Deadline())
    with pytest.raises(h.Unavailable, match="head_capacity"):
        h.parse_head(raw[:-1], "sha1", oid(), h.Deadline())


def test_head_entry_limit_is_separate_from_index_limit(monkeypatch):
    monkeypatch.setattr(h, "HEAD_ENTRIES", 2)
    rows = b"".join(f"100644 blob {oid()}\t{i}\0".encode() for i in range(3))
    with pytest.raises(h.Unavailable, match="head_capacity"):
        h.parse_head(rows, "sha1", oid(), h.Deadline())
    with pytest.raises(h.Unavailable, match="head_capacity"):
        h.parse_head(b"x" * (h.HEAD_BYTES + 1), "sha1", oid(), h.Deadline())


def test_mass_staged_deletion_not_bounded_by_surviving_index_entries():
    head = {f"deleted{i:04d}".encode(): ("100644", oid()) for i in range(1001)}
    result = h.staged_paths({}, head, h.Deadline())
    assert len(result) == 1001 and {p["change"] for p in result} == {"deleted"}
    assert {p["mode"] for p in result} == {"100644"}


@pytest.mark.parametrize(
    ("before", "after", "change", "mode"),
    [
        (None, ("120000", "11" * 20), "added", "120000"),
        (("160000", "11" * 20), None, "deleted", "160000"),
        (("100644", "11" * 20), ("100755", "11" * 20), "modified", "100755"),
        (("100644", "11" * 20), ("120000", "11" * 20), "type_changed", "120000"),
        (("120000", "11" * 20), ("160000", "22" * 20), "type_changed", "160000"),
        (("160000", "11" * 20), ("160000", "22" * 20), "modified", "160000"),
    ],
)
def test_staged_type_and_deleted_mode_semantics(before, after, change, mode):
    head = {} if before is None else {b"f": before}
    index = {} if after is None else {b"f": after}
    assert h.staged_paths(index, head, h.Deadline()) == [
        {"safe_relative_path": "f", "change": change, "mode": mode}
    ]


@pytest.mark.parametrize(
    "name",
    [".env", "a/.env.dev", "x/id_rsa", "a.key", "a<secret>", "x/.jt-oz-incoming-7", "secrets/f"],
)
def test_sensitive_staged_names_refuse_entire_output(name):
    with pytest.raises(h.Unavailable, match="path_undisclosable"):
        h.staged_paths({name.encode(): ("100644", oid())}, {}, h.Deadline())


def test_staged_name_total_and_count_bounds():
    many = {f"f{i:04d}".encode(): ("100644", oid()) for i in range(4097)}
    with pytest.raises(h.Unavailable, match="staged_capacity"):
        h.staged_paths(many, {}, h.Deadline())
    large = {(f"f{i:03d}" + "x" * 250).encode(): ("100644", oid()) for i in range(130)}
    with pytest.raises(h.Unavailable, match="staged_capacity"):
        h.staged_paths(large, {}, h.Deadline())


@pytest.mark.parametrize(
    "row",
    [
        b"100644 " + b"11" * 20 + b" 1\tf\0",
        b"bad\0",
        b"100644 " + b"11" * 20 + b" 0\tf",
        (b"100644 " + b"11" * 20 + b" 0\tf\0") * 2,
    ],
)
def test_ls_files_unmerged_malformed_duplicate_or_truncated_refused(row):
    with pytest.raises(h.Unavailable):
        h.parse_ls_files(row, "sha1", h.Deadline())


@pytest.mark.parametrize(
    "key",
    [
        "include.path",
        "includeIf.gitdir:/tmp/.path",
        "extensions.partialClone",
        "extensions.worktreeConfig",
        "remote.origin.promisor",
        "remote.origin.partialCloneFilter",
        "core.alternateRefsCommand",
    ],
)
def test_unsafe_effective_configuration_refused(key):
    with pytest.raises(h.Unavailable):
        h.parse_config((key + "\nprivate-value\0").encode())


def test_config_preserves_order_duplicate_values_bare_and_empty_without_disclosure():
    raw = b"core.bare\0core.value\n\0remote.o.url\nhttps://user:secret@example.invalid/repo\0url.ssh://private/.pushinsteadof\nhttps://public/\0"
    parsed = h.parse_config(raw)
    assert parsed[:2] == [["core.bare", None], ["core.value", ""]]
    assert "secret" not in h.digest(h.canonical_json(parsed))
    assert h.digest(h.canonical_json(parsed)) != h.digest(h.canonical_json(list(reversed(parsed))))


def test_equal_prefix_conflicting_url_rewrites_refused():
    with pytest.raises(h.Unavailable, match="remote_ambiguous"):
        h.parse_config(b"url.a.pushinsteadof\nx\0url.b.pushinsteadof\nx\0")


def test_deadline_is_cumulative_including_parse():
    clock = [0.0]
    deadline = h.Deadline(lambda: clock[0])
    clock[0] = 4.65
    assert deadline.remaining() == pytest.approx(0.1)
    assert deadline.remaining(cleanup=True) == pytest.approx(0.35)
    clock[0] = 4.75
    with pytest.raises(h.Unavailable, match="deadline"):
        h.parse_index(index_bytes(), "sha1", deadline)


def test_stable_owned_fd_bounded_and_no_symlink(tmp_path):
    tmp_path = tmp_path.resolve()
    path = tmp_path / "index"
    path.write_bytes(b"abc")
    raw, _ = h.read_file(str(path), 3, h.Deadline(), os.getuid())
    assert raw == b"abc"
    with pytest.raises(h.Unavailable, match="file_capacity_or_identity"):
        h.read_file(str(path), 2, h.Deadline(), os.getuid())
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(h.Unavailable, match="physical_scope"):
        h.read_file(str(link), 3, h.Deadline(), os.getuid())
    alias = tmp_path / "hardlink"
    os.link(path, alias)
    with pytest.raises(h.Unavailable, match="file_capacity_or_identity"):
        h.read_file(str(path), 3, h.Deadline(), os.getuid())


def test_index_replacement_during_read_refused(tmp_path, monkeypatch):
    tmp_path = tmp_path.resolve()
    path = tmp_path / "index"
    path.write_bytes(b"abc")
    original_read = h.os.read
    replaced = False

    def replacing(fd, count):
        nonlocal replaced
        data = original_read(fd, count)
        if not replaced:
            replaced = True
            alternative = tmp_path / "replacement"
            alternative.write_bytes(b"abc")
            os.replace(alternative, path)
        return data

    monkeypatch.setattr(h.os, "read", replacing)
    with pytest.raises(h.Unavailable, match="file_changed"):
        h.read_file(str(path), 3, h.Deadline(), os.getuid())


def configuration_pin(path, content):
    """Independent stat/hash input for an owned, non-secret configuration fixture."""
    observed = path.stat()
    return {
        "path": str(path),
        "dev": observed.st_dev,
        "ino": observed.st_ino,
        "uid": observed.st_uid,
        "gid": observed.st_gid,
        "mode": observed.st_mode & 0o7777,
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def test_pinned_configuration_reads_original_descriptor(tmp_path):
    path = tmp_path.resolve() / "config"
    content = b"[core]\nfilemode = true\n"
    path.write_bytes(content)
    path.chmod(0o600)
    raw, _ = h.file_pin(configuration_pin(path, content), h.Deadline())
    assert raw == content


@pytest.mark.parametrize("replacement_content", [b"same-config", b"other-value"])
def test_config_replacement_after_pin_check_is_rejected_before_read(
    tmp_path, monkeypatch, replacement_content
):
    folder = tmp_path.resolve()
    path, replacement = folder / "config", folder / "unregistered-canary"
    path.write_bytes(b"same-config")
    replacement.write_bytes(replacement_content)
    path.chmod(0o600)
    replacement.chmod(0o600)
    pin = configuration_pin(path, b"same-config")
    foreign_identity = (replacement.stat().st_dev, replacement.stat().st_ino)
    real_check, real_read = h.check_pin, os.read
    foreign_reads = []

    def replace_after_validation(*args, **kwargs):
        result = real_check(*args, **kwargs)
        replacement.replace(path)
        return result

    def observe_read(fd, count):
        observed = os.fstat(fd)
        data = real_read(fd, count)
        if (observed.st_dev, observed.st_ino) == foreign_identity:
            foreign_reads.append(len(data))
        return data

    monkeypatch.setattr(h, "check_pin", replace_after_validation)
    monkeypatch.setattr(h.os, "read", observe_read)
    with pytest.raises(h.Unavailable, match="file_identity"):
        h.file_pin(pin, h.Deadline())
    assert foreign_reads == []


@pytest.mark.parametrize("changed_mode", [0o400, 0o640, 0o644])
def test_config_mode_change_after_pin_check_is_rejected_before_read(
    tmp_path, monkeypatch, changed_mode
):
    path = tmp_path.resolve() / "config"
    content = b"same-owned-nonsecret-config"
    path.write_bytes(content)
    path.chmod(0o600)
    pin = configuration_pin(path, content)
    real_check, real_read = h.check_pin, os.read
    reads = []

    def change_after_validation(*args, **kwargs):
        result = real_check(*args, **kwargs)
        path.chmod(changed_mode)
        return result

    def observe_read(fd, count):
        reads.append(fd)
        return real_read(fd, count)

    monkeypatch.setattr(h, "check_pin", change_after_validation)
    monkeypatch.setattr(h.os, "read", observe_read)
    with pytest.raises(h.Unavailable, match="file_identity"):
        h.file_pin(pin, h.Deadline())
    assert reads == []


def test_ancestor_symlink_inserted_after_path_check_never_reads_canary(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    project, foreign, held = root / "project", root / "outside", root / "held"
    project.mkdir()
    foreign.mkdir()
    path = project / "config"
    path.write_bytes(b"registered")
    canary = foreign / "config"
    canary.write_bytes(b"unregister")
    foreign_identity = (canary.stat().st_dev, canary.stat().st_ino)
    real_check, real_read = h.no_symlinks, os.read
    swapped, foreign_reads = False, []

    def replace_after_validation(*args, **kwargs):
        nonlocal swapped
        result = real_check(*args, **kwargs)
        if not swapped:
            swapped = True
            project.rename(held)
            project.symlink_to(foreign, target_is_directory=True)
        return result

    def observe_read(fd, count):
        observed = os.fstat(fd)
        data = real_read(fd, count)
        if (observed.st_dev, observed.st_ino) == foreign_identity:
            foreign_reads.append(len(data))
        return data

    monkeypatch.setattr(h, "no_symlinks", replace_after_validation)
    monkeypatch.setattr(h.os, "read", observe_read)
    with pytest.raises((OSError, h.Unavailable)) as error:
        h.read_file(str(path), 10, h.Deadline(), os.getuid())
    if isinstance(error.value, OSError):
        assert error.value.errno in {errno.ELOOP, errno.ENOTDIR}
    else:
        assert str(error.value) == "physical_scope"
    assert swapped and foreign_reads == []


def test_opened_parent_replacement_is_rejected_before_descriptor_read(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    project, foreign, held = root / "project", root / "outside", root / "held"
    project.mkdir()
    foreign.mkdir()
    path = project / "config"
    path.write_bytes(b"registered")
    (foreign / "config").write_bytes(b"unregister")
    real_open, real_read = os.open, os.read
    swapped, reads = False, []

    def replace_after_leaf_open(name, *args, **kwargs):
        nonlocal swapped
        fd = real_open(name, *args, **kwargs)
        if name == "config" and kwargs.get("dir_fd") is not None and not swapped:
            swapped = True
            project.rename(held)
            project.symlink_to(foreign, target_is_directory=True)
        return fd

    def observe_read(fd, count):
        reads.append(fd)
        return real_read(fd, count)

    monkeypatch.setattr(h.os, "open", replace_after_leaf_open)
    monkeypatch.setattr(h.os, "read", observe_read)
    with pytest.raises(h.Unavailable, match="physical_scope"):
        h.read_file(str(path), 10, h.Deadline(), os.getuid())
    assert swapped and reads == []


def test_no_inherited_git_override_is_accepted(monkeypatch):
    monkeypatch.setenv("GIT_INDEX_FILE", "/private/foreign-index")
    with pytest.raises(h.Unavailable, match="inherited_git_environment"):
        h.child_environment({})


def python_child(tmp_path, code, monkeypatch, *, cap=4096):
    """Controlled local Python fixture, not a Native command or Git fixture."""
    observed = []
    popen = subprocess.Popen

    def track(*args, **kwargs):
        process = popen(*args, **kwargs)
        observed.append(process)
        return process

    monkeypatch.setattr(h.subprocess, "Popen", track)
    runner = h.Children(h.Deadline(), str(tmp_path), {"PATH": "/usr/bin:/bin"})
    return runner, observed, [sys.executable, "-I", "-B", "-c", code], cap


def test_streamed_child_stdout_success_is_private_and_reaped(tmp_path, monkeypatch):
    runner, observed, argv, cap = python_child(tmp_path, "print('ok')", monkeypatch)
    assert runner.run(argv, cap) == b"ok\n"
    assert len(observed) == 1 and observed[0].poll() == 0


@pytest.mark.parametrize(
    "code", ["import os; os.write(1,b'x'*65536)", "import os; os.write(2,b'x'*65536)"]
)
def test_streamed_child_caps_kill_and_reap_without_returning_partial(tmp_path, monkeypatch, code):
    monkeypatch.setattr(h, "STDERR_BYTES", 32)
    runner, observed, argv, _ = python_child(tmp_path, code, monkeypatch)
    with pytest.raises(h.Unavailable, match="child_capacity"):
        runner.run(argv, 32)
    assert len(observed) == 1 and observed[0].poll() is not None


def test_streamed_aggregate_limit_is_not_reset_per_child(tmp_path, monkeypatch):
    monkeypatch.setattr(h, "AGGREGATE_BYTES", 100)
    runner, observed, argv, _ = python_child(
        tmp_path, "import os; os.write(1,b'x'*60)", monkeypatch
    )
    assert len(runner.run(argv, 100)) == 60
    with pytest.raises(h.Unavailable, match="aggregate_capacity"):
        runner.run(argv, 100)
    assert len(observed) == 2 and all(p.poll() is not None for p in observed)


def test_streamed_deadline_kills_and_reaps_sleeping_child(tmp_path, monkeypatch):
    monkeypatch.setattr(h, "SECONDS", 0.4)
    runner, observed, argv, _ = python_child(tmp_path, "import time; time.sleep(30)", monkeypatch)
    with pytest.raises(h.Unavailable, match="deadline"):
        runner.run(argv, 100)
    assert len(observed) == 1 and observed[0].poll() is not None


def test_nonzero_and_stderr_never_leak_child_secrets(tmp_path, monkeypatch):
    runner, observed, argv, _ = python_child(
        tmp_path, "import sys; sys.stderr.write('private token'); sys.exit(1)", monkeypatch
    )
    with pytest.raises(h.Unavailable) as error:
        runner.run(argv)
    assert str(error.value) == "git_unavailable"
    assert observed[0].poll() is not None


def test_cli_rejects_extra_arguments_and_hides_os_errors(monkeypatch, capsys):
    assert h.main(["--scope", "a" * 64, "--path", "/private"]) == 2
    assert "arguments" in capsys.readouterr().out
    monkeypatch.setattr(
        h, "load_registry", lambda *_: (_ for _ in ()).throw(OSError("private secret"))
    )
    assert h.main(["--scope", "a" * 64]) == 2
    assert json.loads(capsys.readouterr().out) == {
        "format": "git-inspect225-unavailable-v1",
        "code": "unavailable",
    }


def test_duplicate_registry_keys_and_nonfinite_refused():
    for raw in [b'{"x":1,"x":2}', b'{"x":NaN}']:
        with pytest.raises(h.Unavailable):
            h.strict_json(raw)


def test_source_has_no_repository_mutation_or_unbounded_capture():
    source = HELPER.read_text()
    tree = ast.parse(source)
    assert "capture_output=" not in source
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "communicate"
        for node in ast.walk(tree)
    )
    git_calls = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"git", "line"}
        ):
            if node.args and isinstance(node.args[0], ast.Constant):
                git_calls.append(node.args[0].value)
    assert set(git_calls) <= {
        "--version",
        "config",
        "remote",
        "rev-parse",
        "symbolic-ref",
        "ls-files",
        "ls-tree",
    }
    assert {"ls-files", "ls-tree", "remote", "config"} <= set(git_calls)


def synthetic_capture(
    monkeypatch, *, head_drift=False, index_drift=False, config_drift=False, location_drift=False
):
    """Exercise capture wiring with synthetic metadata, never registry/Host proof."""
    inspector = object.__new__(h.Inspector)
    inspector.deadline = h.Deadline()
    inspector.registry = {
        "git": {"path": "/reviewed/git", "version": h.METADATA_GIT_VERSION, "sha256": "b" * 64},
        "python": {},
        "script_sha256": "c" * 64,
    }
    inspector.entry = {
        "cwd": {"path": "/reviewed/repo"},
        "git_dir": {"path": "/reviewed/repo/.git"},
        "common_dir": {"path": "/reviewed/repo/.git"},
        "object_dir": {},
        "home": {},
        "index_uid": 1000,
    }
    raw = index_bytes([(b"f", "100644", oid())])
    head_oid = oid(byte="44")
    head_tree = leaf_tree(b"f", value=oid(byte="22"))
    head_reads = 0
    commands = []

    def git(*args, **kwargs):
        nonlocal head_reads
        commands.append(args)
        values = {
            ("--version",): ("git version " + h.METADATA_GIT_VERSION + "\n").encode(),
            ("rev-parse", "--path-format=absolute", "--show-toplevel"): b"/reviewed/repo\n",
            ("rev-parse", "--absolute-git-dir"): b"/reviewed/repo/.git\n",
            ("rev-parse", "--path-format=absolute", "--git-common-dir"): b"/reviewed/repo/.git\n",
            ("rev-parse", "--is-bare-repository"): b"false\n",
            ("rev-parse", "--show-object-format"): b"sha1\n",
            ("symbolic-ref", "--quiet", "HEAD"): b"refs/heads/main\n",
            ("rev-parse", "--verify", head_oid + "^{tree}"): head_tree.encode() + b"\n",
            ("ls-files", "--stage", "-z"): f"100644 {oid()} 0\tf\0".encode(),
            (
                "ls-tree",
                "-r",
                "-t",
                "-z",
                "--full-tree",
                head_tree,
            ): f"100644 blob {oid(byte='22')}\tf\0".encode(),
        }
        if args == ("rev-parse", "--verify", "HEAD^{commit}"):
            head_reads += 1
            return (
                (oid(byte="55") if head_drift and head_reads == 2 else head_oid) + "\n"
            ).encode()
        if location_drift and args == ("rev-parse", "--absolute-git-dir"):
            return b"/foreign/.git\n"
        return values[args]

    config_reads = 0

    def config():
        nonlocal config_reads
        config_reads += 1
        return ([], "changed" if config_drift and config_reads == 2 else "same", [])

    index_reads = 0

    def read_file(*args):
        nonlocal index_reads
        index_reads += 1
        return (
            raw + b"tamper" if index_drift and index_reads == 2 else raw,
            ("synthetic-identical-FD",),
        )

    inspector.git = git
    inspector.config = config
    monkeypatch.setattr(h, "read_file", read_file)
    monkeypatch.setattr(h, "object_store_guard", lambda *_: ["synthetic-object-inventory"])
    monkeypatch.setattr(h, "check_pin", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(h, "binary_pin", lambda *_: None)
    return inspector, commands


def test_synthetic_full_capture_exact_existing_output_contract(monkeypatch):
    from jt_oz_bridge.domain.git_evidence import GitIndexEvidence

    inspector, commands = synthetic_capture(monkeypatch)
    result = inspector.capture("a" * 64)
    parsed = GitIndexEvidence.model_validate(result)
    assert parsed.index_entries == 1
    assert parsed.staged_paths[0].change == "modified"
    assert parsed.complete_index is True
    assert parsed.remote_live_verified is False
    assert parsed.working_tree_content_verified is False
    assert len(h.canonical_json(result)) < 65536
    assert {cmd[0] for cmd in commands} <= {
        "--version",
        "rev-parse",
        "symbolic-ref",
        "ls-files",
        "ls-tree",
    }


@pytest.mark.parametrize(
    ("option", "code"),
    [
        ("head_drift", "head_changed"),
        ("index_drift", "index_changed"),
        ("config_drift", "configuration_changed"),
        ("location_drift", "physical_scope"),
    ],
)
def test_synthetic_capture_rejects_each_drift_without_partial_evidence(monkeypatch, option, code):
    inspector, _ = synthetic_capture(monkeypatch, **{option: True})
    with pytest.raises(h.Unavailable, match=code):
        inspector.capture("a" * 64)


def test_synthetic_capture_rejects_final_json_capacity(monkeypatch):
    inspector, _ = synthetic_capture(monkeypatch)
    monkeypatch.setattr(h, "FINAL_BYTES", 32)
    with pytest.raises(h.Unavailable, match="output_capacity"):
        inspector.capture("a" * 64)


def test_effective_remote_digest_includes_rewrite_and_non_url_settings(monkeypatch):
    inspector = object.__new__(h.Inspector)
    inspector.deadline = h.Deadline()
    inspector.entry = {
        "home": {"path": "/reviewed-home"},
        "common_dir": {"path": "/repo/.git"},
        "configs": {
            "system": None,
            "xdg": None,
            "global": None,
            "local": {"path": "/repo/.git/config"},
        },
    }
    local = b"remote.origin.url\nhttps://user:secret@example.invalid/repo\0url.ssh://internal/.pushinsteadof\nhttps://example.invalid/\0"
    changed = [False]
    calls = []

    def git(*args, **kwargs):
        calls.append(args)
        if args[:2] == ("config", "--file"):
            return local
        if args[0] == "config":
            return local + (
                b"remote.origin.fetch\n+refs/heads/*:refs/remotes/origin/*\0" if changed[0] else b""
            )
        assert args == ("remote", "get-url", "--push", "--all", "origin")
        return b"ssh://private-user:private-secret@internal/repo\n"

    inspector.git = git
    monkeypatch.setattr(h, "file_pin", lambda *_: (local, ("synthetic-file-pin",)))
    monkeypatch.setattr(h.os.path, "lexists", lambda _: False)
    before = inspector.config()
    changed[0] = True
    after = inspector.config()
    assert before[2][0]["safe_alias"] == "origin"
    assert before[2][0]["push_config_sha256"] != after[2][0]["push_config_sha256"]
    serialized = json.dumps(before)
    assert (
        "secret" not in serialized and "internal" not in serialized and "https://" not in serialized
    )
    assert all(call[0] in {"config", "remote"} for call in calls)


@pytest.mark.parametrize("urls", [b"one\ntwo\n", b"", b"one\r\n", b"private\0\n"])
def test_multiple_or_malformed_push_urls_refuse_whole_capture(monkeypatch, urls):
    inspector = object.__new__(h.Inspector)
    inspector.deadline = h.Deadline()
    inspector.entry = {
        "home": {"path": "/h"},
        "common_dir": {"path": "/r/.git"},
        "configs": {
            "system": None,
            "xdg": None,
            "global": None,
            "local": {"path": "/r/.git/config"},
        },
    }
    local = b"remote.o.url\nprivate\0"
    inspector.git = lambda *args, **kwargs: urls if args[0] == "remote" else local
    monkeypatch.setattr(h, "file_pin", lambda *_: (local, ("synthetic-pin",)))
    monkeypatch.setattr(h.os.path, "lexists", lambda _: False)
    with pytest.raises(h.Unavailable, match="remote_ambiguous"):
        inspector.config()


@pytest.mark.parametrize(
    "kind", ["alternates", "http-alternates", "replace", "promisor", "symlink"]
)
def test_unqualified_object_storage_refused_without_git(tmp_path, kind):
    common = tmp_path.resolve() / "git"
    objects = common / "objects"
    (objects / "info").mkdir(parents=True)
    (objects / "pack").mkdir()
    if kind in {"alternates", "http-alternates"}:
        (objects / "info" / kind).write_bytes(b"")
    elif kind == "replace":
        (common / "refs" / "replace").mkdir(parents=True)
    elif kind == "promisor":
        (objects / "pack" / "pack-a.promisor").write_bytes(b"")
    else:
        (objects / "aa").symlink_to(tmp_path.resolve(), target_is_directory=True)
    entry = {
        "common_dir": {"path": str(common)},
        "object_dir": {"path": str(objects)},
        "index_uid": os.getuid(),
    }
    with pytest.raises(h.Unavailable):
        h.object_store_guard(entry, h.Deadline())


def test_implicit_directory_fanout_is_bounded_before_allocation(monkeypatch):
    monkeypatch.setattr(h, "TREE_NODES", 2)
    with pytest.raises(h.Unavailable, match="tree_capacity"):
        h.tree_oids({b"a/b/c": ("100644", oid())}, "sha1", deadline=h.Deadline())


@pytest.mark.parametrize("length", [4095, 4096])
def test_saturated_index_name_length_uses_real_nul_terminated_path(length):
    path = b"/".join([b"a" * 255] * 16)
    if length == 4096:
        path = b"/".join([b"a" * 255] * 15 + [b"a" * 254, b"b"])
    assert len(path) == length
    entries, _, _ = h.parse_index(
        index_bytes([(path, "100644", oid("sha256"))], "sha256", 3), "sha256", h.Deadline()
    )
    assert list(entries) == [path]


class SyntheticChildClock:
    """Controlled scheduling fixture, not process timing or Linux evidence."""

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class SyntheticChildStream:
    def __init__(self, clock, close_cost=0):
        self.clock, self.close_cost = clock, close_cost
        self.closed = False

    def fileno(self):
        return 123  # os.set_blocking is stubbed; this FD is never opened/read.

    def close(self):
        self.clock.now += self.close_cost
        self.closed = True


class SyntheticChildSelector:
    """Model pipes already at EOF; real streaming/caps have separate fixtures."""

    def register(self, *_):
        pass

    def get_map(self):
        return {}

    def close(self):
        pass


def synthetic_child(
    monkeypatch,
    *,
    normal_wait,
    cleanup_wait=0,
    kill_cost=0,
    close_cost=0,
    spawn_cost=0,
    selector_failure=False,
    selector_close_failure=False,
):
    clock = SyntheticChildClock()
    deadline = h.Deadline(clock)
    waits, kills, processes = [], [], []

    class Process:
        pid = 123456  # killpg is stubbed; no actual process or signal exists.

        def __init__(self):
            self.returncode = None
            self.stdout = SyntheticChildStream(clock, close_cost)
            self.stderr = SyntheticChildStream(clock)
            self.wait_calls = 0
            self.observed_status = None

        def wait(self, *, timeout):
            self.wait_calls += 1
            waits.append((clock.now, timeout))
            clock.now += cleanup_wait
            self.returncode = self.observed_status if self.observed_status is not None else -9
            return self.returncode

        def poll(self):
            raise AssertionError("must not reap before group termination")

    def popen(*_, **__):
        clock.now += spawn_cost
        process = Process()
        processes.append(process)
        return process

    def killpg(*_):
        assert processes[-1].returncode is None
        assert processes[-1].wait_calls == 0
        kills.append(clock.now)
        clock.now += kill_cost

    def waitid(kind, pid, flags):
        assert kind == os.P_PID and pid == processes[-1].pid
        assert flags == os.WEXITED | os.WNOHANG | os.WNOWAIT
        process = processes[-1]
        timeout = deadline.remaining()
        waits.append((clock.now, timeout))
        normal_wait(process, clock, timeout)
        process.observed_status = process.returncode
        process.returncode = None
        return SimpleNamespace(si_code=os.CLD_EXITED, si_status=process.observed_status)

    def selector():
        if selector_failure:
            raise OSError("synthetic selector allocation failure")
        if selector_close_failure:

            class BadCloseSelector(SyntheticChildSelector):
                def close(self):
                    raise OSError("synthetic selector close failure")

            return BadCloseSelector()
        return SyntheticChildSelector()

    monkeypatch.setattr(h.subprocess, "Popen", popen)
    monkeypatch.setattr(h.selectors, "DefaultSelector", selector)
    monkeypatch.setattr(h.os, "set_blocking", lambda *_: None)
    monkeypatch.setattr(h.os, "killpg", killpg)
    monkeypatch.setattr(h.os, "waitid", waitid)
    monkeypatch.setattr(h.signal, "getsignal", lambda *_: h.signal.SIG_DFL)
    runner = h.Children(deadline, "/synthetic-not-opened", {})
    return runner, clock, waits, kills, processes


def test_child_wait_and_reap_share_one_total_deadline_with_reserved_cleanup(monkeypatch):
    def exhausting_work(_, clock, timeout):
        clock.now += timeout
        raise subprocess.TimeoutExpired("synthetic", timeout)

    runner, clock, waits, kills, processes = synthetic_child(
        monkeypatch, normal_wait=exhausting_work, kill_cost=0.20, cleanup_wait=0.04
    )
    clock.now = 4.60  # Earlier registry/parse/read work is not a fresh budget.
    with pytest.raises(h.Unavailable, match="deadline"):
        runner.run(["synthetic-never-executed"])
    assert waits[0] == pytest.approx((4.60, 0.15))
    assert waits[1] == pytest.approx((4.95, 0.05))
    assert kills == pytest.approx([4.75])
    assert clock.now == pytest.approx(4.99)
    assert processes[0].returncode == -9
    assert processes[0].stdout.closed and processes[0].stderr.closed


def test_late_reap_return_cannot_preserve_success_or_claim_cleanup_qualified(monkeypatch):
    def exhausting_work(_, clock, timeout):
        clock.now += timeout
        raise subprocess.TimeoutExpired("synthetic", timeout)

    runner, clock, waits, _, processes = synthetic_child(
        monkeypatch, normal_wait=exhausting_work, kill_cost=0.20, cleanup_wait=0.06
    )
    with pytest.raises(h.Unavailable, match="deadline"):
        runner.run(["synthetic-never-executed"])
    assert waits[-1] == pytest.approx((4.95, 0.05))
    assert clock.now > runner.deadline.expires
    assert processes[0].returncode == -9


def test_successful_child_with_late_group_cleanup_does_not_return_bytes(monkeypatch):
    def successful_work(process, clock, _):
        clock.now = 4.70
        process.returncode = 0

    runner, clock, waits, _, processes = synthetic_child(
        monkeypatch, normal_wait=successful_work, kill_cost=0.31
    )
    with pytest.raises(h.Unavailable, match="deadline"):
        runner.run(["synthetic-never-executed"])
    assert len(waits) == 1
    assert clock.now > runner.deadline.expires
    assert processes[0].observed_status == 0  # Exit zero alone is insufficient.
    assert processes[0].returncode is None  # Total budget exhausted before reap.


def test_closing_child_pipes_is_in_same_total_cleanup_clock(monkeypatch):
    def successful_work(process, clock, _):
        clock.now = 4.70
        process.returncode = 0

    runner, clock, _, _, processes = synthetic_child(
        monkeypatch, normal_wait=successful_work, kill_cost=0.29, close_cost=0.02
    )
    with pytest.raises(h.Unavailable, match="deadline"):
        runner.run(["synthetic-never-executed"])
    assert clock.now > runner.deadline.expires
    assert processes[0].stdout.closed and processes[0].stderr.closed


def test_selector_setup_failure_still_terminates_and_reaps_child(monkeypatch):
    def reap(process, *_):
        process.returncode = -9

    runner, _, waits, kills, processes = synthetic_child(
        monkeypatch, normal_wait=reap, selector_failure=True
    )
    with pytest.raises(OSError, match="synthetic selector"):
        runner.run(["synthetic-never-executed"])
    assert len(kills) == len(waits) == 1
    assert processes[0].returncode == -9
    assert processes[0].stdout.closed and processes[0].stderr.closed


def test_second_child_does_not_reset_earlier_child_or_parse_time(monkeypatch):
    def successful_work(process, clock, _):
        clock.now += 2.4
        process.returncode = 0

    runner, clock, waits, _, processes = synthetic_child(monkeypatch, normal_wait=successful_work)
    assert runner.run(["synthetic-one"]) == b""
    with pytest.raises(h.Unavailable, match="deadline"):
        runner.run(["synthetic-two"])
    assert waits[0] == pytest.approx((0.0, 4.75))
    assert waits[2] == pytest.approx((2.4, 2.35))
    assert waits[1] == pytest.approx((2.4, 2.6))
    assert waits[3] == pytest.approx((4.8, 0.2))
    assert clock.now == pytest.approx(4.8)
    assert all(process.returncode == 0 for process in processes)


def test_spawn_cost_consumes_the_same_budget_before_cleanup(monkeypatch):
    def reap(process, *_):
        process.returncode = -9

    runner, clock, waits, _, processes = synthetic_child(
        monkeypatch, normal_wait=reap, spawn_cost=0.30, kill_cost=0.06
    )
    clock.now = 4.60
    with pytest.raises(h.Unavailable, match="deadline"):
        runner.run(["synthetic-never-executed"])
    assert waits[0] == pytest.approx((4.96, 0.04))
    assert processes[0].returncode == -9


def test_config_parse_uses_invocation_clock_instead_of_its_own_budget():
    clock = SyntheticChildClock()
    deadline = h.Deadline(clock)
    clock.now = 4.75
    with pytest.raises(h.Unavailable, match="deadline"):
        h.parse_config(b"remote.origin.url\nprivate\0", deadline)
    with pytest.raises(h.Unavailable, match="deadline"):
        h.strict_json(b'{"scope":"synthetic"}', deadline)
    assert deadline.remaining(cleanup=True) == pytest.approx(0.25)
    clock.now = 5.0
    with pytest.raises(h.Unavailable, match="deadline"):
        deadline.check(cleanup=True)


def test_head_tree_is_resolved_from_the_captured_commit_not_mutable_head():
    inspector = object.__new__(h.Inspector)
    calls = []
    commit, tree = oid(byte="11"), oid(byte="22")
    answers = {
        ("symbolic-ref", "--quiet", "HEAD"): "refs/heads/main",
        ("rev-parse", "--verify", "HEAD^{commit}"): commit,
        ("rev-parse", "--verify", commit + "^{tree}"): tree,
    }

    def line(*args):
        calls.append(args)
        return answers[args]

    inspector.line = line
    assert inspector.head("sha1") == ("main", commit, tree)
    assert ("rev-parse", "--verify", commit + "^{tree}") in calls
    assert ("rev-parse", "--verify", "HEAD^{tree}") not in calls
    assert calls.count(("rev-parse", "--verify", "HEAD^{commit}")) == 2
    assert calls.count(("symbolic-ref", "--quiet", "HEAD")) == 2


@pytest.mark.parametrize("changed", ["commit", "branch"])
def test_head_change_while_resolving_commit_tree_is_refused(changed):
    inspector = object.__new__(h.Inspector)
    commit, tree = oid(byte="11"), oid(byte="22")
    reads = {"commit": 0, "branch": 0}

    def line(*args):
        if args[0] == "symbolic-ref":
            reads["branch"] += 1
            return (
                "refs/heads/other"
                if changed == "branch" and reads["branch"] == 2
                else "refs/heads/main"
            )
        if args[-1] == "HEAD^{commit}":
            reads["commit"] += 1
            return oid(byte="33") if changed == "commit" and reads["commit"] == 2 else commit
        assert args[-1] == commit + "^{tree}"
        return tree

    inspector.line = line
    with pytest.raises(h.Unavailable, match="head_changed"):
        inspector.head("sha1")


def test_child_environment_denies_every_transport_and_requires_actual_no_lazy_flag(monkeypatch):
    for key in list(os.environ):
        if key.startswith("GIT_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("HOME", "/reviewed-home")
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "private-credential-proxy")
    entry = {
        "home": {"path": "/reviewed-home"},
        "cwd": {"path": "/reviewed-not-opened"},
        "configs": {"system": None},
    }
    env = h.child_environment(entry)
    assert env["GIT_ALLOW_PROTOCOL"] == ""
    assert env["GIT_PROTOCOL_FROM_USER"] == "0"
    assert env["GIT_NO_LAZY_FETCH"] == "1"
    assert "HTTPS_PROXY" not in env
    inspector = h.Inspector({"git": {"path": "/root-pinned-not-executed"}}, entry, h.Deadline())
    assert inspector.prefix[1] == "--no-lazy-fetch"
    assert inspector.children.env["GIT_ALLOW_PROTOCOL"] == ""


def test_file_descriptor_cleanup_observed_overrun_cannot_return_bytes(tmp_path, monkeypatch):
    path = tmp_path.resolve() / "synthetic-index"
    path.write_bytes(b"abc")
    clock = SyntheticChildClock()
    deadline = h.Deadline(clock)
    real_open, real_close = os.open, os.close
    opened, closed = [], []

    def tracked_open(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def late_close(fd):
        real_close(fd)
        closed.append(fd)
        clock.now = 5.01

    monkeypatch.setattr(h.os, "open", tracked_open)
    monkeypatch.setattr(h.os, "close", late_close)
    with pytest.raises(h.Unavailable, match="deadline"):
        h.read_file(str(path), 3, deadline, os.getuid())
    assert len(opened) > 1 and closed == list(reversed(opened))
    for fd in closed:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_index_semantic_parse_hash_overrun_is_not_complete_evidence(monkeypatch):
    clock = SyntheticChildClock()
    deadline = h.Deadline(clock)

    def late_digest(_):
        clock.now = 5.01
        return "a" * 64

    monkeypatch.setattr(h, "digest", late_digest)
    with pytest.raises(h.Unavailable, match="deadline"):
        h.parse_index(index_bytes(), "sha1", deadline)


def test_late_stdout_flush_cannot_exit_zero_with_successful_evidence(monkeypatch):
    clock = SyntheticChildClock()
    deadline = h.Deadline(clock)
    script = b"synthetic-installed-script"
    registry = {"script_sha256": hashlib.sha256(script).hexdigest()}
    original_registry = (b"synthetic-registry", ("synthetic-file-identity",))

    class Inspector:
        def __init__(self, *_):
            pass

        def capture(self, _, *, capture_started_at):
            return {
                "format": "synthetic-not-native-proof",
                "capture_started_at": capture_started_at,
            }

    class Buffer:
        def __init__(self):
            self.output = bytearray()

        def write(self, value):
            self.output.extend(value)

        def flush(self):
            clock.now = 5.01

    class Stdout:
        def __init__(self):
            self.buffer = Buffer()
            self.errors = []

        def write(self, value):
            self.errors.append(value)

    stdout = Stdout()
    monkeypatch.setattr(h, "Deadline", lambda: deadline)
    monkeypatch.setattr(h, "time", SimpleNamespace(time=lambda: 1000 + clock.now))
    monkeypatch.setattr(h, "load_registry", lambda *_: (registry, {}, original_registry))
    monkeypatch.setattr(h, "Inspector", Inspector)
    monkeypatch.setattr(h, "root_controlled", lambda *_: None)
    monkeypatch.setattr(
        h,
        "read_file",
        lambda path, *_: (
            original_registry if path == h.REGISTRY else (script, ("synthetic-script",))
        ),
    )
    monkeypatch.setattr(h, "sys", SimpleNamespace(stdout=stdout))
    assert h.main(["--scope", "a" * 64]) == 2
    assert clock.now > deadline.expires
    assert stdout.buffer.output
    assert '"code":"deadline"' in "".join(stdout.errors)


def test_selector_close_failure_occurs_after_child_termination_and_reap(monkeypatch):
    def successful_work(process, *_):
        process.returncode = 0

    runner, _, _, kills, processes = synthetic_child(
        monkeypatch, normal_wait=successful_work, selector_close_failure=True
    )
    with pytest.raises(OSError, match="selector close"):
        runner.run(["synthetic-never-executed"])
    assert len(kills) == 1 and processes[0].returncode == 0
    assert processes[0].stdout.closed and processes[0].stderr.closed


def test_ignored_sigchld_is_refused_before_starting_a_child(monkeypatch):
    monkeypatch.setattr(h.signal, "getsignal", lambda *_: h.signal.SIG_IGN)
    started = []
    monkeypatch.setattr(h.subprocess, "Popen", lambda *_args, **_kwargs: started.append(True))
    with pytest.raises(h.Unavailable, match="child_reaping_policy"):
        h.Children(h.Deadline(), "/synthetic-not-opened", {}).run(["synthetic-never-executed"])
    assert started == []


@pytest.mark.parametrize("mode", [0o104755, 0o102755, 0o100644])
def test_root_pinned_binary_must_be_executable_without_setid(monkeypatch, mode):
    monkeypatch.setattr(h, "root_controlled", lambda *_: None)
    monkeypatch.setattr(
        h, "os", SimpleNamespace(stat=lambda *_args, **_kwargs: SimpleNamespace(st_mode=mode))
    )

    def no_read(*_):
        raise AssertionError("refused metadata must not reach binary read")

    monkeypatch.setattr(h, "read_file", no_read)
    with pytest.raises(h.Unavailable, match="binary_identity"):
        h.binary_pin(
            {"path": "/root-pinned/not-opened", "sha256": "a" * 64, "version": "2.45.0"},
            h.Deadline(),
        )


def test_version_label_cannot_bypass_actual_no_lazy_fetch_flag_failure(monkeypatch):
    monkeypatch.setattr(h, "child_environment", lambda _: {"GIT_ALLOW_PROTOCOL": ""})
    inspector = h.Inspector(
        {"git": {"path": "/root-pinned/not-executed", "version": h.METADATA_GIT_VERSION}},
        {"cwd": {"path": "/synthetic-not-opened"}},
        h.Deadline(),
    )
    calls = []

    class UnsupportedFlag:
        def run(self, argv, cap):
            calls.append((argv, cap))
            assert argv[1] == "--no-lazy-fetch"
            raise h.Unavailable("git_unavailable")

    inspector.children = UnsupportedFlag()
    with pytest.raises(h.Unavailable, match="git_unavailable"):
        inspector.capture("a" * 64)
    assert len(calls) == 1 and calls[0][0][-1] == "--version"


@pytest.mark.parametrize(
    "version",
    ["2.43.0", "2.56.0", "2.56.0.jtoz-metadata0", "2.56.0.jtoz-metadata2", ""],
)
def test_unqualified_config_policy_never_starts_a_git_child(monkeypatch, version):
    inspector = object.__new__(h.Inspector)
    inspector.deadline = h.Deadline()
    inspector.registry = {"git": {"version": version}}

    def forbidden(*args, **kwargs):
        pytest.fail("unqualified Git must not initialize or read repository configuration")

    monkeypatch.setattr(inspector, "line", forbidden)
    monkeypatch.setattr(inspector, "config", forbidden)
    monkeypatch.setattr(h.subprocess, "Popen", forbidden)
    with pytest.raises(h.Unavailable, match="git_config_policy_unqualified"):
        inspector.capture("a" * 64)


def test_root_packet_and_helper_require_the_same_metadata_git_profile():
    from typing import get_args

    from jt_oz_bridge.domain.git_evidence import RootReviewedGitEvidencePin

    assert get_args(RootReviewedGitEvidencePin.model_fields["git_version"].annotation) == (
        h.METADATA_GIT_VERSION,
    )


def test_claimed_metadata_profile_with_vanilla_version_never_reads_config(monkeypatch):
    inspector, _ = synthetic_capture(monkeypatch)
    calls = []

    def git(*args, **kwargs):
        calls.append(args)
        assert args == ("--version",)
        return b"git version 2.56.0\n"

    def forbidden():
        pytest.fail("a version mismatch must fail before configuration inspection")

    inspector.git = git
    inspector.config = forbidden
    with pytest.raises(h.Unavailable, match="git_identity"):
        inspector.capture("a" * 64)
    assert calls == [("--version",)]


@pytest.mark.parametrize("value", [-1, 2**53 + 1, float("inf"), float("nan"), True])
def test_output_timestamps_cannot_claim_schema_validity_with_invalid_clock(value):
    with pytest.raises(h.Unavailable, match="clock"):
        h.capture_time(value)
