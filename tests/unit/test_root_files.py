"""Filesystem guards with explicitly synthetic root metadata on a user temp tree."""

import hashlib
import os
import stat
from pathlib import Path

import pytest

from jt_oz_bridge.security.root_files import pinned_root_bytes, root_bytes


def synthetic_root_metadata(monkeypatch):
    lstat, fstat = Path.lstat, os.fstat

    def rooted(info):
        fields = list(info)
        fields[4] = 0
        if stat.S_ISDIR(info.st_mode):
            fields[0] &= ~0o022
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "lstat", lambda path: rooted(lstat(path)))
    monkeypatch.setattr(os, "fstat", lambda fd: rooted(fstat(fd)))


def test_root_read_is_bounded_pinned_and_exact(tmp_path, monkeypatch):
    synthetic_root_metadata(monkeypatch)
    path = tmp_path / "evidence.json"
    data = b'{"exact":"original"}\n'
    path.write_bytes(data)
    path.chmod(0o640)
    assert pinned_root_bytes(path, hashlib.sha256(data).hexdigest()) == data
    with pytest.raises(ValueError, match="digest_changed"):
        pinned_root_bytes(path, "0" * 64)
    with pytest.raises(ValueError, match="too_large"):
        root_bytes(path, maximum=4)


@pytest.mark.parametrize("mode", [0o660, 0o646, 0o666])
def test_group_or_other_writable_evidence_never_becomes_a_certificate(tmp_path, monkeypatch, mode):
    synthetic_root_metadata(monkeypatch)
    path = tmp_path / "evidence"
    path.write_text("not trusted")
    path.chmod(mode)
    with pytest.raises(ValueError, match="regular_file_required"):
        root_bytes(path)


@pytest.mark.parametrize("kind", ["file_link", "directory_link", "fifo"])
def test_symlinks_and_nonregular_files_are_rejected_without_blocking(tmp_path, monkeypatch, kind):
    synthetic_root_metadata(monkeypatch)
    path = tmp_path / "evidence"
    if kind == "fifo":
        os.mkfifo(path, 0o600)
    elif kind == "file_link":
        actual = tmp_path / "actual"
        actual.write_text("not through link")
        path.symlink_to(actual)
    else:
        actual = tmp_path / "actual"
        actual.mkdir()
        (actual / "file").write_text("not through parent link")
        path.symlink_to(actual, target_is_directory=True)
        path /= "file"
    with pytest.raises((ValueError, OSError)):
        root_bytes(path)


def test_file_identity_change_after_open_refuses_read(tmp_path, monkeypatch):
    synthetic_root_metadata(monkeypatch)
    path = tmp_path / "evidence"
    path.write_text("content")
    current = Path.lstat

    def changed(target):
        info = current(target)
        if target == path:
            fields = list(info)
            fields[1] += 1
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(Path, "lstat", changed)
    with pytest.raises(ValueError, match="file_changed"):
        root_bytes(path)


def test_actual_untrusted_ancestry_or_owner_is_not_accepted(tmp_path):
    path = tmp_path / "evidence"
    path.write_text("user data")
    with pytest.raises(ValueError, match="root_managed"):
        root_bytes(path)


@pytest.mark.parametrize("path", [Path("relative"), Path("/etc/../tmp/file")])
def test_only_explicit_absolute_paths_are_allowed(path):
    with pytest.raises(ValueError, match="absolute"):
        root_bytes(path)
