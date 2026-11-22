"""Real filesystem boundary checks for backup inputs and exclusive outputs."""

import os

import pytest

from jt_oz_bridge.storage.backup_files import (
    BackupFileError,
    PrivateDirectory,
    beneath,
    directory_fd,
)


@pytest.mark.parametrize("name", ["../outside", "..", ".", "a/b", "a\\b", "", "nul\x00x"])
def test_caller_paths_cannot_be_used_as_backup_member_names(tmp_path, name):
    root = PrivateDirectory(tmp_path / "private", create=True)
    try:
        with pytest.raises(BackupFileError):
            root.write(name, b"private")
        assert not root.names()
    finally:
        root.close()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "public"])
def test_non_private_or_indirect_members_are_rejected_before_read(tmp_path, kind):
    root = PrivateDirectory(tmp_path / "private", create=True)
    outside = tmp_path / "outside"
    outside.write_bytes(b"keep original")
    outside.chmod(0o600)
    member = root.path / "member"
    try:
        if kind == "symlink":
            member.symlink_to(outside)
        elif kind == "hardlink":
            os.link(outside, member)
        elif kind == "fifo":
            os.mkfifo(member, 0o600)
        else:
            member.write_bytes(b"private")
            member.chmod(0o644)
        with pytest.raises((BackupFileError, OSError)):
            root.read("member", 100)
        assert outside.read_bytes() == b"keep original"
    finally:
        root.close()


def test_symlink_ancestor_is_rejected_and_existing_file_is_not_overwritten(tmp_path):
    actual = PrivateDirectory(tmp_path / "actual", create=True)
    alias = tmp_path / "alias"
    alias.symlink_to(actual.path, target_is_directory=True)
    try:
        with pytest.raises(OSError):
            PrivateDirectory(alias)
        with pytest.raises(OSError):
            PrivateDirectory(alias / "child", create=True)
        actual.write("original", b"keep")
        with pytest.raises(FileExistsError):
            actual.write("original", b"replace")
        assert actual.read("original", 10) == b"keep"
    finally:
        actual.close()


def test_changed_directory_identity_and_changing_stream_fail_closed(tmp_path):
    root = PrivateDirectory(tmp_path / "private", create=True)
    try:
        root.write("member", b"a" * (2 * 1024**2))
        stream = root.chunks("member", 4 * 1024**2)
        assert len(next(stream)) == 1024**2
        with (root.path / "member").open("ab") as output:
            output.write(b"changed")
        with pytest.raises(BackupFileError, match="changed_during_read"):
            list(stream)
        root.path.rename(tmp_path / "old")
        root.path.mkdir(mode=0o700)
        with pytest.raises(BackupFileError, match="directory_changed"):
            root.verify()
    finally:
        root.close()


def test_directory_ancestry_uses_open_identities_and_relative_paths_are_rejected(tmp_path):
    root = PrivateDirectory(tmp_path / "private", create=True)
    child = PrivateDirectory(root.path / "child", create=True)
    sibling = PrivateDirectory(tmp_path / "sibling", create=True)
    try:
        assert beneath(root, child.path) and beneath(root, root.path)
        assert not beneath(root, sibling.path)
        with pytest.raises(BackupFileError):
            directory_fd(root.path / ".." / "sibling")
        with pytest.raises(BackupFileError):
            directory_fd(type(tmp_path)("relative"))
    finally:
        sibling.close()
        child.close()
        root.close()
