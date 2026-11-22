import os
import uuid

import pytest

from jt_oz_bridge.storage.artifact_files import ArtifactFileError, LocalArtifactFiles


def test_private_root_and_atomic_no_clobber(tmp_path):
    root = tmp_path / "files"
    files = LocalArtifactFiles(root)
    identity = str(uuid.uuid4())
    try:
        files.write(identity, b"ciphertext")
        assert files.read(identity, 100) == b"ciphertext"
        with pytest.raises(ArtifactFileError):
            files.write(identity, b"overwrite")
        assert files.read(identity, 100) == b"ciphertext"
        assert not (root / (identity + ".part")).exists()
        assert files.free_bytes() > 0
    finally:
        files.close()


def test_existing_partial_file_is_not_overwritten_or_deleted(tmp_path):
    root = tmp_path / "files"
    files = LocalArtifactFiles(root)
    identity = str(uuid.uuid4())
    partial = root / (identity + ".part")
    partial.write_bytes(b"retained crash evidence")
    try:
        with pytest.raises(ArtifactFileError):
            files.write(identity, b"new")
        assert partial.read_bytes() == b"retained crash evidence"
    finally:
        files.close()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "public", "fifo", "too-large"])
def test_untrusted_file_properties_cannot_escape_private_storage(tmp_path, kind):
    root = tmp_path / "files"
    files = LocalArtifactFiles(root)
    identity = str(uuid.uuid4())
    target = root / (identity + ".bin")
    outside = tmp_path / "outside"
    outside.write_bytes(b"PRIVATE-MARKER")
    outside.chmod(0o600)
    if kind == "symlink":
        target.symlink_to(outside)
    elif kind == "hardlink":
        os.link(outside, target)
    elif kind == "fifo":
        os.mkfifo(target, 0o600)
    else:
        target.write_bytes(b"content")
        target.chmod(0o644 if kind == "public" else 0o600)
    try:
        with pytest.raises(ArtifactFileError):
            files.read(identity, 1 if kind == "too-large" else 100)
        assert outside.read_bytes() == b"PRIVATE-MARKER"
    finally:
        files.close()


def test_descriptor_anchor_survives_parent_path_replacement_without_following_it(tmp_path):
    root, moved, outside = tmp_path / "files", tmp_path / "moved", tmp_path / "outside"
    outside.mkdir(mode=0o700)
    files = LocalArtifactFiles(root)
    root.rename(moved)
    root.symlink_to(outside)
    identity = str(uuid.uuid4())
    try:
        files.write(identity, b"encrypted")
        assert (moved / (identity + ".bin")).read_bytes() == b"encrypted"
        assert not list(outside.iterdir())
    finally:
        files.close()


def test_root_symlink_and_world_readable_root_are_refused(tmp_path):
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    public.chmod(0o755)
    with pytest.raises(ArtifactFileError):
        LocalArtifactFiles(public)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(private)
    with pytest.raises(ArtifactFileError):
        LocalArtifactFiles(link)
