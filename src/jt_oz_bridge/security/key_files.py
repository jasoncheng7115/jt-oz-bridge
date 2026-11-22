"""Create an explicit master-key file without printing it or replacing a file."""

import base64
import os
import stat
from pathlib import Path


def generate_key_file(path: Path) -> None:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise ValueError("absolute_secret_path_required")
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(parent)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("secret_parent_must_be_owner_only")
        descriptor = os.open(
            path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent
        )
        # On failure leave an owner-only file for inspection rather than replacing it.
        with os.fdopen(descriptor, "wb") as target:
            target.write(base64.b64encode(os.urandom(32)) + b"\n")
            target.flush()
            os.fsync(target.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)
