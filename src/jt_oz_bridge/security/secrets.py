"""Resolve references only on demand. Never include supplied values in exceptions."""

import os
import stat
from pathlib import Path

from pydantic import SecretStr


class SecretUnavailable(ValueError):
    pass


def resolve_secret(reference: str) -> SecretStr:
    kind, _, name = reference.partition(":")
    if kind == "env":
        value = os.environ.get(name, "")
    elif kind == "file" and Path(name).is_absolute():
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as source:
                info = os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                    raise SecretUnavailable("secret file must be regular and owner-only")
                if info.st_uid not in {os.geteuid(), 0} or info.st_size > 65536:
                    raise SecretUnavailable("secret file ownership or size rejected")
                value = source.read(65537).decode().rstrip("\r\n")
        except (OSError, UnicodeError):
            raise SecretUnavailable("secret file is unavailable") from None
    else:
        raise SecretUnavailable("invalid secret reference")
    if not value or len(value) > 65536:
        raise SecretUnavailable("secret is missing or too large")
    return SecretStr(value)
