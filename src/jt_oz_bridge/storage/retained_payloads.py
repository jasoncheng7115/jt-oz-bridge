"""Encrypted, identity-only tombstones; original content hashes remain dedupe keys."""

import math
from typing import Any

from jt_oz_bridge.storage.durable import Conflict

FORMAT = "bridge-retired-payload-v1"


def tombstone(
    kind: str, identity: str, checksum: str, when: float, scope: dict[str, Any]
) -> dict[str, Any]:
    return {
        "format": FORMAT,
        "kind": kind,
        "id": identity,
        "original_hash": checksum,
        "compacted_at": when,
        "scope": scope,
    }


def retained_scope(
    value: dict[str, Any],
    *,
    kind: str,
    identity: str,
    when: float | None,
    checksum: str | None = None,
) -> dict[str, Any]:
    if (
        when is None
        or not math.isfinite(when)
        or when <= 0
        or set(value) != {"format", "kind", "id", "original_hash", "compacted_at", "scope"}
        or value["format"] != FORMAT
        or value["kind"] != kind
        or value["id"] != identity
        or value["compacted_at"] != when
        or not isinstance(value["scope"], dict)
        or not isinstance(value["original_hash"], str)
        or len(value["original_hash"]) != 64
        or any(c not in "0123456789abcdef" for c in value["original_hash"])
        or checksum is not None
        and value["original_hash"] != checksum
    ):
        raise Conflict("retention_tombstone_identity_changed")
    return value["scope"]
