"""Local lineage-v2 fingerprints, not Native fields or execution authority.

Only the explicitly qualified lineage provider uses these projections. Legacy
providers keep the full response digest. Unknown fields, identity, policy,
model/agent, parent/fork/revert and settled outcomes remain in the boundary.
"""

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.storage.durable import digest


@runtime_checkable
class InfoProjection(Protocol):
    def project_info(self, reference: SessionRef, info: dict[str, Any]) -> dict[str, Any]: ...


def info_fingerprint(provider: object, reference: SessionRef, info: dict[str, Any]) -> str:
    return digest(
        provider.project_info(reference, info) if isinstance(provider, InfoProjection) else info
    )


def progress_info(info: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(info)
    for name in ("cost", "tokens", "title"):
        value.pop(name, None)
    times = value.get("time")
    if isinstance(times, dict):
        times = dict(times)
        for name in ("updated", "viewed"):
            times.pop(name, None)
        value["time"] = times
    return value
