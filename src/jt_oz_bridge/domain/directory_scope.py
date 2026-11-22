"""Metadata-only physical directory witnesses; never authorize file contents."""

from typing import Protocol

from pydantic import Field, StrictInt, field_validator, model_validator

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.workspace_paths import canonical_relative
from jt_oz_bridge.storage.durable import digest


def directory_path(value: str) -> str:
    if value:
        canonical_relative(value)
        if len(value.split("/")) > 64:
            raise ValueError("directory_scope_depth_capacity")
    return value


def directory_project_key(reference: SessionRef) -> str:
    return digest(
        {
            "backend_identity": reference.backend_identity,
            "canonical_directory": reference.canonical_directory,
        }
    )


class DirectoryRecord(ControlModel):
    path: str = Field(max_length=4096)
    device: StrictInt = Field(ge=0)
    inode: StrictInt = Field(gt=0)
    uid: StrictInt = Field(ge=0)
    gid: StrictInt = Field(ge=0)
    mode: StrictInt = Field(ge=0, le=0o7777)
    mtime_ns: StrictInt = Field(ge=0)
    ctime_ns: StrictInt = Field(ge=0)

    @field_validator("path")
    @classmethod
    def canonical(cls, value: str) -> str:
        return directory_path(value)


class DirectoryScopeSnapshot(ControlModel):
    project_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    implementation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    server_epoch: str = Field(pattern=r"^[0-9a-f]{32}$")
    observed_at: float = Field(gt=0, allow_inf_nan=False)
    directories: tuple[str, ...] = Field(min_length=1, max_length=1024)
    records: tuple[DirectoryRecord, ...] = Field(min_length=1, max_length=8192)

    @field_validator("directories")
    @classmethod
    def canonical_directories(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for path in value:
            directory_path(path)
        if tuple(sorted(set(value))) != value:
            raise ValueError("directory_scope_unique_sorted_paths_required")
        return value

    @model_validator(mode="after")
    def complete(self) -> "DirectoryScopeSnapshot":
        required = {""}
        for path in self.directories:
            parts = path.split("/") if path else []
            required.update("/".join(parts[:i]) for i in range(1, len(parts) + 1))
        if tuple(r.path for r in self.records) != tuple(sorted(required)):
            raise ValueError("directory_scope_exact_ancestor_records_required")
        return self

    @property
    def fingerprint(self) -> str:
        data = self.model_dump(mode="json")
        data.pop("observed_at")
        return digest(data)


class DirectoryScopeGuard(Protocol):
    def qualified(self, reference: SessionRef) -> bool: ...
    async def observe(
        self, reference: SessionRef, directories: tuple[str, ...]
    ) -> DirectoryScopeSnapshot: ...
    def current(self, reference: SessionRef, snapshot: DirectoryScopeSnapshot) -> bool: ...
