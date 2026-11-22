"""Explicit synthetic directory authority, never an installed certificate."""

import time

from jt_oz_bridge.domain.directory_scope import (
    DirectoryRecord,
    DirectoryScopeSnapshot,
    directory_project_key,
)


class SyntheticDirectoryScope:
    def __init__(self, reference):
        self.reference = reference
        self.enabled, self.generation = True, 1
        self.snapshots, self.calls, self.hook = [], [], None
        self.blocked = set()

    def qualified(self, reference):
        return self.enabled and reference == self.reference

    async def observe(self, reference, directories):
        assert reference == self.reference
        paths = tuple(sorted(set(directories)))
        if not self.enabled or any(path in self.blocked for path in paths):
            raise ValueError("synthetic_directory_scope_denied")
        self.calls.append(paths)
        if self.hook:
            await self.hook(paths, len(self.calls))
        names = {""}
        for path in paths:
            parts = path.split("/") if path else []
            names.update("/".join(parts[:i]) for i in range(1, len(parts) + 1))
        snapshot = DirectoryScopeSnapshot(
            project_key=directory_project_key(reference),
            config_sha256="a" * 64,
            implementation_sha256="b" * 64,
            server_epoch="c" * 32,
            observed_at=time.time(),
            directories=paths,
            records=tuple(
                DirectoryRecord(
                    path=p,
                    device=1,
                    inode=1 + self.generation,
                    uid=1000,
                    gid=1000,
                    mode=0o700,
                    mtime_ns=1,
                    ctime_ns=self.generation,
                )
                for p in sorted(names)
            ),
        )
        self.snapshots.append(snapshot)
        return snapshot

    def current(self, reference, snapshot):
        return (
            self.qualified(reference)
            and any(s is snapshot for s in self.snapshots)
            and time.time() - snapshot.observed_at < 5
        )
