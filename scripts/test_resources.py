"""Bound this run's disposable scratch and stop its own child process group."""

import os
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import IO

GIB = 1024**3
START_FREE = 12 * GIB
RESERVE_FREE = 8 * GIB
SCRATCH_LIMIT = 6 * GIB
POLL_SECONDS = 0.25
SCAN_SECONDS = 5.0


def allocated_bytes(root: Path) -> int:
    """Count allocated regular files once; never follow fixture symlinks."""
    total, seen = 0, set()
    for parent, directories, names in os.walk(root, followlinks=False):
        directories[:] = [name for name in directories if not (Path(parent) / name).is_symlink()]
        for name in names:
            try:
                info = (Path(parent) / name).lstat()
            except FileNotFoundError:
                continue
            identity = info.st_dev, info.st_ino
            if stat.S_ISREG(info.st_mode) and identity not in seen:
                total += getattr(info, "st_blocks", (info.st_size + 511) // 512) * 512
                seen.add(identity)
    return total


class TestResources:
    __test__ = False

    def __init__(self, root: Path, run_id: str, *, scratch_parent: Path | None = None) -> None:
        self.root = root.resolve(strict=True)
        free = shutil.disk_usage(self.root).free
        if free < START_FREE:
            raise OSError("full_test_requires_12_GiB_free_before_start")
        self.scratch = Path(
            tempfile.mkdtemp(prefix=f"jt-oz-full-{run_id}-", dir=scratch_parent)
        ).resolve(strict=True)
        free = min(free, shutil.disk_usage(self.scratch).free)
        if free < START_FREE:
            self.scratch.rmdir()
            raise OSError("full_test_requires_12_GiB_free_before_start")
        info = self.scratch.stat()
        self._identity = info.st_dev, info.st_ino
        (self.scratch / ".run-owner").write_text(run_id)
        self.reason: str | None = None
        self.minimum_free = free
        self.maximum_scratch = 0
        self._scan_at = 0.0
        self._signals: dict[signal.Signals, object] = {}

    def own_scratch(self) -> None:
        info = self.scratch.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or (info.st_dev, info.st_ino) != self._identity
            or info.st_uid != os.getuid()
        ):
            raise OSError("full_test_scratch_identity_changed")

    def install_signal_handlers(self) -> None:
        for value in (signal.SIGINT, signal.SIGTERM):
            self._signals[value] = signal.signal(value, self.interrupt)

    def interrupt(self, number: int, _frame: object) -> None:
        self.reason = self.reason or f"received_signal_{number}"

    def observe(self) -> None:
        self.own_scratch()
        free = min(shutil.disk_usage(path).free for path in (self.root, self.scratch))
        self.minimum_free = min(self.minimum_free, free)
        if free < RESERVE_FREE:
            self.reason = self.reason or "free_space_below_8_GiB"
        if time.monotonic() >= self._scan_at:
            used = allocated_bytes(self.scratch)
            self.maximum_scratch = max(self.maximum_scratch, used)
            self._scan_at = time.monotonic() + SCAN_SECONDS
            if used > SCRATCH_LIMIT:
                self.reason = self.reason or "scratch_exceeds_6_GiB"

    @staticmethod
    def stop(child: subprocess.Popen[bytes]) -> None:
        if os.name == "posix":
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            # Keep the leader unreaped so its PID cannot be reused while a
            # TERM-ignoring descendant survives in this owned process group.
            time.sleep(1)
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError:
                # A zombie-only group can reject a further signal. Accept
                # that result only after checking there are no live members.
                members = subprocess.check_output(["ps", "-axo", "pgid=,stat="], text=True)
                if any(
                    fields[0] == str(child.pid) and not fields[1].startswith("Z")
                    for line in members.splitlines()
                    if len(fields := line.split()) == 2
                ):
                    raise
            child.wait()
            return
        if child.poll() is None:
            child.terminate()
        try:
            child.wait(timeout=1)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()

    def run(self, command: list[str], log: IO[str], env: dict[str, str]) -> int:
        self.observe()
        if self.reason:
            log.write(f"NOT_RUN: {self.reason}\n")
            return 75
        with subprocess.Popen(
            command,
            cwd=self.root,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=os.name == "posix",
        ) as child:
            try:
                while child.poll() is None:
                    self.observe()
                    if self.reason:
                        self.stop(child)
                        log.write(f"\nINTERRUPTED: {self.reason}\n")
                        return 75
                    time.sleep(POLL_SECONDS)
                self._scan_at = 0.0
                self.observe()
                return 75 if self.reason else child.returncode
            finally:
                if child.poll() is None:
                    self.stop(child)

    def environment(self, parent: dict[str, str]) -> dict[str, str]:
        result = parent.copy()
        result.update(
            TMPDIR=str(self.scratch),
            TMP=str(self.scratch),
            TEMP=str(self.scratch),
            PYTHONDONTWRITEBYTECODE="1",
            RUFF_CACHE_DIR=str(self.scratch / "caches/ruff"),
            MYPY_CACHE_DIR=str(self.scratch / "caches/mypy"),
            UV_CACHE_DIR=str(self.scratch / "caches/uv"),
        )
        return result

    def finish(self, *, passed: bool) -> dict[str, object]:
        self._scan_at = 0.0
        self.observe()
        self.own_scratch()
        retained = not passed or self.reason is not None
        if not retained:
            shutil.rmtree(self.scratch)
        else:
            caches = self.scratch / "caches"
            if caches.is_dir() and not caches.is_symlink():
                shutil.rmtree(caches)
        for value, previous in self._signals.items():
            signal.signal(value, previous)  # type: ignore[arg-type]
        return {
            "scratch_directory": str(self.scratch),
            "minimum_start_free_bytes": START_FREE,
            "minimum_running_free_bytes": RESERVE_FREE,
            "maximum_scratch_bytes": SCRATCH_LIMIT,
            "minimum_observed_free_bytes": self.minimum_free,
            "maximum_observed_allocated_scratch_bytes": self.maximum_scratch,
            "interruption_reason": self.reason,
            "scratch_retained": retained,
            "pytest_retention_policy": "failed",
        }
