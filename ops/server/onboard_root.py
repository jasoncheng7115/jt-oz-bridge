"""Onboard one existing OpenCode Root into the Bridge runtime manifest.

Issues the per-Root file-read and catalog evidence the runtime validators
require by running the installed release's own readers against controlled
fixtures. Native access is GET-only; the Native database is never opened.

Run with the selected release's interpreter, as root, one step at a time:

    python -I -B onboard_root.py <step> --spec spec.json

Steps: prepare, directory, probe, cleanup, seal. They run beside the live Main,
against a private directory helper on spec's probe_socket. The caller then
stops Main and the observer briefly to activate the sealed candidate; this tool
never restarts Native.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

NATIVE_UID = 1000
BRIDGE_UID = 1001
PROBE_SECONDS = 280
MINIMUM_FREE_BYTES = 8 * 1024**3
BRIDGE_DB = "/var/lib/jt-oz-bridge/service/bridge.db"
POLICY_OPERATIONS = (
    "form.cancel",
    "form.reply",
    "model.switch",
    "permission.reply",
    "prompt",
    "session.rename",
)
REVIEW = "installed-evidence-reviewed-for-development-runtime"
FILE_CASES = (
    ("empty.bin", b"", "application/octet-stream"),
    ("binary.bin", b"\x00\xffexact original bytes\r\n", "application/octet-stream"),
    ("繁體 #?%.txt", "繁體中文 exact bytes\r\n".encode(), "text/plain"),
    (
        "board.html",
        b"<!doctype html><html><body>Controlled read qualification.</body></html>",
        "text/html",
    ),
    ("large.bin", b"x" * (20 * 1024**2), "application/octet-stream"),
)
HTML_FIXTURE = b"<html>controlled catalog fixture</html>"


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def dumps(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def need(condition: object, code: str) -> None:
    if not condition:
        raise RuntimeError(code)


def identity(path: Path) -> list[int]:
    s = path.lstat()
    return [
        s.st_dev,
        s.st_ino,
        s.st_uid,
        s.st_gid,
        stat.S_IMODE(s.st_mode),
        s.st_size,
        s.st_mtime_ns,
        s.st_ctime_ns,
        s.st_nlink,
    ]


def write_new(path: Path, raw: bytes, *, group: int = 0, mode: int = 0o640) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        os.fchown(stream.fileno(), 0, group)
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def merge_config(
    text: str,
    *,
    project_id: str,
    backend_id: str,
    directory: str,
    realm_id: str,
    enrollment_file: str,
    locale: str,
) -> str:
    """Point the existing TOML at the candidate and append exactly one project."""
    line = re.compile(r'^"enrollment_file" = ".*"$', re.MULTILINE)
    need(len(line.findall(text)) == 1, "config_enrollment_line_required")
    need(f'"id" = "{project_id}"' not in text, "config_project_already_present")
    merged = line.sub(f'"enrollment_file" = "{enrollment_file}"', text)
    return merged.rstrip("\n") + (
        "\n\n[[projects]]\n"
        f'"id" = "{project_id}"\n'
        '"enabled" = true\n'
        f'"backend_id" = "{backend_id}"\n'
        f'"workspace_root" = "{directory}"\n'
        f'"realm_id" = "{realm_id}"\n'
        '"input_mode" = "authorized_humans_in_bound_topic"\n'
        f'"default_topic_locale" = "{locale}"\n'
    )


def merge_manifest(
    manifest: dict[str, Any],
    *,
    new_backend: dict[str, Any],
    catalogs: dict[str, dict[str, str]],
    directory_scope: dict[str, str],
    grants: list[dict[str, Any]],
) -> dict[str, Any]:
    """Add one Root and repin catalogs; other Root evidence stays byte-identical."""
    session = new_backend["reference"]["upstream_session_id"]
    existing = {b["reference"]["upstream_session_id"] for b in manifest["backends"]}
    need(session not in existing, "manifest_root_already_present")
    need(existing | {session} == set(catalogs), "manifest_catalog_for_every_root_required")
    merged = json.loads(json.dumps(manifest))
    merged["backends"].append(new_backend)
    for backend in merged["backends"]:
        backend["workspace_catalog"] = catalogs[backend["reference"]["upstream_session_id"]]
    merged["directory_scope"] = directory_scope
    merged["grants"] = [*merged["grants"], *grants]
    return merged


def add_directory_root(config: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    need(
        all(r["project_key"] != root["project_key"] for r in config["roots"]),
        "directory_root_present",
    )
    return {**config, "roots": [*config["roots"], root]}


class Spec:
    def __init__(self, path: Path) -> None:
        raw = json.loads(path.read_bytes())
        self.tag: str = raw["tag"]
        need(re.fullmatch(r"[a-z0-9-]{1,40}", self.tag), "spec_tag")
        self.release = Path(raw["release"])
        self.project_id: str = raw["project_id"]
        self.directory = Path(raw["directory"])
        self.session_id: str = raw["session_id"]
        self.native_project_id: str = raw["native_project_id"]
        self.locale: str = raw.get("default_topic_locale", "zh-TW")
        self.config = Path(raw.get("config", "/etc/jt-oz-bridge/config.toml"))
        self.observer = Path(raw.get("observer", "/etc/jt-oz-bridge/local-observer.json"))
        self.helper_config = Path(raw.get("helper_config", "/etc/opencode-directory-probe.json"))
        self.work = Path("/root") / f"jt-oz-onboard-{self.tag}"
        self.shared = Path("/opt/jt-oz-bridge") / f"onboard-{self.tag}"
        self.target = Path("/etc/jt-oz-bridge") / f"runtime-onboard-{self.tag}"
        self.probe_socket = Path(raw["probe_socket"])
        self.spec_path = path


def fixture_root(spec: Spec) -> None:
    need(os.geteuid() == 0, "root_required")
    need(shutil.disk_usage(spec.directory).free >= MINIMUM_FREE_BYTES + 64 * 1024**2, "capacity")


def cmd_prepare(spec: Spec) -> None:
    """Create identified fixtures; each directory gets one catalog namespace."""
    fixture_root(spec)
    os.umask(0o077)
    spec.work.mkdir(mode=0o700)
    spec.shared.mkdir(mode=0o750)
    os.chmod(spec.shared, 0o750)
    os.chown(spec.shared, 0, BRIDGE_UID)
    from jt_oz_bridge.config import load_settings

    settings = load_settings(spec.config)
    directories = {p.workspace_root for p in settings.projects if p.enabled} | {str(spec.directory)}
    nonce = uuid.uuid4().hex
    report = f"報表-{nonce}"
    plan: dict[str, Any] = {
        "nonce": nonce,
        "report": report,
        "catalog": {},
        "entries": [],
        "dirs": [],
    }
    journal = spec.work / "fixtures.json"

    def save() -> None:
        temporary = journal.with_suffix(".tmp")
        temporary.write_bytes(dumps(plan))
        os.replace(temporary, journal)

    def mkdir(path: Path) -> None:
        path.mkdir(mode=0o700)
        os.chown(path, NATIVE_UID, NATIVE_UID)
        plan["dirs"].append(str(path))
        save()

    def put(path: Path, body: bytes) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            os.fchown(stream.fileno(), NATIVE_UID, NATIVE_UID)
            stream.write(body)
        plan["entries"].append({"path": str(path), "sha256": sha(body)})

    def link(path: Path, target: Path) -> None:
        os.symlink(target, path)
        os.chown(path, NATIVE_UID, NATIVE_UID, follow_symlinks=False)
        plan["entries"].append({"path": str(path), "target": str(target)})

    def stage(directory: Path, name: str) -> Path:
        # Native watches Git projects and misses files created in a burst, so
        # each fixture tree is built beside the project and renamed in whole.
        staging = directory.parent / f".jt-oz-onboard-stage-{nonce}-{name}"
        plan["stages"].append({"staging": str(staging), "final": str(directory / name)})
        mkdir(staging)
        return staging

    def place(staging: Path, final: Path) -> None:
        prefix = str(staging)
        for entry in plan["entries"]:
            if entry["path"] == prefix or entry["path"].startswith(prefix + "/"):
                entry["path"] = str(final) + entry["path"][len(prefix) :]
        plan["dirs"] = [
            str(final) + d[len(prefix) :] if d == prefix or d.startswith(prefix + "/") else d
            for d in plan["dirs"]
        ]
        save()
        os.rename(staging, final)

    plan["stages"] = []
    save()
    outside = Path("/opt") / f"jt-oz-onboard-outside-{nonce}"
    mkdir(outside)
    put(outside / "outside-marker.txt", b"controlled outside marker")
    for index, directory in enumerate(sorted(directories)):
        name = f"jt-oz-onboard-catalog{index}-{nonce}"
        inside = stage(Path(directory), name)
        for sub in (
            "nested 子目錄",
            "many",
            ".ssh",
            ".jt-oz-incoming-probe",
            ".jt-oz-preview-probe",
        ):
            mkdir(inside / sub)
        put(inside / f"{report} [1].html", HTML_FIXTURE)
        put(inside / "empty.txt", b"")
        put(inside / "nested 子目錄" / "子檔案.txt", b"controlled Unicode file")
        put(inside / "nested 子目錄" / "second.txt", b"second")
        put(inside / ".env", b"synthetic_non_secret=true")
        put(inside / ".ssh" / "id_ed25519", b"synthetic-not-a-key")
        put(inside / ".jt-oz-incoming-probe" / "payload.txt", b"staging marker")
        put(inside / ".jt-oz-preview-probe" / "page.html", b"preview marker")
        for number in range(1002):
            put(inside / "many" / f"needle-{name}-{number:04d}.txt", b"")
        link(inside / "escape-dir", outside)
        link(inside / "escape-file.txt", outside / "outside-marker.txt")
        place(inside, Path(directory) / name)
        plan["catalog"][directory] = name
        save()
    prefix = f"jt-oz-onboard-files-{nonce}"
    files = stage(spec.directory, prefix)
    plan["files"] = {"prefix": prefix, "cases": []}
    for name, body, mime in FILE_CASES:
        put(files / name, body)
        plan["files"]["cases"].append(
            {
                "filename": name,
                "relative": f"{prefix}/{name}",
                "size": len(body),
                "sha256": sha(body),
                "mime_type": mime,
            }
        )
    outside_file = Path("/var/tmp") / f"{prefix}-outside.bin"
    put(outside_file, b"Controlled outside marker, not a secret.\n")
    link(files / "outside.bin", outside_file)
    place(files, spec.directory / prefix)
    for entry in plan["entries"]:
        entry["identity"] = identity(Path(entry["path"]))
    plan["complete"] = True
    save()
    write_new(spec.shared / "fixtures.json", dumps(plan), group=BRIDGE_UID)
    print(
        json.dumps({"prepared": True, "entries": len(plan["entries"]), "dirs": len(plan["dirs"])})
    )


def cmd_cleanup(spec: Spec) -> None:
    """Remove only entries whose identity is unchanged since prepare."""
    need(os.geteuid() == 0, "root_required")
    plan = json.loads((spec.work / "fixtures.json").read_bytes())
    changed = []
    for entry in plan["entries"]:
        path = Path(entry["path"])
        if not os.path.lexists(path):
            continue
        if "identity" in entry and identity(path)[:6] != entry["identity"][:6]:
            changed.append(entry["path"])
    need(not changed, f"fixture_changed_retained:{changed[:5]}")
    removed = 0
    for entry in reversed(plan["entries"]):
        path = Path(entry["path"])
        if os.path.lexists(path):
            path.unlink()
            removed += 1
    kept = []
    for directory in sorted(plan["dirs"], key=lambda d: -len(Path(d).parts)):
        path = Path(directory)
        if not path.exists():
            continue
        if any(path.iterdir()):
            kept.append(directory)
        else:
            path.rmdir()
    need(not kept, f"unknown_fixture_content_retained:{kept[:5]}")
    receipt = {
        "passed": True,
        "entries_removed": removed,
        "directories_removed": len(plan["dirs"]),
        "unknown_data_deleted": False,
        "completed_at": time.time(),
    }
    write_new(spec.work / "cleanup.json", dumps(receipt), mode=0o600)
    print(json.dumps(receipt))


def host_state() -> dict[str, Any]:
    """Native process identity, recorded without touching its database."""
    out = subprocess.run(
        [
            "systemctl",
            "show",
            "opencode.service",
            "-p",
            "MainPID",
            "-p",
            "InvocationID",
            "-p",
            "NRestarts",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    ).stdout
    props = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    pid = props["MainPID"]
    ticks = int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19])
    exe = Path(f"/proc/{pid}/exe").resolve()
    return {
        "MainPID": pid,
        "InvocationID": props["InvocationID"],
        "nrestarts": int(props["NRestarts"]),
        "start_ticks": ticks,
        "binary_sha256": sha(exe.read_bytes()),
    }


def bridge_counts() -> dict[str, int]:
    """Row counts of the Bridge's own database; the probe never connects to it."""
    connection = sqlite3.connect(f"file:{BRIDGE_DB}?mode=ro", uri=True, timeout=5)
    try:
        names = [
            r[0] for r in connection.execute("select name from sqlite_master where type='table'")
        ]
        return {n: connection.execute(f'select count(*) from "{n}"').fetchone()[0] for n in names}
    finally:
        connection.close()


def cmd_probe(spec: Spec) -> None:
    """Root wrapper: run the GET worker as the Bridge user and retain its output."""
    need(os.geteuid() == 0, "root_required")
    before = host_state()
    counts_before = bridge_counts()
    unit = f"jt-oz-onboard-{spec.tag}-probe.service"
    script = spec.shared / "onboard_root.py"
    if not script.exists():
        write_new(script, Path(__file__).read_bytes(), group=BRIDGE_UID)
    argv = [
        "systemd-run",
        "--unit",
        unit,
        "--wait",
        "--collect",
        "--pipe",
        "--quiet",
        "--service-type=exec",
        "--property=User=jtoz",
        "--property=Group=jtoz",
        "--property=MemoryMax=750M",
        "--property=MemorySwapMax=0",
        f"--property=RuntimeMaxSec={PROBE_SECONDS}",
        "--property=KillMode=control-group",
        "--property=Nice=10",
        "--property=NoNewPrivileges=yes",
        "--property=PrivateTmp=yes",
        "--working-directory=/",
        str(spec.release / "venv/bin/python"),
        "-I",
        "-B",
        str(script),
        "worker",
        "--spec",
        str(spec.shared / "spec.json"),
    ]
    if not (spec.shared / "spec.json").exists():
        write_new(spec.shared / "spec.json", spec.spec_path.read_bytes(), group=BRIDGE_UID)
    done = subprocess.run(argv, capture_output=True, timeout=PROBE_SECONDS + 30, check=False)
    after = host_state()
    counts_after = bridge_counts()
    write_new(spec.work / "probe.stdout", done.stdout, mode=0o600)
    write_new(spec.work / "probe.stderr", done.stderr, mode=0o600)
    write_new(
        spec.work / "probe-terminal.json",
        dumps(
            {
                "actual_terminal": done.returncode,
                "true_join": True,
                "native_before": before,
                "native_after": after,
                "bridge_counts_unchanged": counts_before == counts_after,
                "bridge_counts_changed": sorted(
                    n for n in counts_before if counts_before[n] != counts_after.get(n)
                ),
            }
        ),
        mode=0o600,
    )
    print(done.stderr.decode(errors="replace")[-2000:], file=sys.stderr)
    need(done.returncode == 0, "probe_failed")
    need(before == after, "native_process_changed")
    print(json.dumps({"probe_terminal": 0, "native_unchanged": True}))


class ReadScopeChecks:
    """Pass-through read-scope observation; no fake scope, clock or response."""

    def __init__(self, client: Any) -> None:
        self.client, self.proofs = client, client.proofs
        self.records: list[dict[str, Any]] = []
        self.positive: list[dict[str, Any]] = []
        self.expired = False
        self.original_scope = self.proofs.read_scope

        async def observe(ref: Any) -> Any:
            wall, mono = time.time(), time.monotonic()
            scope = await self.original_scope(ref)
            need(scope.reference == ref and scope.expires_at == scope.issued_at + 5, "scope_shape")
            self.records.append(
                {
                    "scope": scope,
                    "wall_before": wall,
                    "mono_before": mono,
                    "wall_after": time.time(),
                }
            )
            need(len(self.records) <= 96, "bounded_scope_observations")
            return scope

        self.proofs.read_scope = observe

    def mark(self) -> int:
        need(not self.proofs._watched and not self.proofs.witnesses, "mutation_watch_present")
        return len(self.records)

    def _pair(self, mark: int, reference: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        need(len(self.records) == mark + 2, "two_read_scopes_required")
        first, last = self.records[mark:]
        a, b = first["scope"], last["scope"]
        need(
            a.reference == b.reference == reference
            and a.owner_epoch == b.owner_epoch
            and a.connection_epoch == b.connection_epoch
            and a.session_info_sha256 == b.session_info_sha256,
            "read_epoch_changed",
        )
        return first, last

    def file(self, reader: Any, value: Any, mark: int) -> dict[str, Any]:
        first, last = self._pair(mark, value.evidence.reference)
        a = first["scope"]
        context = reader._witnesses[(value.evidence.reference, value.evidence.relative_path)]
        need(
            context.original() is value
            and context.scope is last["scope"]
            and value.evidence.observed_at == a.issued_at
            and value.evidence.expires_at == context.deadline == a.expires_at
            and context.monotonic_deadline <= first["mono_before"] + 5
            and reader.current(value),
            "file_first_scope_deadline_not_preserved",
        )
        row = {
            "kind": "file",
            "first_issued_at": a.issued_at,
            "first_expires_at": a.expires_at,
            "closing_issued_at": last["scope"].issued_at,
            "object_expires_at": value.evidence.expires_at,
            "actual_first_pair_latency_seconds": last["wall_after"] - first["wall_before"],
            "readonly_without_mutation_watch": True,
            "first_scope_deadline_preserved": True,
        }
        self.positive.append(row)
        return row

    def catalog(self, catalog: Any, value: Any, mark: int) -> dict[str, Any]:
        first, last = self._pair(mark, value.reference)
        a = first["scope"]
        context = catalog._observed[id(value)]
        need(
            context.original() is value
            and context.scope is last["scope"]
            and context.scope_deadline == a.expires_at
            and context.deadline <= first["mono_before"] + 5
            and catalog.current(value),
            "catalog_first_scope_deadline_not_preserved",
        )
        row = {
            "kind": "find" if value.query else "list",
            "first_issued_at": a.issued_at,
            "first_expires_at": a.expires_at,
            "closing_issued_at": last["scope"].issued_at,
            "object_scope_deadline": context.scope_deadline,
            "actual_first_pair_latency_seconds": last["wall_after"] - first["wall_before"],
            "readonly_without_mutation_watch": True,
            "first_scope_deadline_preserved": True,
        }
        self.positive.append(row)
        return row

    async def expire_after_fresh_scope(self, original: Any, current: Any, deadline: float) -> None:
        need(type(deadline) in (int, float) and math.isfinite(deadline), "finite_deadline")
        await asyncio.sleep(max(0.0, deadline - time.time()) + 0.05)
        reference = (
            original.reference if hasattr(original, "reference") else original.evidence.reference
        )
        fresh = await self.proofs.read_scope(reference)
        need(
            time.time() >= deadline and fresh.issued_at >= deadline and not current(original),
            "expired_original_revived",
        )
        self.expired = True

    def summary(self, kinds: set[str]) -> dict[str, Any]:
        need(
            self.positive and kinds <= {r["kind"] for r in self.positive} and self.expired,
            "scope_summary",
        )
        return {
            "positive_observations": self.positive,
            "scope_calls": len(self.records),
            "expired_original_after_fresh_scope": True,
            "readonly_without_mutation_watch": True,
            "first_scope_deadline_preserved": True,
        }


async def catalog_probe(
    ref: Any,
    client: Any,
    policy: Any,
    scopes: Any,
    namespace: str,
    report: str,
    requests: list[str],
) -> dict[str, Any]:
    from jt_oz_bridge.adapters.opencode.contracts import ContractError
    from jt_oz_bridge.adapters.opencode.files import _read_once
    from jt_oz_bridge.adapters.opencode.transport import TransportError
    from jt_oz_bridge.adapters.opencode.workspace_catalog import (
        CATALOG_SEMANTICS,
        V2WorkspaceCatalog,
        WorkspaceCatalogAttestation,
    )
    from jt_oz_bridge.security.policy import AccessDenied
    from jt_oz_bridge.security.workspace_paths import disclosed_path
    from jt_oz_bridge.services.catalog_enrollment import CATALOG_CHECKS
    from jt_oz_bridge.storage.durable import digest

    t = client.transport
    operations = frozenset({"fs.list", "fs.find"})
    attestation = WorkspaceCatalogAttestation(
        ref,
        t.profile.sha256,
        policy.fingerprint_sha256,
        CATALOG_SEMANTICS,
        digest({"onboarding_probe": True, "namespace": namespace}),
        operations,
    )
    catalog = V2WorkspaceCatalog(client, {ref: attestation}, directories=scopes)
    checks: dict[str, Any] = {}
    scope_checks = ReadScopeChecks(client)
    original_listing = catalog.listing

    async def observed_listing(*args: Any, **kwargs: Any) -> Any:
        mark = scope_checks.mark()
        value = await original_listing(*args, **kwargs)
        scope_checks.catalog(catalog, value, mark)
        return value

    catalog.listing = observed_listing  # type: ignore[method-assign]

    async def settled_search(query: str, before_attempt: Any = None) -> Any:
        """Native's index keeps settling after a fixture lands; the product fails closed."""
        for attempt in range(12):
            if before_attempt is not None:
                before_attempt()
            try:
                return await catalog.listing(ref, query=query)
            except ContractError as error:
                need(
                    str(error) == "workspace_catalog_search_changed_during_parent_check", str(error)
                )
                need(attempt < 11, "index_never_settled")
                await asyncio.sleep(2.0)
        raise RuntimeError("index_never_settled")

    statuses: list[int] = []

    async def status_seen(response: Any) -> None:
        if response.request.url.path.startswith("/api/fs/read/"):
            statuses.append(response.status_code)

    t.client.event_hooks["response"].append(status_seen)
    try:
        previous, stable = None, 0
        for _ in range(60):
            raw = await t.request(
                "fs.find",
                query={
                    "location": {"directory": ref.canonical_directory},
                    "query": report,
                    "type": "file",
                    "limit": "1001",
                },
            )
            ready = any(e["path"] == namespace + "/" + report + " [1].html" for e in raw["data"])
            value = digest(raw)
            stable = stable + 1 if ready and value == previous else (1 if ready else 0)
            previous = value
            if stable >= 5:
                break
            await asyncio.sleep(1.0)
        need(stable >= 5, "controlled_index_not_stable")

        listed = await catalog.listing(ref, directory=namespace)
        required = {
            namespace + "/" + n
            for n in (report + " [1].html", "empty.txt", "nested 子目錄", "many")
        }
        need(required <= {e.path for e in listed.entries}, "listing_required_entries")
        need(
            listed.hidden_count == 4
            and not any(
                "/.env" in e.path or "/.ssh" in e.path or "/.jt-oz-" in e.path
                for e in listed.entries
            ),
            "protected_names_visible",
        )
        need(
            all(e.path.rpartition("/")[0] == namespace for e in listed.entries), "listing_children"
        )
        need(
            catalog.current(listed) and not catalog.current(listed.model_copy()), "listing_identity"
        )
        checks.update(
            directory_marker_and_immediate_children=True,
            protected_and_managed_names_hidden=True,
            original_object_only=True,
        )

        nested = await catalog.listing(ref, directory=namespace + "/nested 子目錄")
        need(
            {e.path for e in nested.entries}
            == {namespace + "/nested 子目錄/" + n for n in ("子檔案.txt", "second.txt")},
            "nested",
        )
        checks["unicode_nested_root_relative_paths"] = True

        captured: list[tuple[str, ...]] = []
        native_request = t.request

        async def capture_search(operation: str, **kwargs: Any) -> Any:
            value = await native_request(operation, **kwargs)
            if operation == "fs.find" and kwargs.get("query", {}).get("query") == report:
                captured.append(tuple(row["path"] for row in value["data"]))
            return value

        t.request = capture_search
        try:
            found = await settled_search(report, captured.clear)
        finally:
            t.request = native_request
        need(
            len(captured) == 2 and captured[0] == captured[1] and catalog.current(found),
            "search_pair",
        )
        allowed = []
        for path in captured[0]:
            try:
                disclosed_path(path)
            except AccessDenied:
                continue
            allowed.append(path)
        valid = set()
        for parent in sorted({p.rpartition("/")[0] for p in allowed}):
            try:
                observed = await scopes.observe(ref, (parent,))
            except ValueError:
                continue
            need(scopes.current(ref, observed), "scope_current")
            valid.add(parent)
        expected = [p for p in allowed if p.rpartition("/")[0] in valid][:1000]
        need(
            [e.path for e in found.entries] == expected and catalog.current(found), "rank_preserved"
        )
        checks["native_rank_preserved_after_scope_filtering"] = True
        need(
            any(e.path == namespace + "/" + report + " [1].html" for e in found.entries),
            "search_hit",
        )
        need(
            not any(e.path.startswith(namespace + "/escape-dir/") for e in found.entries), "escape"
        )
        checks["outside_search_descendants_absent"] = True
        empty = await catalog.listing(ref, query="jt-oz-no-match-" + uuid.uuid4().hex)
        need(empty.complete and not empty.entries, "empty_search")
        checks["unicode_and_empty_search"] = True

        for _ in range(60):
            raw = await t.request(
                "fs.find",
                query={
                    "location": {"directory": ref.canonical_directory},
                    "query": "needle-" + namespace,
                    "type": "file",
                    "limit": "1001",
                },
            )
            if len(raw["data"]) == 1001:
                break
            await asyncio.sleep(1.0)
        need(len(raw["data"]) == 1001, f"needle_index_incomplete:{len(raw['data'])}")
        search = await settled_search("needle-" + namespace)
        need(
            len(search.entries) == 1000
            and not search.complete
            and all(
                e.kind == "file" and e.path.startswith(namespace + "/many/") for e in search.entries
            ),
            f"truncation:{len(search.entries)}:{search.complete}:{search.hidden_count}",
        )
        checks["thousand_entry_search_reports_truncation"] = True
        try:
            await catalog.listing(ref, directory=namespace + "/many")
        except ContractError as error:
            need(str(error) == "workspace_catalog_response_capacity", "oversized_error")
        else:
            raise RuntimeError("oversized_directory_not_rejected")
        checks["oversized_directory_rejected"] = True

        for path in ("/etc", namespace + "/../", namespace + "//nested", namespace + "\\child"):
            count = len(requests)
            try:
                await catalog.listing(ref, directory=path)
            except ValueError:
                pass
            else:
                raise RuntimeError("invalid_path_not_rejected")
            need(len(requests) == count, "invalid_path_reached_http")
        checks["absolute_traversal_and_separators_rejected_before_http"] = True

        try:
            await catalog.listing(ref, directory=namespace + "/escape-dir")
        except ValueError as error:
            need(str(error) == "directory_scope_probe_failed", "outside_error")
        else:
            raise RuntimeError("outside_directory_not_rejected")
        checks["outside_directory_symlink_rejected"] = True

        inside = await _read_once(
            t, ref, namespace + "/" + report + " [1].html", maximum_bytes=1024
        )
        need(inside.content == HTML_FIXTURE, "inside_bytes")
        mark = len(statuses)
        try:
            await _read_once(t, ref, namespace + "/escape-file.txt", maximum_bytes=1024)
        except TransportError as error:
            need(
                str(error) == "native_file_read_rejected" and statuses[mark:] == [404],
                "outside_file",
            )
        else:
            raise RuntimeError("outside_file_not_rejected")
        checks["exact_inside_bytes_and_outside_symlink_rejected"] = True

        witness = await catalog.listing(ref, directory=namespace + "/nested 子目錄")
        need(catalog.current(witness), "witness_current")
        deadline = catalog._observed[id(witness)].scope_deadline
        await scope_checks.expire_after_fresh_scope(witness, catalog.current, deadline)
        for expired in (listed, nested, found, empty, search, witness):
            need(not catalog.current(expired), "expired_listing_current")
        checks["five_second_original_observation_expires"] = True
        summary = scope_checks.summary({"list", "find"})
        checks["readonly_without_mutation_watch"] = summary["readonly_without_mutation_watch"]
        checks["first_scope_deadline_preserved"] = summary["first_scope_deadline_preserved"]
    finally:
        t.client.event_hooks["response"].remove(status_seen)
        client.proofs.read_scope = scope_checks.original_scope
    return {
        "passed": True,
        "reference": ref.model_dump(mode="json"),
        "operation_checks": {op: {n: checks[n] for n in CATALOG_CHECKS[op]} for op in operations},
        "read_scope_checks": summary,
    }


async def file_probe(ref: Any, client: Any, policy: Any, fixture: dict[str, Any]) -> dict[str, Any]:
    import gc
    import weakref

    import jt_oz_bridge.adapters.opencode.files as module
    from jt_oz_bridge.adapters.opencode.files import (
        FILE_FEATURES,
        FILE_SEMANTICS,
        BinaryReadAttestation,
        V2NativeFileReader,
    )
    from jt_oz_bridge.services.file_enrollment import component_sha

    t = client.transport
    statuses: list[int] = []
    etags: list[str] = []

    async def seen(response: Any) -> None:
        if response.request.url.path.startswith("/api/fs/read/"):
            statuses.append(response.status_code)
            etags.append(response.headers.get("etag", ""))

    t.client.event_hooks["response"].append(seen)
    scope_checks = ReadScopeChecks(client)
    cases: list[dict[str, Any]] = []
    try:
        reader = V2NativeFileReader(
            client,
            attestation=BinaryReadAttestation(
                ref,
                t.profile.sha256,
                FILE_SEMANTICS,
                sha(json.dumps(fixture, sort_keys=True).encode()),
                policy.fingerprint_sha256,
                FILE_FEATURES,
            ),
        )
        for item in fixture["cases"]:
            need(
                not os.access(str(Path(ref.canonical_directory) / item["relative"]), os.R_OK),
                "local_bytes_must_not_substitute_native",
            )
            n = len(statuses)
            mark = scope_checks.mark()
            result = await reader.read(ref, item["relative"])
            observation = scope_checks.file(reader, result, mark)
            p = result.evidence.projection
            need(
                (p.filename, p.size, p.sha256, p.mime_type)
                == (item["filename"], item["size"], item["sha256"], item["mime_type"])
                and sha(result.content) == item["sha256"]
                and statuses[n:] == [200, 200]
                and result.evidence.etag
                and etags[n:] == [result.evidence.etag, result.evidence.etag]
                and reader.current(result),
                "two_exact_native_reads",
            )
            cases.append(
                {
                    "case": item["filename"],
                    "size": item["size"],
                    "sha256": item["sha256"],
                    "mime_type": item["mime_type"],
                    "two_exact_native_reads": True,
                    "matching_ETag_both_reads": True,
                    "ETag_sha256": sha(result.evidence.etag.encode()),
                    "original_object_current": True,
                    "direct_local_read_not_permitted": True,
                    "read_scope_observation": observation,
                }
            )
            if item["filename"] == "empty.bin":
                await scope_checks.expire_after_fresh_scope(
                    result, reader.current, result.evidence.expires_at
                )
            held = weakref.ref(result)
            del result
            gc.collect()
            need(held() is None, "weak_witness_retained")
        for name in ("outside.bin", "missing.bin"):
            n = len(statuses)
            try:
                await reader.read(ref, fixture["prefix"] + "/" + name)
            except ValueError:
                need(statuses[n:] == [404], "native_boundary_rejection")
                cases.append({"case": name, "status": 404, "error_not_file": True})
            else:
                raise RuntimeError("outside_or_missing_returned_file")
    finally:
        t.client.event_hooks["response"].remove(seen)
        client.proofs.read_scope = scope_checks.original_scope
    return {
        "passed": True,
        "reference": ref.model_dump(mode="json"),
        "contract_sha256": t.profile.sha256,
        "native_policy_sha256": policy.fingerprint_sha256,
        "candidate_module_sha256": component_sha(module),
        "file_semantics_sha256": FILE_SEMANTICS,
        "verified_features": sorted(FILE_FEATURES),
        "read_scope_checks": scope_checks.summary({"file"}),
        "readonly_without_mutation_watch": True,
        "first_scope_deadline_preserved": True,
        "cases": cases,
        "native_http_mutations": 0,
        "native_database_bytes_read": False,
        "zulip_requests": 0,
    }


async def worker_main(spec: Spec) -> dict[str, Any]:
    import httpx

    from jt_oz_bridge.adapters.opencode.catalog import V2CatalogProject
    from jt_oz_bridge.adapters.opencode.contracts import OpenAPIProfile
    from jt_oz_bridge.adapters.opencode.directory_scope import (
        DirectoryScopeEnrollment,
        LinuxDirectoryScopeGuard,
    )
    from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
    from jt_oz_bridge.adapters.opencode.host_owner import HostOwnerEnrollment, LinuxHostOwnerProbe
    from jt_oz_bridge.adapters.opencode.live import V2PublicFeed
    from jt_oz_bridge.adapters.opencode.model_settings import (
        MODEL_SETTING_SEMANTICS,
        ModelSettingsAttestation,
    )
    from jt_oz_bridge.adapters.opencode.project_policy import (
        PERMISSION_SOURCE,
        NativePolicyEnrollment,
        V2ProjectPolicyGuard,
    )
    from jt_oz_bridge.adapters.opencode.resources import V2LeafResourceProofs
    from jt_oz_bridge.adapters.opencode.transport import ContractAttestation, V2HTTPTransport
    from jt_oz_bridge.config import load_settings
    from jt_oz_bridge.domain.catalog import ProjectScope
    from jt_oz_bridge.domain.models import SessionRef
    from jt_oz_bridge.security.secrets import resolve_secret
    from jt_oz_bridge.services.runtime_enrollment import RuntimeEnrollment
    from jt_oz_bridge.storage.durable import digest

    settings = load_settings(spec.config)
    assert settings.runtime.enrollment_file is not None
    enrollment = RuntimeEnrollment.model_validate_json(
        Path(settings.runtime.enrollment_file).read_bytes()  # noqa: ASYNC240
    )
    anchor = next(q for q in enrollment.backends if q.protocol_scope == "backend")
    configured = next(b for b in settings.opencode_backends if b.id == anchor.reference.backend_id)
    owner_doc = HostOwnerEnrollment.model_validate_json(anchor.owner.read())
    owner = LinuxHostOwnerProbe(owner_doc, anchor.owner_socket)
    profile = OpenAPIProfile(anchor.schema_file.read())
    fixtures = json.loads((spec.shared / "fixtures.json").read_bytes())
    need(fixtures["complete"], "fixtures_incomplete")
    scopes = LinuxDirectoryScopeGuard(
        DirectoryScopeEnrollment.model_validate_json((spec.shared / "directory.json").read_bytes()),
        spec.probe_socket,
    )
    new_ref = SessionRef(
        backend_id=anchor.reference.backend_id,
        backend_identity=anchor.reference.backend_identity,
        project_id=spec.project_id,
        canonical_directory=str(spec.directory),
        upstream_session_id=spec.session_id,
    )
    entries: list[tuple[SessionRef, str, NativePolicyEnrollment, ModelSettingsAttestation]] = []
    model_ref = SessionRef.model_validate(json.loads(anchor.model_evidence.read())["reference"])

    def model(q_scope: str, q_sha: str, observed: SessionRef) -> ModelSettingsAttestation:
        return ModelSettingsAttestation(
            observed, profile.sha256, MODEL_SETTING_SEMANTICS, q_sha, qualification_scope=q_scope
        )

    for q in enrollment.backends:
        policy = NativePolicyEnrollment.model_validate_json(q.policy.read())
        observed = SessionRef.model_validate(json.loads(q.model_evidence.read())["reference"])
        entries.append(
            (
                q.reference,
                q.native_project_id,
                policy,
                model(q.protocol_scope, q.model_evidence.sha256, observed),
            )
        )
    draft = NativePolicyEnrollment(
        format="native-project-policy-v1",
        reference=new_ref,
        native_project_id=spec.native_project_id,
        contract_sha256=profile.sha256,
        permission_source_sha256=PERMISSION_SOURCE,
        fingerprint_sha256="0" * 64,
        operations=frozenset(POLICY_OPERATIONS),
    )
    entries.append(
        (
            new_ref,
            spec.native_project_id,
            draft,
            model("backend", anchor.model_evidence.sha256, model_ref),
        )
    )
    projects = {
        ref.project_id: V2CatalogProject(
            ProjectScope(**ref.model_dump(exclude={"upstream_session_id"})), native
        )
        for ref, native, _, _ in entries
    }
    transport = V2HTTPTransport(
        configured.base_url,
        profile,
        auth=httpx.BasicAuth(
            "opencode", resolve_secret(configured.credential_ref).get_secret_value()
        ),
        attestation=ContractAttestation(
            profile.sha256,
            anchor.reference.backend_identity,
            owner_doc.version,
            anchor.verified_operations,
        ),
    )
    requests: list[str] = []

    async def get_only(request: Any) -> None:
        need(request.method == "GET" and request.url.host == "127.0.0.1", "get_only")
        requests.append(request.url.path)
        need(len(requests) < 6000, "bounded_gets")

    transport.client.event_hooks["request"].append(get_only)
    feed = V2PublicFeed(
        transport, owner, tuple(e[0] for e in entries), receipts=None, capture_text=False
    )

    async def identity_check() -> bool:
        await feed.current_owner()
        return True

    transport.verify_identity = identity_check
    catalogs: dict[str, Any] = {}
    file_result: dict[str, Any] = {}
    new_policy: dict[str, Any] = {}
    facts_view: dict[str, Any] = {}
    owners = []
    try:
        owners.append((await owner.read()).model_dump(mode="json"))
        await feed.start()
        probed_directories: set[str] = set()
        for ref, _native, policy, attestation in entries:
            proofs = V2LeafResourceProofs(feed, projects, model_settings=attestation)
            guard = V2ProjectPolicyGuard(proofs, {ref: policy})
            client = V2ExecutionClient(transport, projects, proofs=proofs, scope_guard=guard)
            if ref == new_ref:
                first, _ = await guard._bundle_facts(ref)
                second, _ = await guard._bundle_facts(ref)
                need(digest(first) == digest(second), "policy_not_stable")
                policy = draft.model_copy(update={"fingerprint_sha256": digest(first)})
                guard = V2ProjectPolicyGuard(proofs, {ref: policy})
                client = V2ExecutionClient(transport, projects, proofs=proofs, scope_guard=guard)
                new_policy = json.loads(policy.model_dump_json())
                facts_view = {
                    "agent": first["agent"],
                    "session_permissions": first["session_permissions"],
                    "mcp": [m.get("name") for m in first["mcp"]],
                    "saved_permissions": len(first["saved_permissions"]),
                }
            scope = await proofs.read_scope(ref)
            bundle = await guard.bundle(ref)
            need(bundle == (policy.fingerprint_sha256, scope.session_info_sha256), "policy_changed")
            directory = ref.canonical_directory
            namespace = fixtures["catalog"][directory]
            result = await catalog_probe(
                ref, client, policy, scopes, namespace, fixtures["report"], requests
            )
            catalogs[ref.upstream_session_id] = result
            if ref == new_ref:
                file_result = await file_probe(ref, client, policy, fixtures["files"])
            probed_directories.add(directory)
        owners.append((await owner.read()).model_dump(mode="json"))
        need(owners[0]["owner_epoch"] == owners[-1]["owner_epoch"], "owner_changed")
    finally:
        await feed.close()
        await transport.close()
    return {
        "observation_completed": True,
        "catalogs": catalogs,
        "file_read": file_result,
        "new_policy": new_policy,
        "new_policy_facts": facts_view,
        "native_get_count": len(requests),
        "native_mutations": 0,
        "zulip_requests": 0,
        "owners": owners,
    }


def cmd_worker(spec: Spec) -> None:
    need(os.getuid() == BRIDGE_UID, "bridge_uid_required")

    async def bounded() -> dict[str, Any]:
        async with asyncio.timeout(PROBE_SECONDS - 20):
            return await worker_main(spec)

    print(json.dumps(asyncio.run(bounded()), ensure_ascii=False))


def cmd_directory(spec: Spec) -> None:
    """Write candidate helper config and pin; the caller installs and restarts."""
    need(os.geteuid() == 0, "root_required")
    from jt_oz_bridge.adapters.opencode.directory_scope import directory_project_key
    from jt_oz_bridge.config import load_settings
    from jt_oz_bridge.domain.models import SessionRef
    from jt_oz_bridge.services.runtime_enrollment import RuntimeEnrollment

    settings = load_settings(spec.config)
    enrollment = RuntimeEnrollment.model_validate_json(
        Path(settings.runtime.enrollment_file).read_bytes()
    )
    anchor = enrollment.backends[0].reference
    ref = SessionRef(
        backend_id=anchor.backend_id,
        backend_identity=anchor.backend_identity,
        project_id=spec.project_id,
        canonical_directory=str(spec.directory),
        upstream_session_id=spec.session_id,
    )
    s = spec.directory.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == NATIVE_UID, "project_directory_owner")
    root = {
        "device": s.st_dev,
        "directory": str(spec.directory),
        "gid": s.st_gid,
        "inode": s.st_ino,
        "mode": stat.S_IMODE(s.st_mode),
        "project_key": directory_project_key(ref),
        "uid": s.st_uid,
    }
    helper = add_directory_root(json.loads(spec.helper_config.read_bytes()), root)
    helper_raw = dumps(helper)
    pin = json.loads(enrollment.directory_scope.read())
    candidate = {**pin, "config_sha256": sha(helper_raw), "roots": helper["roots"]}
    write_new(spec.work / "helper-config.json", helper_raw, mode=0o600)
    write_new(spec.shared / "directory.json", dumps(candidate), group=BRIDGE_UID)
    print(json.dumps({"config_sha256": sha(helper_raw), "roots": len(helper["roots"])}))


def cmd_seal(spec: Spec) -> None:
    """Build certificates, candidate manifest, config and observer policy."""
    need(os.geteuid() == 0, "root_required")
    import jt_oz_bridge.adapters.opencode.directory_scope as directory_module
    import jt_oz_bridge.adapters.opencode.workspace_catalog as catalog_module
    from jt_oz_bridge.adapters.opencode.directory_scope import DirectoryScopeEnrollment
    from jt_oz_bridge.adapters.opencode.host_owner import HostOwnerEnrollment
    from jt_oz_bridge.adapters.opencode.project_policy import NativePolicyEnrollment
    from jt_oz_bridge.adapters.opencode.workspace_catalog import CATALOG_SEMANTICS
    from jt_oz_bridge.config import load_settings
    from jt_oz_bridge.domain.models import SessionRef
    from jt_oz_bridge.services.catalog_enrollment import catalog_qualification
    from jt_oz_bridge.services.file_enrollment import component_sha, native_file_qualification
    from jt_oz_bridge.services.runtime_enrollment import RuntimeEnrollment

    terminal = json.loads((spec.work / "probe-terminal.json").read_bytes())
    need(
        terminal["actual_terminal"] == 0 and terminal["native_before"] == terminal["native_after"],
        "probe_terminal",
    )
    # Live Main keeps ingesting Zulip events; the probe itself never connects to this database.
    need(
        set(terminal["bridge_counts_changed"]) <= {"input_events"},
        "bridge_counts_changed_during_probe",
    )
    cleanup = json.loads((spec.work / "cleanup.json").read_bytes())
    need(cleanup["passed"] is True, "cleanup_required")
    stdout = (spec.work / "probe.stdout").read_bytes()
    observed = json.loads(stdout)
    settings = load_settings(spec.config)
    manifest_raw = Path(settings.runtime.enrollment_file).read_bytes()
    manifest = json.loads(manifest_raw)
    enrollment = RuntimeEnrollment.model_validate_json(manifest_raw)
    directory_raw = (spec.shared / "directory.json").read_bytes()
    directories = DirectoryScopeEnrollment.model_validate_json(directory_raw)
    owner = HostOwnerEnrollment.model_validate_json(enrollment.backends[0].owner.read())
    target = spec.target
    target.mkdir(mode=0o750)
    os.chmod(target, 0o750)
    os.chown(target, 0, BRIDGE_UID)
    tool_sha = sha(Path(__file__).read_bytes())
    pin_directory = {"path": str(target / "directory.json"), "sha256": sha(directory_raw)}
    write_new(target / "directory.json", directory_raw, group=BRIDGE_UID)
    anchor = next(b for b in manifest["backends"] if b["protocol_scope"] == "backend")
    contract = anchor["schema_file"]["sha256"]
    policy_raw = dumps(observed["new_policy"])
    write_new(target / "policy.json", policy_raw, group=BRIDGE_UID)
    new_policy = NativePolicyEnrollment.model_validate_json(policy_raw)
    new_ref = new_policy.reference
    catalogs: dict[str, dict[str, str]] = {}
    fingerprints = {
        q.reference.upstream_session_id: NativePolicyEnrollment.model_validate_json(
            q.policy.read()
        ).fingerprint_sha256
        for q in enrollment.backends
    } | {new_ref.upstream_session_id: new_policy.fingerprint_sha256}
    native = terminal["native_after"]
    for session_id, row in observed["catalogs"].items():
        ref = SessionRef.model_validate(row["reference"])
        physical = next(
            r.model_dump(mode="json")
            for r in directories.roots
            if r.project_key == directory_module.directory_project_key(ref)
        )
        operations = sorted(row["operation_checks"])
        doc = {
            "format": "qualified-original-workspace-catalog-v2",
            "operator_review": REVIEW,
            "reference": row["reference"],
            "contract_sha256": contract,
            "native_policy_sha256": fingerprints[session_id],
            "executable_sha256": owner.executable_sha256,
            "catalog_component_sha256": component_sha(catalog_module),
            "directory_component_sha256": component_sha(directory_module),
            "semantics_sha256": CATALOG_SEMANTICS,
            "directory_enrollment_sha256": pin_directory["sha256"],
            "directory_config_sha256": directories.config_sha256,
            "directory_implementation_sha256": directories.implementation_sha256,
            "physical_root": physical,
            "operations": operations,
            "observation": {
                "passed": True,
                "native_database_bytes_read": False,
                "native_http_mutations": 0,
                "zulip_http_mutations": 0,
                "original_processes_unchanged": True,
                "live_bridge_counts_unchanged": True,
                "live_bridge_ingest_tables_changed": terminal["bridge_counts_changed"],
                "controlled_probe_cleanup_complete": True,
                "evidence_sha256": sha(stdout),
                "checks": row["operation_checks"],
            },
            "onboarding_tool_sha256": tool_sha,
            "formal_acceptance": False,
        }
        raw = dumps(doc)
        name = f"catalog-{session_id}.json"
        write_new(target / name, raw, group=BRIDGE_UID)
        catalog_qualification(
            raw,
            reference=ref,
            contract_sha256=contract,
            native_policy_sha256=fingerprints[session_id],
            owner=owner,
            directories=directories,
            directory_enrollment_sha256=pin_directory["sha256"],
            evidence_sha256=sha(raw),
        )
        catalogs[session_id] = {"path": str(target / name), "sha256": sha(raw)}
    file_doc = {
        "format": "qualified-native-file-read-v2",
        "operator_review": REVIEW,
        "host_check": {
            "passed": True,
            "native_restart": False,
            "native_mutations": 0,
            "native_database_bytes_read": False,
            "native_process_unchanged": True,
            "controlled_probe_cleanup_complete": True,
            "native_before": {**native, "owner_epoch": observed["owners"][0]["owner_epoch"]},
            "native_after": {**native, "owner_epoch": observed["owners"][-1]["owner_epoch"]},
        },
        "native_read": observed["file_read"],
        "raw_evidence_sha256": sha(stdout),
        "cleanup_receipt_sha256": sha((spec.work / "cleanup.json").read_bytes()),
        "onboarding_tool_sha256": tool_sha,
        "Human_acceptance": False,
        "formal_acceptance": False,
    }
    file_raw = dumps(file_doc)
    write_new(target / "file_read.json", file_raw, group=BRIDGE_UID)
    native_file_qualification(
        file_raw,
        reference=new_ref,
        contract_sha256=contract,
        native_policy_sha256=new_policy.fingerprint_sha256,
        executable_sha256=owner.executable_sha256,
        evidence_sha256=sha(file_raw),
    )
    new_backend = {
        **json.loads(json.dumps(anchor)),
        "reference": new_ref.model_dump(mode="json"),
        "native_project_id": spec.native_project_id,
        "policy": {"path": str(target / "policy.json"), "sha256": sha(policy_raw)},
        "file_read": {"path": str(target / "file_read.json"), "sha256": sha(file_raw)},
        "protocol_scope": "backend",
    }
    users = sorted({g["user_id"] for g in manifest["grants"]})
    merged = merge_manifest(
        manifest,
        new_backend=new_backend,
        catalogs=catalogs,
        directory_scope=pin_directory,
        grants=[
            {"project_id": spec.project_id, "roles": ["administrator"], "user_id": u} for u in users
        ],
    )
    manifest_out = dumps(merged)
    write_new(target / "runtime.json", manifest_out, group=BRIDGE_UID)
    config_out = merge_config(
        spec.config.read_text(),
        project_id=spec.project_id,
        backend_id=new_ref.backend_id,
        directory=str(spec.directory),
        realm_id=merged["realm"]["realm_id"],
        enrollment_file=str(target / "runtime.json"),
        locale=spec.locale,
    )
    write_new(target / "config.toml", config_out.encode(), group=BRIDGE_UID)
    observer = json.loads(spec.observer.read_bytes())
    observer["runtime_enrollment_sha256"] = sha(manifest_out)
    write_new(target / "local-observer.json", dumps(observer), group=BRIDGE_UID)
    print(
        json.dumps(
            {
                "sealed": str(target),
                "runtime_sha256": sha(manifest_out),
                "policy_facts": observed["new_policy_facts"],
            },
            ensure_ascii=False,
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "step", choices=("prepare", "directory", "probe", "worker", "cleanup", "seal")
    )
    parser.add_argument("--spec", type=Path, required=True)
    args = parser.parse_args()
    spec = Spec(args.spec)
    {
        "prepare": cmd_prepare,
        "directory": cmd_directory,
        "probe": cmd_probe,
        "worker": cmd_worker,
        "cleanup": cmd_cleanup,
        "seal": cmd_seal,
    }[args.step](spec)


if __name__ == "__main__":
    main()
