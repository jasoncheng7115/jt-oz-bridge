#!/usr/bin/python3
"""Fixed, repository-read-only Git index evidence helper (stdlib only).

Not enrolled, qualified, or enabled by adding this file, and not a substitute for
the original Native check or policy, plugin and installation qualification. No commit/push authority is
returned. All failures are private fixed codes; Git output is never forwarded.

Supported: SHA-1/SHA-256, complete v2/v3 stage-zero indexes, full HEAD tree,
regular/executable/symlink/gitlink entries, add/modify/delete/type changes.
Renames are delete+add. Unsupported index extensions/formats/configuration fail
closed. TREE cache metadata is syntax checked and NEVER used as tree authority.

Registry: /etc/jt-oz-bridge/git-inspect225.json (root-owned, no group/other write).
Exact CLI: --scope <sha256 of canonical JSON full SessionRef>. Registry keys are
validated below. Per-scope identities are {path,dev,ino,uid,gid,mode}, where mode
is stat.S_IMODE. Config file pins additionally contain sha256. System/xdg/global
config may be null only when absent; local must be <common_dir>/config.
It supports the standard /etc/gitconfig, HOME/.gitconfig and
HOME/.config/git/config context; custom inherited XDG roots are refused. All configured paths are
absolute, symlink-free. Binary pins are {path,sha256,version}; Python's path is
its actual resolved executable. Qualification digests are enrollment inputs,
not self-authenticating live proof. It is not wired to runtime enrollment until a
Git build that passes the checks below is available.

The installed Git must separately qualify the actual --no-lazy-fetch flag and
the empty GIT_ALLOW_PROTOCOL transport whitelist. A "2.43" version string is
insufficient; unsupported flags fail before repository inspection. This file
does not upgrade or establish support in the active Native/Git installation.
"""

import hashlib
import json
import math
import os
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path

REGISTRY = "/etc/jt-oz-bridge/git-inspect225.json"
SCRIPT = "/opt/jt-oz-bridge/git-inspect225.py"
VERSION = "git-inspect225-v1"
METADATA_GIT_VERSION = "2.56.0.jtoz-metadata1"
SECONDS = 5.0
CLEANUP_SECONDS = 0.25
INDEX_BYTES = 4 * 1024 * 1024
INDEX_ENTRIES = 4096
HEAD_BYTES = 8 * 1024 * 1024
HEAD_ENTRIES = 16384
TREE_NODES = 16385
CHILD_BYTES = 8 * 1024 * 1024
STDERR_BYTES = 65536
AGGREGATE_BYTES = 24 * 1024 * 1024
CONFIG_BYTES = 256 * 1024
FINAL_BYTES = 65536
MODES = {"100644", "100755", "120000", "160000"}
SHA = re.compile(r"[0-9a-f]{64}\Z")
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,119}\Z")
REF_KEYS = {
    "backend_id",
    "backend_identity",
    "upstream_session_id",
    "project_id",
    "canonical_directory",
}
DENIED = frozenset(
    {
        ".git",
        ".ssh",
        ".aws",
        ".azure",
        ".docker",
        ".gnupg",
        ".kube",
        ".pki",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".pgpass",
        ".git-credentials",
        "auth.json",
        "credentials.json",
        "secrets.json",
        "secrets",
        "credentials",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
    }
)


class Unavailable(Exception):
    """Only a fixed, non-sensitive code may leave this process."""


def require(condition, code="unsupported"):
    if not condition:
        raise Unavailable(code)


def canonical_json(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def capture_time(value=None):
    value = time.time() if value is None else value
    require(
        type(value) in {int, float} and math.isfinite(value) and 0 <= value <= 2**53,
        "clock",
    )
    return value


def strict_json(raw, deadline=None):
    def pairs(items):
        result = {}
        for key, value in items:
            if deadline:
                deadline.check()
            require(key not in result, "registry_json")
            result[key] = value
        return result

    def bad_constant(_):
        raise Unavailable("registry_json")

    try:
        if deadline:
            deadline.check()
        result = json.loads(raw, object_pairs_hook=pairs, parse_constant=bad_constant)
        if deadline:
            deadline.check()
        return result
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise Unavailable("registry_json") from None


class Deadline:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.start = clock()
        # One clock/expiry for the entire invocation, not a new wait budget per
        # child. Ordinary work stops early to reserve time for kill + waitpid.
        self.expires = self.start + SECONDS
        self.work_expires = self.expires - min(CLEANUP_SECONDS, SECONDS / 4)

    def remaining(self, *, cleanup=False):
        now = self.clock()
        require(now >= self.start, "deadline")
        remaining = (self.expires if cleanup else self.work_expires) - now
        require(remaining > 0, "deadline")
        return remaining

    def check(self, *, cleanup=False):
        self.remaining(cleanup=cleanup)


class Children:
    """Private bounded byte capture. Never shell, pager, or network commands.

    Normal and exceptional paths use the same total deadline to reap the direct
    child. Cleanup has a reserved slice *inside* that deadline, not a new timeout.
    Uninterruptible kernel I/O/scheduling is not a hard real-time guarantee: an
    observed overrun always fails; outer process supervision remains necessary.
    """

    def __init__(self, deadline, cwd, env):
        self.deadline, self.cwd, self.env = deadline, cwd, env
        self.total = 0

    def run(self, argv, cap=CHILD_BYTES):
        self.deadline.check()
        require(type(cap) is int and 0 < cap <= CHILD_BYTES, "child_bound")
        require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "child_reaping_policy")
        chunks = {"out": bytearray(), "err": bytearray()}
        selector = None
        process = subprocess.Popen(
            argv,
            cwd=self.cwd,
            env=self.env,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
        )
        try:
            selector = selectors.DefaultSelector()
            for stream, label in ((process.stdout, "out"), (process.stderr, "err")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            while selector.get_map():
                for key, _ in selector.select(min(0.025, self.deadline.remaining())):
                    try:
                        data = os.read(key.fd, 65536)
                    except BlockingIOError:
                        continue
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    label = key.data
                    self.total += len(data)
                    require(self.total <= AGGREGATE_BYTES, "aggregate_capacity")
                    require(
                        len(chunks[label]) + len(data) <= (cap if label == "out" else STDERR_BYTES),
                        "child_capacity",
                    )
                    chunks[label].extend(data)
                self.deadline.check()
            # Observe exit WITHOUT reaping. This retains the child's PID until
            # group termination and avoids signaling a reused PID/PGID after a
            # successful wait. No poll()/wait() may precede that termination.
            while True:
                self.deadline.check()
                observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if observed is not None:
                    break
                time.sleep(min(0.01, self.deadline.remaining()))
            self.deadline.check()
            require(
                observed.si_code == os.CLD_EXITED and observed.si_status == 0 and not chunks["err"],
                "git_unavailable",
            )
            return bytes(chunks["out"])
        except subprocess.TimeoutExpired:
            raise Unavailable("deadline") from None
        finally:
            try:
                # Attempt termination even when a kernel stall exhausted the
                # deadline. Never grant additional wait time or report success.
                kill_failed = False
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError:
                    kill_failed = True
                try:
                    if process.returncode is None:
                        process.wait(timeout=self.deadline.remaining(cleanup=True))
                except subprocess.TimeoutExpired:
                    raise Unavailable("child_cleanup_unconfirmed") from None
                require(
                    process.returncode is not None and not kill_failed,
                    "child_cleanup_unconfirmed",
                )
                self.deadline.check(cleanup=True)
            finally:
                try:
                    if selector is not None:
                        selector.close()
                finally:
                    try:
                        process.stdout.close()
                    finally:
                        process.stderr.close()
                        # Includes resource closure in the same total clock;
                        # even a successful child's late cleanup cannot pass.
                        self.deadline.check(cleanup=True)


def identity(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode))


def absolute_path(value):
    require(type(value) is str and value.startswith("/") and "\x00" not in value, "physical_scope")
    require(str(Path(value)) == value and ".." not in Path(value).parts, "physical_scope")
    return value


def no_symlinks(path, deadline=None):
    absolute_path(path)
    current = Path("/")
    for part in Path(path).parts[1:]:
        if deadline:
            deadline.check()
        current /= part
        require(not stat.S_ISLNK(os.lstat(current).st_mode), "physical_scope")
    if deadline:
        deadline.check()


def read_file(path, cap, deadline, expected_uid=None, *, expected_identity=None):
    """Bounded regular FD with held parents and optional pre-read file identity.

    The preliminary pathname check is diagnostic, not the symlink boundary.
    Every directory and the leaf are opened relative to held descriptors with
    O_NOFOLLOW. A pinned configuration must match the opened file before even
    its first byte is requested; post-read hashing cannot undo a foreign read.
    This is not an atomic content snapshot or a sandbox for privileged Native.
    """
    deadline.check()
    no_symlinks(path, deadline)
    descriptors = []
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        root_fd = os.open("/", directory_flags)
        descriptors.append(root_fd)
        root_identity = identity(os.fstat(root_fd))
        parent_fd, parents = root_fd, []
        parts = Path(path).parts
        for part in parts[1:-1]:
            deadline.check()
            child_fd = os.open(part, directory_flags, dir_fd=parent_fd)
            descriptors.append(child_fd)
            observed = os.fstat(child_fd)
            require(stat.S_ISDIR(observed.st_mode), "physical_scope")
            parents.append((parent_fd, part, child_fd, identity(observed)))
            parent_fd = child_fd
        fd = os.open(
            parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        descriptors.append(fd)
        before = os.fstat(fd)
        require(
            stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= cap,
            "file_capacity_or_identity",
        )
        require(expected_uid is None or before.st_uid == expected_uid, "file_owner")
        require(
            expected_identity is None or identity(before) == expected_identity,
            "file_identity",
        )

        def parents_current():
            deadline.check()
            require(
                identity(os.fstat(root_fd))
                == identity(os.stat("/", follow_symlinks=False))
                == root_identity,
                "physical_scope",
            )
            for base, name, opened, original in parents:
                deadline.check()
                named = os.stat(name, dir_fd=base, follow_symlinks=False)
                require(
                    stat.S_ISDIR(named.st_mode)
                    and identity(named) == identity(os.fstat(opened)) == original,
                    "physical_scope",
                )
            deadline.check()

        parents_current()
        result = bytearray()
        while True:
            deadline.check()
            data = os.read(fd, min(65536, cap + 1 - len(result)))
            if not data:
                break
            result.extend(data)
            require(len(result) <= cap, "file_capacity_or_identity")
        after = os.fstat(fd)
        current = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)

        def signature(s):
            return (identity(s), s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)

        require(
            signature(before) == signature(after) == signature(current)
            and len(result) == before.st_size,
            "file_changed",
        )
        parents_current()
        deadline.check()
        return bytes(result), signature(before)
    finally:
        close_error = None
        for opened in reversed(descriptors):
            try:
                os.close(opened)
            except OSError as error:
                close_error = close_error or error
        deadline.check(cleanup=True)
        if close_error is not None:
            raise close_error


def check_pin(pin, directory=False, deadline=None):
    keys = {"path", "dev", "ino", "uid", "gid", "mode"}
    require(type(pin) is dict and set(pin) == keys, "registry_schema")
    require(all(type(pin[k]) is int and pin[k] >= 0 for k in keys - {"path"}), "registry_schema")
    no_symlinks(pin["path"], deadline)
    st = os.stat(pin["path"], follow_symlinks=False)
    require(stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode), "physical_scope")
    require(
        identity(st) == tuple(pin[k] for k in ("dev", "ino", "uid", "gid", "mode")),
        "physical_scope",
    )
    require(not st.st_mode & 0o022, "physical_scope")
    if deadline:
        deadline.check()
    return pin["path"]


def file_pin(pin, deadline):
    require(
        type(pin) is dict
        and set(pin) == {"path", "dev", "ino", "uid", "gid", "mode", "sha256"}
        and SHA.fullmatch(pin["sha256"]),
        "registry_schema",
    )
    check_pin({k: v for k, v in pin.items() if k != "sha256"}, deadline=deadline)
    raw, sig = read_file(
        pin["path"],
        CONFIG_BYTES,
        deadline,
        pin["uid"],
        expected_identity=tuple(pin[k] for k in ("dev", "ino", "uid", "gid", "mode")),
    )
    require(digest(raw) == pin["sha256"], "configuration_changed")
    deadline.check()
    return raw, sig


def root_controlled(path, deadline=None):
    no_symlinks(path, deadline)
    for item in [Path(path), *Path(path).parents]:
        if deadline:
            deadline.check()
        st = item.stat()
        require(st.st_uid == 0 and not st.st_mode & 0o022, "root_control")
    if deadline:
        deadline.check()


def binary_pin(pin, deadline):
    require(type(pin) is dict and set(pin) == {"path", "sha256", "version"}, "registry_schema")
    require(
        type(pin["sha256"]) is str
        and SHA.fullmatch(pin["sha256"])
        and type(pin["version"]) is str
        and LABEL.fullmatch(pin["version"]),
        "registry_schema",
    )
    # Every binary ancestor must remain root-controlled; pin the complete ELF.
    root_controlled(pin["path"], deadline)
    mode = os.stat(pin["path"], follow_symlinks=False).st_mode
    require(not mode & 0o6000 and mode & 0o111, "binary_identity")
    raw, sig = read_file(pin["path"], 64 * 1024 * 1024, deadline, 0)
    require(raw.startswith(b"\x7fELF") and digest(raw) == pin["sha256"], "binary_identity")
    deadline.check()
    return sig


def load_registry(scope, deadline):
    raw, signature = read_file(REGISTRY, 65536, deadline, 0)
    root_controlled(REGISTRY, deadline)
    registry = strict_json(raw, deadline)
    require(
        type(registry) is dict
        and set(registry) == {"format", "script_sha256", "python", "git", "scopes"},
        "registry_schema",
    )
    require(
        registry["format"] == "git-inspect225-root-v1"
        and type(registry["scopes"]) is dict
        and 1 <= len(registry["scopes"]) <= 64,
        "registry_schema",
    )
    require(all(type(k) is str and SHA.fullmatch(k) for k in registry["scopes"]), "registry_schema")
    require(scope in registry["scopes"], "scope_unenrolled")
    entry = registry["scopes"][scope]
    require(
        type(entry) is dict
        and set(entry)
        == {
            "reference",
            "cwd",
            "git_dir",
            "common_dir",
            "object_dir",
            "home",
            "index_uid",
            "configs",
            "qualification",
        },
        "registry_schema",
    )
    reference = entry["reference"]
    require(
        type(reference) is dict
        and set(reference) == REF_KEYS
        and all(type(v) is str and 1 <= len(v.encode()) <= 4096 for v in reference.values()),
        "registry_schema",
    )
    require(digest(canonical_json(reference)) == scope, "scope_unenrolled")
    require(
        type(entry["index_uid"]) is int and entry["index_uid"] == os.geteuid() != 0, "scope_user"
    )
    for key in ("cwd", "git_dir", "common_dir", "object_dir", "home"):
        check_pin(entry[key], directory=True, deadline=deadline)
    require(reference["canonical_directory"] == entry["cwd"]["path"] == os.getcwd(), "cwd_changed")
    require(
        entry["object_dir"]["path"] == entry["common_dir"]["path"] + "/objects", "physical_scope"
    )
    require(
        type(entry["configs"]) is dict
        and set(entry["configs"]) == {"system", "xdg", "global", "local"},
        "registry_schema",
    )
    require(
        type(entry["configs"]["local"]) is dict
        and entry["configs"]["local"].get("path") == entry["common_dir"]["path"] + "/config",
        "physical_scope",
    )
    qualification = entry["qualification"]
    require(
        type(qualification) is dict
        and set(qualification)
        == {
            "physical_scope_sha256",
            "native_policy_sha256",
            "plugin_policy_sha256",
            "installed_qualification_sha256",
        }
        and all(type(v) is str and SHA.fullmatch(v) for v in qualification.values()),
        "registry_schema",
    )
    require(
        type(registry["script_sha256"]) is str and SHA.fullmatch(registry["script_sha256"]),
        "registry_schema",
    )
    require(
        str(Path(__file__).absolute()) == SCRIPT and sys.flags.isolated and sys.dont_write_bytecode,
        "script_identity",
    )
    root_controlled(SCRIPT, deadline)
    script, _ = read_file(SCRIPT, 256 * 1024, deadline, 0)
    require(digest(script) == registry["script_sha256"], "script_identity")
    # Native launch command remains /usr/bin/python3; root pin is the actual ELF.
    require(
        str(Path(sys.executable).resolve()) == registry["python"]["path"]
        and ".".join(map(str, sys.version_info[:3])) == registry["python"]["version"],
        "python_identity",
    )
    binary_pin(registry["python"], deadline)
    binary_pin(registry["git"], deadline)
    return registry, entry, (raw, signature)


def canonical_path(raw):
    try:
        value = raw.decode("utf-8", "strict")
    except UnicodeError:
        raise Unavailable("path_unsupported") from None
    require(
        1 <= len(raw) <= 4096
        and not value.startswith("/")
        and "\\" not in value
        and all(ord(c) >= 32 and ord(c) != 127 for c in value),
        "path_unsupported",
    )
    require(
        all(p and p not in {".", ".."} and len(p.encode()) <= 255 for p in value.split("/")),
        "path_unsupported",
    )
    return value


def disclosed(raw):
    value = canonical_path(raw)
    parts = value.casefold().split("/")
    require(not any(c in value for c in "<>@&[]`"), "path_undisclosable")
    require(
        not any(
            p in DENIED
            or p == ".env"
            or p.startswith((".env.", ".jt-oz-incoming-", ".jt-oz-preview-"))
            for p in parts
        ),
        "path_undisclosable",
    )
    require(
        not parts[-1].endswith((".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx", ".tfstate")),
        "path_undisclosable",
    )
    return value


def object_hash(kind, raw, algorithm):
    return hashlib.new(
        algorithm, kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw
    ).hexdigest()


def tree_oids(entries, algorithm, directories=None, deadline=None):
    """Build every tree from canonical bytes, including explicit empty HEAD dirs."""
    nodes = {b"": {}}

    def add_node(path):
        if deadline:
            deadline.check()
        if path not in nodes:
            require(len(nodes) < TREE_NODES, "tree_capacity")
            nodes[path] = {}

    for path in sorted(directories or {}):
        canonical_path(path)
        parts = path.split(b"/")
        for i in range(1, len(parts) + 1):
            prefix = b"/".join(parts[:i])
            add_node(prefix)
    for path, (mode, oid) in entries.items():
        if deadline:
            deadline.check()
        canonical_path(path)
        parts = path.split(b"/")
        for i in range(1, len(parts)):
            add_node(b"/".join(parts[:i]))
        parent = b"/".join(parts[:-1])
        require(parts[-1] not in nodes[parent], "tree_collision")
        nodes[parent][parts[-1]] = (mode, oid)
    children = {path: [] for path in nodes}
    for child in nodes:
        if child:
            children[child.rpartition(b"/")[0]].append(child)
    hashes = {}
    for path in sorted(nodes, key=lambda p: (-p.count(b"/"), -len(p))):
        if deadline:
            deadline.check()
        items = dict(nodes[path])
        for child in children[path]:
            name = child.rpartition(b"/")[2]
            require(name not in items, "tree_collision")
            items[name] = ("40000", hashes[child])
        body = bytearray()
        for name in sorted(items, key=lambda n: n + (b"/" if items[n][0] == "40000" else b"\0")):
            if deadline:
                deadline.check()
            mode, oid = items[name]
            body.extend(mode.encode() + b" " + name + b"\0" + bytes.fromhex(oid))
        hashes[path] = object_hash("tree", bytes(body), algorithm)
    if directories is not None:
        require(all(hashes[p] == oid for p, oid in directories.items()), "head_tree_invalid")
    if deadline:
        deadline.check()
    return hashes[b""], hashes


def cache_tree(raw, oid_size, deadline):
    """Validate TREE's bounded recursive framing; ignore all cached authority."""
    offset, count = 0, 0

    def node(depth, root=False):
        nonlocal offset, count
        deadline.check()
        count += 1
        require(depth <= 128 and count <= INDEX_ENTRIES + 1, "index_extension")
        end = raw.find(b"\0", offset)
        require(end >= offset and end - offset <= 255, "index_extension")
        name = raw[offset:end]
        require(
            (root and not name)
            or (not root and name and b"/" not in name and name not in {b".", b".."}),
            "index_extension",
        )
        offset = end + 1
        end = raw.find(b"\n", offset)
        require(end >= offset and end - offset < 32, "index_extension")
        match = re.fullmatch(rb"(-1|0|[1-9][0-9]*) (0|[1-9][0-9]*)", raw[offset:end])
        require(match is not None, "index_extension")
        nentries, children = map(int, match.groups())
        require(-1 <= nentries <= INDEX_ENTRIES and children <= INDEX_ENTRIES, "index_extension")
        offset = end + 1
        if nentries >= 0:
            require(offset + oid_size <= len(raw), "index_extension")
            offset += oid_size
        names = set()
        for _ in range(children):
            child = node(depth + 1)
            require(child not in names, "index_extension")
            names.add(child)
        return name

    node(0, True)
    require(offset == len(raw), "index_extension")


def parse_index(raw, algorithm, deadline):
    deadline.check()
    require(algorithm in {"sha1", "sha256"}, "object_format")
    oid_size = hashlib.new(algorithm).digest_size
    require(12 + oid_size <= len(raw) <= INDEX_BYTES, "index_capacity")
    require(raw[:4] == b"DIRC", "index_format")
    version, count = struct.unpack_from("!II", raw, 4)
    require(version in {2, 3} and count <= INDEX_ENTRIES, "index_format")
    end = len(raw) - oid_size
    require(hashlib.new(algorithm, raw[:end]).digest() == raw[end:], "index_checksum")
    offset, entries, previous = 12, {}, None
    for _ in range(count):
        deadline.check()
        start = offset
        require(offset + 42 + oid_size <= end, "index_entry")
        mode = format(struct.unpack_from("!10I", raw, offset)[6], "o")
        require(mode in MODES, "index_mode")
        offset += 40
        oid = raw[offset : offset + oid_size].hex()
        require(int(oid, 16) != 0, "index_null_oid")
        offset += oid_size
        flags = struct.unpack_from("!H", raw, offset)[0]
        offset += 2
        require(not flags & 0xB000, "index_flags")  # stage != 0 / assume-valid
        if flags & 0x4000:
            require(version == 3 and offset + 2 <= end, "index_flags")
            extended = struct.unpack_from("!H", raw, offset)[0]
            require(extended == 0, "index_flags")  # no ITA / skip-worktree / reserved
            offset += 2
        nul = raw.find(b"\0", offset, min(end, offset + 4097))
        require(nul >= offset, "index_path")
        path = raw[offset:nul]
        canonical_path(path)
        require(flags & 0xFFF == min(len(path), 0xFFF), "index_name_length")
        require(previous is None or previous < path, "index_order")
        require(path not in entries, "index_duplicate")
        previous = path
        entries[path] = (mode, oid)
        offset = start + ((nul + 1 - start + 7) // 8) * 8
        require(offset <= end and not any(raw[nul:offset]), "index_padding")
    extensions = set()
    while offset < end:
        deadline.check()
        require(offset + 8 <= end, "index_extension")
        name, size = raw[offset : offset + 4], struct.unpack_from("!I", raw, offset + 4)[0]
        offset += 8
        require(name not in extensions and offset + size <= end, "index_extension")
        extensions.add(name)
        # Other optional extensions are also unsupported, rather than silently
        # trusting a sparse/split/shared index or an unfamiliar optimization.
        require(name == b"TREE", "index_extension")
        cache_tree(raw[offset : offset + size], oid_size, deadline)
        offset += size
    tree, _ = tree_oids(entries, algorithm, deadline=deadline)
    semantic = digest(canonical_json([[m, canonical_path(p), o] for p, (m, o) in entries.items()]))
    deadline.check()
    return entries, tree, semantic


def parse_ls_files(raw, algorithm, deadline):
    deadline.check()
    size = 40 if algorithm == "sha1" else 64
    require(not raw or raw.endswith(b"\0"), "index_crosscheck")
    result = {}
    for row in raw.split(b"\0")[:-1]:
        deadline.check()
        require(len(result) < INDEX_ENTRIES, "index_capacity")
        header, sep, path = row.partition(b"\t")
        match = re.fullmatch(
            rb"(100644|100755|120000|160000) ([0-9a-f]{" + str(size).encode() + rb"}) 0", header
        )
        require(sep and match is not None and path not in result, "index_crosscheck")
        canonical_path(path)
        result[path] = (match[1].decode(), match[2].decode())
    deadline.check()
    return result


def parse_head(raw, algorithm, expected_tree, deadline):
    deadline.check()
    require(len(raw) <= HEAD_BYTES and (not raw or raw.endswith(b"\0")), "head_capacity")
    size = 40 if algorithm == "sha1" else 64
    entries, directories, seen = {}, {}, set()
    for row in raw.split(b"\0")[:-1]:
        deadline.check()
        require(len(seen) < HEAD_ENTRIES, "head_capacity")
        header, sep, path = row.partition(b"\t")
        match = re.fullmatch(
            rb"(100644|100755|120000|160000|040000) (blob|tree|commit) ([0-9a-f]{"
            + str(size).encode()
            + rb"})",
            header,
        )
        require(sep and match is not None and path not in seen, "head_tree_invalid")
        canonical_path(path)
        seen.add(path)
        mode, kind, oid = (s.decode() for s in match.groups())
        require(
            kind == {"040000": "tree", "160000": "commit"}.get(mode, "blob"), "head_tree_invalid"
        )
        require(int(oid, 16) != 0, "head_tree_invalid")
        if mode == "040000":
            directories[path] = oid
        else:
            entries[path] = (mode, oid)
    for path in seen:
        deadline.check()
        parent = path.rpartition(b"/")[0]
        require(not parent or parent in directories, "head_tree_incomplete")
    root, _ = tree_oids(entries, algorithm, directories, deadline)
    require(root == expected_tree, "head_tree_invalid")
    deadline.check()
    return entries


def staged_paths(index, head, deadline):
    result, total = [], 0
    for path in sorted(index.keys() | head.keys()):
        deadline.check()
        before, after = head.get(path), index.get(path)
        if before == after:
            continue
        require(len(result) < INDEX_ENTRIES, "staged_capacity")
        name = disclosed(path)
        total += len(path)
        require(total <= 32768, "staged_capacity")
        if before is None:
            change, mode = "added", after[0]
        elif after is None:
            change, mode = "deleted", before[0]
        elif (before[0] == "160000") != (after[0] == "160000") or (before[0] == "120000") != (
            after[0] == "120000"
        ):
            change, mode = "type_changed", after[0]
        else:
            change, mode = "modified", after[0]
        result.append({"safe_relative_path": name, "change": change, "mode": mode})
    deadline.check()
    return result


def parse_config(raw, deadline=None):
    if deadline:
        deadline.check()
    require(len(raw) <= CONFIG_BYTES and (not raw or raw.endswith(b"\0")), "configuration_capacity")
    result = []
    for row in raw.split(b"\0")[:-1]:
        if deadline:
            deadline.check()
        key, sep, value = row.partition(b"\n")
        # Bare booleans have no LF; preserving None distinguishes them from ''.
        require(
            key and len(key) <= 4096 and not any(c < 32 or c == 127 for c in key),
            "configuration_unsupported",
        )
        try:
            k = key.decode("utf-8", "strict")
            v = value.decode("utf-8", "strict") if sep else None
        except UnicodeError:
            raise Unavailable("configuration_unsupported") from None
        lower = k.lower()
        require(not lower.startswith(("include.", "includeif.")), "configuration_include")
        require(
            not (lower.startswith("extensions.") and lower != "extensions.objectformat"),
            "configuration_extension",
        )
        require(
            not (
                lower.startswith("remote.") and lower.endswith((".promisor", ".partialclonefilter"))
            ),
            "partial_clone",
        )
        require(
            not lower.startswith(("core.alternaterefs", "objects.")), "object_store_unsupported"
        )
        result.append([k, v])
    # Equal-length conflicting insteadOf rules are not an unambiguous target.
    rewrites = {}
    for k, v in result:
        if deadline:
            deadline.check()
        lower = k.lower()
        for suffix in (".insteadof", ".pushinsteadof"):
            if lower.startswith("url.") and lower.endswith(suffix):
                require(type(v) is str and v, "remote_ambiguous")
                identity_key = (suffix, v)
                base = k[4 : -len(suffix)]
                require(
                    identity_key not in rewrites or rewrites[identity_key] == base,
                    "remote_ambiguous",
                )
                rewrites[identity_key] = base
    if deadline:
        deadline.check()
    return result


def child_environment(entry):
    require(not any(key.startswith("GIT_") for key in os.environ), "inherited_git_environment")
    require(
        os.environ.get("HOME") == entry["home"]["path"]
        and os.environ.get("XDG_CONFIG_HOME") in {None, entry["home"]["path"] + "/.config"},
        "native_home_context",
    )
    env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": entry["home"]["path"],
        "XDG_CONFIG_HOME": entry["home"]["path"] + "/.config",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_LAZY_FETCH": "1",
        # This overrides every protocol.*.allow setting, including an external
        # helper protocol introduced by a concurrent configuration update.
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
    }
    configs = entry["configs"]
    if configs["system"]:
        env["GIT_CONFIG_SYSTEM"] = configs["system"]["path"]
    else:
        env["GIT_CONFIG_NOSYSTEM"] = "1"
    return env


def object_store_guard(entry, deadline):
    common, objects = entry["common_dir"]["path"], entry["object_dir"]["path"]
    for path in (
        objects + "/info/alternates",
        objects + "/info/http-alternates",
        common + "/shallow",
        common + "/info/grafts",
    ):
        require(not os.path.lexists(path), "object_store_unsupported")
    # No unbounded recursion; any replacement namespace is unsupported.
    require(not os.path.lexists(common + "/refs/replace"), "replacement_objects")
    signatures = []
    for path in (objects, objects + "/info", objects + "/pack"):
        deadline.check()
        if not os.path.lexists(path):
            signatures.append((path, None))
            continue
        no_symlinks(path, deadline)
        st = os.stat(path, follow_symlinks=False)
        require(
            stat.S_ISDIR(st.st_mode) and st.st_uid == entry["index_uid"] and not st.st_mode & 0o022,
            "object_store_unsupported",
        )
        names = []
        with os.scandir(path) as iterator:
            for item in iterator:
                deadline.check()
                require(
                    len(names) < 4096
                    and not item.is_symlink()
                    and not item.name.endswith(".promisor"),
                    "object_store_unsupported",
                )
                names.append(item.name)
        signatures.append((path, identity(st), sorted(names)))
    packed = common + "/packed-refs"
    if os.path.lexists(packed):
        raw, signature = read_file(packed, INDEX_BYTES, deadline, entry["index_uid"])
        require(
            not any(b" refs/replace/" in line for line in raw.splitlines()), "replacement_objects"
        )
        signatures.append((packed, signature, digest(raw)))
    else:
        signatures.append((packed, None))
    deadline.check()
    return signatures


class Inspector:
    def __init__(self, registry, entry, deadline):
        self.registry, self.entry, self.deadline = registry, entry, deadline
        self.children = Children(deadline, entry["cwd"]["path"], child_environment(entry))
        # These overrides disable execution-oriented optimizations. No hooks,
        # diff, filters, credential helpers, fetch, status refresh, or write-tree.
        self.prefix = [
            registry["git"]["path"],
            # Capability must be proved with the actual installed binary; an
            # older Git that ignores the environment variable must fail here.
            "--no-lazy-fetch",
            "--no-replace-objects",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
        ]

    def git(self, *args, cap=CONFIG_BYTES):
        return self.children.run([*self.prefix, *args], cap)

    def line(self, *args):
        raw = self.git(*args, cap=8192)
        require(
            raw.endswith(b"\n") and raw.count(b"\n") == 1 and b"\x00" not in raw, "git_unavailable"
        )
        return raw[:-1].decode("utf-8", "strict")

    def locations(self):
        expected = self.entry
        require(
            self.line("rev-parse", "--path-format=absolute", "--show-toplevel")
            == expected["cwd"]["path"],
            "physical_scope",
        )
        require(
            self.line("rev-parse", "--absolute-git-dir") == expected["git_dir"]["path"],
            "physical_scope",
        )
        require(
            self.line("rev-parse", "--path-format=absolute", "--git-common-dir")
            == expected["common_dir"]["path"],
            "physical_scope",
        )
        require(self.line("rev-parse", "--is-bare-repository") == "false", "physical_scope")

    def head(self, algorithm):
        branch = self.line("symbolic-ref", "--quiet", "HEAD")
        require(
            branch.startswith("refs/heads/") and LABEL.fullmatch(branch[11:]), "branch_unsupported"
        )
        # Qualified branch labels may not include option/revision syntax.
        require(
            all(p and p not in {".", ".."} for p in branch[11:].split("/")) and ".." not in branch,
            "branch_unsupported",
        )
        pattern = r"[0-9a-f]{" + ("40" if algorithm == "sha1" else "64") + r"}"
        commit = self.line("rev-parse", "--verify", "HEAD^{commit}")
        require(re.fullmatch(pattern, commit) and int(commit, 16) != 0, "head_unavailable")
        # Resolve the tree of that exact commit, not a second mutable HEAD.
        tree = self.line("rev-parse", "--verify", commit + "^{tree}")
        require(re.fullmatch(pattern, tree) and int(tree, 16) != 0, "head_unavailable")
        require(
            self.line("rev-parse", "--verify", "HEAD^{commit}") == commit
            and self.line("symbolic-ref", "--quiet", "HEAD") == branch,
            "head_changed",
        )
        return branch[11:], commit, tree

    def config(self):
        pins = []
        expected = {
            "system": "/etc/gitconfig",
            "xdg": self.entry["home"]["path"] + "/.config/git/config",
            "global": self.entry["home"]["path"] + "/.gitconfig",
            "local": self.entry["common_dir"]["path"] + "/config",
        }
        for role in ("system", "xdg", "global", "local"):
            pin = self.entry["configs"][role]
            if pin is None:
                require(
                    role != "local" and not os.path.lexists(expected[role]),
                    "configuration_unenrolled",
                )
                pins.append((role, None))
            else:
                require(
                    type(pin) is dict and pin.get("path") == expected[role],
                    "configuration_unenrolled",
                )
            if pin is not None:
                raw, signature = file_pin(pin, self.deadline)
                # Inspect each file without following includes before any index
                # plumbing. Effective configuration is separately hashed below.
                parse_config(
                    self.git("config", "--file", pin["path"], "--no-includes", "--null", "--list"),
                    self.deadline,
                )
                pins.append((role, signature, digest(raw)))
        effective = parse_config(
            self.git("config", "--no-includes", "--null", "--list"), self.deadline
        )
        aliases = set()
        for key, _ in effective:
            if key.lower().startswith("remote."):
                alias, sep, _ = key[7:].rpartition(".")
                require(sep and LABEL.fullmatch(alias), "remote_alias_unsupported")
                aliases.add(alias)
        require(len(aliases) <= 8, "remote_capacity")
        remotes = []
        for alias in sorted(aliases):
            urls = self.git("remote", "get-url", "--push", "--all", alias, cap=CONFIG_BYTES)
            require(
                urls.endswith(b"\n")
                and urls.count(b"\n") == 1
                and 1 < len(urls) <= 8192
                and b"\x00" not in urls
                and b"\r" not in urls,
                "remote_ambiguous",
            )
            url = urls[:-1].decode("utf-8", "strict")
            require(not any(ord(c) < 32 or ord(c) == 127 for c in url), "remote_ambiguous")
            remotes.append(
                {
                    "safe_alias": alias,
                    "push_config_sha256": digest(
                        canonical_json(
                            {"effective_config": effective, "alias": alias, "push_urls": [url]}
                        )
                    ),
                }
            )
        return pins, digest(canonical_json(effective)), remotes

    def capture(self, scope, *, capture_started_at=None):
        started = capture_time(capture_started_at)
        self.deadline.check()
        # Ordinary Git can follow repository includes during initialization,
        # before `config --no-includes` processes its command-line options.
        # Do not start even a version probe for an unqualified build. The label
        # is only admission: exact ELF/source and pre-read-denial qualification
        # are still required independently of this check.
        require(
            self.registry["git"]["version"] == METADATA_GIT_VERSION,
            "git_config_policy_unqualified",
        )
        require(
            self.line("--version") == "git version " + self.registry["git"]["version"],
            "git_identity",
        )
        # Validate effective configuration and object stores before Git reads.
        config_before = self.config()
        objects_before = object_store_guard(self.entry, self.deadline)
        self.locations()
        algorithm = self.line("rev-parse", "--show-object-format")
        require(algorithm in {"sha1", "sha256"}, "object_format")
        head_before = self.head(algorithm)
        index_path = self.entry["git_dir"]["path"] + "/index"
        index_raw, index_signature = read_file(
            index_path, INDEX_BYTES, self.deadline, self.entry["index_uid"]
        )
        entries, index_tree, semantic = parse_index(index_raw, algorithm, self.deadline)
        require(
            parse_ls_files(
                self.git("ls-files", "--stage", "-z", cap=INDEX_BYTES), algorithm, self.deadline
            )
            == entries,
            "index_crosscheck",
        )
        head_entries = parse_head(
            self.git("ls-tree", "-r", "-t", "-z", "--full-tree", head_before[2], cap=HEAD_BYTES),
            algorithm,
            head_before[2],
            self.deadline,
        )
        staged = staged_paths(entries, head_entries, self.deadline)
        require(self.head(algorithm) == head_before, "head_changed")
        self.locations()
        require(self.config() == config_before, "configuration_changed")
        require(
            object_store_guard(self.entry, self.deadline) == objects_before, "object_store_changed"
        )
        reread, signature = read_file(
            index_path, INDEX_BYTES, self.deadline, self.entry["index_uid"]
        )
        require(reread == index_raw and signature == index_signature, "index_changed")
        for key in ("cwd", "git_dir", "common_dir", "object_dir", "home"):
            check_pin(self.entry[key], directory=True, deadline=self.deadline)
        # Complete binary bytes are rechecked, not mtime-only identities.
        binary_pin(self.registry["python"], self.deadline)
        binary_pin(self.registry["git"], self.deadline)
        finished = capture_time()
        require(0 <= finished - started <= SECONDS, "deadline")
        result = {
            "format": "native-git-index-evidence-v1",
            "scope_sha256": scope,
            "capture_started_at": started,
            "capture_finished_at": finished,
            "git_binary_sha256": self.registry["git"]["sha256"],
            "script_sha256": self.registry["script_sha256"],
            "object_format": algorithm,
            "branch_safe_label": head_before[0],
            "head_oid": head_before[1],
            "head_tree_oid": head_before[2],
            "index_sha256": digest(index_raw),
            "index_semantic_sha256": semantic,
            "index_tree_oid": index_tree,
            "index_entries": len(entries),
            "staged_paths": staged,
            "remote_aliases": config_before[2],
            "complete_index": True,
            "remote_live_verified": False,
            "working_tree_content_verified": False,
        }
        require(len(canonical_json(result)) + 1 <= FINAL_BYTES, "output_capacity")
        self.deadline.check()
        return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        require(len(argv) == 2 and argv[0] == "--scope" and SHA.fullmatch(argv[1]), "arguments")
        started = capture_time()
        deadline = Deadline()
        registry, entry, original_registry = load_registry(argv[1], deadline)
        result = Inspector(registry, entry, deadline).capture(argv[1], capture_started_at=started)
        require(read_file(REGISTRY, 65536, deadline, 0) == original_registry, "registry_changed")
        root_controlled(SCRIPT, deadline)
        script, _ = read_file(SCRIPT, 256 * 1024, deadline, 0)
        require(digest(script) == registry["script_sha256"], "script_identity")
        result["capture_finished_at"] = capture_time()
        require(0 <= result["capture_finished_at"] - started <= SECONDS, "deadline")
        output = canonical_json(result) + b"\n"
        require(len(output) <= FINAL_BYTES, "output_capacity")
        deadline.check()
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()
        # A blocked kernel write cannot be forcibly bounded by Python alone.
        # If it returns after expiry, do not exit 0 with successful evidence.
        deadline.check()
        return 0
    except Unavailable as error:
        # Error messages originate solely from literal internal codes above.
        sys.stdout.write(
            '{"format":"git-inspect225-unavailable-v1","code":' + json.dumps(str(error)) + "}\n"
        )
        return 2
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        OverflowError,
        RecursionError,
        subprocess.SubprocessError,
        AttributeError,
        KeyboardInterrupt,
    ):
        sys.stdout.write('{"format":"git-inspect225-unavailable-v1","code":"unavailable"}\n')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
