"""Enable incoming uploads (and later automatic returns) for one existing Root.

Companion of onboard_root.py. It issues the per-Root workspace and Human-source
evidence the runtime validators require, by running the installed release's own
classes against controlled files. Other Roots' manifest entries stay identical.

Run with the selected release's interpreter, as root:

    python -I -B enable_file_transfer.py preflight --spec spec.json
    python -I -B enable_file_transfer.py prepare   --spec spec.json --message-id N
    python -I -B enable_file_transfer.py activate  --spec spec.json

N is the Human upload message found by `scan-source`. Until it exists, prepare stops
with exit 3 after its Human-free stages and can simply be run again.

Single steps: namespace, probe-workspace, scan-source, probe-source, seal,
rollback, namespace-remove, status. preflight writes nothing; `--spec-inline` lets
it run with no file on the host. prepare only touches its control/shared/target
directories, the empty namespace and controlled files in it. activate stops Main
and the observer briefly, and rolls back automatically on a failed smoke check.

Native access is GET-only and the Native database is never opened. Native is
never restarted. A real Human upload is required for probe-source: this tool
never posts to Zulip and never fabricates a Human source.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid
from collections.abc import AsyncIterator, Iterable
from pathlib import Path
from typing import Any

NATIVE_UID = 1000
NATIVE_GID = 1000
BRIDGE_UID = 1001
NAMESPACE_MODE = 0o2750
PROBE_SECONDS = 300
MINIMUM_FREE_BYTES = 12 * 1024**3
MAXIMUM_USED_FRACTION = 0.80
PROBE_BYTES = 10 * 20 * 1024**2
BRIDGE_DB = "/var/lib/jt-oz-bridge/service/bridge.db"
ASSOCIATION_CONFIG = "/etc/jt-oz-bridge/zulip-upload-association-candidate.json"
DROPIN_DIR = "/etc/systemd/system/jt-oz-bridge.service.d"
DROPIN_NAME = "95-file-transfer.conf"
RELEASE_DROPIN = "90-qualified-release.conf"
PROMOTION_GUARD = "/etc/jt-oz-bridge/promotion-active"
MAIN = "jt-oz-bridge.service"
OBSERVER = "jt-oz-observer.service"
REVIEW = "installed-evidence-reviewed-for-development-runtime"
SETTLE_SECONDS = 30
NAMESPACE_NAME = re.compile(r"\.jt-oz-incoming-[A-Za-z0-9][A-Za-z0-9_-]{0,110}")
UPLOAD_PATH = re.compile(r"\]\((/user_uploads/[^)\s]+)\)")

# A blocker stops the named stage. `prepare` stops at the first stage that has one.
SOURCE_BLOCKERS = frozenset({"human_upload_missing"})


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def dumps(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def need(condition: object, code: str) -> None:
    if not condition:
        raise RuntimeError(code)


def write_new(path: Path, raw: bytes, *, group: int = 0, mode: int = 0o640) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        os.fchown(stream.fileno(), 0, group)
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def replace_exact(path: Path, raw: bytes, *, group: int, mode: int = 0o640) -> None:
    """Atomic install keeping the ownership the service expects."""
    temporary = path.with_name(path.name + f".{uuid.uuid4().hex}.tmp")
    write_new(temporary, raw, group=group, mode=mode)
    os.replace(temporary, path)


# ---------------------------------------------------------------------------
# Pure logic (unit tested; imports no product module).
# ---------------------------------------------------------------------------


def namespace_for(directory: str, name: str) -> str:
    """The product pins the namespace as a direct child of the canonical project."""
    need(NAMESPACE_NAME.fullmatch(name), "namespace_name")
    need(directory.startswith("/") and ".." not in directory.split("/"), "namespace_parent")
    return directory.rstrip("/") + "/" + name


def main_dropin(namespace: str) -> str:
    """ProtectSystem=strict keeps /opt read-only; this makes only the namespace writable.

    Deliberately not `-` prefixed: a removed namespace must fail closed. A project
    under /home would also need ProtectHome=tmpfs plus BindPaths, which is refused
    because the parent is hidden by Main's ProtectHome=true.
    """
    need(not namespace.startswith(("/home/", "/root/", "/run/user/")), "namespace_home_hidden")
    need(re.fullmatch(r"[A-Za-z0-9/._-]+", namespace), "namespace_unit_quoting")
    return f"[Service]\nReadWritePaths={namespace}\n"


def merge_file_manifest(
    manifest: dict[str, Any],
    *,
    session_id: str,
    workspace: dict[str, str],
    source_uploads: dict[str, str],
    source_evidence: dict[str, str],
    generated: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Scope incoming/generated to one Root; every other Root stays byte-identical."""
    merged = json.loads(json.dumps(manifest))
    target = [b for b in merged["backends"] if b["reference"]["upstream_session_id"] == session_id]
    need(len(target) == 1, "manifest_root_required")
    entry = target[0]
    need(not entry.get("workspace") and not entry.get("generated_outputs"), "manifest_root_set")
    need(
        not merged["realm"].get("source_uploads") and not merged["realm"].get("source_evidence"),
        "manifest_source_already_present",
    )
    need(not merged.get("workspace_roots") and not merged.get("generated_roots"), "scope_present")
    entry["workspace"] = workspace
    merged["realm"]["source_uploads"] = source_uploads
    merged["realm"]["source_evidence"] = source_evidence
    merged["workspace_roots"] = [entry["reference"]]
    merged["generated_roots"] = []
    if generated is not None:
        entry["generated_outputs"] = generated
        merged["generated_roots"] = [entry["reference"]]
    merged["format"] = "qualified-consumer-runtime-v7"
    assert_other_roots_unchanged(manifest, merged, session_id)
    return merged


def assert_other_roots_unchanged(
    before: dict[str, Any], after: dict[str, Any], session_id: str
) -> None:
    def others(document: dict[str, Any]) -> list[Any]:
        return [
            b for b in document["backends"] if b["reference"]["upstream_session_id"] != session_id
        ]

    need(others(before) == others(after), "other_root_entry_changed")
    need(before["grants"] == after["grants"], "grants_changed")
    for key in ("directory_scope", "directory_socket", "operator_review"):
        need(before.get(key) == after.get(key), f"manifest_{key}_changed")


def merge_file_config(text: str, *, enrollment_file: str, inputs: bool, generated: bool) -> str:
    """Change exactly the enrollment pin and the two flags; refuse a flag already on."""
    merged = text
    for pattern, replacement in (
        (r'^"enrollment_file" = ".*"$', f'"enrollment_file" = "{enrollment_file}"'),
        (
            r'^"workspace_inputs_enabled" = false$',
            f'"workspace_inputs_enabled" = {str(inputs).lower()}',
        ),
        (
            r'^"generated_returns_enabled" = false$',
            f'"generated_returns_enabled" = {str(generated).lower()}',
        ),
    ):
        compiled = re.compile(pattern, re.MULTILINE)
        need(len(compiled.findall(merged)) == 1, f"config_line_required:{pattern}")
        merged = compiled.sub(replacement, merged)
    return merged


def workspace_certificate(
    *,
    reference: dict[str, Any],
    namespace: dict[str, Any],
    contract_sha256: str,
    native_policy_sha256: str,
    executable_sha256: str,
    native_uid: int,
    workspace_component_sha256: str,
    storage_component_sha256: str,
    workspace_semantics_sha256: str,
    observation: dict[str, Any],
    evidence_sha256: str,
    tool_sha256: str,
) -> dict[str, Any]:
    need(observation.get("files") == 10, "probe_files")
    need(observation.get("controlled_files_removed") is True, "probe_cleanup")
    return {
        "format": "qualified-original-workspace-v1",
        "operator_review": REVIEW,
        "reference": reference,
        "namespace": namespace,
        "contract_sha256": contract_sha256,
        "native_policy_sha256": native_policy_sha256,
        "executable_sha256": executable_sha256,
        "native_uid": native_uid,
        "workspace_component_sha256": workspace_component_sha256,
        "storage_component_sha256": storage_component_sha256,
        "workspace_semantics_sha256": workspace_semantics_sha256,
        "observation": {
            "files": observation["files"],
            "bytes_each": observation["bytes_each"],
            "aggregate_original_object_current": observation["aggregate_original_object_current"],
            "namespace_identity_preserved": observation["namespace_identity_preserved"],
            "controlled_files_removed": observation["controlled_files_removed"],
            "namespace_retained": observation["namespace_retained"],
            "native_database_bytes_read": False,
            "native_mutations": 0,
            "zulip_requests": 0,
            "native_get_count": observation["native_get_count"],
            "evidence_sha256": evidence_sha256,
        },
        "onboarding_tool_sha256": tool_sha256,
        "human_acceptance": False,
        "formal_acceptance": False,
    }


def source_certificate(
    *,
    realm_id: str,
    realm_url: str,
    bot_user_id: int,
    config_raw: bytes,
    config: dict[str, Any],
    transport_component_sha256: str,
    positive: dict[str, Any],
    negatives: dict[str, bool],
    tool_sha256: str,
) -> dict[str, Any]:
    need(positive.get("is_bot") is False and positive.get("author_id") != bot_user_id, "human")
    need(all(value is True for value in negatives.values()), "negative_not_denied")
    return {
        "format": "qualified-original-source-uploads-v1",
        "operator_review": REVIEW,
        "realm_id": realm_id,
        "realm_url": realm_url,
        "bot_user_id": bot_user_id,
        "config_sha256": sha(config_raw),
        "transport_component_sha256": transport_component_sha256,
        "helper_sha256": config["helper_sha256"],
        "remote_policy_sha256": config["remote_policy_sha256"],
        "installed_evidence_sha256": config["installed_evidence_sha256"],
        "positive": positive,
        "negatives": negatives,
        "onboarding_tool_sha256": tool_sha256,
        "human_acceptance": False,
        "formal_acceptance": False,
    }


def negative_requests(
    source: dict[str, Any],
    paths: Iterable[str],
    *,
    other_author: int,
    foreign_channel: int,
    unlinked_path: str,
    nonce: str,
) -> dict[str, dict[str, Any]]:
    """Requests the fixed server helper must deny; none of them can upload or post."""

    def request(upload_paths: list[str], **changed: Any) -> dict[str, Any]:
        return {
            "format": "jt-oz-upload-association-v1",
            "nonce": nonce,
            "source": {**source, **changed},
            "upload_paths": upload_paths,
        }

    selected = list(paths)
    need(unlinked_path not in selected, "unlinked_upload_must_differ")
    need(other_author != source["author_id"], "wrong_author_must_differ")
    need(foreign_channel != source["channel_id"], "foreign_channel_must_differ")
    return {
        "bot-source": request(selected, is_bot=True),
        "foreign-source": request(selected, channel_id=foreign_channel),
        "unlinked-upload": request([unlinked_path]),
        "wrong-author": request(selected, author_id=other_author),
    }


def upload_candidates(messages: Iterable[dict[str, Any]], bot_id: int) -> dict[str, list[dict]]:
    """Split raw-Markdown messages into Human and Bot messages holding upload links."""
    humans: list[dict[str, Any]] = []
    bots: list[dict[str, Any]] = []
    for message in messages:
        paths = list(dict.fromkeys(UPLOAD_PATH.findall(message["content"])))
        if paths:
            bucket = bots if message["sender_id"] == bot_id else humans
            bucket.append({"id": message["id"], "sender_id": message["sender_id"], "paths": paths})
    return {"human": humans, "bot": bots}


def generated_gaps(*, git_project: bool, tool_file_uris: dict[str, int]) -> list[str]:
    """Why generated_qualification cannot pass; facts come from the real Root.

    It requires workspace+snapshot, workspace+tool and inline+tool cases, with 20 MiB
    workspace and inline cases, all in the exact Root. Native emits snapshot files
    only for Git projects, and its built-in tools emit only data: URIs.
    """
    gaps = []
    if not git_project:
        gaps.append("generated_snapshot_origin_unavailable_project_not_git")
    if not tool_file_uris.get("file"):
        gaps.append("generated_workspace_tool_origin_not_emitted_by_builtin_tools")
    if not tool_file_uris.get("data"):
        gaps.append("generated_twenty_mib_inline_case_requires_prompt_in_real_session")
    return gaps


def assess(facts: dict[str, Any], expected: dict[str, str]) -> list[str]:
    """Blocker codes for one read-only fact snapshot."""
    blockers: list[str] = []
    for key in ("config_sha256", "runtime_sha256", "observer_sha256"):
        if expected.get(key) != facts.get(key):
            blockers.append(key.removesuffix("_sha256") + "_changed_since_spec")
    if not facts.get("release_selected"):
        blockers.append("spec_release_is_not_the_selected_release")
    if facts.get("main_active") != "active" or facts.get("observer_active") != "active":
        blockers.append("main_or_observer_not_active")
    if facts.get("native_active") != "active" or facts.get("native_nrestarts") != 0:
        blockers.append("native_not_active_or_restarted")
    if facts.get("promotion_guard"):
        blockers.append("promotion_guard_present")
    if facts.get("dropin_present"):
        blockers.append("file_transfer_dropin_already_present")
    if not facts.get("root_enrolled"):
        blockers.append("root_not_enrolled")
    if facts.get("inputs_enabled") or facts.get("generated_enabled"):
        blockers.append("file_flag_already_enabled")
    if not facts.get("release_scopes_workspace_roots"):
        blockers.append("release_lacks_workspace_roots_scope")
    if facts.get("namespace_state") not in {"absent", "pinned-empty"}:
        blockers.append("namespace_state_unexpected")
    if facts.get("project_owner_uid") != NATIVE_UID:
        blockers.append("project_directory_owner_unexpected")
    if facts.get("project_under_hidden_home"):
        blockers.append("project_under_protect_home")
    if facts.get("association_problem"):
        blockers.append("association_" + str(facts["association_problem"]))
    if facts.get("free_bytes", 0) < MINIMUM_FREE_BYTES:
        blockers.append("capacity_free_below_12gib")
    if facts.get("used_fraction_after_probe", 1.0) >= MAXIMUM_USED_FRACTION:
        blockers.append("capacity_probe_would_cross_80_percent")
    if not facts.get("human_upload_candidates"):
        blockers.append("human_upload_missing")
    return blockers


def stage_blockers(blockers: list[str], *, source_stage: bool) -> list[str]:
    """A missing Human upload blocks only probe-source and later."""
    return [b for b in blockers if source_stage or b not in SOURCE_BLOCKERS]


# ---------------------------------------------------------------------------
# Spec and host facts.
# ---------------------------------------------------------------------------


class Spec:
    def __init__(self, raw_bytes: bytes, path: Path | None) -> None:
        raw = json.loads(raw_bytes)
        self.raw_bytes, self.spec_path = raw_bytes, path
        self.tag: str = raw["tag"]
        need(re.fullmatch(r"[a-z0-9-]{1,40}", self.tag), "spec_tag")
        self.release = Path(raw["release"])
        self.session_id: str = raw["session_id"]
        self.namespace_name: str = raw.get("namespace_name", ".jt-oz-incoming-service")
        self.expected: dict[str, str] = raw["expected"]
        self.source_message_id: int | None = raw.get("source_message_id")
        self.generated_packet: str | None = raw.get("generated_packet")
        self.config = Path(raw.get("config", "/etc/jt-oz-bridge/config.toml"))
        self.observer = Path(raw.get("observer", "/etc/jt-oz-bridge/local-observer.json"))
        self.work = Path("/root") / f"jt-oz-file-transfer-{self.tag}"
        self.shared = Path("/opt/jt-oz-bridge") / f"file-transfer-{self.tag}"
        self.state = Path("/var/lib/jt-oz-qualifications") / f"file-transfer-{self.tag}"
        self.target = Path("/etc/jt-oz-bridge") / f"runtime-files-{self.tag}"
        self.dropin = Path(DROPIN_DIR) / DROPIN_NAME


def load_runtime(spec: Spec) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    import tomllib

    config_text = spec.config.read_bytes()
    config = tomllib.loads(config_text.decode())
    manifest = json.loads(Path(config["runtime"]["enrollment_file"]).read_bytes())
    backend = next(
        (
            b
            for b in manifest["backends"]
            if b["reference"]["upstream_session_id"] == spec.session_id
        ),
        None,
    )
    need(backend is not None, "root_not_enrolled")
    assert backend is not None
    return config, manifest, backend


def systemctl_show(unit: str, *properties: str) -> dict[str, str]:
    arguments = [item for name in properties for item in ("-p", name)]
    out = subprocess.run(
        ["systemctl", "show", unit, *arguments],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    ).stdout
    return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)


def host_state() -> dict[str, Any]:
    """Native process identity, recorded without touching its database."""
    props = systemctl_show(
        "opencode.service", "MainPID", "InvocationID", "NRestarts", "ActiveState"
    )
    pid = props["MainPID"]
    ticks = int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19])
    exe = Path(f"/proc/{pid}/exe").resolve()
    return {
        "MainPID": pid,
        "InvocationID": props["InvocationID"],
        "nrestarts": int(props["NRestarts"]),
        "active": props["ActiveState"],
        "start_ticks": ticks,
        "binary_sha256": sha(exe.read_bytes()),
    }


def http_get(url: str, authorization: str) -> Any:
    """The only network primitive used by read-only root steps: GET, nothing else."""
    request = urllib.request.Request(url, headers={"Authorization": authorization}, method="GET")
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)


def secret_file(reference: str) -> str:
    need(reference.startswith("file:"), "file_secret_reference_required")
    return Path(reference[5:]).read_text().strip()


def scan_channel(config: dict[str, Any], bot_id: int, *, pages: int = 6) -> dict[str, list[dict]]:
    """GET-only, bounded: messages of the allowed channels in raw Markdown."""
    realm = config["zulip_realms"][0]
    token = realm["bot_email"] + ":" + secret_file(realm["api_key_ref"])
    authorization = "Basic " + base64.b64encode(token.encode()).decode()
    del token
    messages: list[dict[str, Any]] = []
    for channel in realm["allowed_channel_ids"]:
        anchor: Any = "newest"
        for _ in range(pages):
            query = {
                "anchor": anchor,
                "num_before": 200,
                "num_after": 0,
                "apply_markdown": "false",
                "narrow": json.dumps([{"operator": "channel", "operand": channel}]),
            }
            url = realm["url"] + "/api/v1/messages?" + urllib.parse.urlencode(query)
            value = http_get(url, authorization)
            messages.extend(value["messages"])
            if value.get("found_oldest") or not value["messages"]:
                break
            anchor = value["messages"][0]["id"] - 1
    return upload_candidates(messages, bot_id)


def native_output_inventory(config: dict[str, Any], session_id: str) -> dict[str, Any]:
    """GET-only metadata counts of the real Root; message text is not retained."""
    backend = config["opencode_backends"][0]
    token = "opencode:" + secret_file(backend["credential_ref"])
    authorization = "Basic " + base64.b64encode(token.encode()).decode()
    del token
    counts = {"assistant": 0, "snapshot_key": 0, "snapshot_files": 0}
    tool_file_uris: dict[str, int] = {}
    cursor = None
    for _ in range(8):
        query = {"limit": "50", **({"cursor": cursor} if cursor else {"order": "desc"})}
        url = (
            backend["base_url"]
            + f"/api/session/{session_id}/message?"
            + urllib.parse.urlencode(query)
        )
        value = http_get(url, authorization)
        for message in value["data"]:
            if message["type"] != "assistant":
                continue
            counts["assistant"] += 1
            counts["snapshot_key"] += "snapshot" in message
            counts["snapshot_files"] += bool((message.get("snapshot") or {}).get("files"))
            for part in message["content"]:
                if part["type"] == "tool" and part["state"]["status"] == "completed":
                    for item in part["state"].get("content", []):
                        if item["type"] == "file":
                            scheme = item["uri"].split(":", 1)[0]
                            tool_file_uris[scheme] = tool_file_uris.get(scheme, 0) + 1
        cursor = value["cursor"].get("next")
        if not cursor:
            break
    return {"counts": counts, "tool_file_uris": tool_file_uris}


def namespace_state(path: Path) -> str:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return "absent"
    if (
        not stat.S_ISDIR(info.st_mode)
        or (info.st_uid, info.st_gid) != (BRIDGE_UID, NATIVE_GID)
        or stat.S_IMODE(info.st_mode) != NAMESPACE_MODE
    ):
        return "foreign"
    return "pinned-empty" if not any(path.iterdir()) else "nonempty"


def association_problem() -> str | None:
    """Local pins only; the remote helper is exercised by probe-source."""
    try:
        raw = Path(ASSOCIATION_CONFIG).read_bytes()
    except FileNotFoundError:
        return "config_missing"
    config = json.loads(raw)
    key = Path(config["key_file"]).lstat()
    if (key.st_uid, stat.S_IMODE(key.st_mode)) != (BRIDGE_UID, 0o400):
        return "key_owner_or_mode"
    if sha(Path(config["known_hosts_file"]).read_bytes()) != config["known_hosts_sha256"]:
        return "known_hosts_changed"
    return None


def disk_facts(path: Path) -> dict[str, Any]:
    usage = shutil.disk_usage(path)
    return {
        "free_bytes": usage.free,
        "used_fraction_after_probe": (usage.used + PROBE_BYTES) / (usage.used + usage.free),
    }


def gather_facts(spec: Spec) -> dict[str, Any]:
    need(os.geteuid() == 0, "root_required")
    config, manifest, backend = load_runtime(spec)
    runtime_path = Path(config["runtime"]["enrollment_file"])
    directory = backend["reference"]["canonical_directory"]
    namespace = Path(namespace_for(directory, spec.namespace_name))
    native = host_state()
    main = systemctl_show(MAIN, "ActiveState")
    observer = systemctl_show(OBSERVER, "ActiveState")
    release_dropin = Path(DROPIN_DIR, RELEASE_DROPIN).read_text()
    project = Path(directory).lstat()
    scan = scan_channel(config, manifest["realm"]["bot_user_id"])
    inventory = native_output_inventory(config, spec.session_id)
    from jt_oz_bridge.services.runtime_enrollment import RuntimeEnrollment

    facts = {
        "config_sha256": sha(spec.config.read_bytes()),
        "runtime_sha256": sha(runtime_path.read_bytes()),
        "observer_sha256": sha(spec.observer.read_bytes()),
        "manifest_format": manifest["format"],
        "release_selected": f"{spec.release}/venv/bin/jt-oz-bridge" in release_dropin,
        "main_active": main["ActiveState"],
        "observer_active": observer["ActiveState"],
        "native_active": native["active"],
        "native_nrestarts": native["nrestarts"],
        "native_pid": native["MainPID"],
        "promotion_guard": os.path.lexists(PROMOTION_GUARD),
        "dropin_present": spec.dropin.exists(),
        "root_enrolled": True,
        "inputs_enabled": config["runtime"].get("workspace_inputs_enabled"),
        "generated_enabled": config["runtime"].get("generated_returns_enabled"),
        "release_scopes_workspace_roots": "workspace_roots" in RuntimeEnrollment.model_fields,
        "namespace": str(namespace),
        "namespace_state": namespace_state(namespace),
        "project_owner_uid": project.st_uid,
        "project_under_hidden_home": directory.startswith(("/home/", "/root/")),
        "association_problem": association_problem(),
        "human_upload_candidates": [m["id"] for m in scan["human"]],
        "bot_upload_candidates": [m["id"] for m in scan["bot"]],
        "real_root_git_project": Path(directory, ".git").exists(),
        "real_root_output_inventory": inventory,
        **disk_facts(Path(directory)),
    }
    facts["generated_gaps"] = generated_gaps(
        git_project=facts["real_root_git_project"], tool_file_uris=inventory["tool_file_uris"]
    )
    return facts


def cmd_preflight(spec: Spec) -> None:
    """Read-only: no file, unit or service changes; Native and Zulip GET only."""
    facts = gather_facts(spec)
    blockers = assess(facts, spec.expected)
    print(json.dumps({"facts": facts, "blockers": blockers}, ensure_ascii=False, indent=2))
    if blockers:
        raise SystemExit(3)


def require_ready(spec: Spec, *, source_stage: bool) -> dict[str, Any]:
    facts = gather_facts(spec)
    blockers = stage_blockers(assess(facts, spec.expected), source_stage=source_stage)
    if blockers:
        print(json.dumps({"blockers": blockers}, indent=2), file=sys.stderr)
        raise SystemExit(3)
    return facts


# ---------------------------------------------------------------------------
# Controlled, Root-owned preparation steps.
# ---------------------------------------------------------------------------


def ensure_directories(spec: Spec) -> None:
    os.umask(0o077)
    spec.work.mkdir(mode=0o700, exist_ok=True)
    if not spec.shared.exists():
        spec.shared.mkdir(mode=0o750)
        os.chmod(spec.shared, 0o750)
        os.chown(spec.shared, 0, BRIDGE_UID)
    if not spec.state.exists():
        spec.state.mkdir(mode=0o700)
        os.chown(spec.state, BRIDGE_UID, BRIDGE_UID)
    tool = spec.shared / Path(__file__).name
    source = Path(__file__).read_bytes()
    if tool.exists():
        need(tool.read_bytes() == source, "tool_changed_between_steps")
    else:
        write_new(tool, source, group=BRIDGE_UID)
    shared_spec = spec.shared / "spec.json"
    if shared_spec.exists():
        need(shared_spec.read_bytes() == spec.raw_bytes, "spec_changed_between_steps")
    else:
        write_new(shared_spec, spec.raw_bytes, group=BRIDGE_UID)


def cmd_namespace(spec: Spec) -> None:
    """Create the empty namespace once; an existing one must be exactly right and empty."""
    require_ready(spec, source_stage=False)
    ensure_directories(spec)
    _, _, backend = load_runtime(spec)
    directory = backend["reference"]["canonical_directory"]
    path = Path(namespace_for(directory, spec.namespace_name))
    created = False
    if namespace_state(path) == "absent":
        os.mkdir(path, 0o750)
        os.chown(path, BRIDGE_UID, NATIVE_GID)
        os.chmod(path, NAMESPACE_MODE)
        created = True
    need(namespace_state(path) == "pinned-empty", "namespace_state_after_create")
    info = path.lstat()
    pin = {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "owner_uid": info.st_uid,
        "reader_gid": info.st_gid,
    }
    receipt = spec.shared / "namespace.json"
    if receipt.exists():
        need(json.loads(receipt.read_bytes())["pin"] == pin, "namespace_identity_changed")
    else:
        write_new(receipt, dumps({"pin": pin, "created_by_tool": created}), group=BRIDGE_UID)
    print(json.dumps({"namespace": pin, "created": created}))


def run_worker(spec: Spec, step: str, *, read_write: list[str]) -> bytes:
    """Run a worker as the Bridge user with Main's protections; keep its real terminal."""
    ensure_directories(spec)
    before = host_state()
    unit = f"jt-oz-files-{spec.tag}-{step}.service"
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
        "--property=CapabilityBoundingSet=",
        "--property=PrivateTmp=yes",
        "--property=PrivateDevices=yes",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=yes",
        "--property=RestrictSUIDSGID=yes",
        "--property=InaccessiblePaths=/var/lib/jt-oz-bridge/service",
        "--property=UMask=0077",
        *[f"--property=ReadWritePaths={path}" for path in read_write],
        "--working-directory=/",
        str(spec.release / "venv/bin/python"),
        "-I",
        "-B",
        str(spec.shared / Path(__file__).name),
        step,
        "--spec",
        str(spec.shared / "spec.json"),
    ]
    done = subprocess.run(argv, capture_output=True, timeout=PROBE_SECONDS + 30, check=False)
    after = host_state()
    attempt = next(n for n in range(1, 1000) if not (spec.work / f"{step}-{n}.stdout").exists())
    terminal = dumps(
        {
            "actual_terminal": done.returncode,
            "true_join": True,
            "attempt": attempt,
            "native_before": before,
            "native_after": after,
        }
    )
    # Every attempt, failed ones included, keeps its raw output and terminal.
    write_new(spec.work / f"{step}-{attempt}.stdout", done.stdout, mode=0o600)
    write_new(spec.work / f"{step}-{attempt}.stderr", done.stderr, mode=0o600)
    write_new(spec.work / f"{step}-{attempt}-terminal.json", terminal, mode=0o600)
    print(done.stderr.decode(errors="replace")[-2000:], file=sys.stderr)
    need(done.returncode == 0, f"{step}_failed")
    need(before == after, "native_process_changed")
    write_new(spec.work / f"{step}-terminal.json", terminal, mode=0o600)
    return done.stdout


class IsolatedPipeline:
    """The release's own composition over an isolated own-database; no consumer starts."""

    def __init__(self, spec: Spec, *, native: bool, zulip: bool) -> None:
        self.spec, self.native, self.zulip = spec, native, zulip
        self.counts = {"native_get": 0, "zulip_get": 0}
        self.opened: list[Any] = []
        self.pipeline: Any = None
        self.lease: Any = None

    async def __aenter__(self) -> IsolatedPipeline:
        from jt_oz_bridge.config import load_settings
        from jt_oz_bridge.security.cipher import EnvelopeCipher
        from jt_oz_bridge.services.runtime_enrollment import (
            BackendRuntimeObserver,
            build_pipeline,
            read_enrollment,
        )
        from jt_oz_bridge.storage.database import Database, migrate
        from jt_oz_bridge.storage.durable import DurableStore
        from jt_oz_bridge.storage.fencing import ConsumerFence

        self.settings = load_settings(self.spec.config)
        need(not self.settings.runtime.workspace_inputs_enabled, "inputs_already_enabled")
        self.enrollment, digest = read_enrollment(self.settings)
        isolated = self.spec.state / f"isolated-{uuid.uuid4().hex}"
        isolated.mkdir(mode=0o700)
        self.settings.app.state_dir = isolated
        keys = {"q": os.urandom(32)}
        self.db = Database(
            "sqlite+aiosqlite:///" + str(isolated / "bridge.db"), cipher=EnvelopeCipher(keys, "q")
        )
        self.store = DurableStore(self.db)
        self.holder = f"file-transfer-{uuid.uuid4().hex}"
        await migrate(self.db.engine)
        self.lease = await self.store.acquire_lease(self.holder, ttl=PROBE_SECONDS)
        need(self.lease is not None, "isolated_lease")
        self.pipeline = build_pipeline(
            self.settings, self.enrollment, digest, self.db, ConsumerFence(self.holder, self.lease)
        )

        async def native_guard(request: Any) -> None:
            need(self.native and request.method == "GET", "native_get_only")
            self.counts["native_get"] += 1

        async def zulip_guard(request: Any) -> None:
            need(self.zulip and request.method == "GET", "zulip_get_only")
            self.counts["zulip_get"] += 1

        self.pipeline.scope.client.client.event_hooks["request"].append(zulip_guard)
        readers = self.pipeline.files.readers
        transports = {id(r.client.transport): r.client.transport for r in readers.values()}
        for transport in transports.values():
            transport.client.event_hooks["request"].append(native_guard)
        if self.native:
            for backend in self.pipeline.backends.values():
                for resource in backend.resources:
                    self.opened.append(resource)
                    owner = getattr(resource.start, "__self__", None)
                    if (
                        isinstance(owner, BackendRuntimeObserver)
                        and resource.start == owner.start_before_restoration
                    ):
                        await owner.start()
                    else:
                        await resource.start()
        return self

    async def __aexit__(self, *_: object) -> None:
        for resource in reversed(self.opened):
            await resource.close()
        if self.pipeline is not None:
            await self.pipeline.close_files()
            await self.pipeline.scope.client.close()
        if self.lease is not None:
            await self.store.release_lease(self.holder, self.lease)
        await self.db.close()


async def workspace_worker(spec: Spec) -> dict[str, Any]:
    from jt_oz_bridge.adapters.opencode.native_workspace import V2SharedWorkspaceHost
    from jt_oz_bridge.domain.attachments import (
        MAX_ATTACHMENT_BYTES,
        MAX_ATTACHMENTS,
        NativeAttachmentProjection,
    )
    from jt_oz_bridge.storage.workspace_files import (
        CHUNK,
        WorkspaceFile,
        WorkspaceFiles,
        WorkspaceInput,
        WorkspaceNamespace,
    )

    pin = json.loads((spec.shared / "namespace.json").read_bytes())["pin"]
    path = Path(pin["path"])
    async with IsolatedPipeline(spec, native=True, zulip=False) as isolated:
        backend = next(
            b
            for b in isolated.enrollment.backends
            if b.reference.upstream_session_id == spec.session_id
        )
        reader = isolated.pipeline.files.readers[backend.reference]
        store = WorkspaceFiles(
            WorkspaceNamespace(**{**pin, "path": path}),
            reserve_free_bytes=isolated.settings.retention.reserve_free_disk_bytes,
        )
        saved: tuple[WorkspaceFile, ...] = ()
        try:
            block = bytes(range(256)) * (CHUNK // 256)
            count = MAX_ATTACHMENT_BYTES // CHUNK
            checksum = hashlib.sha256(block * count).hexdigest()

            async def chunks() -> AsyncIterator[bytes]:
                for _ in range(count):
                    yield block

            # Original names must never become paths: the first one is project-sensitive.
            entries = tuple(
                WorkspaceInput(
                    str(uuid.uuid4()),
                    NativeAttachmentProjection(
                        filename="AGENTS.md" if index == 0 else f"受控檔案-{index}.bin",
                        mime_type="application/octet-stream",
                        size=MAX_ATTACHMENT_BYTES,
                        sha256=checksum,
                    ),
                    chunks(),
                )
                for index in range(MAX_ATTACHMENTS)
            )
            saved = await store.stage(str(uuid.uuid4()), entries)
            need(not (path / "AGENTS.md").exists(), "original_name_became_path")
            host = V2SharedWorkspaceHost(reader, store)
            need(
                host.qualified(backend.reference, reader.client.transport.profile.sha256),
                "namespace_not_qualified",
            )
            witness = await host.prove(backend.reference, saved)
            aggregate = host.current(witness) and len(witness.files) == MAX_ATTACHMENTS
            need(aggregate, "aggregate_not_current")
            evidence = witness.evidence_sha256
            catalog = isolated.pipeline.file_menus.catalogs[backend.reference]
            listing = await catalog.listing(backend.reference)
            need(catalog.current(listing), "listing_not_current")
            need(
                not any(e.path.startswith(path.name) for e in listing.entries),
                "namespace_disclosed_in_catalog",
            )
            store.check()
            need(set(os.listdir(path)) == {f.storage_name for f in saved}, "unknown_namespace_file")
        finally:
            removed = 0
            for item in saved:
                await store.remove(item)
                removed += 1
            store.check()
            remaining = os.listdir(path)
            store.close()
        need(removed == MAX_ATTACHMENTS and not remaining, "controlled_files_not_removed")
        return {
            "files": MAX_ATTACHMENTS,
            "bytes_each": MAX_ATTACHMENT_BYTES,
            "aggregate_original_object_current": True,
            "namespace_identity_preserved": True,
            "controlled_files_removed": True,
            "namespace_retained": True,
            "batch_evidence_sha256": evidence,
            "native_get_count": isolated.counts["native_get"],
            "native_mutations": 0,
            "zulip_requests": isolated.counts["zulip_get"],
            "native_database_bytes_read": False,
            "catalog_hides_namespace": True,
        }


def cmd_worker_workspace(spec: Spec) -> None:
    need(os.getuid() == BRIDGE_UID, "bridge_uid_required")
    print(json.dumps(asyncio.run(asyncio.wait_for(workspace_worker(spec), PROBE_SECONDS - 20))))


def cmd_probe_workspace(spec: Spec) -> None:
    """Ten 20 MiB controlled files; every Native read is a GET."""
    require_ready(spec, source_stage=False)
    pin = json.loads((spec.shared / "namespace.json").read_bytes())["pin"]
    need(namespace_state(Path(pin["path"])) == "pinned-empty", "namespace_must_be_empty")
    stdout = run_worker(spec, "worker-workspace", read_write=[pin["path"], str(spec.state)])
    need(namespace_state(Path(pin["path"])) == "pinned-empty", "namespace_not_empty_after_probe")
    need(Path(pin["path"]).lstat().st_ino == pin["inode"], "namespace_inode_changed")
    write_new(spec.shared / "workspace-observation.json", stdout, group=BRIDGE_UID)
    print(json.dumps({"probe_terminal": 0, "observation_sha256": sha(stdout)}))


def cmd_scan_source(spec: Spec) -> None:
    """GET-only list of messages with upload links; never posts anything."""
    config, manifest, _ = load_runtime(spec)
    scan = scan_channel(config, manifest["realm"]["bot_user_id"])
    print(json.dumps(scan, ensure_ascii=False, indent=2))


async def source_worker(spec: Spec, request: dict[str, Any], config_sha: str) -> dict[str, Any]:
    from jt_oz_bridge.adapters.zulip.scope import ZulipSourceReader
    from jt_oz_bridge.security.policy import AccessDenied
    from jt_oz_bridge.services.prompt_attachments import source_uploads
    from jt_oz_bridge.services.runtime_enrollment import RootFile
    from jt_oz_bridge.services.upload_associations import SSHUploadAssociations, ssh_exchange
    from jt_oz_bridge.storage.durable import digest

    pin = RootFile(path=Path(ASSOCIATION_CONFIG), sha256=config_sha)
    async with IsolatedPipeline(spec, native=False, zulip=True) as isolated:
        realm = isolated.settings.zulip_realms[0]
        channels = list(realm.allowed_channel_ids)
        need(len(channels) == 1, "single_channel_scope_required")

        async def fixed_channel(_realm: str, _message: int) -> int:
            return channels[0]

        reader = ZulipSourceReader(isolated.pipeline.scope, fixed_channel)
        source = await reader.read(realm.id, request["message_id"])
        need(not source.is_bot and not source.deleted, "human_source_required")
        need(source.author_id in realm.allowed_user_ids, "source_author_not_allowed")
        uploads = source_uploads(source, realm.url)
        need(uploads, "source_message_has_no_rendered_upload_link")
        associations = SSHUploadAssociations(pin)
        witness = await associations.authorize(source, uploads)
        current = associations.current(witness)
        need(current, "association_witness_not_current")
        need(witness.source_sha256 == digest(source.model_dump(mode="json")), "source_changed")
        config = associations.configuration()
        others = [u for u in realm.allowed_user_ids if u != source.author_id]
        need(others, "second_allowed_human_required_for_wrong_author")
        requests = negative_requests(
            source.model_dump(mode="json"),
            ["/user_uploads/" + u.path_id for u in uploads],
            other_author=others[0],
            foreign_channel=channels[0] + 1000000,
            unlinked_path=request["unlinked_path"],
            nonce=uuid.uuid4().hex,
        )
        negatives: dict[str, bool] = {}
        for name, payload in requests.items():
            encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
            reply = json.loads(await ssh_exchange(config, encoded))
            negatives[name] = reply.get("allowed") is False
        need(all(negatives.values()), "helper_allowed_a_negative")
        try:
            await associations.authorize(source.model_copy(update={"is_bot": True}), uploads)
        except AccessDenied:
            client_denied = True
        else:
            raise RuntimeError("client_allowed_bot_source")
        return {
            "positive": {
                "author_id": source.author_id,
                "channel_id": source.channel_id,
                "message_id": source.message_id,
                "upload_count": len(uploads),
                "mode": "human-source",
                "is_bot": False,
                "transaction_read_only": True,
                "original_association_current": current,
                "source_sha256": witness.source_sha256,
            },
            "negatives": negatives,
            "client_denied_bot_source": client_denied,
            "zulip_get_count": isolated.counts["zulip_get"],
            "native_requests": isolated.counts["native_get"],
            "message_posts": 0,
        }


def cmd_worker_source(spec: Spec) -> None:
    need(os.getuid() == BRIDGE_UID, "bridge_uid_required")
    request = json.loads((spec.shared / "source-request.json").read_bytes())
    config_sha = sha(Path(ASSOCIATION_CONFIG).read_bytes())
    print(json.dumps(asyncio.run(asyncio.wait_for(source_worker(spec, request, config_sha), 120))))


def cmd_probe_source(spec: Spec) -> None:
    """Positive needs a genuine Human upload message; negatives go to the real helper."""
    facts = require_ready(spec, source_stage=True)
    message = spec.source_message_id
    need(type(message) is int, "spec_source_message_id_required")
    need(message in facts["human_upload_candidates"], "source_message_is_not_a_human_upload")
    config, manifest, _ = load_runtime(spec)
    bots = scan_channel(config, manifest["realm"]["bot_user_id"])["bot"]
    need(bots, "existing_unlinked_bot_upload_required")
    request = {"message_id": message, "unlinked_path": bots[0]["paths"][0]}
    ensure_directories(spec)
    request_path = spec.shared / "source-request.json"
    if request_path.exists():
        need(json.loads(request_path.read_bytes()) == request, "source_request_changed")
    else:
        write_new(request_path, dumps(request), group=BRIDGE_UID)
    stdout = run_worker(spec, "worker-source", read_write=[str(spec.state)])
    write_new(spec.shared / "source-observation.json", stdout, group=BRIDGE_UID)
    print(json.dumps({"probe_terminal": 0, "observation_sha256": sha(stdout)}))


# ---------------------------------------------------------------------------
# Seal, activate, rollback.
# ---------------------------------------------------------------------------


def cmd_seal(spec: Spec) -> None:
    """Build and validate candidate files; nothing live is changed here."""
    from jt_oz_bridge.adapters.opencode import native_workspace
    from jt_oz_bridge.adapters.opencode.host_owner import HostOwnerEnrollment
    from jt_oz_bridge.adapters.opencode.project_policy import NativePolicyEnrollment
    from jt_oz_bridge.config import load_settings
    from jt_oz_bridge.domain.workspace_attachments import WORKSPACE_SEMANTICS
    from jt_oz_bridge.services import upload_associations
    from jt_oz_bridge.services.file_enrollment import component_sha
    from jt_oz_bridge.services.runtime_enrollment import RuntimeEnrollment, read_enrollment
    from jt_oz_bridge.storage import workspace_files

    facts = require_ready(spec, source_stage=True)
    terminals = ("worker-workspace", "worker-source")
    for step in terminals:
        terminal = json.loads((spec.work / f"{step}-terminal.json").read_bytes())
        need(terminal["actual_terminal"] == 0, f"{step}_terminal")
        need(terminal["native_before"] == terminal["native_after"], f"{step}_native_changed")
    config_text = spec.config.read_text()
    config, manifest, backend = load_runtime(spec)
    tool_sha = sha(Path(__file__).read_bytes())
    pin = json.loads((spec.shared / "namespace.json").read_bytes())["pin"]
    workspace_raw = (spec.shared / "workspace-observation.json").read_bytes()
    source_raw = (spec.shared / "source-observation.json").read_bytes()
    owner = HostOwnerEnrollment.model_validate_json(Path(backend["owner"]["path"]).read_bytes())
    policy = NativePolicyEnrollment.model_validate_json(
        Path(backend["policy"]["path"]).read_bytes()
    )
    target = spec.target
    target.mkdir(mode=0o750)
    os.chmod(target, 0o750)
    os.chown(target, 0, BRIDGE_UID)

    def install(name: str, raw: bytes) -> dict[str, str]:
        write_new(target / name, raw, group=BRIDGE_UID)
        return {"path": str(target / name), "sha256": sha(raw)}

    workspace_pin = install(
        "workspace.json",
        dumps(
            workspace_certificate(
                reference=backend["reference"],
                namespace=pin,
                contract_sha256=backend["schema_file"]["sha256"],
                native_policy_sha256=policy.fingerprint_sha256,
                executable_sha256=owner.executable_sha256,
                native_uid=owner.native_uid,
                workspace_component_sha256=component_sha(native_workspace),
                storage_component_sha256=component_sha(workspace_files),
                workspace_semantics_sha256=WORKSPACE_SEMANTICS,
                observation=json.loads(workspace_raw),
                evidence_sha256=sha(workspace_raw),
                tool_sha256=tool_sha,
            )
        ),
    )
    association_raw = Path(ASSOCIATION_CONFIG).read_bytes()
    source_pin = install("source-uploads.json", association_raw)
    observed = json.loads(source_raw)
    evidence_pin = install(
        "source-evidence.json",
        dumps(
            source_certificate(
                realm_id=manifest["realm"]["realm_id"],
                realm_url=manifest["realm"]["url"],
                bot_user_id=manifest["realm"]["bot_user_id"],
                config_raw=association_raw,
                config=json.loads(association_raw),
                transport_component_sha256=component_sha(upload_associations),
                positive=observed["positive"],
                negatives=observed["negatives"],
                tool_sha256=tool_sha,
            )
        ),
    )
    generated_pin = None
    if spec.generated_packet is not None:
        # This tool cannot produce the packet; see generated_gaps. A Root-reviewed one
        # is copied and must pass the release's own validator through read_enrollment.
        generated_pin = install("generated-outputs.json", Path(spec.generated_packet).read_bytes())
    merged = merge_file_manifest(
        manifest,
        session_id=spec.session_id,
        workspace=workspace_pin,
        source_uploads=source_pin,
        source_evidence=evidence_pin,
        generated=generated_pin,
    )
    manifest_raw = dumps(merged)
    RuntimeEnrollment.model_validate_json(manifest_raw)
    install("runtime.json", manifest_raw)
    config_out = merge_file_config(
        config_text,
        enrollment_file=str(target / "runtime.json"),
        inputs=True,
        generated=generated_pin is not None,
    )
    install("config.toml", config_out.encode())
    observer = json.loads(spec.observer.read_bytes())
    observer["runtime_enrollment_sha256"] = sha(manifest_raw)
    install("local-observer.json", dumps(observer))
    dropin = main_dropin(pin["path"]).encode()
    install(DROPIN_NAME, dropin)
    read_enrollment(load_settings(target / "config.toml"))
    done = subprocess.run(
        [
            "runuser",
            "-u",
            "jtoz",
            "--",
            str(spec.release / "venv/bin/jt-oz-bridge"),
            "--config",
            str(target / "config.toml"),
            "validate",
        ],
        capture_output=True,
        timeout=120,
        check=False,
    )
    need(done.returncode == 0, "candidate_validate_failed")
    receipt = {
        "config_before": facts["config_sha256"],
        "runtime_before": facts["runtime_sha256"],
        "observer_before": facts["observer_sha256"],
        "config_after": sha(config_out.encode()),
        "runtime_after": sha(manifest_raw),
        "observer_after": sha(dumps(observer)),
        "dropin_after": sha(dropin),
        "namespace": pin,
        "inputs_enabled": True,
        "generated_enabled": generated_pin is not None,
        "formal_acceptance": False,
    }
    write_new(spec.work / "seal.json", dumps(receipt), mode=0o600)
    print(json.dumps({"sealed": str(target), **receipt}, ensure_ascii=False))


def cmd_prepare(spec: Spec) -> None:
    """Everything before the service window; resumable, each step checks its receipt."""
    cmd_namespace(spec)
    if not (spec.work / "worker-workspace-terminal.json").exists():
        cmd_probe_workspace(spec)
    if not (spec.work / "worker-source-terminal.json").exists():
        cmd_probe_source(spec)
    if not (spec.work / "seal.json").exists():
        cmd_seal(spec)
    print(json.dumps({"prepared": True, "next": "activate"}))


def main_process_opens(pid: str, path: str) -> bool:
    for fd in Path(f"/proc/{pid}/fd").iterdir():
        try:
            if os.readlink(fd) == path:
                return True
        except OSError:
            continue
    return False


def smoke(spec: Spec, seal: dict[str, Any], native_before: dict[str, Any]) -> dict[str, Any]:
    """Unit state, stable PID, namespace FD held by Main, Native untouched."""
    first = systemctl_show(MAIN, "ActiveState", "MainPID")
    need(first["ActiveState"] == "active" and first["MainPID"] != "0", "main_not_active")
    time.sleep(SETTLE_SECONDS)
    second = systemctl_show(MAIN, "ActiveState", "MainPID")
    need(first == second, "main_restarted_during_settle")
    need(
        main_process_opens(second["MainPID"], seal["namespace"]["path"]),
        "main_does_not_hold_namespace",
    )
    info = Path(seal["namespace"]["path"]).lstat()
    need(info.st_ino == seal["namespace"]["inode"], "namespace_inode_changed")
    need(host_state() == native_before, "native_process_changed")
    need(sha(spec.config.read_bytes()) == seal["config_after"], "config_changed_during_window")
    return {"main_pid": second["MainPID"], "namespace_fd_held": True, "native_unchanged": True}


def restore(spec: Spec, seal: dict[str, Any]) -> None:
    """Back to the exact earlier files. The own database is never restored over new data."""
    subprocess.run(["systemctl", "stop", OBSERVER, MAIN], timeout=120, check=False)
    replace_exact(spec.config, (spec.work / "config.before").read_bytes(), group=BRIDGE_UID)
    replace_exact(spec.observer, (spec.work / "observer.before").read_bytes(), group=BRIDGE_UID)
    need(sha(spec.config.read_bytes()) == seal["config_before"], "restore_config_hash")
    need(sha(spec.observer.read_bytes()) == seal["observer_before"], "restore_observer_hash")
    if spec.dropin.exists():
        need(sha(spec.dropin.read_bytes()) == seal["dropin_after"], "dropin_changed")
        spec.dropin.unlink()
    subprocess.run(["systemctl", "daemon-reload"], timeout=60, check=True)
    subprocess.run(["systemctl", "start", MAIN], timeout=120, check=True)
    subprocess.run(["systemctl", "start", OBSERVER], timeout=60, check=True)


def backup_own_database(destination: Path) -> None:
    source = sqlite3.connect(f"file:{BRIDGE_DB}?mode=ro", uri=True, timeout=10)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    target = sqlite3.connect(destination)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()


def cmd_activate(spec: Spec) -> None:
    """Short service window; any failure restores files and restarts. Native is untouched."""
    need(os.geteuid() == 0, "root_required")
    seal = json.loads((spec.work / "seal.json").read_bytes())
    facts = require_ready(spec, source_stage=True)
    for key, before in (
        ("config_sha256", "config_before"),
        ("runtime_sha256", "runtime_before"),
        ("observer_sha256", "observer_before"),
    ):
        need(facts[key] == seal[before], f"{key}_changed_since_seal")
    for name, key in (
        ("config.toml", "config_after"),
        ("runtime.json", "runtime_after"),
        ("local-observer.json", "observer_after"),
        (DROPIN_NAME, "dropin_after"),
    ):
        need(sha((spec.target / name).read_bytes()) == seal[key], f"sealed_{name}_changed")
    for name, live in (("config.before", spec.config), ("observer.before", spec.observer)):
        saved = spec.work / name
        if saved.exists():  # A retried activate after a rollback.
            need(saved.read_bytes() == live.read_bytes(), f"{name}_differs_from_live")
        else:
            write_new(saved, live.read_bytes(), group=BRIDGE_UID)
    native_before = host_state()
    subprocess.run(["systemctl", "stop", OBSERVER, MAIN], timeout=120, check=True)
    try:
        backup_own_database(spec.work / f"bridge-before-{int(time.time())}.db")
        replace_exact(spec.dropin, (spec.target / DROPIN_NAME).read_bytes(), group=0, mode=0o644)
        subprocess.run(["systemctl", "daemon-reload"], timeout=60, check=True)
        subprocess.run(
            [
                "runuser",
                "-u",
                "jtoz",
                "--",
                str(spec.release / "venv/bin/jt-oz-bridge"),
                "--config",
                str(spec.target / "config.toml"),
                "enroll-runtime",
            ],
            timeout=PROBE_SECONDS,
            check=True,
        )
        replace_exact(spec.config, (spec.target / "config.toml").read_bytes(), group=BRIDGE_UID)
        replace_exact(
            spec.observer, (spec.target / "local-observer.json").read_bytes(), group=BRIDGE_UID
        )
        subprocess.run(["systemctl", "start", MAIN], timeout=120, check=True)
        result = smoke(spec, seal, native_before)
        subprocess.run(["systemctl", "start", OBSERVER], timeout=60, check=True)
        time.sleep(3)
        need(
            systemctl_show(OBSERVER, "ActiveState")["ActiveState"] == "active",
            "observer_not_active",
        )
    except BaseException as error:
        print(f"ROLLBACK: {type(error).__name__}: {error}", file=sys.stderr)
        restore(spec, seal)
        print(json.dumps({"rolled_back": True, "native_unchanged": host_state() == native_before}))
        raise SystemExit(1) from None
    write_new(spec.work / "activated.json", dumps({**seal, **result}), mode=0o600)
    print(json.dumps({"activated": True, **result}))


def cmd_rollback(spec: Spec) -> None:
    """Operator rollback. Certificates, the namespace and the database are kept."""
    need(os.geteuid() == 0, "root_required")
    seal = json.loads((spec.work / "seal.json").read_bytes())
    native_before = host_state()
    restore(spec, seal)
    time.sleep(SETTLE_SECONDS)
    need(systemctl_show(MAIN, "ActiveState")["ActiveState"] == "active", "main_not_active")
    need(host_state() == native_before, "native_process_changed")
    print(json.dumps({"rolled_back": True, "native_unchanged": True}))


def cmd_namespace_remove(spec: Spec) -> None:
    """Only after rollback: only an empty directory with the recorded identity."""
    need(os.geteuid() == 0, "root_required")
    need(not spec.dropin.exists(), "rollback_first")
    pin = json.loads((spec.shared / "namespace.json").read_bytes())["pin"]
    path = Path(pin["path"])
    need(namespace_state(path) == "pinned-empty", "namespace_not_empty_retained")
    need(path.lstat().st_ino == pin["inode"], "namespace_identity_changed")
    path.rmdir()
    print(json.dumps({"namespace_removed": str(path)}))


def cmd_status(spec: Spec) -> None:
    names = (
        "worker-workspace-terminal.json",
        "worker-source-terminal.json",
        "seal.json",
        "activated.json",
    )
    print(json.dumps({name: (spec.work / name).exists() for name in names}, indent=2))


STEPS = {
    "preflight": cmd_preflight,
    "prepare": cmd_prepare,
    "activate": cmd_activate,
    "namespace": cmd_namespace,
    "probe-workspace": cmd_probe_workspace,
    "worker-workspace": cmd_worker_workspace,
    "scan-source": cmd_scan_source,
    "probe-source": cmd_probe_source,
    "worker-source": cmd_worker_source,
    "seal": cmd_seal,
    "rollback": cmd_rollback,
    "namespace-remove": cmd_namespace_remove,
    "status": cmd_status,
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("step", choices=tuple(STEPS))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--spec", type=Path)
    group.add_argument("--spec-inline")
    # The Human upload usually happens after the spec is frozen, so it is an argument.
    parser.add_argument("--message-id", type=int)
    args = parser.parse_args()
    if args.spec_inline is not None:
        need(args.step == "preflight", "inline_spec_is_for_preflight_only")
        spec = Spec(args.spec_inline.encode(), None)
    else:
        spec = Spec(args.spec.read_bytes(), args.spec)
    if args.message_id is not None:
        spec.source_message_id = args.message_id
    STEPS[args.step](spec)


if __name__ == "__main__":
    main()
