"""Issue the installed tree-lineage observation that lets an enrolled Root keep its subagents.

A Root enrolled with the leaf provider refuses all work as soon as its agent
starts a subagent (``leaf_descendants_require_qualification``). The runtime
switches one Root to the tree provider only through an ``adoption_projects``
entry that names it as ``anchor`` with a root-managed ``SessionAdoptionPolicy``
and a ``LineageQualification`` whose observation is an operator-reviewed
``installed-original-lineage-resource-observation-v1`` document with
``qualification_scope: "tree"``. This tool produces that observation from a
real subagent tree on the live Native, read only through the installed
release's own lineage provider, policy guard and metadata observer, and stages
the switch.

The observation is backend-scope semantic evidence. It is taken on a separate,
disposable top-level session of the anchor's project and directory (the
target) that the Bridge does not know, never on the anchor, an enrolled Root
or a chat-created Root: a subagent can never be removed from a session, and
the runtime establishes the first tree baseline of the anchor and of every
chat-created Root of its project only while that Root has no child.

Run with the selected release's interpreter, as root:

    python -I -B certify_lineage.py plan    --spec spec.json
    python -I -B certify_lineage.py certify --spec spec.json --plan-sha256 HEX \\
        --i-understand-this-sends-operator-prompts-to-the-target-session
    python -I -B certify_lineage.py stage   --spec spec.json

``plan`` (the default) is read-only: GET requests only, nothing written.
``certify`` sends at most MAX_PROMPTS (2) operator prompts to the target and
answers at most MAX_PERMISSION_REPLIES (6) permission requests of the target
and its verified descendants: ``once`` only for the planned subagent start and
the one planned file inside the target's directory, ``reject`` for anything
else, never ``always``. No other Native mutation can leave the worker, and
nothing is retried. Native access runs in a transient unit as the enrolled
Bridge client UID; root only reads pins, records the Native process identity
and writes the outputs. The Native database is never opened and Native is
never restarted. ``stage`` sends GET requests only (the anchor must still have
no child) and writes a new directory only after the repo's own loaders accept
the staged manifest, policy, pin, config and observer in memory.

The prompts are operator RPCs. No Zulip Human message is forged, and nothing
here is Human, mobile or formal acceptance.

spec.json::

    {
      "tag": "lin01",
      "project_id": "example-project",                      # anchor, or "session_id": "ses_..."
      "target_session_id": "ses_...",                       # disposable, same project/directory
      "config": "/etc/jt-oz-bridge/config.toml",            # optional
      "observer": "/etc/jt-oz-bridge/local-observer.json",  # optional
      "output": "/etc/jt-oz-bridge/lineage-<tag>",          # optional, must not exist
      "stage": "/etc/jt-oz-bridge/runtime-lineage-<tag>"    # optional, must not exist
    }
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import copy
import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import time
import uuid
from collections.abc import Awaitable, Callable, Iterator, Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

CONFIRM_FLAG = "--i-understand-this-sends-operator-prompts-to-the-target-session"
MAX_PROMPTS = 2
MAX_PERMISSION_REPLIES = 6
MAX_NATIVE_GETS = 12000
MAX_RESPONSE_BYTES = 1024**3
MAX_WINDOWS = 24
MAX_RUNNING_WINDOWS = 2
WINDOW_ATTEMPTS = 4
MAX_NODES = 8
MAX_CHILD_PAGES = 4
MAX_RECORDS = 10000
TURN_SECONDS = 420
POLL_SECONDS = 1.0
WORKER_SECONDS = 1800
SUBAGENT = "general"
SOURCE_FORMAT = "jt-oz-bridge-operator-lineage-certification-v1"
OBSERVATION_FORMAT = "installed-original-lineage-resource-observation-v1"
PIN_FORMAT = "qualified-original-session-lineage-v1"
POLICY_FORMAT = "original-session-adoption-policy-v1"
OBSERVATION_FILE = "lineage-observation.json"
DETAILS_FILE = "lineage-details.json"
REVIEW = "installed-evidence-reviewed-for-development-runtime"
V1 = "qualified-consumer-runtime-v1"
# Descendants are answered, never prompted: the adoption policy grants only these.
REPLY_OPERATIONS = frozenset({"permission.reply", "form.reply", "form.cancel"})
# Resource, policy and model reads of the lineage stack plus the two mutations.
REQUIRED_OPERATIONS = frozenset(
    {
        "agent.get",
        "event.subscribe",
        "mcp.list",
        "model.default",
        "model.list",
        "permission.saved.list",
        "plugin.list",
        "session.active",
        "session.form.list",
        "session.get",
        "session.inbox.list",
        "session.list",
        "session.message.list",
        "session.permission.list",
        "session.permission.reply",
        "session.prompt",
        "shell.list",
    }
)
WRITE_ACTIONS = frozenset({"edit", "write"})
# What the provider built before a child existed may say about that child.
UNSEEN_ERRORS = (
    "lineage_explicit_original_backend_semantics_required",
    "lineage_original_children_changed",
    "lineage_original_child_not_yet_connected",
    "lineage_child_duplicate_or_parent_changed",
)
CHECK_NAMES = (
    "original_ids_and_parents",
    "complete_resource_reconciliation",
    "queued_and_pending_kinds",
    "same_owner_and_feed",
    "original_five_second_deadline",
    "foreign_and_unseen_children_rejected",
    "policy_and_owner_changes_rejected",
    "no_native_writes",
    "volatile_progress_preserves_identity",
    "settled_message_and_tool_boundaries_remain_exact",
)


class CertifyError(ValueError):
    pass


def need(condition: object, code: str) -> None:
    if not condition:
        raise CertifyError(code)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def dumps(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode()


# --------------------------------------------------------------------------
# Pure functions: no file, socket or network I/O. The unit test drives these.
# --------------------------------------------------------------------------


def cert_directory(tag: str) -> str:
    need(re.fullmatch(r"[a-z0-9-]{1,40}", tag), "tag")
    return f"jt-oz-lineage-{tag}"


def operator_plan(tag: str) -> dict[str, Any]:
    """Two operator prompts and, per step and depth, the only asks certify may approve.

    Depth 0 is the target, 1 a subagent it starts, 2 a subagent of that one.
    Only tiny outputs are requested, so no step makes Bridge handle a large tool read.
    """
    d = cert_directory(tag)
    child_file = f"{d}/child.txt"
    head = (
        "jt-oz-bridge operator certification, step {} of 2. "
        "This is an automated operator check, not a message from a person."
    )
    steps = [
        {
            "step": "tree",
            "text": head.format(1)
            + f" Use the task tool exactly once to start one `{SUBAGENT}` subagent with this "
            'exact task: "Use the write tool once to create the file '
            f"`{child_file}` containing exactly `jt-oz-bridge lineage child` followed by one "
            "newline. Do not use any other tool and do not start subagents. Then reply with "
            'three short sentences about what you did." Do not use any other tool yourself, '
            "do not read or change any file, and when the subagent has finished reply with "
            "the single word OK.",
            "allow": [
                {"depth": 0, "action": "task", "resources": [SUBAGENT]},
                {"depth": 1, "action": "write", "resources": [child_file]},
            ],
        },
        {
            "step": "nested",
            "text": head.format(2)
            + f" Use the task tool exactly once to start one `{SUBAGENT}` subagent with this "
            f'exact task: "Use the task tool exactly once to start one `{SUBAGENT}` subagent '
            "whose task is: reply with the single word OK without using any tool. Do not use "
            'any other tool yourself; when it has finished, reply with the single word OK." '
            "Do not use any other tool yourself, do not read or change any file, and when the "
            "subagent has finished reply with the single word OK.",
            "allow": [
                {"depth": 0, "action": "task", "resources": [SUBAGENT]},
                {"depth": 1, "action": "task", "resources": [SUBAGENT]},
            ],
        },
    ]
    need(len(steps) == MAX_PROMPTS, "prompt_bound")
    return {"directory": d, "child_file": child_file, "steps": steps}


def plan_sha256(
    plan: dict[str, Any],
    *,
    anchor: dict[str, Any],
    target: dict[str, Any],
    policy_sha256: str,
    tool_sha256: str,
) -> str:
    from jt_oz_bridge.storage.durable import digest

    return digest(
        {
            "format": SOURCE_FORMAT,
            "plan": plan,
            "anchor": anchor,
            "target": target,
            "anchor_policy_sha256": policy_sha256,
            "certify_tool_sha256": tool_sha256,
            "limits": {
                "prompts": MAX_PROMPTS,
                "permission_replies": MAX_PERMISSION_REPLIES,
                "native_gets": MAX_NATIVE_GETS,
                "response_bytes": MAX_RESPONSE_BYTES,
                "windows": MAX_WINDOWS,
                "nodes": MAX_NODES,
                "turn_seconds": TURN_SECONDS,
                "worker_seconds": WORKER_SECONDS,
            },
        }
    )


def candidate_attestation(*, tag: str, plan_sha: str) -> str:
    """Stands in for the observation's own pin, which cannot exist before it."""
    from jt_oz_bridge.storage.durable import digest

    return digest({"format": SOURCE_FORMAT, "tag": tag, "plan_sha256": plan_sha})


def prompt_source(*, tag: str, step: str, action_id: str, text: str) -> dict[str, Any]:
    """Stands in for the Zulip message an ordinary prompt would digest."""
    return {
        "format": SOURCE_FORMAT,
        "tag": tag,
        "step": step,
        "action_id": action_id,
        "text_sha256": sha(text.encode()),
        "operator_not_human": True,
    }


def prompt_body(text: str, action_id: str, operation_digest: str) -> dict[str, Any]:
    """Same shape as V2ExecutionClient's prompt body."""
    return {
        "text": text,
        "delivery": "queue",
        "metadata": {
            "jt_oz_bridge": {"action_id": action_id, "operation_digest": operation_digest}
        },
    }


SESSION_ID = r"ses_[A-Za-z0-9_-]{1,128}"
# The id prefix of every session the Bridge creates or forks from chat.
BRIDGE_CREATED = "ses_jtoz_"
MAX_ROOT_PAGES = 20


def mutation_kind(method: str, path: str, target_id: str, nodes: frozenset[str]) -> str | None:
    """Prompts only to the target; replies only to the target or a verified descendant."""
    if method != "POST":
        return None
    if path == f"/api/session/{target_id}/prompt":
        return "prompt"
    match = re.fullmatch(
        r"/api/session/(" + SESSION_ID + r")/permission/[A-Za-z0-9_-]{1,255}/reply", path
    )
    if match and (match.group(1) == target_id or match.group(1) in nodes):
        return "permission.reply"
    return None


def workspace_relative(resource: object, canonical_directory: str) -> str | None:
    """A canonical path inside the target's directory, or None for anything else."""
    from jt_oz_bridge.security.workspace_paths import canonical_relative

    if not isinstance(resource, str):
        return None
    prefix = canonical_directory.rstrip("/") + "/"
    value = resource[len(prefix) :] if resource.startswith(prefix) else resource
    if value.startswith("/") or any(c in value for c in "*?[]{}"):
        return None
    try:
        return canonical_relative(value)
    except ValueError:
        return None


def permission_decision(
    request: object,
    *,
    node_id: str,
    depth: int,
    canonical_directory: str,
    step: Mapping[str, Any],
) -> tuple[str, str]:
    """``once`` only for this step's planned ask at this depth of the tree.

    Another session, depth, tool, path, glob, command or external directory is
    rejected; ``always`` is never answered. OpenCode 2.0.32 names permissions
    ``edit``, ``shell`` and, for the task tool, ``subagent``.
    """
    if not isinstance(request, dict) or request.get("sessionID") != node_id:
        return "reject", "foreign_or_malformed_request"
    action, resources = request.get("action"), request.get("resources")
    if (
        not isinstance(resources, list)
        or not 1 <= len(resources) <= 20
        or any(not isinstance(r, str) for r in resources)
    ):
        return "reject", "explicit_resources_required"
    planned = [a for a in step["allow"] if a["depth"] == depth]
    if action in {"subagent", "task"}:
        if any(a["action"] == "task" and resources == a["resources"] for a in planned):
            return "once", "planned_subagent"
        return "reject", "unplanned_subagent"
    if action in WRITE_ACTIONS:
        allowed = {r for a in planned if a["action"] == "write" for r in a["resources"]}
        paths = [workspace_relative(r, canonical_directory) for r in resources]
        if allowed and all(p is not None and p in allowed for p in paths):
            return "once", "planned_path"
        return "reject", "path_outside_plan"
    return "reject", "unplanned_action"


def child_row_problem(
    row: object, *, parent_id: str, native_project_id: str, canonical_directory: str
) -> str | None:
    """Why a listed child cannot be part of the target's tree (None means it can)."""
    if not isinstance(row, dict) or not isinstance(row.get("id"), str):
        return "malformed_child"
    if not re.fullmatch(SESSION_ID, row["id"]):
        return "child_id_shape"
    if row.get("parentID") != parent_id:
        return "child_parent_changed"
    if row.get("projectID") != native_project_id:
        return "child_foreign_project"
    if row.get("location") != {"directory": canonical_directory}:
        return "child_foreign_directory"
    times = row.get("time")
    if not isinstance(times, dict) or type(times.get("created")) is not int:
        return "child_creation_time_required"
    if times.get("archived") is not None:
        return "child_archived"
    return None


def activation_blockers(scan: Mapping[str, Any]) -> list[str]:
    """Why the staged tree pin would stop the Bridge at its first start (empty means none).

    No journal history exists for a leaf Root, so the runtime records a first
    tree baseline for the anchor and every chat-created Root of its project,
    and refuses (failing the whole startup) any of them that already has a child.
    """
    blockers = []
    if scan.get("anchor_has_children") is not False:
        blockers.append("anchor_has_descendants_first_tree_baseline_impossible")
    grown = scan.get("bridge_created_roots_with_children")
    if grown != []:
        blockers.append("bridge_created_root_has_descendants:" + ",".join(grown or ["unknown"]))
    return blockers


def native_identity(host: Mapping[str, Any], owner: Mapping[str, Any] | None) -> dict[str, Any]:
    """Root's systemd/proc view joined with the owner probe's epoch."""
    return {
        "pid": host.get("pid"),
        "nrestarts": host.get("nrestarts"),
        "binary_sha256": host.get("binary_sha256"),
        "invocation_id": host.get("invocation_id"),
        "start_ticks": host.get("start_ticks"),
        "owner_pid": (owner or {}).get("pid"),
        "owner_epoch": (owner or {}).get("owner_epoch"),
    }


def sent_summary(worker: Mapping[str, Any]) -> dict[str, dict[str, int]]:
    """What actually reached Native, from the per-request records and the wire."""
    summary = {}
    for kind, key in (("prompt", "prompts"), ("permission.reply", "permission_replies")):
        records = worker.get(key) or []
        summary[kind] = {
            "sent": sum(r.get("sent") is True for r in records),
            "not_sent": sum(r.get("sent") is False for r in records),
            "uncertain": sum(r.get("sent") not in (True, False) for r in records),
            "attempted": (worker.get("native_mutation_attempts") or {}).get(kind, 0),
            "answered_by_native": (worker.get("native_mutations") or {}).get(kind, 0),
        }
    return summary


# Observed-evidence evaluation. Every check is computed from what the worker
# recorded; a check that was not exercised is false, never assumed.


def _ok_windows(worker: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [w for w in worker.get("windows") or [] if w.get("ok") is True]


def _final_window(worker: Mapping[str, Any]) -> dict[str, Any] | None:
    settled = [w for w in _ok_windows(worker) if w.get("label") == "nested:settled"]
    return settled[-1] if settled else None


def _snapshot(window: Mapping[str, Any], session_id: str) -> dict[str, Any] | None:
    return next((s for s in window.get("snapshots") or [] if s.get("id") == session_id), None)


def _depths(window: Mapping[str, Any]) -> dict[str, int]:
    return {n["id"]: n["depth"] for n in window.get("nodes") or []}


def check_ids_and_parents(worker: Mapping[str, Any]) -> bool:
    final, target = _final_window(worker), worker.get("target")
    discovered = worker.get("discovered") or {}
    if final is None or not isinstance(target, str):
        return False
    nodes = {n["id"]: n for n in final.get("nodes") or []}
    expected = {target: None} | {sid: row.get("parent") for sid, row in discovered.items()}
    if (
        len(nodes) < 2
        or set(nodes) != set(expected)
        or any(nodes[sid]["parent"] != parent for sid, parent in expected.items())
        or any(
            row.get("project_matches") is not True or row.get("directory_matches") is not True
            for row in discovered.values()
        )
    ):
        return False
    # The same original identity everywhere it was observed.
    seen: dict[str, tuple[Any, ...]] = {}
    for window in _ok_windows(worker):
        for n in window.get("nodes") or []:
            key = (n["parent"], n["created"], n["origin_sha256"], n["policy_sha256"])
            if seen.setdefault(n["id"], key) != key:
                return False
    return True


def child_states(worker: Mapping[str, Any]) -> set[str]:
    states = set()
    for window in _ok_windows(worker):
        depth = _depths(window)
        for s in window.get("snapshots") or []:
            if depth.get(s["id"], 0) >= 1:
                states.add(s["state"])
    return states


def graph_descendants(nodes: list[Mapping[str, Any]]) -> dict[str, list[str]]:
    """Every node's recursive descendants, from the observed parent edges alone."""
    parent = {n["id"]: n["parent"] for n in nodes}
    result: dict[str, set[str]] = {sid: set() for sid in parent}
    for sid in parent:
        seen, up = {sid}, parent[sid]
        while up is not None and up in result and up not in seen:
            result[up].add(sid)
            seen.add(up)
            up = parent[up]
    return {sid: sorted(children) for sid, children in result.items()}


def check_reconciliation(worker: Mapping[str, Any]) -> bool:
    windows, final = _ok_windows(worker), _final_window(worker)
    if final is None or not windows:
        return False
    for window in windows:
        nodes = window.get("nodes") or []
        expected = graph_descendants(nodes)
        snapshots = window.get("snapshots") or []
        if {s["id"] for s in snapshots} != {n["id"] for n in nodes}:
            return False
        if any(
            s.get("reconciled") is not True
            or s["descendants"] != expected[s["id"]]
            or (window.get("provider_descendants") or {}).get(s["id"]) != expected[s["id"]]
            for s in snapshots
        ):
            return False
    return all(s["state"] == "idle" for s in final["snapshots"]) and {
        "running",
        "waiting_permission",
        "idle",
    } <= child_states(worker)


def check_pending_kinds(worker: Mapping[str, Any]) -> bool:
    target = worker.get("target")
    for window in _ok_windows(worker):
        depth, root = _depths(window), _snapshot(window, str(target))
        if root is None or root["state"] == "waiting_permission" or root["pending"]:
            continue
        for item in window.get("interactions") or []:
            node = _snapshot(window, item["id"])
            if (
                node is not None
                and depth.get(item["id"], 0) >= 1
                and item.get("kind_on_node") == "permission"
                and item.get("kind_on_root") is None
                and node["state"] == "waiting_permission"
                and [item["request"], "permission"] in node["pending"]
                and "quiescent" in str(window.get("root_dispatch"))
            ):
                return True
    return False


def check_owner_and_feed(worker: Mapping[str, Any], owner_epoch: object) -> bool:
    windows = _ok_windows(worker)
    epochs: dict[Any, set[Any]] = {}
    for window in windows:
        if window.get("owner_epoch") != owner_epoch:
            return False
        if any(
            s.get("owner_epoch") != owner_epoch
            or s.get("connection_epoch") != window.get("connection_epoch")
            for s in window.get("snapshots") or []
        ):
            return False
        epochs.setdefault(window.get("feed"), set()).add(window.get("connection_epoch"))
    return (
        bool(windows) and isinstance(owner_epoch, str) and all(len(e) == 1 for e in epochs.values())
    )


def deadline_passed(seen: Mapping[str, Any] | None, worker: Mapping[str, Any]) -> bool:
    if not seen:
        return False
    # The runtime's own exact comparison; JSON keeps these floats bit for bit.
    snapshots = [s for w in _ok_windows(worker) for s in w.get("snapshots") or []]
    return bool(
        snapshots
        and all(s["expires_at"] == s["issued_at"] + 5 for s in snapshots)
        and seen.get("issued_at") is not None
        and seen.get("expires_at") == seen["issued_at"] + 5
        and seen.get("proof_current_before") is True
        and seen.get("valid_fence_before") is True
        and seen.get("current_proof_after") is False
        and seen.get("valid_fence_after") is False
        and seen.get("proof_current_after") is False
        and isinstance(seen.get("client_current_after"), str)
        and isinstance(seen.get("dispatch_after"), str)
        and seen.get("native_requests") == 0
    )


def leaf_passed(before: Mapping[str, Any] | None, refused: Mapping[str, Any] | None) -> bool:
    return bool(
        before
        and before.get("error") is None
        and before.get("state") == "idle"
        and refused
        and "leaf_descendants_require_qualification" in str(refused.get("error"))
    )


def unseen_passed(seen: list[Mapping[str, Any]] | None) -> bool:
    return bool(seen) and all(
        any(code in str(item.get("error")) for code in UNSEEN_ERRORS) for item in seen or []
    )


def foreign_passed(seen: Mapping[str, Any] | None) -> bool:
    return bool(
        seen
        and isinstance(seen.get("select"), str)
        and isinstance(seen.get("snapshot"), str)
        and seen.get("native_requests") == 0
    )


def policy_passed(seen: Mapping[str, Any] | None) -> bool:
    return bool(
        seen
        and seen.get("control") is None
        and seen.get("pages_changed", 0) >= 1
        and "native_project_policy_changed_or_unqualified" in str(seen.get("tampered"))
        and "lineage_original_node_policy_required" in str(seen.get("inherited_enrollment"))
    )


def owner_passed(seen: Mapping[str, Any] | None) -> bool:
    return bool(
        seen
        and "control" in seen
        and seen["control"] is None
        and isinstance(seen.get("snapshot"), str)
        and seen.get("current_proof_after") is False
    )


def check_no_writes(worker: Mapping[str, Any]) -> bool:
    windows = worker.get("windows") or []
    return bool(
        windows
        and all(w.get("mutations_during") == 0 for w in windows)
        and (worker.get("negative_reads") or {}).get("mutations_during") == 0
        and worker.get("observation_mutation_attempts") == 0
        and worker.get("native_database_opens") == 0
        and worker.get("workspace_opens") == 0
        and worker.get("refused_native_requests") == 0
    )


def check_volatile_progress(worker: Mapping[str, Any]) -> bool:
    info: dict[str, set[str]] = {}
    for window in _ok_windows(worker):
        for n in window.get("nodes") or []:
            if n["depth"] >= 1:
                info.setdefault(n["id"], set()).add(n["session_info_sha256"])
    # Identity across windows is check_ids_and_parents; here it must have held
    # while the node's Native session info really changed.
    return check_ids_and_parents(worker) and any(len(v) >= 2 for v in info.values())


def settled_passed(seen: Mapping[str, Any] | None, owner_epoch: object) -> bool:
    return bool(
        seen
        and seen.get("states") == ["idle", "idle"]
        and seen.get("state_only") == [False, False]
        and seen.get("cursors", [None])[0] is not None
        and len(set(seen.get("cursors") or [])) == 1
        and len(set(seen.get("fences") or [])) == 1
        and seen.get("dispatch_owner") == owner_epoch
        and seen.get("earlier_active_cursor") is not None
        and seen.get("earlier_active_cursor") not in (seen.get("cursors") or [])
        and seen.get("pages")
        and all(len(set(p)) == 1 for p in seen.get("pages", {}).values())
    )


def lineage_checks(worker: Mapping[str, Any], *, owner_epoch: object) -> dict[str, bool]:
    n = worker.get("negatives") or {}
    checks = {
        "original_ids_and_parents": check_ids_and_parents(worker),
        "complete_resource_reconciliation": check_reconciliation(worker),
        "queued_and_pending_kinds": check_pending_kinds(worker),
        "same_owner_and_feed": check_owner_and_feed(worker, owner_epoch),
        "original_five_second_deadline": deadline_passed(n.get("deadline"), worker),
        "foreign_and_unseen_children_rejected": leaf_passed(
            n.get("leaf_before"), n.get("leaf_refused")
        )
        and unseen_passed(n.get("unseen"))
        and foreign_passed(n.get("foreign")),
        "policy_and_owner_changes_rejected": policy_passed(n.get("policy"))
        and owner_passed(n.get("owner")),
        "no_native_writes": check_no_writes(worker),
        "volatile_progress_preserves_identity": check_volatile_progress(worker),
        "settled_message_and_tool_boundaries_remain_exact": settled_passed(
            n.get("settled"), owner_epoch
        ),
    }
    need(tuple(checks) == CHECK_NAMES, "check_names_changed")
    return checks


def observation_requests(worker: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Every GET made inside an observation window, as the runtime records it."""
    return [
        {"operation": op, "method": "GET", "status": 200, "response_sha256": digest_hex}
        for op, digest_hex in worker.get("rpc_records") or []
    ]


def build_observation(
    *,
    worker: dict[str, Any],
    reference: Any,
    contract_sha256: str,
    executable_sha256: str,
    upstream_version: str,
    verified_operations: frozenset[str],
    host_before: Mapping[str, Any],
    host_after: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """The observation document, its operator details and the list of failed checks.

    Every claim is computed from the worker's and root's observations; a failed
    check is recorded false (never omitted) and nothing is then written.
    """
    from jt_oz_bridge.adapters.opencode.lineage_resources import LINEAGE_SEMANTICS
    from jt_oz_bridge.adapters.opencode.resources import READS
    from jt_oz_bridge.security.json_data import strict_loads
    from jt_oz_bridge.services.runtime_enrollment import LINEAGE_CHECKS, LineageObservation

    need(frozenset(CHECK_NAMES) == LINEAGE_CHECKS, "runtime_lineage_checks_changed")
    failures: list[str] = []
    if worker.get("error"):
        failures.append("worker_error")
    owner_before, owner_after = worker.get("owner_before"), worker.get("owner_after")
    owner_unchanged = (
        isinstance(owner_before, dict)
        and isinstance(owner_after, dict)
        and all(
            owner_before.get(k) == owner_after.get(k)
            for k in ("owner_epoch", "pid", "process_start_ticks", "boot_id", "executable_sha256")
        )
    )
    native_before = native_identity(host_before, owner_before)
    native_after = native_identity(host_after, owner_after)
    restarted = not (dict(host_before) == dict(host_after) and native_before == native_after)
    restarted = restarted or host_before.get("nrestarts") != 0
    replaced = not (
        owner_unchanged
        and native_before["binary_sha256"] == executable_sha256
        and isinstance(owner_before, dict)
        and owner_before.get("executable_sha256") == executable_sha256
        and owner_before.get("version") == upstream_version
        and native_before["pid"] == native_before["owner_pid"]
    )
    for name, bad in (
        ("owner_changed", not owner_unchanged),
        ("native_restarted_or_changed", restarted),
        ("backend_identity_changed", replaced),
        ("native_database_opened", worker.get("native_database_opens") != 0),
        ("workspace_opened_locally", worker.get("workspace_opens") != 0),
        ("non_native_request_attempted", worker.get("non_native_requests", 0) != 0),
        ("native_get_failed", worker.get("failed_gets", 0) != 0),
    ):
        if bad:
            failures.append(name)
    prompts = worker.get("prompts") or []
    replies = worker.get("permission_replies") or []
    admitted = [p for p in prompts if p.get("admitted") is True]
    if len(admitted) != MAX_PROMPTS or len(prompts) != MAX_PROMPTS:
        failures.append(f"operator_prompts:{len(admitted)}/{len(prompts)}")
    mutations = worker.get("native_mutations") or {}
    attempts = worker.get("native_mutation_attempts") or {}
    for kind, records in (("prompt", prompts), ("permission.reply", replies)):
        if (
            any(r.get("sent") is not True for r in records)
            or mutations.get(kind) != len(records)
            or attempts.get(kind) != len(records)
        ):
            failures.append(f"native_mutation_not_exactly_sent:{kind}")
    if len(replies) > MAX_PERMISSION_REPLIES or worker.get("refused_native_requests") != 0:
        failures.append("native_mutation_bound")
    if any(r.get("decision") != "once" for r in replies):
        failures.append("permission_rejected")
    if worker.get("turns_completed") != MAX_PROMPTS:
        failures.append(f"turns_completed:{worker.get('turns_completed')}")
    if not 0 <= worker.get("native_get_count", MAX_NATIVE_GETS + 1) <= MAX_NATIVE_GETS:
        failures.append("native_get_bound")
    if not 0 <= worker.get("native_response_bytes", MAX_RESPONSE_BYTES + 1) <= MAX_RESPONSE_BYTES:
        failures.append("native_byte_bound")
    checks = lineage_checks(worker, owner_epoch=native_before["owner_epoch"])
    failures += [f"check:{name}" for name, ok in checks.items() if not ok]
    requests = observation_requests(worker)
    operations = {r["operation"] for r in requests}
    if not READS <= operations:
        failures.append("observation_reads_incomplete:" + ",".join(sorted(READS - operations)))
    if not operations <= verified_operations:
        outside = sorted(operations - verified_operations)
        failures.append("observation_reads_outside_enrollment:" + ",".join(outside))
    if not 1 <= len(requests) <= MAX_RECORDS:
        failures.append(f"observation_request_records:{len(requests)}")
    final = _final_window(worker)
    graph = (final or {}).get("graph")
    observation: dict[str, Any] = {
        "format": OBSERVATION_FORMAT,
        "backend_id": reference.backend_id,
        "backend_identity": reference.backend_identity,
        "contract_sha256": contract_sha256,
        "executable_sha256": executable_sha256,
        "upstream_version": upstream_version,
        "semantics": LINEAGE_SEMANTICS,
        "qualification_scope": "tree",
        "graph": graph,
        "checks": checks,
        "requests": requests,
        # Mutations inside the GET-only observation windows; the operator setup
        # (prompts and replies between windows) is in the details below.
        "native_http_mutations": worker.get("observation_mutation_attempts"),
        "native_database_bytes_read": worker.get("native_database_opens") != 0,
    }
    if not failures:
        try:
            LineageObservation.model_validate(strict_loads(dumps(observation)))
        except ValueError as error:
            failures.append(f"runtime_validation:{type(error).__name__}:{str(error)[:300]}")
    details = {
        "format": SOURCE_FORMAT,
        "evidence_scope": "operator-rpc-only-not-human-acceptance",
        "human_acceptance": False,
        "mobile_acceptance": False,
        "human_input_fabricated": False,
        "anchor": reference.model_dump(mode="json"),
        "target": worker.get("target_reference"),
        "nodes": worker.get("discovered"),
        "child_states_observed": sorted(child_states(worker)),
        # A queued child needs input to that child; certify never sends one.
        "queued_child_observed": "queued" in child_states(worker),
        "checks": checks,
        "negatives": worker.get("negatives"),
        "windows": [
            {k: v for k, v in w.items() if k != "graph"} for w in worker.get("windows") or []
        ],
        "setup_native_mutations": sent_summary(worker),
        "operator_prompts": [
            {k: p.get(k) for k in ("step", "action_id", "operation_digest", "upstream_id", "sent")}
            | {"operator_not_human": True, "rpc": "session.prompt"}
            for p in prompts
        ],
        "permission_replies": [{k: v for k, v in r.items() if k != "resources"} for r in replies],
        "native_before": native_before,
        "native_after": native_after,
        "native_requests": {
            "gets": worker.get("native_get_count"),
            "response_bytes": worker.get("native_response_bytes"),
            "refused": worker.get("refused_native_requests"),
            "observation_records": len(requests),
        },
        "plan_sha256": worker.get("plan_sha256"),
        "candidate_attestation_sha256": worker.get("candidate_attestation_sha256"),
        "failures": failures,
    }
    return observation, details, failures


def changed_paths(before: Any, after: Any, path: tuple[Any, ...] = ()) -> set[tuple[Any, ...]]:
    if isinstance(before, dict) and isinstance(after, dict):
        out: set[tuple[Any, ...]] = set()
        for key in before.keys() | after.keys():
            if key not in before or key not in after:
                out.add((*path, key))
            else:
                out |= changed_paths(before[key], after[key], (*path, key))
        return out
    if isinstance(before, list) and isinstance(after, list) and len(before) == len(after):
        out = set()
        for index, (a, b) in enumerate(zip(before, after, strict=True)):
            out |= changed_paths(a, b, (*path, index))
        return out
    return set() if before == after and type(before) is type(after) else {path}


def adoption_operations(source_operations: frozenset[str]) -> list[str]:
    operations = sorted(source_operations & REPLY_OPERATIONS)
    need(operations, "anchor_policy_has_no_reply_operations")
    return operations


def adoption_policy(
    reference: dict[str, Any], *, contract_sha256: str, protocol_sha256: str, operations: list[str]
) -> dict[str, Any]:
    """Only reply operations: descendants are answered, never prompted."""
    need(set(operations) <= REPLY_OPERATIONS and operations, "adoption_operations_outside_replies")
    return {
        "format": POLICY_FORMAT,
        "anchor": copy.deepcopy(reference),
        "contract_sha256": contract_sha256,
        "installed_protocol_evidence_sha256": protocol_sha256,
        "protocol_scope": "backend",
        "operations": sorted(operations),
    }


def lineage_pin(observation: dict[str, str]) -> dict[str, Any]:
    return {"format": PIN_FORMAT, "operator_review": REVIEW, "observation": dict(observation)}


def stage_manifest(
    manifest: dict[str, Any],
    reference: dict[str, Any],
    policy: dict[str, str],
    lineage: dict[str, str],
) -> dict[str, Any]:
    """The manifest plus one adoption entry naming this Root as tree anchor; nothing else."""
    fmt = manifest.get("format")
    need(isinstance(fmt, str) and fmt != V1, f"manifest_format_not_stageable:{fmt}")
    merged = copy.deepcopy(manifest)
    targets = [i for i, b in enumerate(merged["backends"]) if b["reference"] == reference]
    need(len(targets) == 1, f"root_not_uniquely_enrolled:{len(targets)}")
    need(
        merged["backends"][targets[0]].get("protocol_scope") == "backend",
        "anchor_must_be_backend_scoped",
    )
    entries = list(merged.get("adoption_projects") or [])
    need(
        all(e["anchor"]["project_id"] != reference["project_id"] for e in entries),
        "project_already_has_adoption_pin",
    )
    entry = {
        "anchor": copy.deepcopy(reference),
        "policy": {"path": policy["path"], "sha256": policy["sha256"]},
        "lineage": {"path": lineage["path"], "sha256": lineage["sha256"]},
    }
    merged["adoption_projects"] = [*entries, entry]
    need(
        changed_paths(manifest, merged) <= {("adoption_projects",)},
        "manifest_change_outside_adoption_scope",
    )
    return merged


def stage_config(text: str, enrollment_file: Path) -> str:
    """Repoint enrollment_file only: the tree provider needs no runtime flag."""
    import tomllib

    before = tomllib.loads(text)
    lines = text.splitlines(keepends=True)
    headers = [
        i
        for i, line in enumerate(lines)
        if re.fullmatch(r'\s*\[\s*"?runtime"?\s*\]\s*(#.*)?\s*', line)
    ]
    need(len(headers) == 1, "config_single_runtime_table_required")
    start = headers[0] + 1
    end = next((i for i in range(start, len(lines)) if re.match(r"\s*\[", lines[i])), len(lines))
    key = re.compile(r'\s*("?)enrollment_file\1\s*=')
    found = [i for i in range(start, end) if key.match(lines[i])]
    need(len(found) == 1, "config_runtime_keys_ambiguous")
    name = '"enrollment_file"' if lines[found[0]].lstrip().startswith('"') else "enrollment_file"
    lines[found[0]] = f"{name} = {json.dumps(str(enrollment_file))}\n"
    staged = "".join(lines)
    expected = copy.deepcopy(before)
    expected["runtime"]["enrollment_file"] = str(enrollment_file)
    need(tomllib.loads(staged) == expected, "config_change_outside_enrollment_pin")
    return staged


def stage_observer(observer: dict[str, Any], manifest_sha256: str) -> dict[str, Any]:
    need(isinstance(observer.get("runtime_enrollment_sha256"), str), "observer_policy_pin_required")
    merged = copy.deepcopy(observer)
    merged["runtime_enrollment_sha256"] = manifest_sha256
    need(
        changed_paths(observer, merged) <= {("runtime_enrollment_sha256",)},
        "observer_change_outside_enrollment_pin",
    )
    return merged


@contextlib.contextmanager
def memory_root_files(files: Mapping[Path, bytes]) -> Iterator[None]:
    """Serve not-yet-written pins to the project's own validators; other paths
    still go through the real root-managed reader."""
    import jt_oz_bridge.security.root_files as root_files
    import jt_oz_bridge.services.runtime_enrollment as runtime

    originals = root_files.root_bytes, runtime.root_bytes

    def read(path: Path, *, maximum: int = 8 * 1024 * 1024) -> bytes:
        if path in files:
            return files[path]
        return originals[0](path, maximum=maximum)

    root_files.root_bytes = runtime.root_bytes = read
    try:
        yield
    finally:
        root_files.root_bytes, runtime.root_bytes = originals


def validate_documents(
    settings: Any, *, manifest_path: Path, files: Mapping[Path, bytes], reference: dict[str, Any]
) -> tuple[Any, str]:
    """The runtime's own loaders over the staged files, before anything is written."""
    from jt_oz_bridge.domain.models import SessionRef
    from jt_oz_bridge.services.runtime_enrollment import adoption_pins, read_enrollment

    need(settings.runtime.enrollment_file == manifest_path, "staged_config_points_elsewhere")
    with memory_root_files(files):
        value, enrollment_sha = read_enrollment(settings)
        pins = adoption_pins(value)
    ref = SessionRef.model_validate(reference)
    need(enrollment_sha == sha(files[manifest_path]), "staged_manifest_digest")
    need(ref.project_id in pins, "staged_adoption_pin_missing")
    policy, lineage = pins[ref.project_id]
    need(policy.anchor == ref, "staged_adoption_anchor_changed")
    need(policy.operations <= REPLY_OPERATIONS, "staged_adoption_operations_outside_replies")
    need(lineage is not None and lineage.qualification_scope == "tree", "staged_tree_lineage")
    anchor = next(b for b in value.backends if b.reference == ref)
    need(
        anchor.agent_settings is None and not anchor.agent_transitions,
        "anchor_agent_switching_tree_root_not_qualified",
    )
    return value, enrollment_sha


def validate_stage(
    settings: Any,
    *,
    manifest_path: Path,
    files: Mapping[Path, bytes],
    observer_raw: bytes,
    reference: dict[str, Any],
) -> str:
    from jt_oz_bridge.security.json_data import strict_loads
    from jt_oz_bridge.services.inspection_runtime import LocalObserverPolicy

    value, enrollment_sha = validate_documents(
        settings, manifest_path=manifest_path, files=files, reference=reference
    )
    policy = LocalObserverPolicy.model_validate(strict_loads(observer_raw))
    need(policy.runtime_enrollment_sha256 == enrollment_sha, "staged_observer_pin")
    need(
        set(policy.backend_evidence) == {b.reference.backend_id for b in value.backends},
        "staged_observer_backend_scope",
    )
    return str(enrollment_sha)


def select_root(enrollment: Any, *, project_id: str | None, session_id: str | None) -> Any:
    need((project_id is None) != (session_id is None), "exactly_one_root_selector_required")
    matches = [
        q
        for q in enrollment.backends
        if (project_id is not None and q.reference.project_id == project_id)
        or (session_id is not None and q.reference.upstream_session_id == session_id)
    ]
    need(len(matches) == 1, f"root_not_uniquely_enrolled:{len(matches)}")
    return matches[0]


def root_preflight(
    q: Any, manifest: dict[str, Any], enrollment: Any, target_id: str, source_operations: Any
) -> list[str]:
    """Why this anchor/target pair cannot be certified or staged (empty means it can)."""
    problems = []
    if q.protocol_scope != "backend":
        problems.append("anchor_must_be_backend_scoped")
    missing = sorted(REQUIRED_OPERATIONS - set(q.verified_operations))
    if missing:
        problems.append("verified_operations_missing:" + ",".join(missing))
    if manifest.get("format") == V1:
        problems.append("manifest_format_not_stageable:" + V1)
    if any(
        e.get("anchor", {}).get("project_id") == q.reference.project_id
        for e in manifest.get("adoption_projects") or []
    ):
        problems.append("project_already_has_adoption_pin")
    if q.agent_settings is not None or q.agent_transitions:
        problems.append("anchor_agent_switching_tree_root_not_qualified")
    if not set(source_operations) & REPLY_OPERATIONS:
        problems.append("anchor_policy_has_no_reply_operations")
    if not re.fullmatch(SESSION_ID, target_id):
        problems.append("target_session_id_shape")
    # Chat-created and forked Roots are registered by the runtime; a tree
    # startup would have to baseline them too, and a child makes that fail.
    if target_id.startswith(BRIDGE_CREATED):
        problems.append("target_must_not_be_a_bridge_created_root")
    # Children can never be removed: certify must not grow an enrolled Root.
    if target_id in {b.reference.upstream_session_id for b in enrollment.backends}:
        problems.append("target_must_be_a_disposable_unenrolled_session")
    return problems


# --------------------------------------------------------------------------
# Native worker: runs as the enrolled Bridge client UID in a transient unit.
# --------------------------------------------------------------------------


class Wire:
    """Counts what reaches httpx; refuses foreign origins and any other mutation.

    ``attempts`` counts mutations httpx began; ``sent`` counts only those Native
    answered. The transport's write boundary can still refuse an attempt.
    """

    def __init__(self, base_url: str, target_id: str, *, allow_mutations: bool) -> None:
        import httpx

        url = httpx.URL(base_url)
        self.origin = (url.host, url.port)
        self.target_id, self.allow = target_id, allow_mutations
        self.nodes: set[str] = set()
        self.gets = 0
        self.failed_gets = 0
        self.attempts = {"prompt": 0, "permission.reply": 0}
        self.sent = {"prompt": 0, "permission.reply": 0}
        self.refused = 0
        self.foreign = 0
        self.response_bytes = 0
        self.unknown_length = 0
        self.statuses: list[list[Any]] = []

    def kind(self, request: Any) -> str | None:
        return mutation_kind(
            request.method, request.url.path, self.target_id, frozenset(self.nodes)
        )

    async def request(self, request: Any) -> None:
        if (request.url.host, request.url.port) != self.origin:
            self.foreign += 1
            raise CertifyError("non_native_origin_refused")
        if request.method == "GET":
            self.gets += 1
            need(self.gets <= MAX_NATIVE_GETS, "bounded_native_gets")
            return
        kind = self.kind(request)
        bound = MAX_PROMPTS if kind == "prompt" else MAX_PERMISSION_REPLIES
        if not self.allow or kind is None or self.attempts[kind] >= bound:
            self.refused += 1
            raise CertifyError("unexpected_native_mutation_refused")
        self.attempts[kind] += 1

    async def response(self, response: Any) -> None:
        request = response.request
        if request.method != "GET":
            self.statuses.append([request.method, request.url.path, response.status_code])
            kind = self.kind(request)
            if kind is not None:
                self.sent[kind] += 1  # Native answered, so the request reached it.
        elif response.status_code != 200:
            self.failed_gets += 1
        length = response.headers.get("content-length", "")
        if re.fullmatch(r"[0-9]{1,15}", length):
            self.response_bytes += int(length)
            need(self.response_bytes <= MAX_RESPONSE_BYTES, "bounded_native_response_bytes")
        else:
            self.unknown_length += 1

    def install(self, transport: Any) -> Wire:
        # First, ahead of the transport's own boundary hook: a real pool re-runs
        # before_send at the headers trace, after every hook.
        transport.client.event_hooks["request"].insert(0, self.request)
        transport.client.event_hooks["response"].append(self.response)
        return self


def one_attempt(wire: Wire, kind: str, slot: int) -> Callable[[], None]:
    """The before_send guard for the ``slot``-th mutation of ``kind``.

    The transport runs it before the request and again at its write boundary
    (headers and body), after the Wire hook already counted this very attempt:
    it is idempotent for that attempt and refuses only a further one.
    """

    def guard() -> None:
        need(wire.attempts[kind] <= slot, f"second_{kind}_attempt_refused")

    return guard


async def send_mutation(
    ctx: SimpleNamespace, kind: str, record: dict[str, Any], operation: str, **kwargs: Any
) -> Any:
    """One attempt through the Bridge transport; records whether Native got it."""
    from jt_oz_bridge.adapters.opencode.transport import TransportNotSent

    answered = ctx.wire.sent[kind]
    record["sent"] = "uncertain"
    try:
        value = await ctx.transport.request(operation, **kwargs)
    except TransportNotSent:
        record["sent"] = False  # refused before any byte left this process
        raise
    except BaseException:
        record["sent"] = True if ctx.wire.sent[kind] > answered else "uncertain"
        raise
    record["sent"] = True
    return value


class Audit:
    """Counts local opens of the workspace or Native database by this process."""

    def __init__(self, workspace: str, dataset: str) -> None:
        self.workspace = workspace.rstrip("/") + "/"
        self.dataset = dataset
        self.workspace_opens = self.database_opens = 0

    def __call__(self, event: str, args: tuple[Any, ...]) -> None:
        if event != "open" or not args:
            return
        path = args[0]
        if isinstance(path, bytes):
            path = path.decode(errors="replace")
        if not isinstance(path, (str, os.PathLike)):
            return
        path = os.fspath(path)
        if path.startswith(self.dataset):
            self.database_opens += 1
        if path == self.workspace[:-1] or path.startswith(self.workspace):
            self.workspace_opens += 1


class Recorder:
    """Wraps transport.request/events: digests GETs made inside observation windows.

    ``mutate`` may alter one decoded response for a negative check; Native
    itself is never changed. Event streams are digested frame by frame.
    """

    def __init__(self, transport: Any) -> None:
        self.transport = transport
        self.original, self.original_events = transport.request, transport.events
        self.active = False
        self.records: list[list[str]] = []
        self.streams: list[dict[str, Any]] = []
        self.mutate: Callable[[str, Any], bool] | None = None
        self.applied = 0

    async def request(self, operation: str, **kwargs: Any) -> Any:
        from jt_oz_bridge.adapters.opencode.transport import READ_OPERATIONS
        from jt_oz_bridge.storage.durable import digest

        value = await self.original(operation, **kwargs)
        if operation in READ_OPERATIONS:
            if self.active:
                self.records.append([operation, digest(value)])
            if self.mutate is not None:
                value = copy.deepcopy(value)
                self.applied += bool(self.mutate(operation, value))
        return value

    async def events(self, operation: str, **kwargs: Any) -> Any:
        entry: dict[str, Any] = {"operation": operation, "hash": hashlib.sha256(), "frames": 0}
        self.streams.append(entry)
        async for frame in self.original_events(operation, **kwargs):
            entry["hash"].update(f"{frame.event}\0{frame.event_id}\0{frame.data}\0".encode())
            entry["frames"] += 1
            yield frame

    def stream_records(self) -> list[list[str]]:
        # A stream yields frames only after Native answered 200 text/event-stream.
        return [[s["operation"], s["hash"].hexdigest()] for s in self.streams if s["frames"]]

    def install(self) -> Recorder:
        self.transport.request = self.request
        self.transport.events = self.events
        return self


@contextlib.contextmanager
def observing(ctx: SimpleNamespace, record: dict[str, Any]) -> Iterator[None]:
    """GET-only window: every request is recorded and no mutation may start."""
    before = sum(ctx.wire.attempts.values()) + ctx.wire.refused
    ctx.recorder.active = True
    try:
        yield
    finally:
        ctx.recorder.active = False
        delta = sum(ctx.wire.attempts.values()) + ctx.wire.refused - before
        record["mutations_during"] = record.get("mutations_during", 0) + delta


def context(job: dict[str, Any]) -> SimpleNamespace:
    """Pinned components, the same ones build_pipeline composes for the anchor."""
    import httpx

    from jt_oz_bridge.adapters.opencode.catalog import V2CatalogProject
    from jt_oz_bridge.adapters.opencode.contracts import OpenAPIProfile
    from jt_oz_bridge.adapters.opencode.existing_sessions import ExistingSessionProtocol
    from jt_oz_bridge.adapters.opencode.host_owner import HostOwnerEnrollment, LinuxHostOwnerProbe
    from jt_oz_bridge.adapters.opencode.lineage_resources import (
        LINEAGE_SEMANTICS,
        LineageResourceAttestation,
    )
    from jt_oz_bridge.adapters.opencode.model_settings import (
        MODEL_SETTING_SEMANTICS,
        ModelSettingsAttestation,
    )
    from jt_oz_bridge.adapters.opencode.project_policy import NativePolicyEnrollment
    from jt_oz_bridge.adapters.opencode.resources import READS
    from jt_oz_bridge.adapters.opencode.transport import ContractAttestation, V2HTTPTransport
    from jt_oz_bridge.config import load_settings
    from jt_oz_bridge.domain.catalog import ProjectScope
    from jt_oz_bridge.domain.models import SessionRef
    from jt_oz_bridge.security.json_data import strict_loads
    from jt_oz_bridge.security.root_files import root_bytes
    from jt_oz_bridge.security.secrets import resolve_secret
    from jt_oz_bridge.services.runtime_enrollment import adoption_protocol_sha256, read_enrollment

    settings = load_settings(Path(job["config"]))
    enrollment, _ = read_enrollment(settings)
    assert settings.runtime.enrollment_file is not None
    manifest = strict_loads(root_bytes(settings.runtime.enrollment_file))
    q = select_root(enrollment, project_id=job.get("project_id"), session_id=job.get("session_id"))
    anchor = q.reference
    owner_doc = HostOwnerEnrollment.model_validate(strict_loads(q.owner.read()))
    need(os.getuid() == owner_doc.client_uid, "enrolled_bridge_client_uid_required")
    policy = NativePolicyEnrollment.model_validate(strict_loads(q.policy.read()))
    need(policy.reference == anchor, "anchor_policy_reference")
    problems = root_preflight(q, manifest, enrollment, job["target_session_id"], policy.operations)
    need(not problems, f"root_not_certifiable:{problems}")
    target = anchor.model_copy(update={"upstream_session_id": job["target_session_id"]})
    configured = next(b for b in settings.opencode_backends if b.id == anchor.backend_id)
    profile = OpenAPIProfile(q.schema_file.read())
    transport = V2HTTPTransport(
        configured.base_url,
        profile,
        auth=httpx.BasicAuth(
            "opencode", resolve_secret(configured.credential_ref).get_secret_value()
        ),
        attestation=ContractAttestation(
            profile.sha256, anchor.backend_identity, owner_doc.version, q.verified_operations
        ),
    )
    model_doc = strict_loads(q.model_evidence.read())
    model_settings = ModelSettingsAttestation(
        SessionRef.model_validate(model_doc["reference"]),
        profile.sha256,
        MODEL_SETTING_SEMANTICS,
        q.model_evidence.sha256,
        qualification_scope=q.protocol_scope,
    )
    return SimpleNamespace(
        q=q,
        anchor=anchor,
        target=target,
        owner_doc=owner_doc,
        owner=LinuxHostOwnerProbe(owner_doc, q.owner_socket),
        profile=profile,
        policy=policy,
        transport=transport,
        projects={
            anchor.project_id: V2CatalogProject(
                ProjectScope(**anchor.model_dump(exclude={"upstream_session_id"})),
                q.native_project_id,
            )
        },
        # Exactly what V2ExistingSessionFactory hands its lineage providers.
        model_settings=model_settings if model_settings.qualification_scope == "backend" else None,
        anchor_model_settings=model_settings,
        protocol=ExistingSessionProtocol(
            anchor.backend_id,
            anchor.backend_identity,
            profile.sha256,
            adoption_protocol_sha256(q),
            q.verified_operations,
        ),
        operations=frozenset(adoption_operations(policy.operations)),
        attestation_for=lambda evidence_sha: LineageResourceAttestation(
            anchor.backend_id,
            anchor.backend_identity,
            profile.sha256,
            LINEAGE_SEMANTICS,
            evidence_sha,
            READS,
            qualification_scope="tree",
        ),
    )


async def allowed() -> bool:
    """The operator authority of this root-launched run; never a Human grant."""
    return True


@contextlib.asynccontextmanager
async def opened(ctx: SimpleNamespace) -> Any:
    """One feed for anchor and target with the runtime's metadata observer."""
    from jt_oz_bridge.adapters.opencode.existing_session_graph import (
        V2ExistingSessionGraphObserver,
    )
    from jt_oz_bridge.adapters.opencode.existing_sessions import V2ExistingSessionObserver
    from jt_oz_bridge.adapters.opencode.live import V2PublicFeed
    from jt_oz_bridge.adapters.opencode.project_policy import V2ProjectPolicyGuard
    from jt_oz_bridge.adapters.opencode.resources import V2LeafResourceProofs

    feed = V2PublicFeed(
        ctx.transport, ctx.owner, (ctx.anchor, ctx.target), receipts=None, capture_text=False
    )
    anchor = V2LeafResourceProofs(feed, ctx.projects, model_settings=ctx.anchor_model_settings)
    guard = V2ProjectPolicyGuard(anchor, {ctx.anchor: ctx.policy})
    observer = V2ExistingSessionObserver(guard, ctx.protocol, ctx.anchor)
    try:
        await feed.start()
        yield SimpleNamespace(
            feed=feed,
            guard=guard,
            observer=observer,
            graph=V2ExistingSessionGraphObserver(observer),
            leaf=V2LeafResourceProofs(feed, ctx.projects, model_settings=ctx.model_settings),
            known=set(),
            index=0,
        )
    finally:
        await feed.close()


def tree_view(
    ctx: SimpleNamespace, s: SimpleNamespace, graph: Any, evidence_sha: str
) -> SimpleNamespace:
    """The lineage provider, per-node policy guard and client the factory would build."""
    from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
    from jt_oz_bridge.adapters.opencode.lineage_policy import V2LineagePolicyGuard
    from jt_oz_bridge.adapters.opencode.lineage_resources import V2LineageResourceProofs
    from jt_oz_bridge.adapters.opencode.project_policy import (
        PERMISSION_SOURCE,
        NativePolicyEnrollment,
    )
    from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA

    proofs = V2LineageResourceProofs(
        s.feed,
        ctx.projects,
        graph,
        ctx.attestation_for(evidence_sha),
        current=s.graph.current,
        model_settings=ctx.model_settings,
    )
    enrollments = {
        node.reference: NativePolicyEnrollment.model_validate(
            {
                "format": "native-project-policy-v1",
                "reference": node.reference,
                "native_project_id": node.native_project_id,
                "contract_sha256": INSTALLED_SCHEMA,
                "permission_source_sha256": PERMISSION_SOURCE,
                "fingerprint_sha256": node.policy_sha256,
                "operations": ctx.operations,
            }
        )
        for node in graph.nodes
    }
    guard = V2LineagePolicyGuard(proofs, enrollments)
    client = V2ExecutionClient(ctx.transport, ctx.projects, proofs=proofs, scope_guard=guard)
    return SimpleNamespace(
        graph=graph, proofs=proofs, guard=guard, client=client, enrollments=enrollments
    )


def node_rows(graph: Any) -> list[dict[str, Any]]:
    depth = {graph.reference: 0}
    rows = []
    for node in graph.nodes:  # breadth-first: parents precede children
        parent = node.parent_reference
        if parent is not None:
            depth[node.reference] = depth[parent] + 1
        rows.append(
            {
                "id": node.reference.upstream_session_id,
                "parent": parent.upstream_session_id if parent is not None else None,
                "depth": depth[node.reference],
                "created": node.native_created_at,
                "origin_sha256": node.origin_sha256,
                "policy_sha256": node.policy_sha256,
                "session_info_sha256": node.session_info_sha256,
                "progress_info_sha256": node.progress_info_sha256,
            }
        )
    return rows


async def observe_tree(
    ctx: SimpleNamespace,
    s: SimpleNamespace,
    record: dict[str, Any],
    evidence_sha: str,
    pending: tuple[tuple[str, str], ...],
) -> SimpleNamespace:
    """One complete fresh observation of the target's tree through the lineage stack."""
    assert s.feed.index is not None
    record["connection_epoch"] = s.feed.index.require_live()
    graph = await s.graph.observe(ctx.target, authorize=allowed)
    view = tree_view(ctx, s, graph, evidence_sha)
    await view.proofs.watch_graph(authorize=allowed)
    snapshots, proofs = [], {}
    for node in graph.nodes:
        ref = node.reference
        snapshot, proof = await view.client.qualified_snapshot(ref)
        witness = view.proofs.witnesses[ref]
        proofs[ref.upstream_session_id] = proof
        snapshots.append(
            {
                "id": ref.upstream_session_id,
                "state": str(snapshot.state),
                "reconciled": snapshot.reconciled,
                "descendants": sorted(d.upstream_session_id for d in snapshot.descendants),
                "cursor": proof.cursor,
                "resource_fence": proof.resource_fence,
                "issued_at": proof.issued_at,
                "expires_at": proof.expires_at,
                "connection_epoch": proof.connection_epoch,
                "owner_epoch": witness.owner_epoch,
                "state_only_fence": witness.state_only_fence,
                "pending": [list(p) for p in witness.pending],
            }
        )
    interactions = []
    root_epoch = proofs[ctx.target.upstream_session_id].connection_epoch
    for session_id, request_id in pending:
        ref = ctx.target.model_copy(update={"upstream_session_id": session_id})
        interactions.append(
            {
                "id": session_id,
                "request": request_id,
                "kind_on_node": await view.proofs.interaction_kind(
                    ref, request_id, proofs[session_id].connection_epoch
                ),
                "kind_on_root": await view.proofs.interaction_kind(
                    ctx.target, request_id, root_epoch
                ),
            }
        )
    root_proof = proofs[ctx.target.upstream_session_id]
    record.update(
        graph=graph.model_dump(mode="json"),
        graph_sha256=graph.graph_sha256,
        owner_epoch=graph.owner_epoch,
        nodes=node_rows(graph),
        provider_descendants={
            n.reference.upstream_session_id: sorted(
                d.upstream_session_id for d in view.proofs.descendants(n.reference)
            )
            for n in graph.nodes
        },
        snapshots=snapshots,
        interactions=interactions,
        root_dispatch=rejected_now(lambda: view.proofs.dispatch_owner_epoch(ctx.target, root_proof))
        or "dispatchable",
    )
    return view


async def window(
    ctx: SimpleNamespace,
    s: SimpleNamespace,
    label: str,
    result: dict[str, Any],
    *,
    pending: tuple[tuple[str, str], ...] = (),
    required: bool = False,
) -> SimpleNamespace | None:
    """A bounded number of attempts at one GET-only tree observation.

    Optional windows leave room for every later required one; skipping one
    never stops a running turn halfway.
    """
    used = len(result["windows"])
    if not required and used >= MAX_WINDOWS - 2 * MAX_PROMPTS:
        result["windows_skipped"] = result.get("windows_skipped", 0) + 1
        return None
    need(used < MAX_WINDOWS, "observation_window_bound")
    record: dict[str, Any] = {"label": label, "feed": s.index, "ok": False, "errors": []}
    result["windows"].append(record)
    with observing(ctx, record):
        for _ in range(WINDOW_ATTEMPTS):
            try:
                view = await observe_tree(ctx, s, record, result["candidate"], pending)
            except ValueError as error:  # ContractError, boundary changes, pydantic
                record["errors"].append(f"{type(error).__name__}:{str(error)[:200]}")
                continue
            record["ok"] = True
            return view
    return None


async def rejected(call: Awaitable[Any]) -> str | None:
    try:
        await call
    except Exception as error:  # ContractError, AccessDenied, pydantic errors included
        return f"{type(error).__name__}:{str(error)[:200]}"
    return None


def rejected_now(call: Callable[[], Any]) -> str | None:
    try:
        call()
    except Exception as error:
        return f"{type(error).__name__}:{str(error)[:200]}"
    return None


async def wait_until(deadline: float) -> None:
    await asyncio.sleep(max(0.0, deadline - time.time()) + 0.1)


def requests(ctx: SimpleNamespace) -> int:
    return int(ctx.wire.gets + sum(ctx.wire.attempts.values()))


async def check_leaf_before(ctx: SimpleNamespace, s: SimpleNamespace) -> dict[str, Any]:
    """The leaf provider still accepts the childless target (a positive control)."""
    try:
        witness = await s.leaf.watch(ctx.target, require_idle=True)
    except Exception as error:
        return {"error": f"{type(error).__name__}:{str(error)[:200]}", "state": None}
    finally:
        s.leaf.revoke_watch(ctx.target)
    return {"error": None, "state": str(witness.state)}


async def check_leaf_refused(ctx: SimpleNamespace, s: SimpleNamespace) -> dict[str, Any]:
    """The production leaf provider refuses the same target once it has a child."""
    error = await rejected(s.leaf.watch(ctx.target))
    s.leaf.revoke_watch(ctx.target)
    return {"error": error}


async def check_unseen(ctx: SimpleNamespace, view: SimpleNamespace) -> dict[str, Any]:
    """A provider built before a child existed refuses the tree that has it."""
    errors = []
    for _ in range(WINDOW_ATTEMPTS):
        error = await rejected(view.client.qualified_snapshot(ctx.target))
        errors.append(error)
        if error is None or any(code in error for code in UNSEEN_ERRORS):
            break
    return {"error": errors[-1], "attempts": errors}


async def check_foreign(ctx: SimpleNamespace, view: SimpleNamespace) -> dict[str, Any]:
    """The anchor itself is outside the observed tree: refused before any request."""
    before = requests(ctx)
    seen = {
        "foreign_reference": ctx.anchor.model_dump(mode="json"),
        "select": rejected_now(lambda: view.proofs.select(ctx.anchor)),
        "snapshot": await rejected(view.client.qualified_snapshot(ctx.anchor)),
    }
    return seen | {"native_requests": requests(ctx) - before}


class ChangedOwner:
    """The real owner proof seen through a different epoch; Native is untouched."""

    owner_epoch = "0" * 64

    def __init__(self, real: Any) -> None:
        self._real = real

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


async def check_owner(ctx: SimpleNamespace, s: SimpleNamespace, view: Any) -> dict[str, Any]:
    real = s.feed.current_owner

    async def changed() -> Any:
        return ChangedOwner(await real())

    # The same view proves the target first, so a refusal is the owner's doing.
    control = await rejected(view.client.qualified_snapshot(ctx.target))
    s.feed.current_owner = changed  # instance attribute over the bound method
    try:
        error = await rejected(view.client.qualified_snapshot(ctx.target))
    finally:
        del s.feed.current_owner
    return {
        "injected_at": "owner-probe-result",
        "control": control,
        "snapshot": error,
        "current_proof_after": view.proofs.current_proof(ctx.target) is not None,
    }


def change_agent_rules(operation: str, value: Any) -> bool:
    """Drop (or add) one agent permission rule in a decoded agent.get response."""
    if operation != "agent.get" or not isinstance(value.get("data"), dict):
        return False
    rules = value["data"].get("permissions")
    if isinstance(rules, list) and rules:
        rules.pop()
    else:
        value["data"]["permissions"] = [{"action": "*", "resource": "*", "effect": "deny"}]
    return True


async def check_policy(ctx: SimpleNamespace, view: Any, child: Any) -> dict[str, Any]:
    """A real reply authorization passes, then a changed agent policy is refused."""
    from jt_oz_bridge.adapters.opencode.lineage_policy import V2LineagePolicyGuard

    _, proof = await view.client.qualified_snapshot(child)
    seen: dict[str, Any] = {
        "child": child.upstream_session_id,
        "control": await rejected(view.guard.authorize(child, "permission.reply", proof)),
    }
    _, proof = await view.client.qualified_snapshot(child)
    applied = ctx.recorder.applied
    ctx.recorder.mutate = change_agent_rules
    try:
        seen["tampered"] = await rejected(view.guard.authorize(child, "permission.reply", proof))
    finally:
        ctx.recorder.mutate = None
    seen["pages_changed"] = ctx.recorder.applied - applied
    root = view.enrollments[ctx.target]
    inherited = dict(view.enrollments)
    inherited[child] = inherited[child].model_copy(
        update={"fingerprint_sha256": root.fingerprint_sha256}
    )
    seen["inherited_enrollment"] = rejected_now(
        lambda: V2LineagePolicyGuard(view.proofs, inherited)
    )
    return seen


async def check_settled(ctx: SimpleNamespace, view: Any, result: dict[str, Any]) -> dict[str, Any]:
    """Two idle proofs agree exactly; the settled boundary moved past every active one."""
    from jt_oz_bridge.storage.durable import digest

    first_snapshot, first = await view.client.qualified_snapshot(ctx.target)
    first_witness = view.proofs.witnesses[ctx.target]
    second_snapshot, second = await view.client.qualified_snapshot(ctx.target)
    second_witness = view.proofs.witnesses[ctx.target]
    owner = None
    with contextlib.suppress(ValueError):
        owner = view.proofs.dispatch_owner_epoch(ctx.target, second)
    pages: dict[str, list[str]] = {}
    for node in view.graph.nodes:
        sid = {"sessionID": node.reference.upstream_session_id}
        pages[node.reference.upstream_session_id] = [
            digest(
                await ctx.transport.request(
                    "session.message.list", path=sid, query={"limit": "1", "order": "desc"}
                )
            )
            for _ in range(2)
        ]
    earlier = next(
        (
            s["cursor"]
            for w in result["windows"]
            if w.get("ok")
            for s in w.get("snapshots") or []
            if s["id"] == ctx.target.upstream_session_id and s["state"] != "idle"
        ),
        None,
    )
    return {
        "states": [str(first_snapshot.state), str(second_snapshot.state)],
        "state_only": [first_witness.state_only_fence, second_witness.state_only_fence],
        "cursors": [first.cursor, second.cursor],
        "fences": [first.resource_fence, second.resource_fence],
        "dispatch_owner": owner,
        "earlier_active_cursor": earlier,
        "pages": pages,
    }


async def check_deadline(
    ctx: SimpleNamespace,
    view: Any,
    expire: Callable[[float], Awaitable[None]] = wait_until,
) -> dict[str, Any]:
    """A fresh current proof authorizes nothing past its five seconds, with no new request.

    The proof must be current right before the wait; otherwise every "after"
    refusal would hold for another reason and prove nothing about the deadline.
    """
    _, proof = await view.client.qualified_snapshot(ctx.target)
    before = requests(ctx)
    current_before = view.proofs.proof_current(ctx.target, proof)
    valid_before = view.proofs.valid_fence(ctx.target, proof.resource_fence)
    await expire(proof.expires_at)
    return {
        "issued_at": proof.issued_at,
        "expires_at": proof.expires_at,
        "proof_current_before": current_before,
        "valid_fence_before": valid_before,
        "current_proof_after": view.proofs.current_proof(ctx.target) is not None,
        "valid_fence_after": view.proofs.valid_fence(ctx.target, proof.resource_fence),
        "proof_current_after": view.proofs.proof_current(ctx.target, proof),
        "client_current_after": rejected_now(lambda: view.client.current(ctx.target, proof)),
        "dispatch_after": rejected_now(lambda: view.proofs.dispatch_owner_epoch(ctx.target, proof)),
        "native_requests": requests(ctx) - before,
    }


async def target_quiet(ctx: SimpleNamespace, nodes: Mapping[str, Mapping[str, Any]]) -> str | None:
    """Positive Idle with nothing pending anywhere in the tree; the latest Idle id."""
    from jt_oz_bridge.adapters.opencode.aborted_turn import aborted_head

    t = ctx.transport
    active = (await t.request("session.active"))["data"]
    for session_id in nodes:
        sid = {"sessionID": session_id}
        need(session_id not in active, "tree_busy")
        need(not (await t.request("session.permission.list", path=sid))["data"], "tree_pending")
        need(not (await t.request("session.form.list", path=sid))["data"], "tree_pending")
    sid = {"sessionID": ctx.target.upstream_session_id}
    need(not (await t.request("session.inbox.list", path=sid))["data"], "target_has_queued_input")
    latest = (
        await t.request("session.message.list", path=sid, query={"limit": "1", "order": "desc"})
    )["data"]
    # A declined permission ends its turn without an Idle; the leaf provider's
    # require_idle watch has already reconciled that exact tail. Only before
    # this run's first prompt; afterwards only an Idle counts.
    untouched = not any(ctx.wire.attempts.values())
    need(
        not latest or latest[0]["type"] == "idle" or untouched and aborted_head(latest[0]),
        "target_latest_message_not_idle",
    )
    return latest[0]["id"] if latest else None


async def child_rows(t: Any, parent: str) -> list[dict[str, Any]]:
    """Every direct child of ``parent``, following cursors like the runtime graph.

    OpenCode 2.0.32 returns a ``next`` cursor even on a short page; only the
    following empty page has none.
    """
    rows: list[dict[str, Any]] = []
    cursor: str | None = None
    seen: set[str] = set()
    for _ in range(MAX_CHILD_PAGES):
        query = {"parentID": parent, "limit": "100", "order": "asc"}
        if cursor is not None:
            query["cursor"] = cursor
        page = await t.request("session.list", query=query)
        need(len(page["data"]) <= 100, "child_page_bound")
        rows.extend(page["data"])
        need(len(rows) <= MAX_NODES, "tree_node_bound")
        cursor = page["cursor"].get("next")
        if cursor is None:
            return rows
        need(
            bool(cursor) and len(cursor) <= 8192 and cursor not in seen,
            "child_cursor_not_progressing",
        )
        seen.add(cursor)
    raise CertifyError("child_page_bound")


async def discover(
    ctx: SimpleNamespace, s: SimpleNamespace, result: dict[str, Any]
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """GET the complete current tree; verify and enroll new descendants."""
    t, target = ctx.transport, ctx.target
    nodes: dict[str, dict[str, Any]] = {target.upstream_session_id: {"parent": None, "depth": 0}}
    queue = [target.upstream_session_id]
    while queue:
        parent = queue.pop(0)
        for row in await child_rows(t, parent):
            problem = child_row_problem(
                row,
                parent_id=parent,
                native_project_id=ctx.q.native_project_id,
                canonical_directory=target.canonical_directory,
            )
            need(problem is None, f"child_refused:{problem}")
            need(row["id"] not in nodes, "child_duplicate_or_cycle")
            nodes[row["id"]] = {"parent": parent, "depth": nodes[parent]["depth"] + 1}
            need(len(nodes) <= MAX_NODES, "tree_node_bound")
            queue.append(row["id"])
            if row["id"] not in result["discovered"]:
                result["discovered"][row["id"]] = {
                    "parent": parent,
                    "depth": nodes[row["id"]]["depth"],
                    "created": row["time"]["created"],
                    "agent": row.get("agent"),
                    "project_matches": row["projectID"] == ctx.q.native_project_id,
                    "directory_matches": row["location"]["directory"] == target.canonical_directory,
                    "step": result["stage"],
                }
    new = [sid for sid in nodes if sid != target.upstream_session_id and sid not in s.known]
    for session_id in new:
        ref = target.model_copy(update={"upstream_session_id": session_id})
        await s.feed.enroll_reference(ref, authorize=allowed)
        s.known.add(session_id)
        ctx.wire.nodes.add(session_id)
    return nodes, new


async def answer(
    ctx: SimpleNamespace,
    step: dict[str, Any],
    item: dict[str, Any],
    node_id: str,
    depth: int,
    result: dict[str, Any],
) -> None:
    from jt_oz_bridge.storage.durable import digest

    try:
        ctx.profile.validate(
            "component:Permission.Request",
            {"$ref": "#/components/schemas/Permission.Request"},
            item,
        )
        decision, reason = permission_decision(
            item,
            node_id=node_id,
            depth=depth,
            canonical_directory=ctx.target.canonical_directory,
            step=step,
        )
    except ValueError:
        # Never leave a node blocked on a request we cannot read: refuse it.
        decision, reason = "reject", "request_shape_unqualified"
    need(isinstance(item.get("id"), str), "permission_request_without_id")
    resources = [r for r in item.get("resources") or [] if isinstance(r, str)]
    reply = {
        "step": step["step"],
        "session_id": node_id,
        "depth": depth,
        "request_sha256": digest(item),
        "action": str(item.get("action"))[:64],
        "resources": resources if decision == "once" else None,
        "resource_sha256": [sha(r.encode()) for r in resources],
        "decision": decision,
        "reason": reason,
        "sent": False,
    }
    result["permission_replies"].append(reply)
    slot = len(result["permission_replies"])
    need(slot <= MAX_PERMISSION_REPLIES, "reply_bound")
    await send_mutation(
        ctx,
        "permission.reply",
        reply,
        "session.permission.reply",
        path={"sessionID": node_id, "requestID": item["id"]},
        body={"decision": decision},
        before_send=one_attempt(ctx.wire, "permission.reply", slot),
    )
    # A reject ends the step; nothing else is sent to make it succeed.
    need(decision == "once", f"permission_refused:{reason}")


async def run_step(
    ctx: SimpleNamespace,
    s: SimpleNamespace,
    step: dict[str, Any],
    job: dict[str, Any],
    result: dict[str, Any],
) -> SimpleNamespace:
    """One operator prompt; observe the tree as it grows, waits and settles."""
    from jt_oz_bridge.storage.durable import digest

    t, target, name = ctx.transport, ctx.target, step["step"]
    nodes, _ = await discover(ctx, s, result)
    idle_before = await target_quiet(ctx, nodes)
    before = await window(ctx, s, f"{name}:before", result, required=True)
    need(before is not None, "tree_not_observable_before_prompt")
    assert before is not None
    action_id = uuid.uuid4().hex
    source = prompt_source(tag=job["tag"], step=name, action_id=action_id, text=step["text"])
    body = prompt_body(step["text"], action_id, digest(source))
    record: dict[str, Any] = {
        "step": name,
        "action_id": action_id,
        "operation_digest": digest(source),
        "operator_source": source,
        "admitted": False,
        "sent": False,
    }
    result["prompts"].append(record)
    slot = len(result["prompts"])
    need(slot <= MAX_PROMPTS, "prompt_bound")
    value = await send_mutation(
        ctx,
        "prompt",
        record,
        "session.prompt",
        path={"sessionID": target.upstream_session_id},
        body=body,
        before_send=one_attempt(ctx.wire, "prompt", slot),
    )
    raw = value["data"]
    need(
        raw["sessionID"] == target.upstream_session_id
        and raw["payload"]["text"] == step["text"]
        and raw["delivery"] == "queue"
        and raw["payload"].get("metadata", {}).get("jt_oz_bridge")
        == body["metadata"]["jt_oz_bridge"]
        and not raw["payload"].get("files"),
        "prompt_acknowledgement_mismatch",
    )
    record.update(admitted=True, upstream_id=raw["id"])
    deadline = time.monotonic() + TURN_SECONDS
    answered: set[str] = set()
    running = 0
    while True:
        need(time.monotonic() < deadline, "turn_deadline_exceeded_left_running")
        nodes, new = await discover(ctx, s, result)
        if new:
            negatives = result["negatives"]
            unseen = negatives.setdefault("unseen", [])
            if len(unseen) < s.index + 1:  # once per step, on this step's feed
                with observing(ctx, result["negative_reads"]):
                    unseen.append(await check_unseen(ctx, before))
                    if "leaf_refused" not in negatives:
                        negatives["leaf_refused"] = await check_leaf_refused(ctx, s)
            await window(ctx, s, f"{name}:grown", result)
        pending = []
        for session_id, node in nodes.items():
            sid = {"sessionID": session_id}
            forms = (await t.request("session.form.list", path=sid))["data"]
            need(not forms, "tree_asked_a_question_left_pending")
            for item in (await t.request("session.permission.list", path=sid))["data"]:
                if item.get("id") not in answered:
                    pending.append((session_id, node["depth"], item))
        for session_id, depth, item in pending:
            answered.add(str(item.get("id")))
            # Observe the real waiting node before answering it.
            await window(
                ctx,
                s,
                f"{name}:waiting",
                result,
                pending=((session_id, str(item.get("id"))),),
                required=True,
            )
            await answer(ctx, step, item, session_id, depth, result)
            await window(ctx, s, f"{name}:resumed", result)
        active = (await t.request("session.active"))["data"]
        if not pending:
            busy = [sid for sid, node in nodes.items() if sid in active and node["depth"] >= 1]
            if busy and running < MAX_RUNNING_WINDOWS:
                running += 1
                await window(ctx, s, f"{name}:running", result)
            latest = (
                await t.request(
                    "session.message.list",
                    path={"sessionID": target.upstream_session_id},
                    query={"limit": "1", "order": "desc"},
                )
            )["data"]
            if (
                latest
                and latest[0]["type"] == "idle"
                and latest[0]["id"] != idle_before
                and not any(sid in active for sid in nodes)
            ):
                record["outcome"] = latest[0].get("outcome")
                break
        await asyncio.sleep(POLL_SECONDS)
    settled = await window(ctx, s, f"{name}:settled", result, required=True)
    need(settled is not None, "tree_not_observable_after_settling")
    assert settled is not None
    return settled


async def scan_activation(ctx: SimpleNamespace) -> dict[str, Any]:
    """GET only: does the anchor, or any chat-created Root of its project, have a child?"""
    t, anchor = ctx.transport, ctx.anchor

    async def has_child(session_id: str) -> bool:
        page = await t.request(
            "session.list", query={"parentID": session_id, "limit": "1", "order": "asc"}
        )
        return bool(page["data"]) or page["cursor"].get("next") is not None

    roots: list[str] = []
    cursor: str | None = None
    cursors: set[str] = set()
    for _ in range(MAX_ROOT_PAGES):
        query = {
            "directory": anchor.canonical_directory,
            "project": ctx.q.native_project_id,
            "parentID": "null",
            "limit": "100",
            "order": "desc",
        }
        if cursor is not None:
            query["cursor"] = cursor
        page = await t.request("session.list", query=query)
        roots += [row["id"] for row in page["data"] if isinstance(row.get("id"), str)]
        cursor = page["cursor"].get("next")
        if cursor is None:
            break
        need(cursor not in cursors and len(cursor) <= 8192, "project_root_cursor_not_progressing")
        cursors.add(cursor)
    else:
        raise CertifyError("project_root_listing_bound")
    created = sorted({sid for sid in roots if sid.startswith(BRIDGE_CREATED)})
    return {
        "anchor_has_children": await has_child(anchor.upstream_session_id),
        "project_roots": len(set(roots)),
        "bridge_created_roots": len(created),
        "bridge_created_roots_with_children": [sid for sid in created if await has_child(sid)],
    }


async def target_policy(ctx: SimpleNamespace, s: SimpleNamespace) -> dict[str, Any]:
    """What the operator needs to judge whether the planned asks will be asked."""
    _origin, facts, _info, _progress = await s.observer.bundle(ctx.target, None)
    return {
        "agent": facts["agent"],
        "session_permissions": facts["session_permissions"],
        "mcp": [m.get("name") for m in facts["mcp"]],
        "saved_permissions": len(facts["saved_permissions"]),
    }


async def worker_main(job: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Fills ``result`` in place so a timeout still reports what happened."""
    from jt_oz_bridge.storage.durable import digest

    mode = job["mode"]
    if mode == "certify":
        need(job.get("confirmed_operator_prompts") is True, "explicit_operator_prompt_flag")
    ctx = context(job)
    t = ctx.transport
    ctx.audit = Audit(ctx.target.canonical_directory, ctx.owner_doc.dataset_path)
    sys.addaudithook(ctx.audit)
    ctx.wire = Wire(
        str(t.client.base_url), ctx.target.upstream_session_id, allow_mutations=mode == "certify"
    ).install(t)
    ctx.recorder = Recorder(t).install()
    plan = operator_plan(job["tag"])
    plan_sha = plan_sha256(
        plan,
        anchor=ctx.anchor.model_dump(mode="json"),
        target=ctx.target.model_dump(mode="json"),
        policy_sha256=ctx.policy.fingerprint_sha256,
        tool_sha256=job["tool_sha256"],
    )
    result.update(
        {
            "mode": mode,
            "tag": job["tag"],
            "stage": "start",
            "error": None,
            "target": ctx.target.upstream_session_id,
            "target_reference": ctx.target.model_dump(mode="json"),
            "plan_sha256": plan_sha,
            "candidate": candidate_attestation(tag=job["tag"], plan_sha=plan_sha),
            "prompts": [],
            "permission_replies": [],
            "turns_completed": 0,
            "discovered": {},
            "windows": [],
            "negatives": {},
            "negative_reads": {"mutations_during": 0},
            "owner_before": None,
            "owner_after": None,
        }
    )
    result["candidate_attestation_sha256"] = result["candidate"]
    try:
        result["owner_before"] = (await ctx.owner.read()).model_dump(mode="json")
        epoch = result["owner_before"]["owner_epoch"]

        async def same_owner() -> bool:
            observed = await ctx.owner.read()
            return (
                observed.owner_epoch == epoch
                and observed.backend_identity == ctx.anchor.backend_identity
                and observed.version == ctx.owner_doc.version
            )

        t.verify_identity = same_owner
        result["stage"] = "preflight"
        if mode == "anchor":
            result["activation"] = await scan_activation(ctx)
            result["owner_after"] = (await ctx.owner.read()).model_dump(mode="json")
            result["stage"] = "anchor-checked"
            return result
        async with opened(ctx) as s:
            first, _ = await s.guard._bundle_facts(ctx.anchor)
            second, _ = await s.guard._bundle_facts(ctx.anchor)
            need(digest(first) == digest(second), "anchor_policy_facts_unstable")
            need(digest(first) == ctx.policy.fingerprint_sha256, "anchor_policy_drifted_from_pin")
            info = (
                await t.request("session.get", path={"sessionID": ctx.target.upstream_session_id})
            )["data"]
            need("parentID" not in info, "target_must_be_a_top_level_session")
            need(
                "jt_oz_bridge" not in (info.get("metadata") or {}),
                "target_must_not_be_a_bridge_created_root",
            )
            need(info.get("projectID") == ctx.q.native_project_id, "target_foreign_project")
            need(
                info.get("location") == {"directory": ctx.target.canonical_directory},
                "target_foreign_directory",
            )
            result["activation"] = await scan_activation(ctx)
            nodes, _ = await discover(ctx, s, result)
            result["target_children"] = len(nodes) - 1
            result["target_policy"] = await target_policy(ctx, s)
            result["idle_before"] = await target_quiet(ctx, nodes)
            with observing(ctx, result["negative_reads"]):
                result["negatives"]["leaf_before"] = await check_leaf_before(ctx, s)
            if mode != "certify":
                view = await window(ctx, s, "plan:before", result, required=True)
                result["lineage_stack_composed"] = view is not None
        if mode != "certify":
            result["owner_after"] = (await ctx.owner.read()).model_dump(mode="json")
            result["stage"] = "planned"
            return result
        need(plan_sha == job["expected_plan_sha256"], "plan_changed_since_plan")
        need(result["target_children"] == 0, "target_must_be_childless_before_certify")
        last = None
        for index, step in enumerate(plan["steps"]):
            result["stage"] = "turn:" + step["step"]
            async with opened(ctx) as s:
                s.index = index
                last = await run_step(ctx, s, step, job, result)
                result["turns_completed"] = index + 1
                if index + 1 < len(plan["steps"]):
                    continue
                result["stage"] = "negatives"
                need(len(last.graph.nodes) >= 2, "no_descendant_observed")
                children = [n.reference for n in last.graph.nodes if n.parent_reference]
                negatives = result["negatives"]
                with observing(ctx, result["negative_reads"]):
                    negatives["policy"] = await check_policy(ctx, last, children[0])
                    negatives["settled"] = await check_settled(ctx, last, result)
                    negatives["deadline"] = await check_deadline(ctx, last)
                    negatives["foreign"] = await check_foreign(ctx, last)
                    # Last: an injected owner revokes this view's current proofs.
                    negatives["owner"] = await check_owner(ctx, s, last)
        result["owner_after"] = (await ctx.owner.read()).model_dump(mode="json")
        result["stage"] = "observed"
    except Exception as error:  # report everything; root decides what is written
        result["error"] = f"{type(error).__name__}:{error}"[:500]
        if result["owner_after"] is None:
            with contextlib.suppress(Exception):
                result["owner_after"] = (await ctx.owner.read()).model_dump(mode="json")
    finally:
        result["observation_mutation_attempts"] = sum(
            w.get("mutations_during", 0) for w in result["windows"]
        ) + result["negative_reads"].get("mutations_during", 0)
        result["rpc_records"] = ctx.recorder.records + ctx.recorder.stream_records()
        result["native_get_count"] = ctx.wire.gets
        result["failed_gets"] = ctx.wire.failed_gets
        result["native_mutations"] = dict(ctx.wire.sent)
        result["native_mutation_attempts"] = dict(ctx.wire.attempts)
        result["refused_native_requests"] = ctx.wire.refused
        result["non_native_requests"] = ctx.wire.foreign
        result["native_response_bytes"] = ctx.wire.response_bytes
        result["responses_without_length"] = ctx.wire.unknown_length
        result["native_statuses"] = ctx.wire.statuses
        result["workspace_opens"] = ctx.audit.workspace_opens
        result["native_database_opens"] = ctx.audit.database_opens
        result["observed_at"] = time.time()
        await t.close()
    return result


def cmd_worker(job: dict[str, Any], confirmed: bool) -> None:
    need(job.get("mode") in {"plan", "certify", "anchor"}, "worker_mode")
    if job["mode"] == "certify":
        need(confirmed, "explicit_operator_prompt_flag_required")
        job["confirmed_operator_prompts"] = True
    result: dict[str, Any] = {"mode": job["mode"], "prompts": []}

    async def bounded() -> None:
        async with asyncio.timeout(WORKER_SECONDS - 60):
            await worker_main(job, result)

    try:
        asyncio.run(bounded())
    except BaseException as error:  # e.g. timeout: keep the partial transcript
        result["error"] = result.get("error") or f"{type(error).__name__}:{error}"[:500]
    print(json.dumps(result, ensure_ascii=False, allow_nan=False, default=str))


# --------------------------------------------------------------------------
# Root wrapper: reads pins, launches the worker, writes root-owned outputs.
# --------------------------------------------------------------------------


class Spec:
    def __init__(self, path: Path) -> None:
        raw = json.loads(path.read_bytes())
        need(isinstance(raw, dict), "spec_object_required")
        self.tag: str = raw["tag"]
        cert_directory(self.tag)
        self.project_id: str | None = raw.get("project_id")
        self.session_id: str | None = raw.get("session_id")
        need(
            (self.project_id is None) != (self.session_id is None),
            "spec_requires_exactly_one_of_project_id_or_session_id",
        )
        self.target_session_id = raw.get("target_session_id")
        need(
            isinstance(self.target_session_id, str)
            and re.fullmatch(SESSION_ID, self.target_session_id),
            "spec_target_session_id_required",
        )
        self.config = Path(raw.get("config", "/etc/jt-oz-bridge/config.toml"))
        self.observer = Path(raw.get("observer", "/etc/jt-oz-bridge/local-observer.json"))
        self.output = Path(raw.get("output", f"/etc/jt-oz-bridge/lineage-{self.tag}"))
        self.stage = Path(raw.get("stage", f"/etc/jt-oz-bridge/runtime-lineage-{self.tag}"))
        for value in (self.config, self.observer, self.output, self.stage):
            need(value.is_absolute() and ".." not in value.parts, "spec_paths_absolute")

    def job(self, mode: str, tool_sha256: str) -> dict[str, Any]:
        return {
            "mode": mode,
            "tag": self.tag,
            "config": str(self.config),
            "project_id": self.project_id,
            "session_id": self.session_id,
            "target_session_id": self.target_session_id,
            "tool_sha256": tool_sha256,
        }


def root_ancestry(path: Path) -> None:
    """Every existing ancestor root-owned and not group/other writable."""
    for directory in reversed(path.parents):
        info = directory.lstat()
        need(
            stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            f"root_managed_ancestry_required:{directory}",
        )


def write_new(path: Path, raw: bytes, *, group: int = 0, mode: int = 0o640) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        os.fchown(stream.fileno(), 0, group)
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def new_directory(path: Path, group: int) -> None:
    root_ancestry(path)
    need(not os.path.lexists(path), f"output_directory_exists_refused:{path}")
    path.mkdir(mode=0o750)
    os.chown(path, 0, group)
    os.chmod(path, 0o750)


def load_target(spec: Spec) -> tuple[Any, Any, Any, dict[str, Any], Any, Any]:
    from jt_oz_bridge.adapters.opencode.host_owner import HostOwnerEnrollment
    from jt_oz_bridge.adapters.opencode.project_policy import NativePolicyEnrollment
    from jt_oz_bridge.config import load_settings
    from jt_oz_bridge.security.json_data import strict_loads
    from jt_oz_bridge.security.root_files import root_bytes
    from jt_oz_bridge.services.runtime_enrollment import read_enrollment

    settings = load_settings(spec.config)
    enrollment, _ = read_enrollment(settings)
    assert settings.runtime.enrollment_file is not None
    manifest = strict_loads(root_bytes(settings.runtime.enrollment_file))
    q = select_root(enrollment, project_id=spec.project_id, session_id=spec.session_id)
    owner_doc = HostOwnerEnrollment.model_validate(strict_loads(q.owner.read()))
    policy = NativePolicyEnrollment.model_validate(strict_loads(q.policy.read()))
    return q, owner_doc, policy, manifest, settings, enrollment


def host_state(unit: str) -> dict[str, Any]:
    """Native process identity from systemd and /proc; its database is never touched."""
    out = subprocess.run(
        ["systemctl", "show", unit, "-p", "MainPID", "-p", "InvocationID", "-p", "NRestarts"],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    ).stdout
    props = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    pid = int(props["MainPID"])
    need(pid > 1, "native_not_running")
    ticks = int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19])
    # /proc/PID/exe is a kernel-produced link to the running binary.
    with open(f"/proc/{pid}/exe", "rb") as binary:
        digest = hashlib.file_digest(binary, "sha256").hexdigest()
    return {
        "pid": pid,
        "invocation_id": props["InvocationID"],
        "nrestarts": int(props["NRestarts"]),
        "start_ticks": ticks,
        "binary_sha256": digest,
    }


def run_worker(job: dict[str, Any], client_uid: int, confirmed: bool) -> tuple[int, bytes, bytes]:
    """Transient unit as the enrolled client UID; the script travels on stdin."""
    account = pwd.getpwuid(client_uid)
    argv = [
        "systemd-run",
        "--unit",
        f"jt-oz-certify-lineage-{job['tag']}-{job['mode']}-{uuid.uuid4().hex[:8]}.service",
        "--wait",
        "--collect",
        "--pipe",
        "--quiet",
        "--service-type=exec",
        f"--property=User={account.pw_name}",
        f"--property=Group={account.pw_gid}",
        "--property=MemoryMax=750M",
        "--property=MemorySwapMax=0",
        f"--property=RuntimeMaxSec={WORKER_SECONDS}",
        "--property=KillMode=control-group",
        "--property=Nice=10",
        "--property=NoNewPrivileges=yes",
        "--property=PrivateTmp=yes",
        "--working-directory=/",
        sys.executable,
        "-I",
        "-B",
        "-",
        "worker",
        "--job",
        json.dumps(job, ensure_ascii=False, sort_keys=True),
    ]
    if confirmed:
        argv.append(CONFIRM_FLAG)
    done = subprocess.run(
        argv,
        input=Path(__file__).read_bytes(),
        capture_output=True,
        timeout=WORKER_SECONDS + 60,
        check=False,
    )
    return done.returncode, done.stdout, done.stderr


def last_json(stdout: bytes) -> dict[str, Any] | None:
    for line in reversed(stdout.decode(errors="replace").splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    return None


WARNINGS = (
    "certify permanently gives the target session subagent children; never name the anchor, "
    "an enrolled Root or a chat-created (ses_jtoz_) Root as target; a failed run needs a new "
    "childless target",
    "the leaf provider refuses the target from then on; if it is bound in Zulip, that topic "
    "stops working",
    "the planned file stays in <canonical_directory>/<directory> of the real workspace",
    "the two operator turns become part of the target's history; if the target is bound and "
    "the native mirror is on, the live Bridge may mirror them into that topic",
    "the runtime records a first tree baseline for the anchor and every chat-created Root of "
    "its project only while that Root has no child, and a refusal stops the whole startup; "
    "stage refuses while activation_blockers is not empty",
    "the journal binds each baseline to this exact observation: re-pinning another one, or a "
    "Native upgrade, invalidates the history of a Root that has since grown children",
    "no interrupt, form reply or retry is ever sent: a turn past its deadline or a pending "
    "question is left as it is and certify fails",
    "any other input to the target during certify breaks the isolated turns and certify fails",
)


def cmd_plan(spec: Spec) -> None:
    need(os.geteuid() == 0, "root_required")
    q, owner_doc, policy, manifest, _, enrollment = load_target(spec)
    tool_sha = sha(Path(__file__).read_bytes())
    plan = operator_plan(spec.tag)
    target = q.reference.model_dump(mode="json") | {"upstream_session_id": spec.target_session_id}
    plan_sha = plan_sha256(
        plan,
        anchor=q.reference.model_dump(mode="json"),
        target=target,
        policy_sha256=policy.fingerprint_sha256,
        tool_sha256=tool_sha,
    )
    problems = root_preflight(q, manifest, enrollment, spec.target_session_id, policy.operations)
    worker: dict[str, Any] | None = None
    if not problems:
        code, stdout, stderr = run_worker(spec.job("plan", tool_sha), owner_doc.client_uid, False)
        worker = last_json(stdout)
        if code != 0 or worker is None or worker.get("error") or worker.get("stage") != "planned":
            print(stderr.decode(errors="replace")[-2000:], file=sys.stderr)
            raise CertifyError(f"plan_worker_failed:{code}:{(worker or {}).get('error')}")
        need(
            sum((worker.get("native_mutation_attempts") or {}).values()) == 0,
            "plan_must_not_mutate",
        )
        need(worker["plan_sha256"] == plan_sha, "plan_digest_differs_in_worker")
        need(
            worker["owner_before"]["owner_epoch"] == worker["owner_after"]["owner_epoch"],
            "owner_changed_during_plan",
        )
        if worker.get("target_children"):
            problems.append("target_must_be_childless_before_certify")
        leaf = worker["negatives"].get("leaf_before") or {}
        if leaf.get("error") is not None or leaf.get("state") != "idle":
            problems.append("target_not_idle_through_the_leaf_provider")
        if not worker.get("lineage_stack_composed"):
            problems.append("target_not_observable_through_the_lineage_stack")
    scan = (worker or {}).get("activation")
    print(
        json.dumps(
            {
                "planned": not problems,
                "problems": problems,
                # Certify can still run; stage refuses while any of these holds.
                "activation_blockers": activation_blockers(scan) if scan else None,
                "native_mutations": 0,
                "native_get_count": (worker or {}).get("native_get_count", 0),
                "anchor": q.reference.model_dump(mode="json"),
                "target": target,
                "activation_scan": scan,
                "target_children": (worker or {}).get("target_children"),
                "target_policy": (worker or {}).get("target_policy"),
                "adoption_operations": sorted(set(policy.operations) & REPLY_OPERATIONS),
                "manifest_format": manifest.get("format"),
                "owner_epoch": ((worker or {}).get("owner_before") or {}).get("owner_epoch"),
                "native_host": host_state(owner_doc.unit),
                "certification_directory": plan["directory"],
                "prompts": [s["text"] for s in plan["steps"]],
                "approvable": {s["step"]: s["allow"] for s in plan["steps"]},
                "maximum_native_mutations": {
                    "session.prompt": MAX_PROMPTS,
                    "session.permission.reply": MAX_PERMISSION_REPLIES,
                },
                "limits": {
                    "native_gets": MAX_NATIVE_GETS,
                    "response_bytes": MAX_RESPONSE_BYTES,
                    "windows": MAX_WINDOWS,
                    "nodes": MAX_NODES,
                    "turn_seconds": TURN_SECONDS,
                    "worker_seconds": WORKER_SECONDS,
                },
                "warnings": list(WARNINGS),
                "output_directory": str(spec.output),
                "output_directory_exists": os.path.lexists(spec.output),
                "plan_sha256": plan_sha,
                "next": f"certify --spec <spec> --plan-sha256 {plan_sha} {CONFIRM_FLAG}",
            },
            ensure_ascii=False,
            indent=2,
        )
    )


def staged_documents(
    q: Any,
    policy: Any,
    manifest: dict[str, Any],
    *,
    stage: Path,
    observation_path: Path,
    observation_raw: bytes,
) -> dict[Path, bytes]:
    """Policy, lineage pin and manifest of the stage directory, in memory."""
    from jt_oz_bridge.services.runtime_enrollment import adoption_protocol_sha256

    reference = q.reference.model_dump(mode="json")
    policy_raw = dumps(
        adoption_policy(
            reference,
            contract_sha256=q.schema_file.sha256,
            protocol_sha256=adoption_protocol_sha256(q),
            operations=adoption_operations(policy.operations),
        )
    )
    pin_raw = dumps(lineage_pin({"path": str(observation_path), "sha256": sha(observation_raw)}))
    manifest_raw = dumps(
        stage_manifest(
            manifest,
            reference,
            {"path": str(stage / "adoption-policy.json"), "sha256": sha(policy_raw)},
            {"path": str(stage / "lineage.json"), "sha256": sha(pin_raw)},
        )
    )
    return {
        stage / "adoption-policy.json": policy_raw,
        stage / "lineage.json": pin_raw,
        stage / "runtime.json": manifest_raw,
        observation_path: observation_raw,
    }


def cmd_certify(spec: Spec, expected_plan: str, confirmed: bool) -> None:
    need(confirmed, "explicit_operator_prompt_flag_required")
    need(os.geteuid() == 0, "root_required")
    need(re.fullmatch(r"[0-9a-f]{64}", expected_plan), "plan_sha256_from_plan_required")
    q, owner_doc, policy, manifest, settings, enrollment = load_target(spec)
    problems = root_preflight(q, manifest, enrollment, spec.target_session_id, policy.operations)
    need(not problems, f"root_not_certifiable:{problems}")
    tool_sha = sha(Path(__file__).read_bytes())
    target = q.reference.model_dump(mode="json") | {"upstream_session_id": spec.target_session_id}
    plan_sha = plan_sha256(
        operator_plan(spec.tag),
        anchor=q.reference.model_dump(mode="json"),
        target=target,
        policy_sha256=policy.fingerprint_sha256,
        tool_sha256=tool_sha,
    )
    need(plan_sha == expected_plan, "plan_changed_since_plan")
    host_before = host_state(owner_doc.unit)
    need(host_before["nrestarts"] == 0, "native_nrestarts_must_be_zero_before_certify")
    group = pwd.getpwuid(owner_doc.client_uid).pw_gid
    out = spec.output
    new_directory(out, group)
    reservation = {
        "status": "reserved_before_operator_prompts",
        "tag": spec.tag,
        "anchor": q.reference.model_dump(mode="json"),
        "target": target,
        "plan_sha256": plan_sha,
        "certify_tool_sha256": tool_sha,
        "native_before": host_before,
        "reserved_at": time.time(),
    }
    write_new(out / "reservation.json", dumps(reservation), mode=0o600)
    job = spec.job("certify", tool_sha) | {"expected_plan_sha256": plan_sha}
    code, stdout, stderr = run_worker(job, owner_doc.client_uid, True)
    host_after = host_state(owner_doc.unit)
    write_new(out / "worker.stdout", stdout, mode=0o600)
    write_new(out / "worker.stderr", stderr, mode=0o600)
    worker = last_json(stdout) or {"error": "worker_output_missing"}
    observation, details, failures = build_observation(
        worker=worker,
        reference=q.reference,
        contract_sha256=q.schema_file.sha256,
        executable_sha256=owner_doc.executable_sha256,
        upstream_version=owner_doc.version,
        verified_operations=q.verified_operations,
        host_before=host_before,
        host_after=host_after,
    )
    if code != 0:
        failures.append(f"worker_returncode:{code}")
    raw = dumps(observation)
    if not failures:
        # The exact pins stage will write, through the runtime's own loaders.
        try:
            files = staged_documents(
                q,
                policy,
                manifest,
                stage=spec.stage,
                observation_path=out / OBSERVATION_FILE,
                observation_raw=raw,
            )
            runtime = settings.runtime.model_copy(
                update={"enrollment_file": spec.stage / "runtime.json"}
            )
            validate_documents(
                settings.model_copy(update={"runtime": runtime}),
                manifest_path=spec.stage / "runtime.json",
                files=files,
                reference=q.reference.model_dump(mode="json"),
            )
        except ValueError as error:
            failures.append(f"runtime_pin_validation:{type(error).__name__}:{str(error)[:300]}")
    details["failures"] = failures
    transcript = {
        "worker_error": worker.get("error"),
        "worker_stage": worker.get("stage"),
        "prompts": worker.get("prompts"),
        "permission_replies": worker.get("permission_replies"),
        "native_statuses": worker.get("native_statuses"),
        "native_before": host_before,
        "native_after": host_after,
        "failures": failures,
    }
    write_new(out / "transcript.json", dumps(transcript), group=group)
    if failures:
        receipt = {
            "status": "failed",
            "failures": failures,
            # Per kind: answered by Native, refused before sending, or uncertain.
            "native_mutations": sent_summary(worker),
            # Only what was discovered before the failure; a run that fails
            # earlier may still have left the target with a child.
            "target_children_discovered": bool(worker.get("discovered")),
            "files_left_in_workspace": f"{q.reference.canonical_directory}/"
            + cert_directory(spec.tag),
        }
        write_new(out / "FAILED.json", dumps(receipt), mode=0o600)
        write_new(out / "rejected-observation.json", raw, mode=0o600)
        write_new(out / "rejected-details.json", dumps(details), mode=0o600)
        print(stderr.decode(errors="replace")[-2000:], file=sys.stderr)
        raise CertifyError(f"certify_failed:{failures[:8]}")
    write_new(out / DETAILS_FILE, dumps(details), group=group)
    write_new(out / OBSERVATION_FILE, raw, group=group)
    print(
        json.dumps(
            {
                "certified": True,
                "human_acceptance": False,
                "output_directory": str(out),
                "observation": {"path": str(out / OBSERVATION_FILE), "sha256": sha(raw)},
                "nodes": len(observation["graph"]["nodes"]),
                "child_states_observed": details["child_states_observed"],
                "next": "stage --spec <spec>",
            },
            ensure_ascii=False,
            indent=2,
        )
    )


def cmd_stage(spec: Spec) -> None:
    need(os.geteuid() == 0, "root_required")
    import tomllib

    from jt_oz_bridge.config import Settings
    from jt_oz_bridge.security.root_files import root_bytes

    q, owner_doc, policy, manifest, settings, enrollment = load_target(spec)
    problems = root_preflight(q, manifest, enrollment, spec.target_session_id, policy.operations)
    need(not problems, f"root_not_stageable:{problems}")
    observation_path = spec.output / OBSERVATION_FILE
    observation_raw = root_bytes(observation_path)
    graph = json.loads(observation_raw)["graph"]["reference"]
    need(graph["upstream_session_id"] == spec.target_session_id, "observation_target_changed")
    tool_sha = sha(Path(__file__).read_bytes())
    code, stdout, stderr = run_worker(spec.job("anchor", tool_sha), owner_doc.client_uid, False)
    worker = last_json(stdout)
    if (
        code != 0
        or worker is None
        or worker.get("error")
        or worker.get("stage") != "anchor-checked"
    ):
        print(stderr.decode(errors="replace")[-2000:], file=sys.stderr)
        raise CertifyError(f"anchor_check_failed:{code}:{(worker or {}).get('error')}")
    need(sum((worker.get("native_mutation_attempts") or {}).values()) == 0, "stage_must_not_mutate")
    # No journal history exists for a leaf Root: its first tree baseline is
    # recorded only while it has no child, else startup refuses every Root.
    blockers = activation_blockers(worker.get("activation") or {})
    need(not blockers, f"tree_activation_blocked:{blockers}")
    target = spec.stage
    files = staged_documents(
        q,
        policy,
        manifest,
        stage=target,
        observation_path=observation_path,
        observation_raw=observation_raw,
    )
    manifest_out = files[target / "runtime.json"]
    config_out = stage_config(root_bytes(spec.config).decode(), target / "runtime.json")
    observer = json.loads(root_bytes(spec.observer))
    observer_out = dumps(stage_observer(observer, sha(manifest_out)))
    staged = Settings.model_validate(tomllib.loads(config_out))
    validate_stage(
        staged,
        manifest_path=target / "runtime.json",
        files=files,
        observer_raw=observer_out,
        reference=q.reference.model_dump(mode="json"),
    )
    group = pwd.getpwuid(owner_doc.client_uid).pw_gid
    new_directory(target, group)
    for name in ("adoption-policy.json", "lineage.json", "runtime.json"):
        write_new(target / name, files[target / name], group=group)
    write_new(target / "config.toml", config_out.encode(), group=group)
    write_new(target / "local-observer.json", observer_out, group=group)
    assert settings.runtime.enrollment_file is not None
    print(
        json.dumps(
            {
                "staged": str(target),
                "runtime_sha256": sha(manifest_out),
                "previous_runtime": str(settings.runtime.enrollment_file),
                "manifest_format": manifest.get("format"),
                "anchor": q.reference.model_dump(mode="json"),
                "adoption_operations": json.loads(files[target / "adoption-policy.json"])[
                    "operations"
                ],
                "lineage_observation": {
                    "path": str(observation_path),
                    "sha256": sha(observation_raw),
                },
                "reminder": (
                    "Nothing is active yet. The anchor must still have no child when the Bridge "
                    "first starts on this file. Run the full gate for the release, then point "
                    "the Bridge and observer units at the staged config.toml and "
                    "local-observer.json; the previous files are the rollback."
                ),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0] if __doc__ else None)
    parser.add_argument(
        "step", nargs="?", default="plan", choices=("plan", "certify", "stage", "worker")
    )
    parser.add_argument("--spec", type=Path)
    parser.add_argument("--job")
    parser.add_argument("--plan-sha256")
    parser.add_argument(CONFIRM_FLAG, dest="confirmed", action="store_true")
    args = parser.parse_args(argv)
    if args.step == "certify":
        # Checked before reading anything, so a missing flag never touches Native.
        need(args.confirmed, "explicit_operator_prompt_flag_required")
        need(args.plan_sha256, "plan_sha256_from_plan_required")
    if args.step == "worker":
        need(args.job, "worker_job_required")
        cmd_worker(json.loads(args.job), args.confirmed)
        return
    need(not args.confirmed or args.step == "certify", "only_certify_takes_the_prompt_flag")
    need(args.spec is not None, "spec_required")
    spec = Spec(args.spec)
    if args.step == "plan":
        cmd_plan(spec)
    elif args.step == "stage":
        cmd_stage(spec)
    else:
        cmd_certify(spec, args.plan_sha256, args.confirmed)


if __name__ == "__main__":
    main()
