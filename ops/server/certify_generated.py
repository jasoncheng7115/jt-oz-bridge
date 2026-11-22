"""Issue the per-Root evidence that lets the Bridge return OpenCode-generated files.

Automatic generated returns (``runtime.generated_returns_enabled``) need, per
Root, a root-owned generated-outputs bundle pinned as that Root's
``generated_outputs`` in a v7 runtime manifest that names the Root in
``generated_roots``. This tool produces a scoped ``qualified-generated-outputs-v2``
bundle for ONE enrolled Root from real turns of that Root on the live Native,
read back only through the installed release's own generated-output reader. It
declares exactly the output origins and the largest byte size its real cases
covered; the runtime counts every other output as unsupported. It also stages
the manifest, config and observer policy that switch it on.

Run with the selected release's interpreter, as root:

    python -I -B certify_generated.py plan    --spec spec.json
    python -I -B certify_generated.py certify --spec spec.json --plan-sha256 HEX \\
        --i-understand-this-sends-operator-prompts-to-the-original-root
    python -I -B certify_generated.py stage   --spec spec.json

``plan`` (the default) is read-only: GET requests only, nothing written.
``certify`` sends at most MAX_PROMPTS (2) operator prompts to the Root and
answers at most MAX_PERMISSION_REPLIES (12) of that Root's own permission
requests: ``once`` only for the planned files inside the Root's canonical
directory and the one planned command, ``reject`` for anything else, never
``always``. No other Native mutation can leave the worker, and nothing is
retried. Native access runs in a transient unit as the enrolled Bridge client
UID; root only reads pins, records the Native process identity and writes the
outputs. The Native database is never opened and Native is never restarted.
``stage`` sends no request at all; it writes a new directory only after the
repo's own loaders accept the staged manifest, config and observer in memory.

The prompts are operator RPCs. No Zulip Human message is forged, and nothing
here is Human, mobile or formal acceptance.

spec.json::

    {
      "tag": "gen01",
      "project_id": "example-project",                      # or "session_id": "ses_..."
      "config": "/etc/jt-oz-bridge/config.toml",            # optional
      "observer": "/etc/jt-oz-bridge/local-observer.json",  # optional
      "output": "/etc/jt-oz-bridge/generated-<tag>",        # optional, must not exist
      "stage": "/etc/jt-oz-bridge/runtime-generated-<tag>"  # optional, must not exist
    }
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import copy
import dataclasses
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

CONFIRM_FLAG = "--i-understand-this-sends-operator-prompts-to-the-original-root"
MAX_PROMPTS = 2
MAX_PERMISSION_REPLIES = 12
MAX_NATIVE_GETS = 8000
MAX_RESPONSE_BYTES = 2 * 1024**3
MAX_BYTE_CASES = 16
TURN_SECONDS = 420
POLL_SECONDS = 2.0
WORKER_SECONDS = 1800
LARGE = 20 * 1024 * 1024
SOURCE_FORMAT = "jt-oz-bridge-operator-generated-certification-v1"
BUNDLE_FILE = "generated-outputs.json"
V5, V7 = "qualified-consumer-runtime-v5", "qualified-consumer-runtime-v7"
REVIEW = "installed-evidence-reviewed-for-development-runtime"
# The reader and the prompts need these; certify never adds an operation.
REQUIRED_OPERATIONS = frozenset(
    {
        "event.subscribe",
        "fs.read",
        "session.active",
        "session.form.list",
        "session.get",
        "session.inbox.list",
        "session.message.list",
        "session.permission.list",
        "session.permission.reply",
        "session.prompt",
    }
)
WRITE_ACTIONS = frozenset({"edit", "write"})
# Never contacted: a TEST-NET-2 documentation address used only as injected data.
EXTERNAL_URI = "https://198.51.100.7/jt-oz-certification-external-output"
PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
SEALED_CHECKS = frozenset(
    {
        "copied-and-expired-objects-rejected",
        "foreign-root-rejected",
        "changed-owner-rejected",
        "changed-output-rejected",
        "protected-path-not-disclosed",
    }
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
    return f"jt-oz-generated-{tag}"


def generated_command(directory: str) -> str:
    """The one shell command certify may approve, verbatim."""
    blocks = "".join(
        f"d.joinpath('{name}').write_bytes(bytes(range(256))*{size // 256});"
        for name, size in BLOCKS.items()
    )
    return (
        'python3 -c "import base64,pathlib;'
        f"d=pathlib.Path('{directory}');d.mkdir();"
        "d.joinpath('binary.bin').write_bytes(bytes(range(256)));"
        f"{blocks}"
        f"d.joinpath('pixel.png').write_bytes(base64.b64decode('{PNG}'))\""
    )


# Sizes up to the hard bound: the evidence declares the largest one Native's
# snapshot actually lists and the reader actually returns, nothing more.
BLOCKS = {
    "block-64k.bin": 64 * 1024,
    "block-1m.bin": 1024 * 1024,
    "block-5m.bin": 5 * 1024 * 1024,
    "block-20m.bin": LARGE,
}
WRITTEN = {
    "empty.txt": b"",
    "unicode.txt": "繁體中文 ✓ naïve café 🙂\n".encode(),
    "報告-中文.txt": "報告內容：產出檔案測試\n".encode(),
    "board.html": b"<!doctype html><html><body><p>jt-oz-bridge plain generated file</p>"
    b"</body></html>\n",
    # Placeholders only; they exist to prove protected paths stay undisclosed.
    ".env": b"JTOZ_CERTIFICATION_PLACEHOLDER=not-a-secret\n",
    "credentials.json": b'{"placeholder": "not-a-secret"}\n',
}
PROTECTED = (".env", "credentials.json")


def requested_files(directory: str) -> dict[str, bytes]:
    """Exact bytes each planned file is asked to hold (recorded, never a pass rule)."""
    produced = {
        "binary.bin": bytes(range(256)),
        "pixel.png": base64.b64decode(PNG),
        **{name: bytes(range(256)) * (size // 256) for name, size in BLOCKS.items()},
    }
    return {f"{directory}/{name}": raw for name, raw in {**produced, **WRITTEN}.items()}


def operator_plan(tag: str) -> dict[str, Any]:
    """Two operator prompts and, per step, the only paths/command it may approve.

    OpenCode 2.0.32 reports a turn's files only as assistant snapshot paths,
    not as tool-file or inline output, so no step asks for one, and no step
    makes the agent read a 20 MiB file.
    """
    from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES

    need(LARGE == MAX_ATTACHMENT_BYTES, "twenty_mib_bound_changed")
    d = cert_directory(tag)
    command = generated_command(d)
    head = (
        "jt-oz-bridge operator certification, step {} of 2. "
        "This is an automated operator check, not a message from a person."
    )
    written = "\n".join(
        f"{i}. `{d}/{name}`: "
        + (
            "empty (0 bytes)."
            if not raw
            else f"exactly `{raw.decode().rstrip(chr(10))}` followed by one newline."
        )
        for i, (name, raw) in enumerate(WRITTEN.items(), start=1)
    )
    steps = [
        {
            "step": "quiet",
            "text": head.format(1) + " Reply with the single word OK. Do not use any tool, "
            "and do not create, change or read any file.",
            "write_files": [],
            "read_files": [],
            "commands": [],
        },
        {
            "step": "files",
            "text": head.format(2)
            + "\nFirst run exactly this one shell command, unchanged, from the project "
            f"directory (it creates the directory `{d}` and {2 + len(BLOCKS)} files in it):\n"
            + command
            + "\nThen, with the write tool, create exactly these files with exactly this "
            "content:\n"
            + written
            + f"\nDo not run any other command, do not touch anything outside `{d}`, do not "
            "start subagents, and finish with a one-line summary.",
            "write_files": [f"{d}/{name}" for name in WRITTEN],
            # The agent may look at its own planned files; nothing else is readable.
            "read_files": sorted(requested_files(d)),
            "commands": [command],
        },
    ]
    need(len(steps) == MAX_PROMPTS, "prompt_bound")
    return {"directory": d, "steps": steps}


def plan_sha256(
    plan: dict[str, Any], *, reference: dict[str, Any], policy_sha256: str, tool_sha256: str
) -> str:
    from jt_oz_bridge.storage.durable import digest

    return digest(
        {
            "format": SOURCE_FORMAT,
            "plan": plan,
            "reference": reference,
            "native_policy_sha256": policy_sha256,
            "certify_tool_sha256": tool_sha256,
            "limits": {
                "prompts": MAX_PROMPTS,
                "permission_replies": MAX_PERMISSION_REPLIES,
                "native_gets": MAX_NATIVE_GETS,
                "response_bytes": MAX_RESPONSE_BYTES,
                "byte_cases": MAX_BYTE_CASES,
                "turn_seconds": TURN_SECONDS,
                "worker_seconds": WORKER_SECONDS,
            },
        }
    )


def candidate_attestation(*, tag: str, plan_sha: str) -> str:
    """Stands in for the bundle's own pin, which cannot exist before the bundle."""
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
    """Same shape as V2ExecutionClient's prompt body, so the turn reader correlates it."""
    return {
        "text": text,
        "delivery": "queue",
        "metadata": {
            "jt_oz_bridge": {"action_id": action_id, "operation_digest": operation_digest}
        },
    }


def mutation_kind(method: str, path: str, session_id: str) -> str | None:
    """The only two Native mutations certify may send; anything else is None."""
    if method != "POST":
        return None
    base = "/api/session/" + session_id
    if path == base + "/prompt":
        return "prompt"
    if re.fullmatch(re.escape(base) + r"/permission/[A-Za-z0-9_-]{1,255}/reply", path):
        return "permission.reply"
    return None


def workspace_relative(resource: object, canonical_directory: str) -> str | None:
    """A canonical path inside the Root's directory, or None for anything else."""
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
    request: object, *, session_id: str, canonical_directory: str, step: Mapping[str, Any]
) -> tuple[str, str]:
    """``once`` only for this step's planned files/command in the Root's directory.

    Everything else (another session, tool, path, glob or command, external
    directories) is rejected; ``always`` is never answered.
    """
    if not isinstance(request, dict) or request.get("sessionID") != session_id:
        return "reject", "foreign_or_malformed_request"
    action, resources = request.get("action"), request.get("resources")
    if (
        not isinstance(resources, list)
        or not 1 <= len(resources) <= 20
        or any(not isinstance(r, str) for r in resources)
    ):
        return "reject", "explicit_resources_required"
    # OpenCode 2.0.32 asks for shell commands as ``shell``; older builds said ``bash``.
    if action in {"shell", "bash"}:
        if all(r in step["commands"] for r in resources):
            return "once", "planned_command"
        return "reject", "unplanned_command"
    if action in WRITE_ACTIONS:
        allowed = step["write_files"]
    elif action == "read":
        allowed = step["read_files"]
    else:
        return "reject", "unplanned_action"
    paths = [workspace_relative(r, canonical_directory) for r in resources]
    if all(p is not None and p in allowed for p in paths):
        return "once", "planned_path"
    return "reject", "path_outside_plan"


def file_key(file: Any) -> dict[str, Any]:
    value: dict[str, Any] = file.model_dump(mode="json")
    return value


def choose_cases(files: Any, directory: str, limit: int) -> list[dict[str, Any]]:
    """Our own outputs only: inline tool data first, then tool paths, then snapshots."""
    prefix = directory + "/"
    chosen = [f for f in files if f.kind == "inline" or (f.path or "").startswith(prefix)]

    def rank(f: Any) -> int:
        if f.kind == "inline":
            return 0
        return 1 if f.origin == "tool" else 2

    return [file_key(f) for f in sorted(chosen, key=rank)[: max(0, limit)]]


def exact_bytes(content: bytes, evidence: Any) -> bool:
    """The issued bytes equal the sealed projection and its Native/inline origin."""
    p = evidence.projection
    same = len(content) == p.size and sha(content) == p.sha256
    if evidence.selection.kind == "workspace":
        return bool(same and evidence.native is not None and evidence.native.projection == p)
    return bool(
        same
        and evidence.native is None
        and (p.size, p.sha256) == (evidence.selection.size, evidence.selection.sha256)
    )


def observed_scope(evidence: list[Any]) -> Any:
    """Exactly the origins real byte cases covered and the largest size they returned."""
    from jt_oz_bridge.adapters.opencode.generated_files import GeneratedScope

    if not evidence:
        return None
    try:
        return GeneratedScope(
            frozenset((e.selection.kind, e.selection.origin) for e in evidence),
            max(e.projection.size for e in evidence),
        )
    except ValueError:  # e.g. only empty files: no positive size was observed
        return None


def coverage(evidence: list[Any], inventories: list[Any]) -> list[str]:
    """What the scoped generated_qualification would still miss; empty means complete."""
    missing = []
    if observed_scope(evidence) is None:
        missing.append("observed_scope")
    if not 5 <= len(evidence) <= 20:
        missing.append(f"byte_case_count:{len(evidence)}")
    if not 2 <= len(inventories) <= 20:
        missing.append(f"inventory_count:{len(inventories)}")
    if not any(not d.files for d in inventories):
        missing.append("empty_inventory")
    if not any(d.files for d in inventories):
        missing.append("nonempty_inventory")
    known = {d.stable_sha256 for d in inventories}
    if any(e.discovery().stable_sha256 not in known for e in evidence):
        missing.append("byte_case_inventory")
    return missing


def unqualified_outputs(inventories: list[Any], scope: Any) -> list[dict[str, Any]]:
    """Outputs Native listed but no case read: the runtime will count them unsupported."""
    seen: dict[tuple[str, str], int] = {}
    for d in inventories:
        for f in d.files:
            if scope is None or not scope.admits(f):
                seen[(f.kind, f.origin)] = seen.get((f.kind, f.origin), 0) + 1
    return [{"kind": k, "origin": o, "count": n} for (k, o), n in sorted(seen.items())]


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


def rehash(value: dict[str, Any]) -> dict[str, Any]:
    """Reseal an evidence dump's metadata digest, as a forger would."""
    from jt_oz_bridge.adapters.opencode.generated_files import OUTPUT_SEMANTICS
    from jt_oz_bridge.storage.durable import digest

    value["metadata_sha256"] = digest(
        {
            "turn": value["turn"],
            "outputs": value["files"],
            "hidden": value["hidden_count"],
            "unsupported": value["unsupported_count"],
            "semantics": OUTPUT_SEMANTICS,
        }
    )
    return value


def sealed_negatives(
    bundle: dict[str, Any],
    *,
    reference: Any,
    contract_sha256: str,
    executable_sha256: str,
    foreign: dict[str, Any],
    protected: list[str],
) -> dict[str, Any]:
    """Forged variants of the real bundle must each fail the runtime validator.

    The control (same bundle, every negative marked true) must pass first;
    otherwise a rejection would prove nothing about the forged field.
    """
    from jt_oz_bridge.adapters.opencode.generated_files import GeneratedFile
    from jt_oz_bridge.services.generated_enrollment import NEGATIVE_CHECKS, generated_qualification

    base = copy.deepcopy(bundle) | {"negative_checks": dict.fromkeys(NEGATIVE_CHECKS, True)}

    def outcome(value: dict[str, Any]) -> str | None:
        raw = dumps(value)
        try:
            generated_qualification(
                raw,
                reference=reference,
                contract_sha256=contract_sha256,
                executable_sha256=executable_sha256,
                evidence_sha256=sha(raw),
            )
        except ValueError as error:
            return f"{type(error).__name__}:{str(error)[:200]}"
        return None

    control = outcome(base)
    result: dict[str, Any] = {"control_rejected": control}
    if control is not None or not base["byte_cases"]:
        return result | dict.fromkeys(SEALED_CHECKS, False)

    def forged(change: Callable[[dict[str, Any]], None]) -> str | None:
        value = copy.deepcopy(base)
        change(value)
        return outcome(value)

    def extend_deadline(v: dict[str, Any]) -> None:
        e = v["byte_cases"][0]["evidence"]
        e["expires_at"] = e["turn"]["expires_at"] + 1

    def move_root(v: dict[str, Any]) -> None:
        for item in [*v["inventories"], *(c["evidence"] for c in v["byte_cases"])]:
            item["turn"]["correlation"]["reference"] = foreign
            if item.get("native"):
                item["native"]["reference"] = foreign
            rehash(item)

    def change_owner(v: dict[str, Any]) -> None:
        v["native_before"]["owner_epoch"] = v["native_after"]["owner_epoch"] = "0" * 64

    def change_inventory(v: dict[str, Any]) -> None:
        e = v["byte_cases"][0]["evidence"]
        e["files"][-1]["file_index"] += 1000
        rehash(e)

    result["deadline_extended"] = forged(extend_deadline)
    result["moved_to_foreign_root"] = forged(move_root)
    result["owner_epoch_changed"] = forged(change_owner)
    result["output_inventory_changed"] = forged(change_inventory)
    # A protected name can neither be sealed as an output nor appear in the bundle.
    try:
        GeneratedFile(
            origin="snapshot",
            assistant_id="forged",
            file_index=0,
            kind="workspace",
            path=protected[0],
            name=protected[0].rsplit("/", 1)[-1],
        )
        result["protected_output_model"] = None
    except ValueError as error:
        result["protected_output_model"] = f"{type(error).__name__}:{str(error)[:200]}"
    result["protected_paths_in_outputs"] = protected_outputs(bundle, protected)
    return result | {
        "copied-and-expired-objects-rejected": result["deadline_extended"] is not None,
        "foreign-root-rejected": result["moved_to_foreign_root"] is not None,
        "changed-owner-rejected": result["owner_epoch_changed"] is not None,
        "changed-output-rejected": result["output_inventory_changed"] is not None,
        "protected-path-not-disclosed": result["protected_output_model"] is not None
        and not result["protected_paths_in_outputs"],
    }


def protected_outputs(bundle: dict[str, Any], protected: list[str]) -> list[str]:
    """Protected names found in any sealed output entry (the prompt text that asked
    for them is correlation data, not a disclosure)."""
    entries: list[Any] = [d.get("files") for d in bundle.get("inventories", [])]
    for case in bundle.get("byte_cases", []):
        e = case.get("evidence") or {}
        entries += [e.get("selection"), e.get("files"), e.get("projection")]
        entries.append((e.get("native") or {}).get("relative_path"))
    text = json.dumps(entries, ensure_ascii=False)
    names = {p.rsplit("/", 1)[-1] for p in protected}
    return sorted({p for p in protected if p in text} | {n for n in names if json.dumps(n) in text})


def build_bundle(
    *,
    worker: dict[str, Any],
    reference: Any,
    contract_sha256: str,
    executable_sha256: str,
    host_before: Mapping[str, Any],
    host_after: Mapping[str, Any],
    tool_sha256: str,
    plan_sha: str,
    observed_at: float,
) -> tuple[dict[str, Any], list[str]]:
    """The scoped qualified-generated-outputs-v2 bundle plus the list of failed checks.

    Every claim is computed from the worker's and root's observations; a failed
    check is recorded false (never omitted) and the bundle is then not written.
    """
    from jt_oz_bridge.adapters.opencode import generated_files as component
    from jt_oz_bridge.adapters.opencode.generated_files import (
        BYTE_FEATURES,
        BYTE_SEMANTICS,
        OUTPUT_FEATURES,
        OUTPUT_SEMANTICS,
        GeneratedByteEvidence,
        GeneratedDiscoveryEvidence,
    )
    from jt_oz_bridge.services.file_enrollment import component_sha
    from jt_oz_bridge.services.generated_enrollment import (
        NEGATIVE_CHECKS,
        SCOPED_FORMAT,
        generated_qualification,
        scope_document,
    )

    failures: list[str] = []
    ref = reference.model_dump(mode="json")
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
    host_unchanged = dict(host_before) == dict(host_after) and native_before == native_after
    restarted = not host_unchanged or host_before.get("nrestarts") != 0
    replaced = not (
        owner_unchanged
        and native_before["binary_sha256"] == executable_sha256
        and isinstance(owner_before, dict)
        and owner_before.get("executable_sha256") == executable_sha256
        and native_before["pid"] == native_before["owner_pid"]
    )
    for name, bad in (
        ("owner_changed", not owner_unchanged),
        ("native_restarted_or_changed", restarted),
        ("backend_identity_changed", replaced),
        ("native_database_opened", worker.get("native_database_opens") != 0),
        ("workspace_opened_locally", worker.get("workspace_opens") != 0),
        ("non_native_request_attempted", worker.get("non_native_requests", 0) != 0),
    ):
        if bad:
            failures.append(name)
    prompts = worker.get("prompts") or []
    admitted = [p for p in prompts if p.get("admitted") is True]
    mutations = worker.get("native_mutations") or {}
    replies = worker.get("permission_replies") or []
    if len(admitted) != MAX_PROMPTS or len(prompts) != MAX_PROMPTS:
        failures.append(f"operator_prompts:{len(admitted)}/{len(prompts)}")
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
    actions = {p.get("action_id") for p in admitted}
    evidence, inventories, cases = [], [], []
    try:
        inventories = [GeneratedDiscoveryEvidence.model_validate(v) for v in worker["inventories"]]
        evidence = [GeneratedByteEvidence.model_validate(c["evidence"]) for c in worker["cases"]]
    except (KeyError, TypeError, ValueError) as error:
        failures.append(f"evidence_model:{type(error).__name__}:{str(error)[:200]}")
    for case, value in zip(worker.get("cases", []), evidence, strict=False):
        flags = {
            k: case.get(k) is True
            for k in ("original_object_current", "exact_native_bytes_verified")
        }
        flags["no_direct_local_read"] = case.get("workspace_opens") == 0
        if not all(flags.values()):
            failures.append(f"byte_case_flags:{value.selection.name}")
        cases.append(
            flags
            | {
                "evidence": value.model_dump(mode="json"),
                "requested_bytes_matched": case.get("requested_bytes_matched"),
            }
        )
    turns = [*inventories, *(e.discovery() for e in evidence)]
    actual = bool(turns) and all(
        d.turn.correlation.reference == reference
        and d.turn.correlation.action_id in actions
        and d.turn.owner_epoch == native_before["owner_epoch"]
        for d in turns
    )
    if not actual:
        failures.append("outputs_not_from_this_root_and_its_operator_turns")
    failures += [f"coverage:{m}" for m in coverage(evidence, inventories)]
    scope = observed_scope(evidence)
    bundle: dict[str, Any] = {
        "format": SCOPED_FORMAT,
        # Only what real byte cases covered; everything else stays unsupported.
        "scope": scope_document(scope) if scope is not None else None,
        "unqualified_outputs_seen": unqualified_outputs(inventories, scope),
        "operator_review": REVIEW,
        "evidence_scope": "operator-rpc-only-not-human-acceptance",
        "actual_original_native_outputs": actual,
        "human_input_fabricated": False,
        "backend_replaced": replaced,
        "native_database_bytes_read": worker.get("native_database_opens") != 0,
        "native_restarted": restarted,
        "reference": ref,
        "contract_sha256": contract_sha256,
        "metadata_semantics_sha256": OUTPUT_SEMANTICS,
        "byte_semantics_sha256": BYTE_SEMANTICS,
        "component_sha256": component_sha(component),
        "metadata_features": sorted(OUTPUT_FEATURES),
        "byte_features": sorted(BYTE_FEATURES),
        "native_before": native_before,
        "native_after": native_after,
        "inventories": [d.model_dump(mode="json") for d in inventories],
        "byte_cases": cases,
        "operator_prompts": [
            {k: p.get(k) for k in ("step", "action_id", "operation_digest", "upstream_id", "sent")}
            | {"operator_not_human": True, "rpc": "session.prompt"}
            for p in prompts
        ],
        # Raw resources stay in transcript.json; the bundle keeps their digests only.
        "permission_replies": [{k: v for k, v in r.items() if k != "resources"} for r in replies],
        "native_requests": {
            "gets": worker.get("native_get_count"),
            "mutations": mutations,
            "response_bytes": worker.get("native_response_bytes"),
            "refused": worker.get("refused_native_requests"),
        },
        "plan_sha256": plan_sha,
        "candidate_attestation_sha256": worker.get("candidate_attestation_sha256"),
        "certify_tool_sha256": tool_sha256,
        "human_acceptance": False,
        "mobile_acceptance": False,
        "observed_at": observed_at,
    }
    live = worker.get("negative_checks") or {}
    sealed = sealed_negatives(
        bundle,
        reference=reference,
        contract_sha256=contract_sha256,
        executable_sha256=executable_sha256,
        foreign=worker.get("foreign_reference") or {},
        protected=[f"{worker.get('directory')}/{p}" for p in PROTECTED],
    )
    checks = {
        name: (live.get(name) or {}).get("passed") is True
        and (name not in SEALED_CHECKS or sealed.get(name) is True)
        for name in sorted(NEGATIVE_CHECKS)
    }
    bundle["negative_checks"] = checks
    bundle["negative_check_details"] = {"live": live, "sealed": sealed}
    failures += [f"negative:{name}" for name, ok in checks.items() if not ok]
    if not failures:
        raw = dumps(bundle)
        try:
            generated_qualification(
                raw,
                reference=reference,
                contract_sha256=contract_sha256,
                executable_sha256=executable_sha256,
                evidence_sha256=sha(raw),
            )
        except ValueError as error:
            failures.append(f"runtime_validation:{type(error).__name__}:{str(error)[:300]}")
    return bundle, failures


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


def stage_manifest(
    manifest: dict[str, Any], reference: dict[str, Any], pin: dict[str, str]
) -> dict[str, Any]:
    """v5/v7 manifest plus this Root's pin and explicit v7 scope; nothing else changes."""
    fmt = manifest.get("format")
    need(fmt in {V5, V7}, f"manifest_format_not_stageable:{fmt}")
    need(fmt == V7 or "generated_roots" not in manifest, "v5_manifest_has_generated_roots")
    merged = copy.deepcopy(manifest)
    targets = [i for i, b in enumerate(merged["backends"]) if b["reference"] == reference]
    need(len(targets) == 1, f"root_not_uniquely_enrolled:{len(targets)}")
    backend = merged["backends"][targets[0]]
    need(backend.get("generated_outputs") is None, "root_already_has_generated_outputs")
    need(backend.get("file_read") is not None, "root_file_read_qualification_required")
    roots = list(merged.get("generated_roots") or [])
    need(reference not in roots, "root_already_in_generated_roots")
    backend["generated_outputs"] = {"path": pin["path"], "sha256": pin["sha256"]}
    merged["format"] = V7
    merged["generated_roots"] = [*roots, copy.deepcopy(reference)]
    allowed = {("format",), ("generated_roots",), ("backends", targets[0], "generated_outputs")}
    need(changed_paths(manifest, merged) <= allowed, "manifest_change_outside_generated_scope")
    return merged


def stage_config(text: str, enrollment_file: Path) -> str:
    """Repoint enrollment_file and enable generated returns; every other line kept."""
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

    def find(name: str) -> list[int]:
        key = re.compile(r'\s*("?)' + name + r"\1\s*=")
        return [i for i in range(start, end) if key.match(lines[i])]

    enrollment, generated = find("enrollment_file"), find("generated_returns_enabled")
    need(len(enrollment) == 1 and len(generated) <= 1, "config_runtime_keys_ambiguous")

    def assign(name: str, value: str, like: str) -> str:
        key = f'"{name}"' if like.lstrip().startswith('"') else name
        return f"{key} = {value}\n"

    line = lines[enrollment[0]]
    lines[enrollment[0]] = assign("enrollment_file", json.dumps(str(enrollment_file)), line)
    if generated:
        lines[generated[0]] = assign("generated_returns_enabled", "true", lines[generated[0]])
    else:
        lines.insert(enrollment[0] + 1, assign("generated_returns_enabled", "true", line))
    staged = "".join(lines)
    expected = copy.deepcopy(before)
    expected["runtime"]["enrollment_file"] = str(enrollment_file)
    expected["runtime"]["generated_returns_enabled"] = True
    need(tomllib.loads(staged) == expected, "config_change_outside_runtime_generated_scope")
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


def validate_stage(
    settings: Any,
    *,
    manifest_path: Path,
    manifest_raw: bytes,
    observer_raw: bytes,
    reference: dict[str, Any],
) -> str:
    """The runtime's own loaders over the staged files, before anything is written."""
    from jt_oz_bridge.domain.models import SessionRef
    from jt_oz_bridge.security.json_data import strict_loads
    from jt_oz_bridge.services.inspection_runtime import LocalObserverPolicy
    from jt_oz_bridge.services.runtime_enrollment import read_enrollment

    need(settings.runtime.enrollment_file == manifest_path, "staged_config_points_elsewhere")
    need(settings.runtime.generated_returns_enabled is True, "staged_config_generated_disabled")
    with memory_root_files({manifest_path: manifest_raw}):
        value, enrollment_sha = read_enrollment(settings)
    ref = SessionRef.model_validate(reference)
    need(enrollment_sha == sha(manifest_raw), "staged_manifest_digest")
    need(value.generated_references() == {ref}, "staged_generated_scope_must_be_exactly_this_root")
    need(value.realm.file_upload is not None, "staged_file_returns_qualification_required")
    need(
        next(b for b in value.backends if b.reference == ref).file_read is not None,
        "staged_root_file_reader_required",
    )
    policy = LocalObserverPolicy.model_validate(strict_loads(observer_raw))
    need(policy.runtime_enrollment_sha256 == enrollment_sha, "staged_observer_pin")
    need(
        set(policy.backend_evidence) == {b.reference.backend_id for b in value.backends},
        "staged_observer_backend_scope",
    )
    return enrollment_sha


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


def root_preflight(q: Any, manifest: dict[str, Any]) -> list[str]:
    """Why this Root cannot be certified or staged as is (empty means it can)."""
    problems = []
    missing = sorted(REQUIRED_OPERATIONS - set(q.verified_operations))
    if missing:
        problems.append("verified_operations_missing:" + ",".join(missing))
    if q.file_read is None:
        problems.append("root_file_read_qualification_required")
    if q.generated_outputs is not None:
        problems.append("root_already_has_generated_outputs")
    if manifest.get("format") not in {V5, V7}:
        problems.append(f"manifest_format_not_stageable:{manifest.get('format')}")
    return problems


# --------------------------------------------------------------------------
# Live negative checks: the real reader against real captured outputs.
# Each returns observations; "passed" is true only if every rejection was seen.
# --------------------------------------------------------------------------


async def rejected(call: Awaitable[Any]) -> str | None:
    try:
        await call
    except ValueError as error:  # ContractError and pydantic errors included
        return f"{type(error).__name__}:{str(error)[:200]}"
    return None


def rejected_now(call: Callable[[], Any]) -> str | None:
    try:
        call()
    except ValueError as error:
        return f"{type(error).__name__}:{str(error)[:200]}"
    return None


def small_pick(outputs: Any, directory: str) -> Any:
    """A cheap real selection: the small HTML file, else a small inline item."""
    files = outputs.files
    for f in files:
        if f.path == f"{directory}/board.html":
            return f
    for f in files:
        if f.kind == "inline" and (f.size or 0) < 1024 * 1024:
            return f
    need(files, "no_generated_output_to_check")
    return files[0]


async def wait_until(deadline: float) -> None:
    await asyncio.sleep(max(0.0, deadline - time.time()) + 0.1)


async def check_copied_and_expired(
    reader: Any,
    c: Any,
    requests: Callable[[], int],
    directory: str,
    expire: Callable[[float], Awaitable[None]] = wait_until,
) -> dict[str, Any]:
    outputs = await reader.capture(c)
    pick = small_pick(outputs, directory)
    data = await reader.read(outputs, pick)
    before = requests()
    copied = dataclasses.replace(outputs)
    seen: dict[str, Any] = {
        "copied_outputs_current": reader.current(copied),
        "copied_outputs_read": await rejected(reader.read(copied, pick)),
        "copied_selection_read": await rejected(reader.read(outputs, pick.model_copy())),
        "copied_bytes_current": reader.current_bytes(dataclasses.replace(data)),
        "copied_bytes_evidence": rejected_now(lambda: reader.evidence(dataclasses.replace(data))),
    }
    await expire(outputs.expires_at)
    seen |= {
        "expired_outputs_current": reader.current(outputs),
        "expired_bytes_current": reader.current_bytes(data),
        "expired_read": await rejected(reader.read(outputs, pick)),
        "expired_evidence": rejected_now(lambda: reader.evidence(data)),
        "native_requests": requests() - before,
    }
    seen["passed"] = (
        all(seen[k] is False for k in seen if k.endswith("_current"))
        and all(isinstance(seen[k], str) for k in seen if k.endswith(("_read", "_evidence")))
        and seen["native_requests"] == 0
    )
    return seen


async def check_foreign_root(
    reader: Any, c: Any, foreign: Any, requests: Callable[[], int]
) -> dict[str, Any]:
    before = requests()
    error = await rejected(reader.capture(c.model_copy(update={"reference": foreign})))
    seen = {
        "foreign_reference": foreign.model_dump(mode="json"),
        "capture": error,
        "native_requests": requests() - before,
    }
    return seen | {"passed": error is not None and seen["native_requests"] == 0}


class ChangedOwner:
    """The real owner proof seen through a different epoch; Native is untouched."""

    owner_epoch = "0" * 64

    def __init__(self, real: Any) -> None:
        self._real = real

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


async def check_changed_owner(reader: Any, c: Any, directory: str) -> dict[str, Any]:
    feed = reader.turns.proofs.feed
    outputs = await reader.capture(c)
    pick = small_pick(outputs, directory)
    issued = set(reader._bytes)
    real = feed.current_owner

    async def changed() -> Any:
        return ChangedOwner(await real())

    feed.current_owner = changed  # instance attribute over the bound method
    try:
        read_error = await rejected(reader.read(outputs, pick))
        capture_error = await rejected(reader.capture(c))
    finally:
        del feed.current_owner
    new = sorted(map(str, set(reader._bytes) - issued))
    seen = {
        "injected_at": "owner-probe-result",
        "read": read_error,
        "capture": capture_error,
        "bytes_issued": len(new),
    }
    return seen | {"passed": bool(read_error and capture_error and not new)}


class Tap:
    """Wraps transport.request; may record or alter message pages for a check."""

    def __init__(self, transport: Any) -> None:
        self.transport, self.original = transport, transport.request
        self.mutate: Callable[[dict[str, Any]], bool] | None = None
        self.record = False
        self.pages: list[Any] = []
        self.applied = 0

    async def request(self, operation: str, **kwargs: Any) -> Any:
        value = await self.original(operation, **kwargs)
        if operation == "session.message.list" and (kwargs.get("query") or {}).get("limit") == "50":
            if self.mutate is not None:
                value = copy.deepcopy(value)
                self.applied += bool(self.mutate(value))
            if self.record:
                self.pages.append(value)
        return value

    def install(self) -> Tap:
        self.transport.request = self.request
        return self

    def remove(self) -> None:
        self.transport.request = self.original


def change_output(page: dict[str, Any], target: Any) -> bool:
    """Rename exactly the raw entry the reader issued as ``target``.

    A trial showed why a blind rename proves nothing: it hit a tool file item
    the projection already hid, so the issued outputs did not change at all.
    """
    for message in page["data"]:
        if message.get("type") != "assistant" or message.get("id") != target.assistant_id:
            continue
        if target.origin == "snapshot":
            files = message.get("snapshot", {}).get("files", [])
            if target.file_index < len(files) and files[target.file_index] == target.path:
                files[target.file_index] += ".changed"
                return True
            return False
        content = message.get("content", [])
        if target.content_index is None or target.content_index >= len(content):
            return False
        part = content[target.content_index]
        items = part.get("state", {}).get("content", [])
        if part.get("id") != target.tool_id or target.file_index >= len(items):
            return False
        item = items[target.file_index]
        item["name"] = (item.get("name") or "output") + ".changed"
        if item.get("uri", "").startswith("file:"):
            item["uri"] += ".changed"
        return True
    return False


def add_external_uri(page: dict[str, Any]) -> bool:
    for message in page["data"]:
        if message.get("type") != "assistant":
            continue
        for part in message.get("content", []):
            if part.get("type") == "tool" and part["state"].get("status") == "completed":
                part["state"].setdefault("content", []).append(
                    {"type": "file", "uri": EXTERNAL_URI, "mime": "text/plain", "name": "x.txt"}
                )
                return True
    return False


async def check_changed_output(
    reader: Any, c: Any, tap: Tap, directory: str, earlier: list[Any]
) -> dict[str, Any]:
    """An issued output changed under the read is refused, and a real later turn
    makes every earlier turn's outputs uncapturable."""
    outputs = await reader.capture(c)
    pick = small_pick(outputs, directory)
    issued = set(reader._bytes)
    applied = tap.applied
    tap.mutate = lambda page: change_output(page, pick)
    try:
        error = await rejected(reader.read(outputs, pick))
    finally:
        tap.mutate = None
    # An intervening user input is the exact boundary the turn reader refuses.
    later = [await rejected(reader.capture(old)) for old in earlier]
    seen = {
        "injected_at": "message-page-response",
        "target": file_key(pick),
        "pages_changed": tap.applied - applied,
        "read": error,
        "bytes_issued": len(set(reader._bytes) - issued),
        "later_turn": later,
    }
    return seen | {
        "passed": bool(
            seen["pages_changed"]
            and error
            and "generated_selected_output_changed" in error
            and not seen["bytes_issued"]
            and later
            and all(e and "native_resource_intervening_input_or_terminal" in e for e in later)
        )
    }


async def check_external_uri(
    reader: Any, c: Any, tap: Tap, foreign_requests: Callable[[], int]
) -> dict[str, Any]:
    baseline = await reader.capture(c)
    before, applied = foreign_requests(), tap.applied
    tap.mutate = add_external_uri
    try:
        injected = await reader.capture(c)
    finally:
        tap.mutate = None
    uri = sha(EXTERNAL_URI.encode())
    seen = {
        "injected_at": "message-page-response",
        "pages_changed": tap.applied - applied,
        "unsupported_before": baseline.unsupported_count,
        "unsupported_after": injected.unsupported_count,
        "files_unchanged": injected.files == baseline.files,
        "uri_exposed": any(f.uri_sha256 == uri for f in injected.files),
        "non_native_requests": foreign_requests() - before,
    }
    return seen | {
        "passed": bool(
            seen["pages_changed"]
            and seen["unsupported_after"] == seen["unsupported_before"] + 1
            and seen["files_unchanged"]
            and not seen["uri_exposed"]
            and seen["non_native_requests"] == 0
        )
    }


def check_protected(
    pages: list[Any], discovery: Any, canonical_directory: str, protected: list[str]
) -> dict[str, Any]:
    """The real turn wrote protected names; none reached the issued inventory."""
    ids = set(discovery.turn.turn.ordered_message_ids)
    raw = set()
    for page in pages:
        for m in page["data"]:
            if m["id"] in ids and m["type"] == "assistant":
                for path in m.get("snapshot", {}).get("files", []):
                    raw.add(workspace_relative(path, canonical_directory) or path)
    present = sorted(raw & set(protected))
    leaked = protected_outputs(
        {"inventories": [{"files": [f.model_dump(mode="json") for f in discovery.files]}]},
        protected,
    )
    seen = {
        "protected_in_native_snapshot": present,
        "hidden_count": discovery.hidden_count,
        "leaked": leaked,
    }
    return seen | {
        "passed": bool(present) and discovery.hidden_count >= len(present) and not leaked
    }


# --------------------------------------------------------------------------
# Native worker: runs as the enrolled Bridge client UID in a transient unit.
# --------------------------------------------------------------------------


class Wire:
    """Counts what reaches httpx; refuses foreign origins and any other mutation.

    ``attempts`` counts mutations httpx began; ``sent`` counts only those Native
    answered. The transport's write boundary can still refuse an attempt.
    """

    def __init__(self, base_url: str, session_id: str, *, allow_mutations: bool) -> None:
        import httpx

        url = httpx.URL(base_url)
        self.origin = (url.host, url.port)
        self.session_id, self.allow = session_id, allow_mutations
        self.gets = 0
        self.attempts = {"prompt": 0, "permission.reply": 0}
        self.sent = {"prompt": 0, "permission.reply": 0}
        self.refused = 0
        self.foreign = 0
        self.response_bytes = 0
        self.unknown_length = 0
        self.statuses: list[list[Any]] = []

    async def request(self, request: Any) -> None:
        if (request.url.host, request.url.port) != self.origin:
            self.foreign += 1
            raise CertifyError("non_native_origin_refused")
        if request.method == "GET":
            self.gets += 1
            need(self.gets <= MAX_NATIVE_GETS, "bounded_native_gets")
            return
        kind = mutation_kind(request.method, request.url.path, self.session_id)
        bound = MAX_PROMPTS if kind == "prompt" else MAX_PERMISSION_REPLIES
        if not self.allow or kind is None or self.attempts[kind] >= bound:
            self.refused += 1
            raise CertifyError("unexpected_native_mutation_refused")
        self.attempts[kind] += 1

    async def response(self, response: Any) -> None:
        request = response.request
        if request.method != "GET":
            self.statuses.append([request.method, request.url.path, response.status_code])
            kind = mutation_kind(request.method, request.url.path, self.session_id)
            if kind is not None:
                self.sent[kind] += 1  # Native answered, so the request reached it.
        length = response.headers.get("content-length", "")
        if re.fullmatch(r"[0-9]{1,15}", length):
            self.response_bytes += int(length)
            need(self.response_bytes <= MAX_RESPONSE_BYTES, "bounded_native_response_bytes")
        else:
            self.unknown_length += 1

    def install(self, transport: Any) -> Wire:
        # First, ahead of the transport's own boundary hook: a real pool re-runs
        # before_send at the headers trace, after every hook, and the mock pool's
        # boundary must see this attempt already counted in the same order.
        transport.client.event_hooks["request"].insert(0, self.request)
        transport.client.event_hooks["response"].append(self.response)
        return self


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


def context(job: dict[str, Any]) -> SimpleNamespace:
    """Pinned components, the same ones build_pipeline composes for this Root."""
    import httpx

    from jt_oz_bridge.adapters.opencode.contracts import OpenAPIProfile
    from jt_oz_bridge.adapters.opencode.host_owner import HostOwnerEnrollment, LinuxHostOwnerProbe
    from jt_oz_bridge.adapters.opencode.project_policy import NativePolicyEnrollment
    from jt_oz_bridge.adapters.opencode.transport import ContractAttestation, V2HTTPTransport
    from jt_oz_bridge.adapters.opencode.turn_resources import NativeResourceTurn
    from jt_oz_bridge.config import load_settings
    from jt_oz_bridge.domain.models import SessionRef
    from jt_oz_bridge.security.json_data import strict_loads
    from jt_oz_bridge.security.secrets import resolve_secret
    from jt_oz_bridge.services.file_enrollment import native_file_qualification
    from jt_oz_bridge.services.runtime_enrollment import read_enrollment

    settings = load_settings(Path(job["config"]))
    enrollment, enrollment_sha = read_enrollment(settings)
    q = select_root(enrollment, project_id=job.get("project_id"), session_id=job.get("session_id"))
    ref = q.reference
    configured = next(b for b in settings.opencode_backends if b.id == ref.backend_id)
    owner_doc = HostOwnerEnrollment.model_validate(strict_loads(q.owner.read()))
    need(os.getuid() == owner_doc.client_uid, "enrolled_bridge_client_uid_required")
    need(REQUIRED_OPERATIONS <= q.verified_operations and q.file_read, "root_not_certifiable")
    profile = OpenAPIProfile(q.schema_file.read())
    policy = NativePolicyEnrollment.model_validate(strict_loads(q.policy.read()))
    need(policy.reference == ref, "root_policy_reference")
    transport = V2HTTPTransport(
        configured.base_url,
        profile,
        auth=httpx.BasicAuth(
            "opencode", resolve_secret(configured.credential_ref).get_secret_value()
        ),
        attestation=ContractAttestation(
            profile.sha256, ref.backend_identity, owner_doc.version, q.verified_operations
        ),
    )
    others = [b.reference for b in enrollment.backends if b.reference != ref]
    return SimpleNamespace(
        q=q,
        ref=ref,
        enrollment_sha=enrollment_sha,
        owner_doc=owner_doc,
        owner=LinuxHostOwnerProbe(owner_doc, q.owner_socket),
        profile=profile,
        policy=policy,
        transport=transport,
        model_doc=strict_loads(q.model_evidence.read()),
        outcomes=frozenset(
            NativeResourceTurn.model_validate(strict_loads(pin.read())["evidence"]).turn.outcome
            for pin in q.outcome_evidence
        ),
        file_attestation=native_file_qualification(
            q.file_read.read(),
            reference=ref,
            contract_sha256=profile.sha256,
            native_policy_sha256=policy.fingerprint_sha256,
            executable_sha256=owner_doc.executable_sha256,
            evidence_sha256=q.file_read.sha256,
        ),
        # Another enrolled Root when there is one; a never-enrolled id otherwise.
        foreign=others[0]
        if others
        else SessionRef.model_validate(
            ref.model_dump() | {"upstream_session_id": "ses_jtoz_" + "0" * 32}
        ),
    )


@contextlib.asynccontextmanager
async def opened(ctx: SimpleNamespace, attestation_sha: str) -> Any:
    """A fresh feed and reader stack, started after the turn so no large tool event
    passes through it; closed before the next prompt."""
    from jt_oz_bridge.adapters.opencode.catalog import V2CatalogProject
    from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
    from jt_oz_bridge.adapters.opencode.files import V2NativeFileReader
    from jt_oz_bridge.adapters.opencode.generated_files import (
        BYTE_FEATURES,
        BYTE_SEMANTICS,
        OUTPUT_FEATURES,
        OUTPUT_SEMANTICS,
        GeneratedBytesAttestation,
        GeneratedFileAttestation,
        V2GeneratedFileReader,
    )
    from jt_oz_bridge.adapters.opencode.live import V2PublicFeed
    from jt_oz_bridge.adapters.opencode.model_settings import (
        MODEL_SETTING_SEMANTICS,
        ModelSettingsAttestation,
    )
    from jt_oz_bridge.adapters.opencode.project_policy import V2ProjectPolicyGuard
    from jt_oz_bridge.adapters.opencode.resources import V2LeafResourceProofs
    from jt_oz_bridge.adapters.opencode.turn_resources import (
        RESOURCE_SEMANTICS,
        RESOURCE_TYPES,
        ResourceSemanticAttestation,
        V2TurnResourceReader,
    )
    from jt_oz_bridge.domain.catalog import ProjectScope
    from jt_oz_bridge.domain.models import SessionRef

    ref, t = ctx.ref, ctx.transport
    feed = V2PublicFeed(t, ctx.owner, (ref,), receipts=None, capture_text=False)
    projects = {
        ref.project_id: V2CatalogProject(
            ProjectScope(**ref.model_dump(exclude={"upstream_session_id"})), ctx.q.native_project_id
        )
    }
    proofs = V2LeafResourceProofs(
        feed,
        projects,
        model_settings=ModelSettingsAttestation(
            SessionRef.model_validate(ctx.model_doc["reference"]),
            t.profile.sha256,
            MODEL_SETTING_SEMANTICS,
            ctx.q.model_evidence.sha256,
            qualification_scope=ctx.q.protocol_scope,
        ),
    )
    guard = V2ProjectPolicyGuard(proofs, {ref: ctx.policy})
    execution = V2ExecutionClient(t, projects, proofs=proofs, scope_guard=guard)
    files = V2NativeFileReader(execution, attestation=ctx.file_attestation)
    turns = V2TurnResourceReader(
        execution,
        attestation=ResourceSemanticAttestation(
            ref.backend_id,
            ref.backend_identity,
            t.profile.sha256,
            RESOURCE_SEMANTICS,
            ctx.enrollment_sha,
            RESOURCE_TYPES,
            ctx.outcomes,
        ),
    )
    # This run is the qualification itself: the candidate attestations exist for
    # this process only; the pinned bundle's own digest replaces them at runtime.
    reader = V2GeneratedFileReader(
        turns,
        attestation=GeneratedFileAttestation(
            ref, t.profile.sha256, OUTPUT_SEMANTICS, attestation_sha, OUTPUT_FEATURES
        ),
        file_reader=files,
        byte_attestation=GeneratedBytesAttestation(
            ref, t.profile.sha256, BYTE_SEMANTICS, attestation_sha, BYTE_FEATURES
        ),
    )
    try:
        await feed.start()
        await proofs.watch(ref, require_idle=True)
        yield SimpleNamespace(feed=feed, proofs=proofs, guard=guard, reader=reader)
    finally:
        await feed.close()


async def root_quiet(ctx: SimpleNamespace) -> str | None:
    """Positive Idle with nothing pending; returns the latest Idle message id."""
    t, sid = ctx.transport, {"sessionID": ctx.ref.upstream_session_id}
    active = (await t.request("session.active"))["data"]
    inbox = (await t.request("session.inbox.list", path=sid))["data"]
    permissions = (await t.request("session.permission.list", path=sid))["data"]
    forms = (await t.request("session.form.list", path=sid))["data"]
    latest = (
        await t.request("session.message.list", path=sid, query={"limit": "1", "order": "desc"})
    )["data"]
    need(ctx.ref.upstream_session_id not in active, "root_busy")
    need(not inbox and not permissions and not forms, "root_has_pending_input_or_request")
    from jt_oz_bridge.adapters.opencode.aborted_turn import aborted_head

    # A declined permission ends its turn without an Idle. Before this run's
    # first prompt, the Bridge's own resource proof (watched with
    # require_idle) has already reconciled that exact aborted tail, so its
    # head is just as good a boundary; after any prompt only an Idle counts.
    wire = getattr(ctx, "wire", None)
    untouched = wire is None or not any(wire.attempts.values())
    need(
        not latest or latest[0]["type"] == "idle" or untouched and aborted_head(latest[0]),
        "root_latest_message_not_idle",
    )
    return latest[0]["id"] if latest else None


async def run_turn(
    ctx: SimpleNamespace, step: dict[str, Any], job: dict[str, Any], result: dict[str, Any]
) -> Any:
    """One operator prompt, then wait for its Idle while answering only planned asks."""
    from jt_oz_bridge.adapters.opencode.turn_resources import TurnCorrelation
    from jt_oz_bridge.storage.durable import digest

    t, ref = ctx.transport, ctx.ref
    sid = {"sessionID": ref.upstream_session_id}
    idle_before = await root_quiet(ctx)
    action_id = uuid.uuid4().hex
    source = prompt_source(
        tag=job["tag"], step=step["step"], action_id=action_id, text=step["text"]
    )
    body = prompt_body(step["text"], action_id, digest(source))
    record: dict[str, Any] = {
        "step": step["step"],
        "action_id": action_id,
        "operation_digest": digest(source),
        "operator_source": source,
        "admitted": False,
        "sent": False,
    }
    result["prompts"].append(record)
    need(len(result["prompts"]) <= MAX_PROMPTS, "prompt_bound")

    def one_prompt() -> None:
        # The transport calls this before the request and again at its write
        # boundary, after the Wire hook has counted this very attempt: it must be
        # idempotent for that one attempt and refuse only a second one.
        need(ctx.wire.attempts["prompt"] <= len(result["prompts"]), "second_prompt_for_step")

    value = await send_mutation(
        ctx, "prompt", record, "session.prompt", path=sid, body=body, before_send=one_prompt
    )
    raw = value["data"]
    need(
        raw["sessionID"] == ref.upstream_session_id
        and raw["payload"]["text"] == step["text"]
        and raw["delivery"] == "queue"
        and raw["payload"].get("metadata", {}).get("jt_oz_bridge")
        == body["metadata"]["jt_oz_bridge"]
        and not raw["payload"].get("files"),
        "prompt_acknowledgement_mismatch",
    )
    record.update(admitted=True, upstream_id=raw["id"])
    correlation = TurnCorrelation(
        reference=ref,
        action_id=action_id,
        operation_digest=digest(source),
        upstream_id=raw["id"],
        text=step["text"],
    )
    deadline = time.monotonic() + TURN_SECONDS
    answered: set[str] = set()
    while True:
        need(time.monotonic() < deadline, "turn_deadline_exceeded_left_running")
        forms = (await t.request("session.form.list", path=sid))["data"]
        need(not forms, "root_asked_a_question_left_pending")
        permissions = (await t.request("session.permission.list", path=sid))["data"]
        for item in permissions:
            if item.get("id") in answered:
                continue
            try:
                ctx.profile.validate(
                    "component:Permission.Request",
                    {"$ref": "#/components/schemas/Permission.Request"},
                    item,
                )
                decision, reason = permission_decision(
                    item,
                    session_id=ref.upstream_session_id,
                    canonical_directory=ref.canonical_directory,
                    step=step,
                )
            except ValueError:
                # Never leave the Root blocked on a request we cannot read: refuse it.
                decision, reason = "reject", "request_shape_unqualified"
            need(isinstance(item.get("id"), str), "permission_request_without_id")
            answered.add(item["id"])
            resources = [r for r in item.get("resources") or [] if isinstance(r, str)]
            reply = {
                "step": step["step"],
                "request_sha256": digest(item),
                "action": str(item.get("action"))[:64],
                "resources": resources if decision == "once" else None,
                "resource_sha256": [sha(r.encode()) for r in resources],
                "decision": decision,
                "reason": reason,
                "sent": False,
            }
            result["permission_replies"].append(reply)
            need(len(result["permission_replies"]) <= MAX_PERMISSION_REPLIES, "reply_bound")
            await send_mutation(
                ctx,
                "permission.reply",
                reply,
                "session.permission.reply",
                path=sid | {"requestID": item["id"]},
                body={"decision": decision},
            )
            # A reject ends the step; nothing else is sent to make it succeed.
            need(decision == "once", f"permission_refused:{reason}")
        if not permissions:
            latest = (
                await t.request(
                    "session.message.list", path=sid, query={"limit": "1", "order": "desc"}
                )
            )["data"]
            active = (await t.request("session.active"))["data"]
            if (
                latest
                and latest[0]["type"] == "idle"
                and latest[0]["id"] != idle_before
                and ref.upstream_session_id not in active
            ):
                record["outcome"] = latest[0].get("outcome")
                return correlation
        await asyncio.sleep(POLL_SECONDS)


async def collect(
    ctx: SimpleNamespace, s: SimpleNamespace, c: Any, limit: int, result: dict[str, Any]
) -> Any:
    """Inventory plus up to ``limit`` byte cases, each from its own fresh capture."""
    reader = s.reader
    outputs = await reader.capture(c)
    inventory = reader.discovery_evidence(outputs)
    result["inventories"].append(inventory.model_dump(mode="json"))
    expected = requested_files(cert_directory(result["tag"]))
    for key in choose_cases(outputs.files, cert_directory(result["tag"]), limit):
        try:
            opens = ctx.audit.workspace_opens
            outputs = await reader.capture(c)
            match = [f for f in outputs.files if file_key(f) == key]
            need(len(match) == 1, "selection_not_unique_in_fresh_capture")
            data = await reader.read(outputs, match[0])
            current = reader.current_bytes(data)
            evidence = reader.evidence(data)
            discovery = reader.discovery_evidence(outputs)
            exact = exact_bytes(data.content, evidence)
            wanted = expected.get(match[0].path or "")
            matched = None if wanted is None else sha(wanted) == sha(data.content)
            del data
        except ValueError as error:
            result["case_errors"].append(
                {"selection": key, "error": f"{type(error).__name__}:{str(error)[:300]}"}
            )
            continue
        if discovery.stable_sha256 != evidence.discovery().stable_sha256:
            result["case_errors"].append({"selection": key, "error": "inventory_not_stable"})
            continue
        result["inventories"].append(discovery.model_dump(mode="json"))
        result["cases"].append(
            {
                "original_object_current": current,
                "exact_native_bytes_verified": exact,
                "workspace_opens": ctx.audit.workspace_opens - opens,
                "requested_bytes_matched": matched,
                "evidence": evidence.model_dump(mode="json"),
            }
        )
    return inventory


async def worker_main(job: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Fills ``result`` in place so a timeout still reports what happened."""
    from jt_oz_bridge.storage.durable import digest

    certify = job["mode"] == "certify"
    if certify:
        need(job.get("confirmed_operator_prompts") is True, "explicit_operator_prompt_flag")
    ctx = context(job)
    ref, t = ctx.ref, ctx.transport
    ctx.audit = Audit(ref.canonical_directory, ctx.owner_doc.dataset_path)
    sys.addaudithook(ctx.audit)
    ctx.wire = Wire(str(t.client.base_url), ref.upstream_session_id, allow_mutations=certify)
    ctx.wire.install(t)
    plan = operator_plan(job["tag"])
    plan_sha = plan_sha256(
        plan,
        reference=ref.model_dump(mode="json"),
        policy_sha256=ctx.policy.fingerprint_sha256,
        tool_sha256=job["tool_sha256"],
    )
    attestation_sha = candidate_attestation(tag=job["tag"], plan_sha=plan_sha)
    result.update(
        {
            "mode": job["mode"],
            "tag": job["tag"],
            "stage": "start",
            "error": None,
            "reference": ref.model_dump(mode="json"),
            "directory": plan["directory"],
            "plan_sha256": plan_sha,
            "candidate_attestation_sha256": attestation_sha,
            "foreign_reference": ctx.foreign.model_dump(mode="json"),
            "prompts": [],
            "permission_replies": [],
            "turns_completed": 0,
            "inventories": [],
            "cases": [],
            "case_errors": [],
            "negative_checks": {},
            "owner_before": None,
            "owner_after": None,
        }
    )
    try:
        result["owner_before"] = (await ctx.owner.read()).model_dump(mode="json")
        epoch = result["owner_before"]["owner_epoch"]

        async def same_owner() -> bool:
            observed = await ctx.owner.read()
            return (
                observed.owner_epoch == epoch
                and observed.backend_identity == ref.backend_identity
                and observed.version == ctx.owner_doc.version
            )

        t.verify_identity = same_owner
        result["stage"] = "preflight"
        async with opened(ctx, attestation_sha) as s:
            first, _ = await s.guard._bundle_facts(ref)
            second, _ = await s.guard._bundle_facts(ref)
            need(digest(first) == digest(second), "root_policy_facts_unstable")
            need(digest(first) == ctx.policy.fingerprint_sha256, "root_policy_drifted_from_pin")
            result["live"] = {
                "agent": first["agent"],
                "session_permissions": first["session_permissions"],
                "mcp": [m.get("name") for m in first["mcp"]],
                "saved_permissions": len(first["saved_permissions"]),
            }
        result["idle_before"] = await root_quiet(ctx)
        if not certify:
            result["owner_after"] = (await ctx.owner.read()).model_dump(mode="json")
            result["stage"] = "planned"
            return result
        need(plan_sha == job["expected_plan_sha256"], "plan_changed_since_plan")
        tap = Tap(t).install()

        def requests() -> int:
            return int(ctx.wire.gets + sum(ctx.wire.attempts.values()))

        correlations = []
        for index, step in enumerate(plan["steps"]):
            result["stage"] = "turn:" + step["step"]
            correlations.append(await run_turn(ctx, step, job, result))
            result["turns_completed"] = index + 1
            result["stage"] = "capture:" + step["step"]
            async with opened(ctx, attestation_sha) as s:
                c = correlations[-1]
                if step["step"] == "quiet":
                    outputs = await s.reader.capture(c)
                    result["inventories"].append(
                        s.reader.discovery_evidence(outputs).model_dump(mode="json")
                    )
                    continue
                await collect(ctx, s, c, MAX_BYTE_CASES - len(result["cases"]), result)
                checks = result["negative_checks"]
                if step["step"] == "files":
                    # Small pages only: this turn's raw snapshot names, kept in memory.
                    tap.record, tap.pages = True, []
                    try:
                        outputs = await s.reader.capture(c)
                        inventory = s.reader.discovery_evidence(outputs)
                    finally:
                        tap.record = False
                    checks["protected-path-not-disclosed"] = check_protected(
                        tap.pages,
                        inventory,
                        ref.canonical_directory,
                        [f"{plan['directory']}/{p}" for p in PROTECTED],
                    )
                    tap.pages = []
                    checks["copied-and-expired-objects-rejected"] = await check_copied_and_expired(
                        s.reader, c, requests, plan["directory"]
                    )
                    checks["foreign-root-rejected"] = await check_foreign_root(
                        s.reader, c, ctx.foreign, requests
                    )
                    checks["external-uri-not-fetched"] = await check_external_uri(
                        s.reader, c, tap, lambda: ctx.wire.foreign
                    )
                    # The files turn is itself the real later turn for the quiet one.
                    checks["changed-output-rejected"] = await check_changed_output(
                        s.reader, c, tap, plan["directory"], correlations[:-1]
                    )
                    checks["changed-owner-rejected"] = await check_changed_owner(
                        s.reader, c, plan["directory"]
                    )
        result["owner_after"] = (await ctx.owner.read()).model_dump(mode="json")
        result["stage"] = "observed"
    except Exception as error:  # report everything; root decides what is written
        result["error"] = f"{type(error).__name__}:{error}"[:500]
        if result["owner_after"] is None:
            with contextlib.suppress(Exception):
                result["owner_after"] = (await ctx.owner.read()).model_dump(mode="json")
    finally:
        result["native_get_count"] = ctx.wire.gets
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
    need(job.get("mode") in {"plan", "certify"}, "worker_mode")
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
        self.config = Path(raw.get("config", "/etc/jt-oz-bridge/config.toml"))
        self.observer = Path(raw.get("observer", "/etc/jt-oz-bridge/local-observer.json"))
        self.output = Path(raw.get("output", f"/etc/jt-oz-bridge/generated-{self.tag}"))
        self.stage = Path(raw.get("stage", f"/etc/jt-oz-bridge/runtime-generated-{self.tag}"))
        for value in (self.config, self.observer, self.output, self.stage):
            need(value.is_absolute() and ".." not in value.parts, "spec_paths_absolute")

    def job(self, mode: str, tool_sha256: str) -> dict[str, Any]:
        return {
            "mode": mode,
            "tag": self.tag,
            "config": str(self.config),
            "project_id": self.project_id,
            "session_id": self.session_id,
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


def load_target(spec: Spec) -> tuple[Any, Any, Any, dict[str, Any], Any]:
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
    return q, owner_doc, policy, manifest, settings


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
        f"jt-oz-certify-generated-{job['tag']}-{job['mode']}-{uuid.uuid4().hex[:8]}.service",
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
    "certify writes the planned files into <canonical_directory>/<directory> of the Root's "
    "real workspace and leaves them there",
    "the two operator turns become part of the Root's history; if the Root is bound in "
    "Zulip and the native mirror is on, the live Bridge may mirror them into that topic",
    "the evidence qualifies only the output origins and the largest size actually read; "
    "the runtime counts every other output as unsupported",
    "no interrupt, form reply or retry is ever sent: a turn past its deadline or a pending "
    "question is left as it is and certify fails",
    "any other input to this Root during certify breaks the isolated turns and certify fails",
)


def cmd_plan(spec: Spec) -> None:
    need(os.geteuid() == 0, "root_required")
    q, owner_doc, policy, manifest, _ = load_target(spec)
    tool_sha = sha(Path(__file__).read_bytes())
    plan = operator_plan(spec.tag)
    plan_sha = plan_sha256(
        plan,
        reference=q.reference.model_dump(mode="json"),
        policy_sha256=policy.fingerprint_sha256,
        tool_sha256=tool_sha,
    )
    problems = root_preflight(q, manifest)
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
    print(
        json.dumps(
            {
                "planned": not problems,
                "problems": problems,
                "native_mutations": 0,
                "native_get_count": (worker or {}).get("native_get_count", 0),
                "root": q.reference.model_dump(mode="json"),
                "manifest_format": manifest.get("format"),
                "live_policy": (worker or {}).get("live"),
                "owner_epoch": ((worker or {}).get("owner_before") or {}).get("owner_epoch"),
                "native_host": host_state(owner_doc.unit),
                "certification_directory": plan["directory"],
                "prompts": [s["text"] for s in plan["steps"]],
                "approvable": {
                    s["step"]: {k: s[k] for k in ("write_files", "read_files", "commands")}
                    for s in plan["steps"]
                },
                "maximum_native_mutations": {
                    "session.prompt": MAX_PROMPTS,
                    "session.permission.reply": MAX_PERMISSION_REPLIES,
                },
                "limits": {
                    "native_gets": MAX_NATIVE_GETS,
                    "response_bytes": MAX_RESPONSE_BYTES,
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


def cmd_certify(spec: Spec, expected_plan: str, confirmed: bool) -> None:
    need(confirmed, "explicit_operator_prompt_flag_required")
    need(os.geteuid() == 0, "root_required")
    need(re.fullmatch(r"[0-9a-f]{64}", expected_plan), "plan_sha256_from_plan_required")
    q, owner_doc, policy, manifest, _ = load_target(spec)
    problems = root_preflight(q, manifest)
    need(not problems, f"root_not_certifiable:{problems}")
    tool_sha = sha(Path(__file__).read_bytes())
    plan_sha = plan_sha256(
        operator_plan(spec.tag),
        reference=q.reference.model_dump(mode="json"),
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
        "root": q.reference.model_dump(mode="json"),
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
    bundle, failures = build_bundle(
        worker=worker,
        reference=q.reference,
        contract_sha256=q.schema_file.sha256,
        executable_sha256=owner_doc.executable_sha256,
        host_before=host_before,
        host_after=host_after,
        tool_sha256=tool_sha,
        plan_sha=plan_sha,
        observed_at=time.time(),
    )
    if code != 0:
        failures.append(f"worker_returncode:{code}")
    transcript = {
        "worker_error": worker.get("error"),
        "worker_stage": worker.get("stage"),
        "case_errors": worker.get("case_errors"),
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
            "files_left_in_workspace": f"{q.reference.canonical_directory}/"
            + cert_directory(spec.tag),
        }
        write_new(out / "FAILED.json", dumps(receipt), mode=0o600)
        write_new(out / "rejected-bundle.json", dumps(bundle), mode=0o600)
        print(stderr.decode(errors="replace")[-2000:], file=sys.stderr)
        raise CertifyError(f"certify_failed:{failures[:8]}")
    raw = dumps(bundle)
    write_new(out / BUNDLE_FILE, raw, group=group)
    print(
        json.dumps(
            {
                "certified": True,
                "human_acceptance": False,
                "output_directory": str(out),
                "generated_outputs": {"path": str(out / BUNDLE_FILE), "sha256": sha(raw)},
                "byte_cases": len(bundle["byte_cases"]),
                "inventories": len(bundle["inventories"]),
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
    from jt_oz_bridge.services.generated_enrollment import generated_qualification

    q, owner_doc, _, manifest, settings = load_target(spec)
    bundle_path = spec.output / BUNDLE_FILE
    bundle_raw = root_bytes(bundle_path)
    generated_qualification(
        bundle_raw,
        reference=q.reference,
        contract_sha256=q.schema_file.sha256,
        executable_sha256=owner_doc.executable_sha256,
        evidence_sha256=sha(bundle_raw),
    )
    target = spec.stage
    reference = q.reference.model_dump(mode="json")
    merged = stage_manifest(
        manifest, reference, {"path": str(bundle_path), "sha256": sha(bundle_raw)}
    )
    manifest_out = dumps(merged)
    config_out = stage_config(root_bytes(spec.config).decode(), target / "runtime.json")
    observer = json.loads(root_bytes(spec.observer))
    observer_out = dumps(stage_observer(observer, sha(manifest_out)))
    staged = Settings.model_validate(tomllib.loads(config_out))
    validate_stage(
        staged,
        manifest_path=target / "runtime.json",
        manifest_raw=manifest_out,
        observer_raw=observer_out,
        reference=reference,
    )
    group = pwd.getpwuid(owner_doc.client_uid).pw_gid
    new_directory(target, group)
    write_new(target / "runtime.json", manifest_out, group=group)
    write_new(target / "config.toml", config_out.encode(), group=group)
    write_new(target / "local-observer.json", observer_out, group=group)
    assert settings.runtime.enrollment_file is not None
    print(
        json.dumps(
            {
                "staged": str(target),
                "runtime_sha256": sha(manifest_out),
                "previous_runtime": str(settings.runtime.enrollment_file),
                "manifest_format": merged["format"],
                "generated_scope": json.loads(bundle_raw).get("scope"),
                "generated_roots": merged["generated_roots"],
                "reminder": (
                    "Nothing is active yet. Run the full gate for the release, then point "
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
