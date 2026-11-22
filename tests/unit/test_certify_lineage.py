"""Offline checks of the tree-lineage certification tool.

Synthetic data only: no Native, socket, systemd or root file is touched. The
observation windows run against the contract suite's mocked Native tree, and
nothing here is installed, operator, Human or mobile qualification evidence.
"""

import copy
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from jt_oz_bridge.adapters.opencode.existing_session_graph import graph_identity
from jt_oz_bridge.adapters.opencode.lineage_resources import (
    LINEAGE_SEMANTICS,
    LineageResourceAttestation,
)
from jt_oz_bridge.adapters.opencode.model_catalog import READS as MODEL_READS
from jt_oz_bridge.adapters.opencode.project_policy import POLICY_READS
from jt_oz_bridge.adapters.opencode.resources import READS
from jt_oz_bridge.domain.existing_sessions import (
    ExistingSessionGraphObservation,
    ExistingSessionObservation,
)
from jt_oz_bridge.services import runtime_enrollment as runtime
from jt_oz_bridge.storage.durable import digest
from tests.integration.test_runtime_enrollment import enrolled  # noqa: F401  (fixture)

TOOL = Path(__file__).resolve().parents[2] / "ops" / "server" / "certify_lineage.py"
_spec = importlib.util.spec_from_file_location("certify_lineage", TOOL)
assert _spec is not None and _spec.loader is not None
tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tool)

DIRECTORY = tool.cert_directory("unit")
CHILD_FILE = f"{DIRECTORY}/child.txt"
CANONICAL = "/home/opencode/workspaces/synthetic"
TARGET_ID, CHILD_ID, SECOND_ID, GRAND_ID = (
    "ses_target_disposable",
    "ses_child_one",
    "ses_child_two",
    "ses_grandchild",
)
OWNER = "a" * 64


def step(name):
    return next(s for s in tool.operator_plan("unit")["steps"] if s["step"] == name)


def test_plan_has_two_bounded_prompts_and_a_stable_digest():
    plan = tool.operator_plan("unit")
    assert [s["step"] for s in plan["steps"]] == ["tree", "nested"]
    assert len(plan["steps"]) == tool.MAX_PROMPTS == 2 and tool.MAX_PERMISSION_REPLIES == 6
    assert plan["child_file"] == CHILD_FILE
    assert tool.operator_plan("unit") == plan
    # Tiny outputs only: nothing is read and no shell command is planned.
    text = json.dumps(plan)
    assert "read tool" not in text and "shell" not in text
    assert all(s["text"].count("not a message from a person") == 1 for s in plan["steps"])
    anchor, target = {"upstream_session_id": "ses_anchor"}, {"upstream_session_id": TARGET_ID}
    args = {"anchor": anchor, "target": target, "policy_sha256": "b" * 64, "tool_sha256": "f" * 64}
    first = tool.plan_sha256(plan, **args)
    assert first == tool.plan_sha256(tool.operator_plan("unit"), **args)
    for key, value in (
        ("anchor", {"upstream_session_id": "ses_other"}),
        ("target", {"upstream_session_id": "ses_other"}),
        ("policy_sha256", "c" * 64),
        ("tool_sha256", "e" * 64),
    ):
        assert tool.plan_sha256(plan, **(args | {key: value})) != first
    with pytest.raises(ValueError):
        tool.cert_directory("../escape")


def test_required_operations_and_checks_match_the_runtime():
    assert READS | POLICY_READS | MODEL_READS <= tool.REQUIRED_OPERATIONS
    assert {"session.prompt", "session.permission.reply"} <= tool.REQUIRED_OPERATIONS
    assert frozenset(tool.CHECK_NAMES) == runtime.LINEAGE_CHECKS
    assert tool.REPLY_OPERATIONS == {"permission.reply", "form.reply", "form.cancel"}


def ask(action, *resources, session=CHILD_ID):
    return {"id": "per_1", "sessionID": session, "action": action, "resources": list(resources)}


@pytest.mark.parametrize(
    "name, depth, asked, decision",
    [
        ("tree", 0, ask("task", tool.SUBAGENT, session=TARGET_ID), "once"),
        # OpenCode 2.0 asks for the task tool as ``subagent``.
        ("tree", 0, ask("subagent", tool.SUBAGENT, session=TARGET_ID), "once"),
        ("tree", 1, ask("subagent", tool.SUBAGENT), "reject"),
        ("tree", 1, ask("edit", CHILD_FILE), "once"),
        ("tree", 1, ask("write", f"{CANONICAL}/{CHILD_FILE}"), "once"),
        ("nested", 0, ask("task", tool.SUBAGENT, session=TARGET_ID), "once"),
        ("nested", 1, ask("task", tool.SUBAGENT), "once"),
        # Everything else is rejected, never widened.
        ("tree", 1, ask("task", tool.SUBAGENT), "reject"),  # the child starts nothing
        ("tree", 0, ask("edit", CHILD_FILE, session=TARGET_ID), "reject"),
        ("nested", 1, ask("edit", CHILD_FILE), "reject"),
        ("nested", 2, ask("task", tool.SUBAGENT), "reject"),
        ("tree", 0, ask("task", "build", session=TARGET_ID), "reject"),
        ("tree", 0, ask("task", tool.SUBAGENT, "build", session=TARGET_ID), "reject"),
        ("tree", 1, ask("edit", f"{DIRECTORY}/other.txt"), "reject"),
        ("tree", 1, ask("edit", f"{DIRECTORY}/../child.txt"), "reject"),
        ("tree", 1, ask("edit", f"{DIRECTORY}/*"), "reject"),
        ("tree", 1, ask("edit", CHILD_FILE, "/etc/passwd"), "reject"),
        ("tree", 1, ask("edit", f"{CANONICAL}-other/{CHILD_FILE}"), "reject"),
        ("tree", 1, ask("shell", "ls"), "reject"),
        ("tree", 1, ask("bash", "ls"), "reject"),
        ("tree", 1, ask("read", CHILD_FILE), "reject"),
        ("tree", 1, ask("external_directory", "/tmp/*"), "reject"),
        ("tree", 1, ask("webfetch", "https://example.com"), "reject"),
        ("tree", 1, ask("edit"), "reject"),
        ("tree", 1, ask("edit", CHILD_FILE, session=SECOND_ID), "reject"),
        ("tree", 1, None, "reject"),
    ],
)
def test_permission_replies_are_once_only_for_the_planned_ask_at_its_depth(
    name, depth, asked, decision
):
    node = TARGET_ID if depth == 0 else CHILD_ID
    got, reason = tool.permission_decision(
        asked, node_id=node, depth=depth, canonical_directory=CANONICAL, step=step(name)
    )
    assert got == decision, reason
    assert got in {"once", "reject"}  # `always` can never be produced


def request(method, path, host="127.0.0.1", port=4096):
    return SimpleNamespace(method=method, url=SimpleNamespace(host=host, port=port, path=path))


async def test_wire_allows_only_target_prompts_and_replies_inside_the_verified_tree():
    base = "/api/session/" + TARGET_ID
    plan = tool.Wire("http://127.0.0.1:4096", TARGET_ID, allow_mutations=False)
    await plan.request(request("GET", base))
    with pytest.raises(ValueError, match="unexpected_native_mutation"):
        await plan.request(request("POST", base + "/prompt"))
    wire = tool.Wire("http://127.0.0.1:4096", TARGET_ID, allow_mutations=True)
    child_reply = f"/api/session/{CHILD_ID}/permission/per_c/reply"
    # Not yet a verified descendant: refused.
    with pytest.raises(ValueError, match="unexpected_native_mutation"):
        await wire.request(request("POST", child_reply))
    wire.nodes.add(CHILD_ID)
    for refused in (
        request("POST", "/api/session"),
        request("POST", base + "/interrupt"),
        request("POST", base + "/form/frm_1/reply"),
        request("POST", f"/api/session/{CHILD_ID}/prompt"),
        request("POST", "/api/session/ses_other/permission/per_x/reply"),
        request("POST", base + "/permission/../reply"),
        request("PATCH", base),
        request("DELETE", base),
    ):
        with pytest.raises(ValueError, match="unexpected_native_mutation"):
            await wire.request(refused)
    for _ in range(tool.MAX_PROMPTS):
        await wire.request(request("POST", base + "/prompt"))
    with pytest.raises(ValueError, match="unexpected_native_mutation"):
        await wire.request(request("POST", base + "/prompt"))
    for index in range(tool.MAX_PERMISSION_REPLIES):
        path = child_reply if index % 2 else f"{base}/permission/per_{index}/reply"
        await wire.request(request("POST", path))
    with pytest.raises(ValueError, match="unexpected_native_mutation"):
        await wire.request(request("POST", child_reply))
    with pytest.raises(ValueError, match="non_native_origin"):
        await wire.request(request("GET", "/x", host="198.51.100.7"))
    assert wire.attempts == {"prompt": 2, "permission.reply": 6}
    assert wire.sent == {"prompt": 0, "permission.reply": 0}  # nothing was answered
    assert wire.refused == 11 and wire.foreign == 1 and plan.refused == 1


async def test_wire_bounds_gets_and_counts_failed_gets(monkeypatch):
    monkeypatch.setattr(tool, "MAX_NATIVE_GETS", 1)
    wire = tool.Wire("http://127.0.0.1:4096", TARGET_ID, allow_mutations=False)
    await wire.request(request("GET", "/a"))
    with pytest.raises(ValueError, match="bounded_native_gets"):
        await wire.request(request("GET", "/b"))
    for status in (200, 404):
        await wire.response(
            SimpleNamespace(request=request("GET", "/a"), status_code=status, headers={})
        )
    assert wire.failed_gets == 1 and wire.unknown_length == 2


@pytest.mark.parametrize(
    "change, problem",
    [
        ({}, None),
        ({"parentID": "ses_other"}, "child_parent_changed"),
        ({"projectID": "other"}, "child_foreign_project"),
        ({"location": {"directory": CANONICAL + "-other"}}, "child_foreign_directory"),
        ({"time": {"created": 2, "archived": 3}}, "child_archived"),
        ({"time": {"created": "2"}}, "child_creation_time_required"),
        ({"id": "not-a-session"}, "child_id_shape"),
    ],
)
def test_listed_children_must_stay_in_the_target_tree(change, problem):
    row = {
        "id": CHILD_ID,
        "parentID": TARGET_ID,
        "projectID": "global",
        "location": {"directory": CANONICAL},
        "time": {"created": 2},
    } | change
    assert (
        tool.child_row_problem(
            row, parent_id=TARGET_ID, native_project_id="global", canonical_directory=CANONICAL
        )
        == problem
    )
    assert tool.child_row_problem(
        None, parent_id="x", native_project_id="g", canonical_directory="/"
    )


def test_graph_descendants_follow_observed_parent_edges_only():
    rows = [
        {"id": "t", "parent": None},
        {"id": "c", "parent": "t"},
        {"id": "g", "parent": "c"},
        {"id": "s", "parent": "t"},
    ]
    assert tool.graph_descendants(rows) == {"t": ["c", "g", "s"], "c": ["g"], "g": [], "s": []}


# --------------------------------------------------------------------------
# Evidence assembly: a synthetic worker transcript against the runtime models.
# --------------------------------------------------------------------------


def observed(ref, created, parent=None, parent_created=None, info="c"):
    origin = {"reference": ref.model_dump(mode="json"), "created_at": created}
    return ExistingSessionObservation(
        reference=ref,
        native_project_id="global",
        native_created_at=created,
        parent_reference=parent,
        parent_created_at=parent_created,
        origin_sha256=digest(origin),
        policy_sha256=digest({"policy": ref.upstream_session_id}),
        session_info_sha256=info * 64,
        progress_info_sha256="9" * 64,
        owner_epoch=OWNER,
        observed_at=100,
        expires_at=105,
    )


def tree(base, *, children=(), info="c"):
    refs = {
        sid: base.model_copy(update={"upstream_session_id": sid})
        for sid in (TARGET_ID, CHILD_ID, SECOND_ID, GRAND_ID)
    }
    created = {TARGET_ID: 1, CHILD_ID: 2, SECOND_ID: 3, GRAND_ID: 4}
    parents = {CHILD_ID: TARGET_ID, SECOND_ID: TARGET_ID, GRAND_ID: SECOND_ID}
    nodes = [observed(refs[TARGET_ID], 1)]
    for sid in children:
        parent = parents[sid]
        nodes.append(observed(refs[sid], created[sid], refs[parent], created[parent], info))
    return ExistingSessionGraphObservation(
        reference=refs[TARGET_ID],
        nodes=tuple(nodes),
        graph_sha256=graph_identity(tuple(nodes)),
        owner_epoch=OWNER,
        observed_at=100,
        expires_at=105,
    )


QUIESCENT = "ContractError:lineage_dispatch_original_quiescent_graph_required"


def window(label, feed, graph, states, *, pending=None, interactions=(), dispatch=QUIESCENT):
    rows = tool.node_rows(graph)
    below = tool.graph_descendants(rows)
    return {
        "label": label,
        "feed": feed,
        "ok": True,
        "errors": [],
        "mutations_during": 0,
        "connection_epoch": f"connection-{feed}",
        "graph": graph.model_dump(mode="json"),
        "graph_sha256": graph.graph_sha256,
        "owner_epoch": OWNER,
        "nodes": rows,
        "provider_descendants": below,
        "snapshots": [
            {
                "id": r["id"],
                "state": states[r["id"]],
                "reconciled": True,
                "descendants": below[r["id"]],
                "cursor": f"resource-sha256:{label}:{r['id']}",
                "resource_fence": "f" * 64,
                "issued_at": 1730000000.123,
                "expires_at": 1730000000.123 + 5,
                "connection_epoch": f"connection-{feed}",
                "owner_epoch": OWNER,
                "state_only_fence": states[r["id"]] != "idle",
                "pending": (pending or {}).get(r["id"], []),
            }
            for r in rows
        ],
        "interactions": list(interactions),
        "root_dispatch": dispatch,
    }


def owner_evidence(exe, version):
    return {
        "owner_epoch": OWNER,
        "pid": 42,
        "process_start_ticks": 7,
        "boot_id": "00000000-0000-4000-8000-000000000001",
        "executable_sha256": exe,
        "version": version,
    }


def host(exe):
    return {"pid": 42, "nrestarts": 0, "binary_sha256": exe, "invocation_id": "i", "start_ticks": 7}


def passing_worker(base, exe, version="2.0.32"):
    one, all_ = (CHILD_ID,), (CHILD_ID, SECOND_ID, GRAND_ID)
    idle = dict.fromkeys((TARGET_ID, *all_), "idle")
    windows = [
        window("tree:before", 0, tree(base), idle),
        window(
            "tree:grown",
            0,
            tree(base, children=one),
            idle | {TARGET_ID: "running", CHILD_ID: "running"},
        ),
        window(
            "tree:waiting",
            0,
            tree(base, children=one),
            idle | {TARGET_ID: "running", CHILD_ID: "waiting_permission"},
            pending={CHILD_ID: [["per_1", "permission"]]},
            interactions=[
                {
                    "id": CHILD_ID,
                    "request": "per_1",
                    "kind_on_node": "permission",
                    "kind_on_root": None,
                }
            ],
        ),
        window(
            "tree:settled", 0, tree(base, children=one, info="d"), idle, dispatch="dispatchable"
        ),
        window(
            "nested:before", 1, tree(base, children=one, info="d"), idle, dispatch="dispatchable"
        ),
        window(
            "nested:grown",
            1,
            tree(base, children=all_, info="d"),
            idle | {TARGET_ID: "running", SECOND_ID: "running", GRAND_ID: "running"},
        ),
        window(
            "nested:settled", 1, tree(base, children=all_, info="e"), idle, dispatch="dispatchable"
        ),
    ]
    discovered = {
        sid: {
            "parent": parent,
            "depth": depth,
            "created": created,
            "agent": "general",
            "project_matches": True,
            "directory_matches": True,
        }
        for sid, parent, depth, created in (
            (CHILD_ID, TARGET_ID, 1, 2),
            (SECOND_ID, TARGET_ID, 1, 3),
            (GRAND_ID, SECOND_ID, 2, 4),
        )
    }
    unseen = {"error": "ContractError:lineage_explicit_original_backend_semantics_required"}
    prompt = {"admitted": True, "sent": True}
    return {
        "target": TARGET_ID,
        "target_reference": base.model_dump(mode="json") | {"upstream_session_id": TARGET_ID},
        "discovered": discovered,
        "windows": windows,
        "negatives": {
            "leaf_before": {"error": None, "state": "idle"},
            "leaf_refused": {"error": "ContractError:leaf_descendants_require_qualification"},
            "unseen": [unseen, dict(unseen)],
            "foreign": {
                "select": "ContractError:x",
                "snapshot": "ContractError:y",
                "native_requests": 0,
            },
            "policy": {
                "control": None,
                "pages_changed": 1,
                "tampered": "ContractError:native_project_policy_changed_or_unqualified",
                "inherited_enrollment": "ValueError:lineage_original_node_policy_required",
            },
            "owner": {
                "control": None,
                "snapshot": "ContractError:owner",
                "current_proof_after": False,
            },
            "settled": {
                "states": ["idle", "idle"],
                "state_only": [False, False],
                "cursors": ["resource-sha256:settled"] * 2,
                "fences": ["f" * 64] * 2,
                "dispatch_owner": OWNER,
                "earlier_active_cursor": "resource-sha256:active",
                "pages": {TARGET_ID: ["p", "p"], CHILD_ID: ["q", "q"]},
            },
            "deadline": {
                "issued_at": 1730000000.123,
                "expires_at": 1730000000.123 + 5,
                "proof_current_before": True,
                "valid_fence_before": True,
                "current_proof_after": False,
                "valid_fence_after": False,
                "proof_current_after": False,
                "client_current_after": "ContractError:expired",
                "dispatch_after": "ContractError:expired",
                "native_requests": 0,
            },
        },
        "negative_reads": {"mutations_during": 0},
        "observation_mutation_attempts": 0,
        "rpc_records": [[op, "d" * 64] for op in sorted(READS | POLICY_READS)],
        "prompts": [prompt | {"step": "tree"}, prompt | {"step": "nested"}],
        "permission_replies": [{"decision": "once", "sent": True}],
        "native_mutations": {"prompt": 2, "permission.reply": 1},
        "native_mutation_attempts": {"prompt": 2, "permission.reply": 1},
        "refused_native_requests": 0,
        "turns_completed": 2,
        "native_get_count": 900,
        "native_response_bytes": 10_000,
        "failed_gets": 0,
        "non_native_requests": 0,
        "native_database_opens": 0,
        "workspace_opens": 0,
        "owner_before": owner_evidence(exe, version),
        "owner_after": owner_evidence(exe, version),
    }


@pytest.fixture
def anchor(enrolled):  # noqa: F811
    """The integration suite's enrolled Root as a backend-scoped tree anchor."""
    manifest = enrolled.manifest
    manifest["format"] = "qualified-consumer-runtime-v2"
    native = manifest["backends"][0]
    native["protocol_scope"] = "backend"
    native["verified_operations"] = sorted(
        set(native["verified_operations"]) | tool.REQUIRED_OPERATIONS
    )
    policy = json.loads(enrolled.documents[Path(native["policy"]["path"])])
    policy["operations"] = ["prompt", "permission.reply", "form.reply"]
    native["policy"] = enrolled.pin("policy-replies.json", policy)
    enrolled.save()
    value, _ = runtime.read_enrollment(enrolled.settings)
    q = value.backends[0]
    owner = json.loads(enrolled.documents[Path(native["owner"]["path"])])
    from jt_oz_bridge.adapters.opencode.project_policy import NativePolicyEnrollment

    return SimpleNamespace(
        g=enrolled,
        q=q,
        value=value,
        policy=NativePolicyEnrollment.model_validate(policy),
        exe=owner["executable_sha256"],
        version=owner["version"],
    )


def assemble(a, worker):
    return tool.build_observation(
        worker=worker,
        reference=a.q.reference,
        contract_sha256=a.q.schema_file.sha256,
        executable_sha256=a.exe,
        upstream_version=a.version,
        verified_operations=a.q.verified_operations,
        host_before=host(a.exe),
        host_after=host(a.exe),
    )


STAGE = Path("/etc/jtoz-synthetic/runtime-lineage-unit")
OBSERVATION = Path("/etc/jtoz-synthetic/lineage-unit/lineage-observation.json")


def staged_settings(a):
    runtime_settings = a.g.settings.runtime.model_copy(
        update={"enrollment_file": STAGE / "runtime.json"}
    )
    return a.g.settings.model_copy(update={"runtime": runtime_settings})


def test_assembled_observation_passes_the_runtime_lineage_pin(anchor):
    a = anchor
    observation, details, failures = assemble(a, passing_worker(a.q.reference, a.exe, a.version))
    assert failures == [] and details["failures"] == []
    assert all(observation["checks"].values()) and len(observation["checks"]) == 10
    assert (
        observation["qualification_scope"] == "tree" and observation["native_http_mutations"] == 0
    )
    assert observation["graph"]["reference"]["upstream_session_id"] == TARGET_ID
    assert details["child_states_observed"] == ["idle", "running", "waiting_permission"]
    assert details["queued_child_observed"] is False  # never claimed
    assert details["setup_native_mutations"]["prompt"]["sent"] == 2
    files = tool.staged_documents(
        a.q,
        a.policy,
        a.g.manifest,
        stage=STAGE,
        observation_path=OBSERVATION,
        observation_raw=tool.dumps(observation),
    )
    value, _ = tool.validate_documents(
        staged_settings(a), manifest_path=STAGE / "runtime.json", files=files, reference=a.g.ref
    )
    with tool.memory_root_files(files):
        policy, lineage = runtime.adoption_pins(value)[a.g.ref["project_id"]]
    assert lineage.qualification_scope == "tree" and lineage.semantics == LINEAGE_SEMANTICS
    assert lineage.installed_evidence_sha256 == tool.sha(tool.dumps(observation))
    assert policy.operations == {"permission.reply", "form.reply"}  # never prompt
    staged = json.loads(files[STAGE / "runtime.json"])
    assert tool.changed_paths(a.g.manifest, staged) == {("adoption_projects",)}


def worker_change(name):
    def apply(w):
        windows, n = w["windows"], w["negatives"]
        if name == "no_running_child":
            for win in windows:
                for s in win["snapshots"]:
                    if s["state"] == "running" and s["id"] != TARGET_ID:
                        s["state"] = "idle"
        elif name == "no_waiting_child":
            windows.pop(2)
        elif name == "kind_on_root":
            windows[2]["interactions"][0]["kind_on_root"] = "permission"
        elif name == "root_dispatchable_while_child_waits":
            windows[2]["root_dispatch"] = "dispatchable"
        elif name == "unreconciled":
            windows[1]["snapshots"][1]["reconciled"] = False
        elif name == "wrong_descendants":
            windows[1]["snapshots"][0]["descendants"] = []
        elif name == "foreign_owner":
            windows[3]["snapshots"][0]["owner_epoch"] = "0" * 64
        elif name == "feed_reconnected":
            windows[2]["connection_epoch"] = "connection-x"
            for s in windows[2]["snapshots"]:
                s["connection_epoch"] = "connection-x"
        elif name == "long_proof":
            windows[0]["snapshots"][0]["expires_at"] += 1
        elif name == "deadline_still_current":
            n["deadline"]["current_proof_after"] = True
        elif name == "deadline_needed_requests":
            n["deadline"]["native_requests"] = 1
        elif name == "deadline_proof_never_current":
            n["deadline"]["proof_current_before"] = False
        elif name == "owner_control_failed":
            n["owner"]["control"] = "ContractError:lineage_original_resource_graph_changed"
        elif name == "leaf_accepted_child":
            n["leaf_refused"]["error"] = None
        elif name == "unseen_accepted":
            n["unseen"][1]["error"] = None
        elif name == "unseen_wrong_reason":
            n["unseen"][0]["error"] = (
                "SnapshotBoundaryChanged:leaf_resource_or_feed_boundary_changed"
            )
        elif name == "foreign_read":
            n["foreign"]["native_requests"] = 2
        elif name == "policy_control_failed":
            n["policy"]["control"] = "ContractError:native_project_policy_changed_or_unqualified"
        elif name == "policy_not_tampered":
            n["policy"]["pages_changed"] = 0
        elif name == "owner_accepted":
            n["owner"]["snapshot"] = None
        elif name == "window_mutated":
            windows[1]["mutations_during"] = 1
            w["observation_mutation_attempts"] = 1
        elif name == "negative_mutated":
            w["negative_reads"]["mutations_during"] = 1
        elif name == "info_never_changed":
            for win in windows:
                for node in win["nodes"]:
                    node["session_info_sha256"] = "c" * 64
        elif name == "identity_changed":
            windows[1]["nodes"][1]["created"] += 1
        elif name == "child_outside_directory":
            w["discovered"][CHILD_ID]["directory_matches"] = False
        elif name == "unknown_child":
            w["discovered"]["ses_unlisted"] = dict(w["discovered"][CHILD_ID])
        elif name == "settled_moved":
            n["settled"]["cursors"][1] = "resource-sha256:other"
        elif name == "settled_never_active":
            n["settled"]["earlier_active_cursor"] = None
        elif name == "settled_page_changed":
            n["settled"]["pages"][CHILD_ID] = ["q", "r"]
        elif name == "reads_missing":
            w["rpc_records"] = [r for r in w["rpc_records"] if r[0] != "shell.list"]
        elif name == "reads_outside_enrollment":
            w["rpc_records"].append(["vcs.status", "d" * 64])
        elif name == "rejected_reply":
            w["permission_replies"][0]["decision"] = "reject"
        elif name == "uncertain_prompt":
            w["prompts"][1]["sent"] = "uncertain"
        elif name == "one_turn":
            w["turns_completed"] = 1
        elif name == "database":
            w["native_database_opens"] = 1
        elif name == "owner_changed":
            w["owner_after"]["owner_epoch"] = "0" * 64
        elif name == "failed_get":
            w["failed_gets"] = 1
        elif name == "worker_error":
            w["error"] = "CertifyError:turn_deadline_exceeded_left_running"
        else:
            raise AssertionError(name)

    return apply


@pytest.mark.parametrize(
    "name, failure",
    [
        ("no_running_child", "check:complete_resource_reconciliation"),
        ("no_waiting_child", "check:queued_and_pending_kinds"),
        ("kind_on_root", "check:queued_and_pending_kinds"),
        ("root_dispatchable_while_child_waits", "check:queued_and_pending_kinds"),
        ("unreconciled", "check:complete_resource_reconciliation"),
        ("wrong_descendants", "check:complete_resource_reconciliation"),
        ("foreign_owner", "check:same_owner_and_feed"),
        ("feed_reconnected", "check:same_owner_and_feed"),
        ("long_proof", "check:original_five_second_deadline"),
        ("deadline_still_current", "check:original_five_second_deadline"),
        ("deadline_proof_never_current", "check:original_five_second_deadline"),
        ("owner_control_failed", "check:policy_and_owner_changes_rejected"),
        ("deadline_needed_requests", "check:original_five_second_deadline"),
        ("leaf_accepted_child", "check:foreign_and_unseen_children_rejected"),
        ("unseen_accepted", "check:foreign_and_unseen_children_rejected"),
        ("unseen_wrong_reason", "check:foreign_and_unseen_children_rejected"),
        ("foreign_read", "check:foreign_and_unseen_children_rejected"),
        ("policy_control_failed", "check:policy_and_owner_changes_rejected"),
        ("policy_not_tampered", "check:policy_and_owner_changes_rejected"),
        ("owner_accepted", "check:policy_and_owner_changes_rejected"),
        ("window_mutated", "check:no_native_writes"),
        ("negative_mutated", "check:no_native_writes"),
        ("info_never_changed", "check:volatile_progress_preserves_identity"),
        ("identity_changed", "check:original_ids_and_parents"),
        ("child_outside_directory", "check:original_ids_and_parents"),
        ("unknown_child", "check:original_ids_and_parents"),
        ("settled_moved", "check:settled_message_and_tool_boundaries_remain_exact"),
        ("settled_never_active", "check:settled_message_and_tool_boundaries_remain_exact"),
        ("settled_page_changed", "check:settled_message_and_tool_boundaries_remain_exact"),
        ("reads_missing", "observation_reads_incomplete:shell.list"),
        ("reads_outside_enrollment", "observation_reads_outside_enrollment:vcs.status"),
        ("rejected_reply", "permission_rejected"),
        ("uncertain_prompt", "native_mutation_not_exactly_sent:prompt"),
        ("one_turn", "turns_completed:1"),
        ("database", "native_database_opened"),
        ("owner_changed", "owner_changed"),
        ("failed_get", "native_get_failed"),
        ("worker_error", "worker_error"),
    ],
)
def test_any_unobserved_or_failed_check_withholds_the_observation(anchor, name, failure):
    a = anchor
    worker = passing_worker(a.q.reference, a.exe, a.version)
    worker_change(name)(worker)
    observation, details, failures = assemble(a, worker)
    assert failure in failures, failures
    assert details["failures"] == failures
    if failure.startswith("check:"):
        assert observation["checks"][failure.removeprefix("check:")] is False


def test_an_empty_or_leaf_run_cannot_produce_a_tree(anchor):
    a = anchor
    _, _, failures = assemble(a, {"error": "worker_output_missing"})
    assert "worker_error" in failures and len([f for f in failures if f.startswith("check:")]) == 10
    worker = passing_worker(a.q.reference, a.exe, a.version)
    worker["windows"] = [w for w in worker["windows"] if w["label"] != "nested:settled"]
    observation, _, failures = assemble(a, worker)
    assert observation["graph"] is None and "check:original_ids_and_parents" in failures


def test_restarted_or_replaced_native_is_refused(anchor):
    a = anchor
    worker = passing_worker(a.q.reference, a.exe, a.version)
    after = host(a.exe) | {"pid": 43}
    _, _, failures = tool.build_observation(
        worker=worker,
        reference=a.q.reference,
        contract_sha256=a.q.schema_file.sha256,
        executable_sha256=a.exe,
        upstream_version=a.version,
        verified_operations=a.q.verified_operations,
        host_before=host(a.exe),
        host_after=after,
    )
    assert "native_restarted_or_changed" in failures
    _, _, failures = tool.build_observation(
        worker=worker,
        reference=a.q.reference,
        contract_sha256=a.q.schema_file.sha256,
        executable_sha256="f" * 64,
        upstream_version=a.version,
        verified_operations=a.q.verified_operations,
        host_before=host(a.exe),
        host_after=host(a.exe),
    )
    assert "backend_identity_changed" in failures


# --------------------------------------------------------------------------
# Staging: one adoption entry, the enrollment pin and the observer pin only.
# --------------------------------------------------------------------------


CONFIG = """# example configuration
[app]
state_dir = "/var/lib/jt-oz-bridge/service"

[runtime]
"enabled" = true
"file_returns_enabled" = true
"enrollment_file" = "/etc/jt-oz-bridge/runtime-example/runtime.json"  # previous enrollment
"session_creation_enabled" = true

[[projects]]
"id" = "p"
"""


def test_stage_config_changes_only_the_enrollment_pin():
    import tomllib

    target = STAGE / "runtime.json"
    staged = tool.stage_config(CONFIG, target)
    before, after = tomllib.loads(CONFIG), tomllib.loads(staged)
    before["runtime"]["enrollment_file"] = str(target)
    assert after == before
    changed = [line for line in staged.splitlines() if line not in CONFIG.splitlines()]
    assert changed == [f'"enrollment_file" = "{target}"']
    bare = tool.stage_config(CONFIG.replace('"enrollment_file"', "enrollment_file"), target)
    assert f'enrollment_file = "{target}"' in bare.splitlines()


@pytest.mark.parametrize(
    "text",
    [
        CONFIG.replace("[runtime]", "[runtime_old]"),
        CONFIG + "\n[runtime]\nx = 1\n",
        CONFIG.replace('"enrollment_file" = ', '# "enrollment_file" = '),
        CONFIG.replace('"session_creation_enabled" = true', 'enrollment_file = "/x"'),
    ],
)
def test_stage_config_refuses_ambiguous_runtime_tables(text):
    with pytest.raises(ValueError):
        tool.stage_config(text, STAGE / "runtime.json")


def pins():
    return (
        {"path": str(STAGE / "adoption-policy.json"), "sha256": "1" * 64},
        {"path": str(STAGE / "lineage.json"), "sha256": "2" * 64},
    )


def test_stage_manifest_adds_only_one_adoption_entry(anchor):
    manifest, ref = anchor.g.manifest, anchor.g.ref
    staged = tool.stage_manifest(manifest, ref, *pins())
    assert staged["adoption_projects"] == [
        {"anchor": ref, "policy": pins()[0], "lineage": pins()[1]}
    ]
    assert "adoption_projects" not in manifest  # the input is never modified
    assert tool.changed_paths(manifest, staged) == {("adoption_projects",)}
    with pytest.raises(ValueError, match="project_already_has_adoption_pin"):
        tool.stage_manifest(staged, ref, *pins())
    with pytest.raises(ValueError, match="root_not_uniquely_enrolled"):
        tool.stage_manifest(manifest, ref | {"upstream_session_id": TARGET_ID}, *pins())
    with pytest.raises(ValueError, match="manifest_format_not_stageable"):
        tool.stage_manifest(manifest | {"format": tool.V1}, ref, *pins())
    session = copy.deepcopy(manifest)
    session["backends"][0]["protocol_scope"] = "session"
    with pytest.raises(ValueError, match="anchor_must_be_backend_scoped"):
        tool.stage_manifest(session, ref, *pins())


def test_adoption_policy_grants_only_reply_operations():
    with pytest.raises(ValueError, match="no_reply_operations"):
        tool.adoption_operations(frozenset({"prompt", "model.switch"}))
    assert tool.adoption_operations(frozenset({"prompt", "permission.reply"})) == [
        "permission.reply"
    ]
    with pytest.raises(ValueError, match="outside_replies"):
        tool.adoption_policy(
            {}, contract_sha256="a" * 64, protocol_sha256="b" * 64, operations=["prompt"]
        )


def observer(g, manifest_sha):
    backend = g.manifest["backends"][0]["reference"]["backend_id"]
    return {
        "format": "local-session-observer-v1",
        "socket": "/run/jt-oz-observer/observer.sock",
        "allowed_uids": [1001],
        "runtime_enrollment_sha256": manifest_sha,
        "backend_evidence": {backend: {"path": "/etc/jtoz-synthetic/o.json", "sha256": "4" * 64}},
        "operator_review": "local-linux-peer-scope-reviewed-no-public-listener",
    }


def staged_files(a, observation=None):
    raw = tool.dumps(observation or assemble(a, passing_worker(a.q.reference, a.exe, a.version))[0])
    return tool.staged_documents(
        a.q, a.policy, a.g.manifest, stage=STAGE, observation_path=OBSERVATION, observation_raw=raw
    )


def test_staged_files_pass_the_runtime_loaders_in_memory(anchor):
    a = anchor
    files = staged_files(a)
    manifest_sha = tool.sha(files[STAGE / "runtime.json"])
    observed_raw = tool.dumps(tool.stage_observer(observer(a.g, "0" * 64), manifest_sha))
    args = {"manifest_path": STAGE / "runtime.json", "files": files, "reference": a.g.ref}
    sha = tool.validate_stage(staged_settings(a), observer_raw=observed_raw, **args)
    assert sha == manifest_sha
    with pytest.raises(ValueError, match="staged_observer_pin"):
        tool.validate_stage(
            staged_settings(a), observer_raw=tool.dumps(observer(a.g, "0" * 64)), **args
        )
    with pytest.raises(ValueError, match="staged_config_points_elsewhere"):
        tool.validate_stage(a.g.settings, observer_raw=observed_raw, **args)


@pytest.mark.parametrize("fault", ["leaf", "binary", "foreign_project", "agent_switching"])
def test_staged_pin_is_refused_by_the_runtime_for_anything_but_this_tree(anchor, fault):
    a = anchor
    observation = assemble(a, passing_worker(a.q.reference, a.exe, a.version))[0]
    if fault == "leaf":
        observation["qualification_scope"] = "leaf"
    elif fault == "binary":
        observation["executable_sha256"] = "f" * 64
    elif fault == "foreign_project":
        for node in observation["graph"]["nodes"]:
            node["native_project_id"] = "other-native-project"
    else:
        native = a.g.manifest["backends"][0]
        native["agent_settings"] = a.g.pin("agent-settings.json", {"synthetic": True})
    files = staged_files(a, observation)
    with pytest.raises(ValueError):
        tool.validate_documents(
            staged_settings(a), manifest_path=STAGE / "runtime.json", files=files, reference=a.g.ref
        )


def test_stage_observer_changes_only_the_manifest_pin(anchor):
    value = observer(anchor.g, "0" * 64)
    staged = tool.stage_observer(value, "5" * 64)
    assert tool.changed_paths(value, staged) == {("runtime_enrollment_sha256",)}
    with pytest.raises(ValueError, match="observer_policy_pin_required"):
        tool.stage_observer({"format": "local-session-observer-v1"}, "5" * 64)


def test_preflight_refuses_an_enrolled_target_and_an_unfit_anchor(anchor):
    a = anchor
    ops = a.policy.operations
    assert tool.root_preflight(a.q, a.g.manifest, a.value, TARGET_ID, ops) == []
    enrolled_root = a.q.reference.upstream_session_id
    assert "target_must_be_a_disposable_unenrolled_session" in tool.root_preflight(
        a.q, a.g.manifest, a.value, enrolled_root, ops
    )
    assert "target_session_id_shape" in tool.root_preflight(a.q, a.g.manifest, a.value, "../x", ops)
    assert "target_must_not_be_a_bridge_created_root" in tool.root_preflight(
        a.q, a.g.manifest, a.value, "ses_jtoz_" + "0" * 32, ops
    )
    assert "anchor_policy_has_no_reply_operations" in tool.root_preflight(
        a.q, a.g.manifest, a.value, TARGET_ID, frozenset({"prompt"})
    )
    session = a.q.model_copy(update={"protocol_scope": "session"})
    assert "anchor_must_be_backend_scoped" in tool.root_preflight(
        session, a.g.manifest, a.value, TARGET_ID, ops
    )
    narrow = a.q.model_copy(update={"verified_operations": frozenset(READS)})
    assert any(
        p.startswith("verified_operations_missing:")
        for p in tool.root_preflight(narrow, a.g.manifest, a.value, TARGET_ID, ops)
    )
    pinned = a.g.manifest | {"adoption_projects": [{"anchor": a.g.ref}]}
    assert "project_already_has_adoption_pin" in tool.root_preflight(
        a.q, pinned, a.value, TARGET_ID, ops
    )


async def test_context_composes_the_pinned_anchor_stack_without_native_io(anchor, monkeypatch):
    from jt_oz_bridge.adapters.opencode.live import V2PublicFeed
    from jt_oz_bridge.services.runtime_enrollment import adoption_protocol_sha256

    a = anchor
    job = {
        "tag": "unit",
        "config": "/unused",
        "project_id": a.g.ref["project_id"],
        "target_session_id": TARGET_ID,
    }
    owner = json.loads(a.g.documents[Path(a.g.manifest["backends"][0]["owner"]["path"])])
    monkeypatch.setattr("jt_oz_bridge.config.load_settings", lambda _: a.g.settings)
    monkeypatch.setattr(tool.os, "getuid", lambda: owner["client_uid"] + 1)
    with pytest.raises(ValueError, match="enrolled_bridge_client_uid_required"):
        tool.context(job)
    monkeypatch.setattr(tool.os, "getuid", lambda: owner["client_uid"])
    with pytest.raises(ValueError, match="target_must_be_a_disposable_unenrolled_session"):
        tool.context(job | {"target_session_id": a.g.ref["upstream_session_id"]})
    ctx = tool.context(job)
    assert ctx.anchor.model_dump(mode="json") == a.g.ref
    assert ctx.target.upstream_session_id == TARGET_ID
    assert ctx.target.model_dump(exclude={"upstream_session_id"}) == ctx.anchor.model_dump(
        exclude={"upstream_session_id"}
    )
    assert ctx.operations == {"permission.reply", "form.reply"}
    assert ctx.protocol.installed_evidence_sha256 == adoption_protocol_sha256(a.q)
    attestation = ctx.attestation_for("e" * 64)
    assert attestation.qualification_scope == "tree" and attestation.operations == READS
    started = []

    async def start(self):
        started.append(self)

    async def close(self):
        started.append("closed")

    monkeypatch.setattr(V2PublicFeed, "start", start)
    monkeypatch.setattr(V2PublicFeed, "close", close)
    async with tool.opened(ctx) as s:
        assert {r.upstream_session_id for r in s.feed.references} == {
            TARGET_ID,
            a.g.ref["upstream_session_id"],
        }
        assert s.observer.reference == ctx.anchor and s.graph.observer is s.observer
        assert s.guard.enrollments == {ctx.anchor: ctx.policy}
        assert s.leaf.feed is s.feed and s.feed.transport is ctx.transport
    assert started == [s.feed, "closed"]
    await ctx.transport.close()


def test_activation_blockers_stop_a_tree_pin_that_could_not_start():
    clear = {"anchor_has_children": False, "bridge_created_roots_with_children": []}
    assert tool.activation_blockers(clear) == []
    assert tool.activation_blockers(clear | {"anchor_has_children": True}) == [
        "anchor_has_descendants_first_tree_baseline_impossible"
    ]
    grown = clear | {"bridge_created_roots_with_children": ["ses_jtoz_" + "a" * 32]}
    assert tool.activation_blockers(grown) == [
        "bridge_created_root_has_descendants:ses_jtoz_" + "a" * 32
    ]
    # Nothing scanned is never "no blocker".
    assert len(tool.activation_blockers({})) == 2


async def test_activation_scan_pages_project_roots_and_checks_only_bridge_created_ones():
    from tests.contract.test_existing_sessions import TARGET

    created, grown = "ses_jtoz_" + "1" * 32, "ses_jtoz_" + "2" * 32
    calls = []

    async def request(operation, *, query=None, path=None):
        assert operation == "session.list" and path is None
        calls.append(query)
        if query.get("parentID") == "null":
            assert query["directory"] == TARGET.canonical_directory
            assert query["project"] == "global"
            if "cursor" not in query:
                return {"data": [{"id": created}, {"id": "ses_tui"}], "cursor": {"next": "c2"}}
            return {"data": [{"id": grown}], "cursor": {}}
        children = [{"id": "ses_child"}] if query["parentID"] == grown else []
        return {"data": children, "cursor": {}}

    ctx = SimpleNamespace(
        transport=SimpleNamespace(request=request),
        anchor=TARGET,
        q=SimpleNamespace(native_project_id="global"),
    )
    scan = await tool.scan_activation(ctx)
    assert scan == {
        "anchor_has_children": False,
        "project_roots": 3,
        "bridge_created_roots": 2,
        "bridge_created_roots_with_children": [grown],
    }
    # Only the anchor and the Bridge-created Roots are asked for children.
    asked = {q["parentID"] for q in calls if q.get("parentID") != "null"}
    assert asked == {TARGET.upstream_session_id, created, grown}


def test_certify_refuses_without_explicit_flag_before_any_io(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("worker launched"))
    monkeypatch.setattr(tool.os, "geteuid", lambda: pytest.fail("checked root before flag"))
    missing = str(tmp_path / "absent-spec.json")
    with pytest.raises(ValueError, match="explicit_operator_prompt_flag_required"):
        tool.main(["certify", "--spec", missing, "--plan-sha256", "0" * 64])
    with pytest.raises(ValueError, match="plan_sha256_from_plan_required"):
        tool.main(["certify", "--spec", missing, tool.CONFIRM_FLAG])
    with pytest.raises(ValueError, match="explicit_operator_prompt_flag_required"):
        tool.main(["worker", "--job", json.dumps({"mode": "certify"})])
    with pytest.raises(ValueError, match="explicit_operator_prompt_flag_required"):
        tool.cmd_certify(SimpleNamespace(), "0" * 64, False)
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"tag": "unit", "project_id": "p", "target_session_id": TARGET_ID}))
    for step_name in ("plan", "stage"):
        with pytest.raises(ValueError, match="only_certify_takes_the_prompt_flag"):
            tool.main([step_name, "--spec", str(spec), tool.CONFIRM_FLAG])
    spec.write_text(json.dumps({"tag": "unit", "project_id": "p"}))
    with pytest.raises(ValueError, match="spec_target_session_id_required"):
        tool.main(["plan", "--spec", str(spec)])
    spec.write_text(json.dumps({"tag": "unit", "target_session_id": TARGET_ID}))
    with pytest.raises(ValueError, match="exactly_one"):
        tool.main(["plan", "--spec", str(spec)])


async def test_worker_refuses_certify_job_without_confirmation():
    with pytest.raises(ValueError, match="explicit_operator_prompt_flag"):
        await tool.worker_main({"mode": "certify", "tag": "unit"}, {})


def test_audit_counts_only_workspace_and_database_opens():
    audit = tool.Audit(CANONICAL, "/home/opencode/.local/share/opencode/opencode.db")
    audit("open", (f"{CANONICAL}/{CHILD_FILE}", "r", 0))
    audit("open", (CANONICAL.encode(), "r", 0))
    audit("open", (f"{CANONICAL}-other/x", "r", 0))
    audit("open", ("/home/opencode/.local/share/opencode/opencode.db-wal", "r", 0))
    audit("open", (3, "r", 0))
    audit("exec", ("/bin/true",))
    assert (audit.workspace_opens, audit.database_opens) == (2, 1)


# --------------------------------------------------------------------------
# Sends through the Bridge's real V2HTTPTransport and its mutation write boundary.
# --------------------------------------------------------------------------


def bridge_transport():
    from unittest.mock import AsyncMock

    import httpx

    from jt_oz_bridge.adapters.opencode.contracts import OpenAPIProfile
    from jt_oz_bridge.adapters.opencode.transport import ContractAttestation, V2HTTPTransport

    profile = OpenAPIProfile(
        Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json").read_bytes()
    )
    posts = []

    def handle(request):
        posts.append(request.url.path)
        body = json.loads(request.content)
        if request.url.path.endswith("/prompt"):
            user = {
                "id": "msg_user",
                "sessionID": TARGET_ID,
                "time": {"created": 0},
                "type": "user",
                "payload": {"text": body["text"], "metadata": body["metadata"]},
                "delivery": body["delivery"],
            }
            return httpx.Response(200, json={"data": user})
        return httpx.Response(204)

    t = V2HTTPTransport(
        "http://127.0.0.1:4096",
        profile,
        attestation=ContractAttestation(
            profile.sha256, "synthetic-identity", "2.0.32", tool.REQUIRED_OPERATIONS
        ),
        transport=httpx.MockTransport(handle),
        verify_identity=AsyncMock(return_value=True),
    )
    wire = tool.Wire(str(t.client.base_url), TARGET_ID, allow_mutations=True).install(t)
    return SimpleNamespace(transport=t, wire=wire), posts


async def test_guards_are_idempotent_for_their_own_attempt_and_refuse_a_second():
    from jt_oz_bridge.adapters.opencode.transport import TransportNotSent

    ctx, posts = bridge_transport()
    ctx.wire.nodes.add(CHILD_ID)
    body = tool.prompt_body("x", "a" * 32, "b" * 64)
    path = {"sessionID": TARGET_ID}
    first, second = {"sent": False}, {"sent": False}
    reply = {"sent": False}
    try:
        await tool.send_mutation(
            ctx,
            "prompt",
            first,
            "session.prompt",
            path=path,
            body=body,
            before_send=tool.one_attempt(ctx.wire, "prompt", 1),
        )
        with pytest.raises(TransportNotSent):
            await tool.send_mutation(
                ctx,
                "prompt",
                second,
                "session.prompt",
                path=path,
                body=body,
                before_send=tool.one_attempt(ctx.wire, "prompt", 1),
            )
        await tool.send_mutation(
            ctx,
            "permission.reply",
            reply,
            "session.permission.reply",
            path={"sessionID": CHILD_ID, "requestID": "per_1"},
            body={"decision": "once"},
            before_send=tool.one_attempt(ctx.wire, "permission.reply", 1),
        )
    finally:
        await ctx.transport.close()
    assert first["sent"] is True and second["sent"] is False and reply["sent"] is True
    assert posts == [
        f"/api/session/{TARGET_ID}/prompt",
        f"/api/session/{CHILD_ID}/permission/per_1/reply",
    ]
    # Count only real sends: the refused second prompt reached nobody.
    summary = tool.sent_summary(
        {
            "prompts": [first, second],
            "permission_replies": [reply],
            "native_mutations": ctx.wire.sent,
            "native_mutation_attempts": ctx.wire.attempts,
        }
    )
    assert summary["prompt"]["sent"] == 1 and summary["prompt"]["not_sent"] == 1
    assert ctx.wire.sent == {"prompt": 1, "permission.reply": 1}


# --------------------------------------------------------------------------
# Observation windows: the real lineage stack on the contract suite's mocked tree.
# --------------------------------------------------------------------------


@pytest.fixture
async def live():
    from jt_oz_bridge.adapters.opencode.resources import V2LeafResourceProofs
    from tests.contract.test_existing_session_graph import CHILD, GRANDCHILD, SIBLING, TARGET
    from tests.contract.test_leaf_resources import REF, finish
    from tests.contract.test_lineage_resources import setup

    anchor_proofs, t, _p, _c, metadata_tree, state, writes, metadata = await setup()
    wire = tool.Wire(str(t.client.base_url), TARGET.upstream_session_id, allow_mutations=False)
    wire.install(t)
    ctx = SimpleNamespace(
        target=TARGET,
        anchor=REF,
        projects=anchor_proofs.projects,
        transport=t,
        model_settings=None,
        operations=frozenset({"permission.reply"}),
        attestation_for=lambda evidence: LineageResourceAttestation(
            REF.backend_id,
            REF.backend_identity,
            t.profile.sha256,
            LINEAGE_SEMANTICS,
            evidence,
            READS,
        ),
        wire=wire,
        recorder=tool.Recorder(t).install(),
    )
    s = SimpleNamespace(
        feed=anchor_proofs.feed,
        graph=metadata,
        leaf=V2LeafResourceProofs(anchor_proofs.feed, anchor_proofs.projects),
        index=0,
        known=set(),
    )
    try:
        yield SimpleNamespace(
            ctx=ctx,
            s=s,
            tree=metadata_tree,
            state=state,
            writes=writes,
            ids=SimpleNamespace(
                target=TARGET.upstream_session_id,
                child=CHILD,
                grandchild=GRANDCHILD,
                sibling=SIBLING,
            ),
        )
    finally:
        await finish(anchor_proofs, t)


def result():
    return {"windows": [], "candidate": "e" * 64, "negatives": {}}


async def test_live_window_reconciles_the_complete_idle_tree_with_get_only_records(live):
    r = result()
    view = await tool.window(live.ctx, live.s, "unit:settled", r, required=True)
    record = r["windows"][0]
    assert view is not None and record["ok"] is True, record["errors"]
    assert record["mutations_during"] == 0 and not live.writes
    assert {s["state"] for s in record["snapshots"]} == {"idle"}
    assert len(record["nodes"]) == 4 and record["root_dispatch"] == "dispatchable"
    assert record["provider_descendants"] == tool.graph_descendants(record["nodes"])
    child = live.ids.child.upstream_session_id
    assert {n["id"]: n["parent"] for n in record["nodes"]}[child] == live.ids.target
    assert all(s["expires_at"] == s["issued_at"] + 5 for s in record["snapshots"])
    operations = {op for op, _ in live.ctx.recorder.records}
    assert READS - {"event.subscribe"} <= operations and POLICY_READS <= operations
    assert all(s["owner_epoch"] == record["owner_epoch"] for s in record["snapshots"])


async def test_live_waiting_child_is_attributed_only_to_itself(live):
    from tests.contract.test_public_live_feed import REAL

    child = live.ids.child
    raw = copy.deepcopy(next(e["data"] for e in REAL if e["type"] == "permission.asked"))
    raw["sessionID"] = child.upstream_session_id
    live.state["resources"][child]["permission"] = [raw]
    live.state["active"][child.upstream_session_id] = {"type": "running"}
    r = result()
    pending = ((child.upstream_session_id, raw["id"]),)
    await tool.window(live.ctx, live.s, "unit:waiting", r, pending=pending, required=True)
    record = r["windows"][0]
    assert record["ok"] is True, record["errors"]
    states = {s["id"]: s for s in record["snapshots"]}
    assert states[child.upstream_session_id]["state"] == "waiting_permission"
    assert states[child.upstream_session_id]["pending"] == [[raw["id"], "permission"]]
    assert states[live.ids.target]["state"] == "idle"  # a parent is never retargeted
    assert record["interactions"] == [
        {
            "id": child.upstream_session_id,
            "request": raw["id"],
            "kind_on_node": "permission",
            "kind_on_root": None,
        }
    ]
    assert "quiescent" in record["root_dispatch"]


async def test_live_unseen_child_foreign_owner_and_policy_changes_are_refused(live):
    r = result()
    view = await tool.window(live.ctx, live.s, "unit:before", r, required=True)
    assert view is not None
    # A child the earlier observation never saw.
    unknown = live.ids.child.model_copy(update={"upstream_session_id": "ses_unseen_child"})
    row = _row(live, live.ids.grandchild, unknown.upstream_session_id)
    live.tree["rows"][unknown] = row
    live.tree["edges"][live.ids.child].append(unknown)
    live.state["resources"][unknown] = copy.deepcopy(live.state["resources"][live.ids.child])
    await live.s.feed.enroll_reference(unknown, authorize=tool.allowed)
    unseen = await tool.check_unseen(live.ctx, view)
    assert any(code in unseen["error"] for code in tool.UNSEEN_ERRORS), unseen
    live.tree["edges"][live.ids.child].remove(unknown)
    del live.tree["rows"][unknown]
    view = await tool.window(live.ctx, live.s, "unit:settled", r, required=True)
    assert view is not None
    foreign = await tool.check_foreign(live.ctx, view)
    assert tool.foreign_passed(foreign), foreign
    policy = await tool.check_policy(live.ctx, view, live.ids.child)
    assert tool.policy_passed(policy), policy
    owner = await tool.check_owner(live.ctx, live.s, view)
    assert tool.owner_passed(owner), owner
    assert not live.writes


async def test_live_settled_boundary_and_deadline(live, monkeypatch):
    import jt_oz_bridge.adapters.opencode.execution as execution
    import jt_oz_bridge.adapters.opencode.lineage_resources as lineage
    import jt_oz_bridge.adapters.opencode.resources as resources

    r = result()
    view = await tool.window(live.ctx, live.s, "unit:settled", r, required=True)
    assert view is not None
    r["windows"][0]["snapshots"][0]["cursor"] = "resource-sha256:earlier"  # synthetic history
    r["windows"][0]["snapshots"][0]["state"] = "running"
    seen = await tool.check_settled(live.ctx, view, r)
    assert seen["states"] == ["idle", "idle"] and seen["state_only"] == [False, False]
    assert seen["cursors"][0] == seen["cursors"][1] and seen["fences"][0] == seen["fences"][1]
    assert all(len(set(p)) == 1 for p in seen["pages"].values())
    assert tool.settled_passed(seen, view.graph.owner_epoch), seen

    async def no_wait(deadline):
        return None

    # Without the wait the same fresh proof is still current: the check fails.
    unexpired = await tool.check_deadline(live.ctx, view, expire=no_wait)
    assert unexpired["proof_current_before"] is True and not tool.deadline_passed(unexpired, r)

    async def expire(deadline):
        late = SimpleNamespace(time=lambda: deadline + 1, monotonic=lambda: deadline + 1)
        for module in (execution, lineage, resources):
            monkeypatch.setattr(module, "time", late)

    deadline = await tool.check_deadline(live.ctx, view, expire=expire)
    assert tool.deadline_passed(deadline, r), deadline


async def test_live_leaf_provider_refuses_the_target_that_has_children(live):
    import httpx

    def leaf_listing(request, state):
        # The leaf codec's own one-row probe; the graph walk uses 100-row pages.
        if request.url.path != "/api/session" or request.url.params.get("limit") != "1":
            return None
        parent = live.ids.child.model_copy(
            update={"upstream_session_id": request.url.params["parentID"]}
        )
        rows = [copy.deepcopy(state["rows"][c]) for c in state["edges"].get(parent, [])[:1]]
        return httpx.Response(200, json={"data": rows, "cursor": {}})

    live.tree["hook"] = leaf_listing
    refused = await tool.check_leaf_refused(live.ctx, live.s)
    assert tool.leaf_passed({"error": None, "state": "idle"}, refused), refused
    for child in list(live.tree["edges"]):
        live.tree["edges"][child] = []
    before = await tool.check_leaf_before(live.ctx, live.s)
    assert before["error"] is None and before["state"] == "idle", before


def _row(live, template, session_id):
    value = copy.deepcopy(live.tree["rows"][template])
    value["id"] = session_id
    return value


async def test_window_budget_keeps_room_for_required_windows():
    r = result()
    r["windows"] = [{}] * (tool.MAX_WINDOWS - 2 * tool.MAX_PROMPTS)
    assert await tool.window(None, SimpleNamespace(index=0), "x:running", r) is None
    assert r["windows_skipped"] == 1 and len(r["windows"]) == tool.MAX_WINDOWS - 4
    r["windows"] = [{}] * tool.MAX_WINDOWS
    with pytest.raises(ValueError, match="observation_window_bound"):
        await tool.window(None, SimpleNamespace(index=0), "x:settled", r, required=True)


# --------------------------------------------------------------------------
# Turn orchestration on a scripted tree; windows and negatives are recorded only.
# --------------------------------------------------------------------------


class FakeTree:
    """A target that starts one subagent which asks once; never a socket."""

    def __init__(self, ctx, asked):
        self.ctx, self.asked = ctx, asked
        self.phase, self.calls, self.prompts, self.replies = "before", [], [], []

    def child_row(self):
        return {
            "id": CHILD_ID,
            "parentID": TARGET_ID,
            "projectID": "global",
            "location": {"directory": self.ctx.target.canonical_directory},
            "time": {"created": 2},
            "agent": "general",
        }

    async def request(self, operation, *, path=None, query=None, body=None, before_send=None):
        self.calls.append(operation)
        sid = (path or {}).get("sessionID")
        if operation in {"session.prompt", "session.permission.reply"}:
            kind = "prompt" if operation == "session.prompt" else "permission.reply"
            self.ctx.wire.attempts[kind] += 1
            if before_send is not None:
                before_send()
            self.ctx.wire.sent[kind] += 1
            if kind == "prompt":
                self.prompts.append(body)
                self.phase = "running"
                payload = {"text": body["text"], "metadata": body["metadata"]}
                return {
                    "data": {
                        "id": "msg_user",
                        "sessionID": TARGET_ID,
                        "delivery": "queue",
                        "payload": payload,
                    }
                }
            self.replies.append((sid, path["requestID"], body["decision"]))
            self.phase = "done"
            return None
        if operation == "session.list":
            running = self.phase != "before" and query["parentID"] == TARGET_ID
            return {"data": [self.child_row()] if running else [], "cursor": {}}
        if operation == "session.permission.list":
            waiting = self.phase == "running" and sid == CHILD_ID
            return {"data": [self.asked] if waiting else []}
        if operation in {"session.form.list", "session.inbox.list"}:
            return {"data": []}
        if operation == "session.active":
            busy = self.phase == "running"
            return {"data": {TARGET_ID: {}, CHILD_ID: {}} if busy else {}}
        assert operation == "session.message.list" and query["limit"] == "1"
        done = self.phase == "done"
        latest = {"id": "msg_idle_after" if done else "msg_idle_before", "type": "idle"}
        return {"data": [latest | {"time": {"created": 1}, "outcome": "succeeded"}]}


def scripted(monkeypatch, asked):
    from jt_oz_bridge.adapters.opencode.contracts import OpenAPIProfile
    from tests.contract.test_existing_sessions import TARGET

    target = TARGET.model_copy(update={"upstream_session_id": TARGET_ID})
    profile = OpenAPIProfile(
        Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json").read_bytes()
    )
    ctx = SimpleNamespace(
        target=target,
        q=SimpleNamespace(native_project_id="global"),
        profile=profile,
        wire=SimpleNamespace(
            attempts={"prompt": 0, "permission.reply": 0},
            sent={"prompt": 0, "permission.reply": 0},
            refused=0,
            nodes=set(),
        ),
        recorder=SimpleNamespace(active=False),
    )
    native = FakeTree(ctx, asked)
    ctx.transport = native
    enrolled_refs = []

    async def enroll(ref, *, authorize):
        assert await authorize() is True
        enrolled_refs.append(ref)

    s = SimpleNamespace(feed=SimpleNamespace(enroll_reference=enroll), known=set(), index=0)
    labels = []

    async def window(ctx, s, label, result, *, pending=(), required=False):
        # The real window is covered above; here only order and phase matter.
        labels.append((label, native.phase, pending))
        return SimpleNamespace(label=label)

    async def unseen(ctx, view):
        return {"error": "ContractError:lineage_original_children_changed", "view": view.label}

    async def leaf(ctx, s):
        return {"error": "ContractError:leaf_descendants_require_qualification"}

    monkeypatch.setattr(tool, "window", window)
    monkeypatch.setattr(tool, "check_unseen", unseen)
    monkeypatch.setattr(tool, "check_leaf_refused", leaf)
    monkeypatch.setattr(tool, "POLL_SECONDS", 0)
    result = {
        "stage": "turn:tree",
        "prompts": [],
        "permission_replies": [],
        "discovered": {},
        "windows": [],
        "negatives": {},
        "negative_reads": {"mutations_during": 0},
    }
    return SimpleNamespace(
        ctx=ctx, s=s, native=native, labels=labels, result=result, enrolled=enrolled_refs
    )


async def test_turn_observes_the_waiting_child_before_answering_it_once(monkeypatch):
    run = scripted(monkeypatch, ask("edit", CHILD_FILE))
    settled = await tool.run_step(run.ctx, run.s, step("tree"), {"tag": "unit"}, run.result)
    assert settled.label == "tree:settled"
    assert [label for label, _, _ in run.labels] == [
        "tree:before",
        "tree:grown",
        "tree:waiting",
        "tree:resumed",
        "tree:settled",
    ]
    phases = {label: phase for label, phase, _ in run.labels}
    assert phases["tree:before"] == "before" and phases["tree:waiting"] == "running"
    pending = {label: p for label, _, p in run.labels}
    assert pending["tree:waiting"] == ((CHILD_ID, "per_1"),)
    assert run.native.replies == [(CHILD_ID, "per_1", "once")]
    assert len(run.native.prompts) == 1 and run.result["prompts"][0]["sent"] is True
    assert run.result["permission_replies"][0]["decision"] == "once"
    assert run.result["discovered"][CHILD_ID]["parent"] == TARGET_ID
    assert run.ctx.wire.nodes == {CHILD_ID}
    assert [r.upstream_session_id for r in run.enrolled] == [CHILD_ID]
    assert run.result["negatives"]["unseen"][0]["view"] == "tree:before"
    assert "leaf_descendants" in run.result["negatives"]["leaf_refused"]["error"]
    assert run.result["prompts"][0]["operator_source"]["operator_not_human"] is True


@pytest.mark.parametrize(
    "asked, reason",
    [
        (ask("edit", f"{DIRECTORY}/other.txt"), "path_outside_plan"),
        (ask("shell", "rm -rf ~"), "unplanned_action"),
        ({"id": "per_1", "sessionID": CHILD_ID, "action": "edit"}, "request_shape_unqualified"),
    ],
)
async def test_turn_rejects_anything_unplanned_and_stops(monkeypatch, asked, reason):
    run = scripted(monkeypatch, asked)
    with pytest.raises(ValueError, match="permission_refused:" + reason):
        await tool.run_step(run.ctx, run.s, step("tree"), {"tag": "unit"}, run.result)
    assert run.native.replies == [(CHILD_ID, "per_1", "reject")]
    assert run.result["permission_replies"][0]["resources"] is None
    assert "tree:settled" not in [label for label, _, _ in run.labels]


async def test_turn_is_never_sent_to_a_busy_tree(monkeypatch):
    run = scripted(monkeypatch, ask("edit", CHILD_FILE))
    run.native.phase = "running"
    with pytest.raises(ValueError, match="tree_busy"):
        await tool.run_step(run.ctx, run.s, step("tree"), {"tag": "unit"}, run.result)
    assert "session.prompt" not in run.native.calls


async def test_a_child_outside_the_target_directory_stops_the_turn(monkeypatch):
    run = scripted(monkeypatch, ask("edit", CHILD_FILE))
    row = run.native.child_row()
    run.native.child_row = lambda: row | {"location": {"directory": "/somewhere/else"}}
    with pytest.raises(ValueError, match="child_refused:child_foreign_directory"):
        await tool.run_step(run.ctx, run.s, step("tree"), {"tag": "unit"}, run.result)
    assert run.native.replies == [] and run.ctx.wire.nodes == set()


class PagedChildren:
    """OpenCode 2.0 child listing: a short page still carries ``next``; the next page is empty."""

    def __init__(self, children):
        self.children, self.queries = children, []

    async def request(self, operation, *, query=None, **_):
        assert operation == "session.list"
        self.queries.append(dict(query))
        if "cursor" in query:
            return {"data": [], "cursor": {"previous": "p2", "next": None}}
        rows = self.children.get(query["parentID"], [])
        if not rows:
            return {"data": [], "cursor": {"previous": None, "next": None}}
        return {"data": rows, "cursor": {"previous": "p1", "next": "n1"}}


async def test_child_rows_follow_the_cursor_past_a_short_page():
    # One child, next cursor set, following page empty.
    native = PagedChildren({TARGET_ID: [{"id": "ses_child"}]})
    assert [r["id"] for r in await tool.child_rows(native, TARGET_ID)] == ["ses_child"]
    assert [("cursor" in q) for q in native.queries] == [False, True]
    assert await tool.child_rows(native, "ses_childless") == []


async def test_child_rows_refuse_a_cursor_that_does_not_progress():
    class Stuck(PagedChildren):
        async def request(self, operation, *, query=None, **_):
            return {"data": [], "cursor": {"previous": None, "next": "same"}}

    with pytest.raises(tool.CertifyError, match="child_cursor_not_progressing"):
        await tool.child_rows(Stuck({}), TARGET_ID)
