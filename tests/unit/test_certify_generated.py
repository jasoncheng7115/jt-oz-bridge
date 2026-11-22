"""Offline checks of the generated-output certification tool.

Synthetic data only: no Native, socket, systemd or root file is touched. The
live negative checks run against the contract suite's mocked Native graph, and
nothing here is installed, operator, Human or mobile qualification evidence.
"""

import copy
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from jt_oz_bridge.adapters.opencode import generated_files as module
from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.services.generated_enrollment import NEGATIVE_CHECKS, generated_qualification
from tests.contract.test_generated_bytes import setup as reader_setup
from tests.contract.test_leaf_resources import REF, finish
from tests.contract.test_turn_resources import C
from tests.integration.test_catalog_enrollment import catalogs  # noqa: F401  (fixture)
from tests.integration.test_file_enrollment import files  # noqa: F401  (fixture)
from tests.integration.test_generated_enrollment import generated  # noqa: F401  (fixture)
from tests.integration.test_runtime_enrollment import enrolled  # noqa: F401  (fixture)

TOOL = Path(__file__).resolve().parents[2] / "ops" / "server" / "certify_generated.py"
_spec = importlib.util.spec_from_file_location("certify_generated", TOOL)
assert _spec is not None and _spec.loader is not None
tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tool)

DIRECTORY = tool.cert_directory("unit")
CANONICAL = "/home/opencode/workspaces/synthetic"
SID = "ses_synthetic_root"


def step(name):
    return next(s for s in tool.operator_plan("unit")["steps"] if s["step"] == name)


def test_plan_has_three_bounded_prompts_and_a_stable_digest():
    plan = tool.operator_plan("unit")
    assert [s["step"] for s in plan["steps"]] == ["quiet", "files"]
    assert len(plan["steps"]) == tool.MAX_PROMPTS == 2 and tool.MAX_PERMISSION_REPLIES == 12
    # No step asks the agent to read anything large.
    assert "read tool" not in json.dumps(plan)
    assert tool.operator_plan("unit") == plan
    ref = {"upstream_session_id": SID}
    first = tool.plan_sha256(plan, reference=ref, policy_sha256="b" * 64, tool_sha256="f" * 64)
    assert first == tool.plan_sha256(
        tool.operator_plan("unit"), reference=ref, policy_sha256="b" * 64, tool_sha256="f" * 64
    )
    for changed in (
        {"policy_sha256": "c" * 64, "tool_sha256": "f" * 64},
        {"policy_sha256": "b" * 64, "tool_sha256": "e" * 64},
    ):
        assert tool.plan_sha256(plan, reference=ref, **changed) != first
    assert all(s["text"].count("not a message from a person") == 1 for s in plan["steps"])
    assert step("quiet")["commands"] == [] and step("quiet")["read_files"] == []
    assert step("files")["commands"] == [tool.generated_command(DIRECTORY)]
    with pytest.raises(ValueError):
        tool.cert_directory("../escape")


def test_planned_command_creates_exactly_the_requested_bytes(tmp_path):
    subprocess.run(["bash", "-c", tool.generated_command(DIRECTORY)], cwd=tmp_path, check=True)
    expected = tool.requested_files(DIRECTORY)
    produced = sorted(p.relative_to(tmp_path).as_posix() for p in (tmp_path / DIRECTORY).iterdir())
    assert produced == sorted(f"{DIRECTORY}/{n}" for n in ("binary.bin", "pixel.png", *tool.BLOCKS))
    for name in produced:
        assert (tmp_path / name).read_bytes() == expected[name]
    assert len(expected[f"{DIRECTORY}/block-20m.bin"]) == MAX_ATTACHMENT_BYTES
    assert [len(expected[f"{DIRECTORY}/{n}"]) for n in tool.BLOCKS] == list(tool.BLOCKS.values())


def ask(action, *resources, session=SID):
    return {"id": "per_1", "sessionID": session, "action": action, "resources": list(resources)}


@pytest.mark.parametrize(
    "name, asked, decision",
    [
        ("files", ask("edit", f"{DIRECTORY}/board.html"), "once"),
        ("files", ask("write", f"{CANONICAL}/{DIRECTORY}/報告-中文.txt"), "once"),
        ("files", ask("edit", f"{DIRECTORY}/.env", f"{DIRECTORY}/empty.txt"), "once"),
        ("files", ask("bash", tool.generated_command(DIRECTORY)), "once"),
        # OpenCode 2.0 names the shell permission ``shell``.
        ("files", ask("shell", tool.generated_command(DIRECTORY)), "once"),
        ("files", ask("read", f"{DIRECTORY}/pixel.png"), "once"),
        ("files", ask("read", f"{CANONICAL}/{DIRECTORY}/block-5m.bin"), "once"),
        # Everything else is rejected, never widened.
        ("quiet", ask("edit", f"{DIRECTORY}/board.html"), "reject"),
        ("quiet", ask("read", f"{DIRECTORY}/pixel.png"), "reject"),
        ("files", ask("read", f"{DIRECTORY}/../secrets.txt"), "reject"),
        ("files", ask("edit", f"{DIRECTORY}/other.txt"), "reject"),
        ("files", ask("edit", f"{DIRECTORY}/board.html", "/etc/passwd"), "reject"),
        ("files", ask("edit", f"{DIRECTORY}/../board.html"), "reject"),
        ("files", ask("edit", f"{DIRECTORY}/*"), "reject"),
        ("files", ask("edit", f"/home/opencode/{DIRECTORY}/board.html"), "reject"),
        ("files", ask("edit", f"{CANONICAL}-other/{DIRECTORY}/board.html"), "reject"),
        ("files", ask("bash", "ls"), "reject"),
        ("files", ask("shell", "ls"), "reject"),
        ("files", ask("bash", tool.generated_command(DIRECTORY) + " ; rm -rf ~"), "reject"),
        ("files", ask("external_directory", "/tmp/*"), "reject"),
        ("files", ask("webfetch", "https://example.com"), "reject"),
        ("files", ask("task", "general"), "reject"),
        ("files", ask("edit"), "reject"),
        ("files", ask("edit", f"{DIRECTORY}/board.html", session="ses_other"), "reject"),
        ("files", None, "reject"),
    ],
)
def test_permission_replies_are_once_only_for_planned_paths_and_command(name, asked, decision):
    got, reason = tool.permission_decision(
        asked, session_id=SID, canonical_directory=CANONICAL, step=step(name)
    )
    assert got == decision, reason
    assert got in {"once", "reject"}  # `always` can never be produced


def request(method, path, host="127.0.0.1", port=4096):
    return SimpleNamespace(method=method, url=SimpleNamespace(host=host, port=port, path=path))


async def test_wire_allows_only_bounded_prompt_and_permission_reply_mutations():
    base = "/api/session/" + SID
    plan = tool.Wire("http://127.0.0.1:4096", SID, allow_mutations=False)
    await plan.request(request("GET", base))
    with pytest.raises(ValueError, match="unexpected_native_mutation"):
        await plan.request(request("POST", base + "/prompt"))
    certify = tool.Wire("http://127.0.0.1:4096", SID, allow_mutations=True)
    for refused in (
        request("POST", "/api/session"),
        request("POST", base + "/interrupt"),
        request("POST", base + "/form/frm_1/reply"),
        request("PATCH", base),
        request("DELETE", base),
        request("POST", "/api/session/ses_other/prompt"),
        request("POST", base + "/permission/../reply"),
    ):
        with pytest.raises(ValueError, match="unexpected_native_mutation"):
            await certify.request(refused)
    for _ in range(tool.MAX_PROMPTS):
        await certify.request(request("POST", base + "/prompt"))
    with pytest.raises(ValueError, match="unexpected_native_mutation"):
        await certify.request(request("POST", base + "/prompt"))
    for index in range(tool.MAX_PERMISSION_REPLIES):
        await certify.request(request("POST", f"{base}/permission/per_{index}/reply"))
    with pytest.raises(ValueError, match="unexpected_native_mutation"):
        await certify.request(request("POST", base + "/permission/per_x/reply"))
    with pytest.raises(ValueError, match="non_native_origin"):
        await certify.request(request("GET", "/jt-oz-certification", host="198.51.100.7"))
    assert certify.attempts == {"prompt": 2, "permission.reply": 12}
    assert certify.sent == {"prompt": 0, "permission.reply": 0}  # nothing was answered
    assert certify.refused == 9 and certify.foreign == 1 and plan.refused == 1
    assert tool.mutation_kind("GET", base + "/prompt", SID) is None


async def test_wire_bounds_gets_and_response_bytes(monkeypatch):
    monkeypatch.setattr(tool, "MAX_NATIVE_GETS", 2)
    monkeypatch.setattr(tool, "MAX_RESPONSE_BYTES", 10)
    wire = tool.Wire("http://127.0.0.1:4096", SID, allow_mutations=False)
    await wire.request(request("GET", "/a"))
    await wire.request(request("GET", "/b"))
    with pytest.raises(ValueError, match="bounded_native_gets"):
        await wire.request(request("GET", "/c"))

    def response(length):
        return SimpleNamespace(
            request=request("GET", "/a"), status_code=200, headers={"content-length": length}
        )

    await wire.response(response("6"))
    await wire.response(response(""))
    with pytest.raises(ValueError, match="bounded_native_response_bytes"):
        await wire.response(response("6"))
    assert wire.unknown_length == 1


# --------------------------------------------------------------------------
# Evidence assembly over the synthetic reviewed packet of the integration suite.
# --------------------------------------------------------------------------


def scenario(g, **changes):
    packet = g.packet
    b = g.manifest["backends"][0]
    exe = json.loads(g.documents[Path(b["owner"]["path"])])["executable_sha256"]
    epoch = packet["native_before"]["owner_epoch"]
    owner = {
        "owner_epoch": epoch,
        "pid": 42,
        "process_start_ticks": 7,
        "boot_id": "00000000-0000-4000-8000-000000000001",
        "executable_sha256": exe,
    }
    host = {
        "pid": 42,
        "nrestarts": 0,
        "binary_sha256": exe,
        "invocation_id": "0" * 32,
        "start_ticks": 7,
    }
    prompts = [
        {"step": s, "action_id": a, "operation_digest": "a" * 64, "admitted": True, "sent": True}
        for s, a in zip(("quiet", "files"), ("q" * 32, C.action_id), strict=True)
    ]
    worker = {
        "error": None,
        "directory": DIRECTORY,
        "owner_before": owner,
        "owner_after": copy.deepcopy(owner),
        "prompts": prompts,
        "native_mutations": {"prompt": 2, "permission.reply": 1},
        "native_mutation_attempts": {"prompt": 2, "permission.reply": 1},
        "permission_replies": [
            {"action": "edit", "decision": "once", "reason": "planned_path", "sent": True}
        ],
        "refused_native_requests": 0,
        "turns_completed": 2,
        "native_get_count": 400,
        "native_response_bytes": 1000,
        "native_database_opens": 0,
        "workspace_opens": 0,
        "inventories": copy.deepcopy(packet["inventories"]),
        "cases": [
            {
                "original_object_current": True,
                "exact_native_bytes_verified": True,
                "workspace_opens": 0,
                "requested_bytes_matched": None,
                "evidence": copy.deepcopy(case["evidence"]),
            }
            for case in packet["byte_cases"]
        ],
        "negative_checks": {name: {"passed": True} for name in NEGATIVE_CHECKS},
        "foreign_reference": g.ref | {"upstream_session_id": "ses_foreign_root"},
        "candidate_attestation_sha256": "d" * 64,
    }
    args = {
        "worker": worker,
        "reference": SessionRef.model_validate(g.ref),
        "contract_sha256": b["schema_file"]["sha256"],
        "executable_sha256": exe,
        "host_before": host,
        "host_after": copy.deepcopy(host),
        "tool_sha256": "f" * 64,
        "plan_sha": "e" * 64,
        "observed_at": 1.0,
    }
    for change in changes.values():
        change(args)
    return args


def test_assembled_bundle_passes_the_runtime_validator_with_observed_fields(generated):  # noqa: F811
    args = scenario(generated)
    bundle, failures = tool.build_bundle(**args)
    assert failures == []
    raw = tool.dumps(bundle)
    metadata, byte_attestation = generated_qualification(
        raw,
        reference=args["reference"],
        contract_sha256=args["contract_sha256"],
        executable_sha256=args["executable_sha256"],
        evidence_sha256=tool.sha(raw),
    )
    assert metadata.installed_evidence_sha256 == byte_attestation.installed_evidence_sha256
    assert bundle["actual_original_native_outputs"] is True
    assert bundle["human_input_fabricated"] is False and bundle["human_acceptance"] is False
    assert bundle["native_before"] == bundle["native_after"]
    assert all(p["operator_not_human"] for p in bundle["operator_prompts"])
    sealed = bundle["negative_check_details"]["sealed"]
    assert sealed["control_rejected"] is None
    assert all(sealed[name] is True for name in tool.SEALED_CHECKS)
    for forged in (
        "deadline_extended",
        "moved_to_foreign_root",
        "owner_epoch_changed",
        "output_inventory_changed",
        "protected_output_model",
    ):
        assert isinstance(sealed[forged], str), forged
    assert bundle["format"] == "qualified-generated-outputs-v2"
    assert metadata.scope.max_bytes == bundle["scope"]["max_bytes"] == MAX_ATTACHMENT_BYTES


def test_a_snapshot_style_run_is_qualified_for_exactly_what_it_read(generated):  # noqa: F811
    # Workspace cases only, all well under 20 MiB.
    from tests.integration.test_generated_enrollment import scoped_packet

    packet = scoped_packet(generated)
    args = scenario(generated)
    args["worker"]["cases"] = [
        {
            "original_object_current": True,
            "exact_native_bytes_verified": True,
            "workspace_opens": 0,
            "requested_bytes_matched": None,
            "evidence": copy.deepcopy(c["evidence"]),
        }
        for c in packet["byte_cases"]
    ]
    bundle, failures = tool.build_bundle(**args)
    assert failures == [], failures
    assert bundle["scope"] == packet["scope"]
    unread = {(u["kind"], u["origin"]) for u in bundle["unqualified_outputs_seen"]}
    assert unread == {("inline", "tool")}
    raw = tool.dumps(bundle)
    metadata, _ = generated_qualification(
        raw,
        reference=args["reference"],
        contract_sha256=args["contract_sha256"],
        executable_sha256=args["executable_sha256"],
        evidence_sha256=tool.sha(raw),
    )
    assert ("inline", "tool") not in metadata.scope.origins
    assert metadata.scope.max_bytes < MAX_ATTACHMENT_BYTES
    assert all(bundle["negative_check_details"]["sealed"][n] for n in tool.SEALED_CHECKS)


def set_worker(key, value):
    return lambda a: a["worker"].__setitem__(key, value)


@pytest.mark.parametrize(
    "change, failure",
    [
        (set_worker("error", "TimeoutError:"), "worker_error"),
        (lambda a: a["worker"]["owner_after"].update(pid=43), "owner_changed"),
        (lambda a: a["host_after"].update(nrestarts=1), "native_restarted_or_changed"),
        (lambda a: a["host_after"].update(invocation_id="1" * 32), "native_restarted_or_changed"),
        (lambda a: a.update(executable_sha256="0" * 64), "backend_identity_changed"),
        (set_worker("native_database_opens", 1), "native_database_opened"),
        (set_worker("workspace_opens", 1), "workspace_opened_locally"),
        (set_worker("non_native_requests", 1), "non_native_request_attempted"),
        (lambda a: a["worker"]["cases"][0].update(workspace_opens=1), "byte_case_flags"),
        (
            lambda a: a["worker"]["cases"][0].update(exact_native_bytes_verified=False),
            "byte_case_flags",
        ),
        (lambda a: a["worker"]["prompts"].pop(), "operator_prompts"),
        (lambda a: a["worker"]["prompts"][0].update(admitted=False), "operator_prompts"),
        (
            lambda a: a["worker"]["native_mutations"].update(prompt=4),
            "native_mutation_not_exactly_sent:prompt",
        ),
        (
            lambda a: a["worker"]["native_mutation_attempts"].update(prompt=4),
            "native_mutation_not_exactly_sent:prompt",
        ),
        (
            lambda a: a["worker"]["prompts"][1].update(sent="uncertain"),
            "native_mutation_not_exactly_sent:prompt",
        ),
        (
            lambda a: a["worker"]["permission_replies"][0].update(sent=False),
            "native_mutation_not_exactly_sent:permission.reply",
        ),
        (set_worker("refused_native_requests", 1), "native_mutation_bound"),
        (
            lambda a: a["worker"]["permission_replies"][0].update(decision="reject"),
            "permission_rejected",
        ),
        (set_worker("turns_completed", 1), "turns_completed"),
        (set_worker("native_get_count", tool.MAX_NATIVE_GETS + 1), "native_get_bound"),
        (
            lambda a: a["worker"]["negative_checks"]["external-uri-not-fetched"].update(
                passed=False
            ),
            "negative:external-uri-not-fetched",
        ),
        (lambda a: a["worker"]["negative_checks"].pop("foreign-root-rejected"), "negative:"),
        (lambda a: a["worker"]["prompts"][1].update(action_id="x" * 32), "outputs_not_from"),
        (lambda a: a["worker"]["inventories"].pop(), "coverage:empty_inventory"),
        (lambda a: a["worker"]["cases"].pop(), "coverage:byte_case_count:4"),
    ],
)
def test_any_unobserved_or_failed_check_withholds_the_bundle(generated, change, failure):  # noqa: F811
    _, failures = tool.build_bundle(**scenario(generated, change=change))
    assert any(f.startswith(failure) for f in failures), failures


def test_sealed_checks_need_a_passing_control(generated):  # noqa: F811
    args = scenario(generated)
    bundle, failures = tool.build_bundle(**args)
    assert not failures
    broken = copy.deepcopy(bundle) | {"component_sha256": "0" * 64}
    sealed = tool.sealed_negatives(
        broken,
        reference=args["reference"],
        contract_sha256=args["contract_sha256"],
        executable_sha256=args["executable_sha256"],
        foreign=args["worker"]["foreign_reference"],
        protected=[f"{DIRECTORY}/.env"],
    )
    assert sealed["control_rejected"] and not any(sealed[n] for n in tool.SEALED_CHECKS)


def test_protected_names_are_found_only_in_output_entries():
    protected = [f"{DIRECTORY}/.env", f"{DIRECTORY}/credentials.json"]
    # The prompt naming the files is correlation text, never a disclosed output.
    prompt = {"turn": {"correlation": {"text": f"write {DIRECTORY}/.env"}}}
    clean = {"inventories": [{"files": [], **prompt}], "byte_cases": [{"evidence": prompt}]}
    assert tool.protected_outputs(clean, protected) == []
    for leak in (
        {"inventories": [{"files": [{"path": f"{DIRECTORY}/.env"}]}]},
        {"inventories": [{"files": [{"name": "credentials.json"}]}]},
        {"byte_cases": [{"evidence": {"native": {"relative_path": f"{DIRECTORY}/.env"}}}]},
        {"byte_cases": [{"evidence": {"projection": {"filename": ".env"}}}]},
    ):
        assert tool.protected_outputs(leak, protected), leak


def test_coverage_and_scope_follow_only_what_cases_observed(generated):  # noqa: F811
    from jt_oz_bridge.adapters.opencode.generated_files import (
        GENERATED_ORIGINS,
        GeneratedByteEvidence,
        GeneratedDiscoveryEvidence,
    )

    p = generated.packet
    evidence = [GeneratedByteEvidence.model_validate(c["evidence"]) for c in p["byte_cases"]]
    inventories = [GeneratedDiscoveryEvidence.model_validate(v) for v in p["inventories"]]
    assert tool.coverage(evidence, inventories) == []
    full = tool.observed_scope(evidence)
    assert full.origins == GENERATED_ORIGINS and full.max_bytes == MAX_ATTACHMENT_BYTES
    small = [e for e in evidence if e.projection.size < MAX_ATTACHMENT_BYTES]
    assert tool.coverage(small, inventories) == ["byte_case_count:3"]
    snapshots = [e for e in small if e.selection.origin == "snapshot"]
    scope = tool.observed_scope(snapshots)
    assert scope.origins == {("workspace", "snapshot")}
    assert scope.max_bytes == max(e.projection.size for e in snapshots)
    # Everything Native listed but no case read is named as unqualified.
    unread = tool.unqualified_outputs(inventories, scope)
    assert {(u["kind"], u["origin"]) for u in unread} == {("inline", "tool"), ("workspace", "tool")}
    assert tool.observed_scope([]) is None
    assert "empty_inventory" in tool.coverage(evidence, [i for i in inventories if i.files])
    assert "byte_case_inventory" in tool.coverage(evidence, inventories[-1:])


def test_case_choice_keeps_only_this_turns_outputs_with_inline_first():
    from jt_oz_bridge.adapters.opencode.generated_files import GeneratedFile

    def workspace(path, origin="snapshot"):
        if origin == "snapshot":
            return GeneratedFile(
                origin="snapshot",
                assistant_id="a",
                file_index=0,
                kind="workspace",
                path=path,
                name=path.rsplit("/", 1)[-1],
            )
        return GeneratedFile(
            origin="tool",
            assistant_id="a",
            content_index=1,
            file_index=0,
            tool_id="t",
            kind="workspace",
            path=path,
            uri_sha256="1" * 64,
        )

    inline = GeneratedFile(
        origin="tool",
        assistant_id="a",
        content_index=1,
        file_index=1,
        tool_id="t",
        kind="inline",
        name="pixel.png",
        mime_type="image/png",
        size=70,
        sha256="2" * 64,
        uri_sha256="3" * 64,
    )
    outputs = (
        workspace(f"{DIRECTORY}/board.html"),
        workspace("unrelated/notes.txt"),
        workspace(f"{DIRECTORY}/binary.bin", "tool"),
        inline,
    )
    chosen = tool.choose_cases(outputs, DIRECTORY, 10)
    assert [c["kind"] for c in chosen] == ["inline", "workspace", "workspace"]
    assert [c["origin"] for c in chosen] == ["tool", "tool", "snapshot"]
    assert "unrelated/notes.txt" not in json.dumps(chosen)
    assert len(tool.choose_cases(outputs, DIRECTORY, 1)) == 1
    assert tool.choose_cases(outputs, DIRECTORY, 0) == []


# --------------------------------------------------------------------------
# Live negative checks: the real reader on the contract suite's mocked Native.
# --------------------------------------------------------------------------


@pytest.fixture
async def live():
    p, t, d, messages, reader, pages, reads, writes = await reader_setup()
    seen = []

    async def count(request):
        seen.append((request.method, request.url.host))

    t.client.event_hooks["request"].append(count)
    try:
        yield SimpleNamespace(
            t=t,
            d=d,
            messages=messages,
            reader=reader,
            requests=lambda: len(seen),
            foreign=lambda: sum(host != "127.0.0.1" for _, host in seen),
            writes=writes,
        )
    finally:
        await finish(p, t)


async def test_live_copied_and_expired_objects_are_rejected_without_requests(live, monkeypatch):
    async def expire(deadline):
        monkeypatch.setattr(module, "time", SimpleNamespace(time=lambda: deadline + 1))

    seen = await tool.check_copied_and_expired(
        live.reader, C, live.requests, DIRECTORY, expire=expire
    )
    assert seen["passed"] is True and seen["native_requests"] == 0, seen
    assert not live.writes


async def test_live_foreign_root_is_rejected_before_any_request(live):
    foreign = REF.model_copy(update={"upstream_session_id": "ses_other_root"})
    seen = await tool.check_foreign_root(live.reader, C, foreign, live.requests)
    assert seen["passed"] is True and "semantics_unqualified" in seen["capture"], seen


async def test_live_changed_owner_issues_no_bytes(live):
    seen = await tool.check_changed_owner(live.reader, C, DIRECTORY)
    assert seen["passed"] is True and seen["bytes_issued"] == 0, seen
    assert "current_owner" not in vars(live.reader.turns.proofs.feed)
    # The unchanged owner still reads normally afterwards.
    outputs = await live.reader.capture(C)
    assert live.reader.current(outputs)


def later_turn(messages):
    """Append a real newer turn (same outputs) above the fixture's turn C."""
    from jt_oz_bridge.adapters.opencode.turn_resources import TurnCorrelation

    idle, assistant, user = (copy.deepcopy(m) for m in messages[:3])
    later = TurnCorrelation(
        reference=REF,
        action_id="action_later",
        operation_digest="c" * 64,
        upstream_id="msg_user_later",
        text="later fixture text",
    )
    idle["id"], assistant["id"] = "msg_idle_later", "msg_assistant_later"
    user.update(id=later.upstream_id, text=later.text)
    user["metadata"]["jt_oz_bridge"] = {
        "action_id": later.action_id,
        "operation_digest": later.operation_digest,
    }
    messages[:0] = [idle, assistant, user]
    return later


async def test_live_changed_output_and_a_real_later_turn_are_both_rejected(live):
    later = later_turn(live.messages)
    tap = tool.Tap(live.t).install()
    try:
        seen = await tool.check_changed_output(live.reader, later, tap, DIRECTORY, [C])
    finally:
        tap.remove()
    assert seen["passed"] is True and seen["pages_changed"] >= 1, seen
    assert "native_resource_intervening_input_or_terminal" in seen["later_turn"][0]
    assert live.t.request == tap.original
    # Without an earlier turn to refuse, the check cannot pass.
    tap = tool.Tap(live.t).install()
    try:
        alone = await tool.check_changed_output(live.reader, later, tap, DIRECTORY, [])
    finally:
        tap.remove()
    assert alone["passed"] is False and "changed" in alone["read"]


async def test_rename_targets_the_issued_output_not_a_hidden_tool_item(live):
    # The newest assistant can hold a tool file item the projection hid;
    # a blind rename changed only that, so the reader rightly issued the bytes.
    hidden = copy.deepcopy(live.messages[1])
    hidden.pop("snapshot")
    hidden["id"] = "msg_assistant_hidden_tool"
    tool_part = next(p for p in hidden["content"] if p.get("type") == "tool")
    tool_part["id"] = "call_hidden"
    tool_part["state"]["content"] = [
        {"type": "file", "uri": "file:///etc/passwd", "mime": "text/plain", "name": "passwd"}
    ]
    live.messages.insert(1, hidden)
    outputs = await live.reader.capture(C)
    assert all(f.assistant_id != hidden["id"] for f in outputs.files)
    tap = tool.Tap(live.t).install()
    try:
        seen = await tool.check_changed_output(live.reader, C, tap, DIRECTORY, [])
    finally:
        tap.remove()
    assert seen["read"] and "generated_selected_output_changed" in seen["read"], seen
    assert seen["bytes_issued"] == 0 and seen["target"]["assistant_id"] != hidden["id"]


async def test_live_external_uri_is_counted_unsupported_and_never_fetched(live):
    tap = tool.Tap(live.t).install()
    try:
        seen = await tool.check_external_uri(live.reader, C, tap, live.foreign)
    finally:
        tap.remove()
    assert seen["passed"] is True, seen
    assert seen["unsupported_after"] == seen["unsupported_before"] + 1
    assert live.foreign() == 0


async def test_live_checks_fail_when_they_cannot_be_exercised(live):
    # A tap that never reaches the reader cannot pass an injected-change check.
    tap = tool.Tap(live.t)
    external = await tool.check_external_uri(live.reader, C, tap, live.foreign)
    changed = await tool.check_changed_output(live.reader, C, tap, DIRECTORY, [C])
    assert external["passed"] is False and external["pages_changed"] == 0
    assert changed["passed"] is False and changed["pages_changed"] == 0
    # Nor can a turn without a completed tool part or a disclosed output.
    bare = {"data": [{"id": "m", "type": "assistant", "content": [{"type": "text"}]}]}
    assert not tool.add_external_uri(copy.deepcopy(bare))
    target = SimpleNamespace(
        assistant_id="m", origin="snapshot", file_index=0, path="board.html", content_index=None
    )
    assert not tool.change_output(copy.deepcopy(bare), target)
    other = {"data": [{"id": "x", "type": "assistant", "snapshot": {"files": ["board.html"]}}]}
    assert not tool.change_output(other, target)


async def test_live_protected_snapshot_name_is_hidden_and_absent(live):
    tap = tool.Tap(live.t).install()
    tap.record = True
    try:
        outputs = await live.reader.capture(C)
        discovery = live.reader.discovery_evidence(outputs)
    finally:
        tap.remove()
    # The fixture's own snapshot lists `.env`; the reader hides it.
    seen = tool.check_protected(tap.pages, discovery, REF.canonical_directory, [".env"])
    assert seen["passed"] is True and seen["protected_in_native_snapshot"] == [".env"], seen
    missing = tool.check_protected(tap.pages, discovery, REF.canonical_directory, ["absent.key"])
    assert missing["passed"] is False


# --------------------------------------------------------------------------
# Staging: v7 manifest, config and observer, validated by the runtime loaders.
# --------------------------------------------------------------------------

CONFIG = """# example configuration
[app]
state_dir = "/var/lib/jt-oz-bridge/service"

[runtime]
"enabled" = true
"file_returns_enabled" = true
"generated_returns_enabled" = false
"enrollment_file" = "/etc/jt-oz-bridge/runtime-example/runtime.json"  # previous enrollment
"session_creation_enabled" = true

[[projects]]
"id" = "p"
"""


def test_stage_config_changes_only_the_enrollment_pin_and_generated_flag():
    import tomllib

    target = Path("/etc/jt-oz-bridge/runtime-generated-unit/runtime.json")
    staged = tool.stage_config(CONFIG, target)
    before, after = tomllib.loads(CONFIG), tomllib.loads(staged)
    assert after["runtime"]["enrollment_file"] == str(target)
    assert after["runtime"]["generated_returns_enabled"] is True
    before["runtime"].update(enrollment_file=str(target), generated_returns_enabled=True)
    assert after == before
    changed = [line for line in staged.splitlines() if line not in CONFIG.splitlines()]
    assert changed == [
        '"generated_returns_enabled" = true',
        f'"enrollment_file" = "{target}"',
    ]
    absent = CONFIG.replace('"generated_returns_enabled" = false\n', "")
    inserted = tool.stage_config(absent.replace('"enrollment_file"', "enrollment_file"), target)
    assert tomllib.loads(inserted)["runtime"]["generated_returns_enabled"] is True
    assert "generated_returns_enabled = true" in inserted.splitlines()


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
        tool.stage_config(text, Path("/etc/jt-oz-bridge/x/runtime.json"))


def v5_manifest(g):
    manifest = copy.deepcopy(g.manifest)
    pin = manifest["backends"][0].pop("generated_outputs")
    manifest["format"] = tool.V5
    return manifest, pin


def test_stage_manifest_adds_only_the_pin_and_explicit_v7_scope(generated):  # noqa: F811
    manifest, pin = v5_manifest(generated)
    staged = tool.stage_manifest(manifest, generated.ref, pin)
    assert staged["format"] == tool.V7 and staged["generated_roots"] == [generated.ref]
    assert staged["backends"][0]["generated_outputs"] == pin
    assert tool.changed_paths(manifest, staged) == {
        ("format",),
        ("generated_roots",),
        ("backends", 0, "generated_outputs"),
    }
    assert "generated_roots" not in manifest  # the input is never modified
    with pytest.raises(ValueError, match="already_has_generated_outputs"):
        tool.stage_manifest(staged | {"format": tool.V7}, generated.ref, pin)
    other = generated.ref | {"upstream_session_id": "ses_not_enrolled"}
    with pytest.raises(ValueError, match="root_not_uniquely_enrolled"):
        tool.stage_manifest(manifest, other, pin)
    for fmt in ("qualified-consumer-runtime-v4", "qualified-consumer-runtime-v6"):
        with pytest.raises(ValueError, match="manifest_format_not_stageable"):
            tool.stage_manifest(manifest | {"format": fmt}, generated.ref, pin)
    with pytest.raises(ValueError, match="v5_manifest_has_generated_roots"):
        tool.stage_manifest(manifest | {"generated_roots": []}, generated.ref, pin)
    no_reader = copy.deepcopy(manifest)
    no_reader["backends"][0].pop("file_read")
    with pytest.raises(ValueError, match="file_read"):
        tool.stage_manifest(no_reader, generated.ref, pin)


def test_stage_manifest_appends_to_an_existing_v7_scope(generated):  # noqa: F811
    manifest, pin = v5_manifest(generated)
    second = copy.deepcopy(manifest["backends"][0])
    second["reference"] = generated.ref | {"upstream_session_id": "ses_second_root"}
    second["generated_outputs"] = {"path": "/etc/jtoz-synthetic/other.json", "sha256": "1" * 64}
    manifest["backends"].append(second)
    manifest["format"] = tool.V7
    manifest["generated_roots"] = [second["reference"]]
    staged = tool.stage_manifest(manifest, generated.ref, pin)
    assert staged["generated_roots"] == [second["reference"], generated.ref]
    assert staged["backends"][1] == second
    with pytest.raises(ValueError, match="already_in_generated_roots"):
        tool.stage_manifest(manifest | {"generated_roots": [generated.ref]}, generated.ref, pin)


def test_changed_paths_sees_type_list_and_key_changes():
    assert tool.changed_paths({"a": [1, 2]}, {"a": [1, 2]}) == set()
    assert tool.changed_paths({"a": [1, 2]}, {"a": [1, 3]}) == {("a", 1)}
    assert tool.changed_paths({"a": [1]}, {"a": [1, 2]}) == {("a",)}
    assert tool.changed_paths({"a": 1}, {"a": True}) == {("a",)}
    assert tool.changed_paths({"a": 1}, {"b": 1}) == {("a",), ("b",)}


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


def test_staged_files_pass_the_runtime_loaders_in_memory(generated):  # noqa: F811
    manifest, pin = v5_manifest(generated)
    staged = tool.stage_manifest(manifest, generated.ref, pin)
    raw = tool.dumps(staged)
    path = Path("/etc/jtoz-synthetic/staged/runtime.json")
    runtime = generated.settings.runtime.model_copy(
        update={"enrollment_file": path, "generated_returns_enabled": True}
    )
    settings = generated.settings.model_copy(update={"runtime": runtime})
    observed = tool.dumps(tool.stage_observer(observer(generated, "0" * 64), tool.sha(raw)))
    assert json.loads(observed)["runtime_enrollment_sha256"] == tool.sha(raw)
    sha = tool.validate_stage(
        settings,
        manifest_path=path,
        manifest_raw=raw,
        observer_raw=observed,
        reference=generated.ref,
    )
    assert sha == tool.sha(raw)
    with pytest.raises(ValueError, match="staged_observer_pin"):
        tool.validate_stage(
            settings,
            manifest_path=path,
            manifest_raw=raw,
            observer_raw=tool.dumps(observer(generated, "0" * 64)),
            reference=generated.ref,
        )
    disabled = settings.model_copy(
        update={"runtime": runtime.model_copy(update={"generated_returns_enabled": False})}
    )
    with pytest.raises(ValueError, match="generated_disabled"):
        tool.validate_stage(
            disabled,
            manifest_path=path,
            manifest_raw=raw,
            observer_raw=observed,
            reference=generated.ref,
        )
    forged = copy.deepcopy(staged)
    forged["backends"][0]["generated_outputs"]["sha256"] = "0" * 64
    with pytest.raises(ValueError):
        tool.validate_stage(
            settings,
            manifest_path=path,
            manifest_raw=tool.dumps(forged),
            observer_raw=tool.dumps(
                tool.stage_observer(observer(generated, "0" * 64), tool.sha(tool.dumps(forged)))
            ),
            reference=generated.ref,
        )


def test_stage_observer_changes_only_the_manifest_pin(generated):  # noqa: F811
    value = observer(generated, "0" * 64)
    staged = tool.stage_observer(value, "5" * 64)
    assert tool.changed_paths(value, staged) == {("runtime_enrollment_sha256",)}
    with pytest.raises(ValueError, match="observer_policy_pin_required"):
        tool.stage_observer({"format": "local-session-observer-v1"}, "5" * 64)


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
    spec.write_text(json.dumps({"tag": "unit", "project_id": "p"}))
    for step_name in ("plan", "stage"):
        with pytest.raises(ValueError, match="only_certify_takes_the_prompt_flag"):
            tool.main([step_name, "--spec", str(spec), tool.CONFIRM_FLAG])
    with pytest.raises(ValueError, match="exactly_one"):
        spec.write_text(json.dumps({"tag": "unit"}))
        tool.main(["plan", "--spec", str(spec)])


async def test_worker_refuses_certify_job_without_confirmation():
    with pytest.raises(ValueError, match="explicit_operator_prompt_flag"):
        await tool.worker_main({"mode": "certify", "tag": "unit"}, {})


def test_audit_counts_only_workspace_and_database_opens():
    audit = tool.Audit(CANONICAL, "/home/opencode/.local/share/opencode/opencode.db")
    audit("open", (f"{CANONICAL}/{DIRECTORY}/board.html", "r", 0))
    audit("open", (CANONICAL.encode(), "r", 0))
    audit("open", (f"{CANONICAL}-other/x", "r", 0))
    audit("open", ("/home/opencode/.local/share/opencode/opencode.db-wal", "r", 0))
    audit("open", (3, "r", 0))
    audit("exec", ("/bin/true",))
    assert (audit.workspace_opens, audit.database_opens) == (2, 1)


class FakeRoot:
    """Scripted Native resources for one operator turn; never a socket."""

    def __init__(self, permissions, *, busy=False):
        self.pending, self.busy = list(permissions), busy
        self.calls, self.replies, self.prompts = [], [], []
        self.running = False

    async def request(self, operation, *, path=None, query=None, body=None, before_send=None):
        self.calls.append(operation)
        if operation == "session.prompt":
            if before_send is not None:
                before_send()
            self.prompts.append(body)
            self.running = True
            payload = {"text": body["text"], "metadata": body["metadata"]}
            return {
                "data": {
                    "id": "msg_user",
                    "sessionID": SID,
                    "delivery": "queue",
                    "payload": payload,
                }
            }
        if operation == "session.permission.reply":
            self.replies.append((path["requestID"], body["decision"]))
            self.pending = [p for p in self.pending if p["id"] != path["requestID"]]
            return None
        if operation == "session.permission.list":
            return {"data": list(self.pending) if self.running else []}
        if operation in {"session.form.list", "session.inbox.list"}:
            return {"data": []}
        if operation == "session.active":
            return {"data": {SID: {"type": "running"}} if self.busy else {}}
        assert operation == "session.message.list" and query["limit"] == "1"
        done = self.running and not self.pending
        latest = {"id": "msg_idle_after" if done else "msg_idle_before", "type": "idle"}
        return {"data": [latest | {"time": {"created": 1}, "outcome": "succeeded"}]}


def turn_context(native):
    from jt_oz_bridge.adapters.opencode.contracts import OpenAPIProfile

    profile = OpenAPIProfile(
        Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json").read_bytes()
    )
    ref = SimpleNamespace(upstream_session_id=SID, canonical_directory=CANONICAL)
    wire = SimpleNamespace(
        attempts={"prompt": 0, "permission.reply": 0}, sent={"prompt": 0, "permission.reply": 0}
    )
    return SimpleNamespace(transport=native, ref=ref, profile=profile, wire=wire)


def turn_result():
    return {"prompts": [], "permission_replies": []}


@pytest.fixture
def correlations(monkeypatch):
    import jt_oz_bridge.adapters.opencode.turn_resources as turn_resources

    monkeypatch.setattr(tool, "POLL_SECONDS", 0)
    # The scripted Root is not a SessionRef; record the correlation fields instead.
    monkeypatch.setattr(turn_resources, "TurnCorrelation", lambda **kwargs: kwargs)


async def test_turn_answers_a_planned_ask_once_and_correlates_the_prompt(correlations):
    native = FakeRoot([ask("edit", f"{DIRECTORY}/board.html")])
    result = turn_result()
    c = await tool.run_turn(turn_context(native), step("files"), {"tag": "unit"}, result)
    assert native.replies == [("per_1", "once")] and len(native.prompts) == 1
    metadata = native.prompts[0]["metadata"]["jt_oz_bridge"]
    assert (c["action_id"], c["operation_digest"]) == (
        metadata["action_id"],
        metadata["operation_digest"],
    )
    assert c["upstream_id"] == "msg_user" and c["text"] == step("files")["text"]
    assert result["prompts"][0]["admitted"] is True
    assert result["prompts"][0]["operator_source"]["operator_not_human"] is True
    assert result["permission_replies"][0]["decision"] == "once"


@pytest.mark.parametrize(
    "asked, reason",
    [
        (ask("bash", "rm -rf ~"), "unplanned_command"),
        (ask("external_directory", "/tmp/*"), "unplanned_action"),
        ({"id": "per_1", "sessionID": SID, "action": "edit"}, "request_shape_unqualified"),
    ],
)
async def test_turn_rejects_anything_unplanned_and_stops(correlations, asked, reason):
    native = FakeRoot([asked])
    result = turn_result()
    with pytest.raises(ValueError, match="permission_refused:" + reason):
        await tool.run_turn(turn_context(native), step("files"), {"tag": "unit"}, result)
    assert native.replies == [("per_1", "reject")]
    assert result["permission_replies"][0]["resources"] is None


async def test_turn_is_never_sent_to_a_busy_root(correlations):
    native = FakeRoot([], busy=True)
    with pytest.raises(ValueError, match="root_busy"):
        await tool.run_turn(turn_context(native), step("quiet"), {"tag": "unit"}, turn_result())
    assert "session.prompt" not in native.calls


async def test_worker_composes_the_pinned_reader_stack_without_native_io(
    generated,  # noqa: F811
    monkeypatch,
):
    from jt_oz_bridge.adapters.opencode.host_owner import HostOwnerEnrollment
    from jt_oz_bridge.adapters.opencode.live import V2PublicFeed
    from jt_oz_bridge.adapters.opencode.resources import V2LeafResourceProofs

    b = generated.manifest["backends"][0]
    owner = HostOwnerEnrollment.model_validate_json(generated.documents[Path(b["owner"]["path"])])
    job = {"tag": "unit", "config": "/unused", "project_id": generated.ref["project_id"]}
    monkeypatch.setattr("jt_oz_bridge.config.load_settings", lambda _: generated.settings)
    monkeypatch.setattr(tool.os, "getuid", lambda: owner.client_uid)
    with pytest.raises(ValueError, match="root_not_certifiable"):
        tool.context(job)
    b["verified_operations"] = sorted(set(b["verified_operations"]) | tool.REQUIRED_OPERATIONS)
    generated.save_catalogs()
    monkeypatch.setattr(tool.os, "getuid", lambda: owner.client_uid + 1)
    with pytest.raises(ValueError, match="enrolled_bridge_client_uid_required"):
        tool.context(job)
    monkeypatch.setattr(tool.os, "getuid", lambda: owner.client_uid)
    ctx = tool.context(job)
    assert ctx.ref == SessionRef.model_validate(generated.ref)
    assert ctx.file_attestation.reference == ctx.ref and ctx.outcomes
    started = []

    async def start(self):
        started.append(self)

    async def watch(self, ref, *, require_idle=False):
        assert require_idle is True
        started.append(ref)

    monkeypatch.setattr(V2PublicFeed, "start", start)
    monkeypatch.setattr(V2LeafResourceProofs, "watch", watch)
    async with tool.opened(ctx, "d" * 64) as s:
        reader = s.reader
        assert reader.file_reader.client is reader.turns.client
        assert reader.turns.client.transport is ctx.transport is s.feed.transport
        assert reader.attestation.installed_evidence_sha256 == "d" * 64
        assert reader.byte_attestation.reference == ctx.ref
        # Exactly the qualification gates the runtime reader enforces.
        assert reader.require_bytes(ctx.ref) is reader.byte_attestation
        assert reader.file_reader.require(ctx.ref) is ctx.file_attestation
        with pytest.raises(ValueError):
            reader.require(ctx.foreign)
    assert started == [s.feed, ctx.ref]
    await ctx.transport.close()


# --------------------------------------------------------------------------
# Sends through the Bridge's real V2HTTPTransport and its mutation write boundary.
# --------------------------------------------------------------------------


def bridge_transport(permissions):
    """A real V2HTTPTransport over httpx.MockTransport, with the tool's Wire installed
    exactly as the worker installs it; Native is a scripted handler."""
    from unittest.mock import AsyncMock

    import httpx

    from jt_oz_bridge.adapters.opencode.contracts import OpenAPIProfile
    from jt_oz_bridge.adapters.opencode.transport import ContractAttestation, V2HTTPTransport

    profile = OpenAPIProfile(
        Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json").read_bytes()
    )
    sid = REF.upstream_session_id
    state = SimpleNamespace(pending=list(permissions), running=False, posts=[])

    def handle(request):
        path = request.url.path
        if request.method == "POST":
            state.posts.append(path)
            body = json.loads(request.content)
            if path.endswith("/prompt"):
                state.running = True
                user = {
                    "id": "msg_user",
                    "sessionID": sid,
                    "time": {"created": 0},
                    "type": "user",
                    "payload": {"text": body["text"], "metadata": body["metadata"]},
                    "delivery": body["delivery"],
                }
                return httpx.Response(200, json={"data": user})
            state.pending = [p for p in state.pending if not path.endswith(f"/{p['id']}/reply")]
            return httpx.Response(204)
        if path.endswith("/permission"):
            return httpx.Response(200, json={"data": state.pending if state.running else []})
        if path.endswith(("/form", "/inbox")) or path.endswith("/session/active"):
            return httpx.Response(200, json={"data": {} if path.endswith("active") else []})
        assert path.endswith("/message"), path
        done = state.running and not state.pending
        idle = {"type": "idle", "time": {"created": 3}, "outcome": "succeeded"}
        idle["id"] = "msg_idle_after" if done else "msg_idle"
        return httpx.Response(200, json={"data": [idle], "cursor": {}})

    t = V2HTTPTransport(
        "http://127.0.0.1:4096",
        profile,
        attestation=ContractAttestation(
            profile.sha256, REF.backend_identity, "2.0.32", tool.REQUIRED_OPERATIONS
        ),
        transport=httpx.MockTransport(handle),
        verify_identity=AsyncMock(return_value=True),
    )
    wire = tool.Wire(str(t.client.base_url), sid, allow_mutations=True).install(t)
    ctx = SimpleNamespace(transport=t, ref=REF, profile=profile, wire=wire)
    return ctx, state


async def test_prompt_and_reply_pass_the_bridge_write_boundary_and_count_as_sent(monkeypatch):
    monkeypatch.setattr(tool, "POLL_SECONDS", 0)
    asked = {
        "id": "per_1",
        "sessionID": REF.upstream_session_id,
        "action": "edit",
        "resources": [f"{DIRECTORY}/board.html"],
    }
    ctx, state = bridge_transport([asked])
    result = turn_result()
    try:
        c = await tool.run_turn(ctx, step("files"), {"tag": "unit"}, result)
    finally:
        await ctx.transport.close()
    sid = REF.upstream_session_id
    assert state.posts == [
        f"/api/session/{sid}/prompt",
        f"/api/session/{sid}/permission/per_1/reply",
    ]
    assert ctx.wire.attempts == ctx.wire.sent == {"prompt": 1, "permission.reply": 1}
    assert result["prompts"][0]["sent"] is True and result["prompts"][0]["admitted"] is True
    assert result["permission_replies"][0]["sent"] is True
    assert c.upstream_id == "msg_user" and c.reference == REF
    summary = tool.sent_summary(
        result | {"native_mutations": ctx.wire.sent, "native_mutation_attempts": ctx.wire.attempts}
    )
    assert summary["prompt"] == {
        "sent": 1,
        "not_sent": 0,
        "uncertain": 0,
        "attempted": 1,
        "answered_by_native": 1,
    }


async def test_a_guard_blind_to_its_own_attempt_is_refused_at_the_boundary_unsent():
    """On a real server, before_send runs again at the headers trace, after the
    Wire hook counted the attempt, so `attempts < prompts` refused its own send."""
    from jt_oz_bridge.adapters.opencode.transport import TransportNotSent

    ctx, state = bridge_transport([])
    record = {"sent": False}
    try:
        with pytest.raises(TransportNotSent, match="write_boundary_rejected"):
            await tool.send_mutation(
                ctx,
                "prompt",
                record,
                "session.prompt",
                path={"sessionID": REF.upstream_session_id},
                body=tool.prompt_body("x", "a" * 32, "b" * 64),
                before_send=lambda: tool.need(ctx.wire.attempts["prompt"] < 1, "old_guard"),
            )
    finally:
        await ctx.transport.close()
    assert record["sent"] is False and state.posts == []
    assert ctx.wire.attempts["prompt"] == 1 and ctx.wire.sent["prompt"] == 0
    summary = tool.sent_summary(
        {
            "prompts": [record],
            "native_mutations": ctx.wire.sent,
            "native_mutation_attempts": ctx.wire.attempts,
        }
    )
    assert summary["prompt"]["sent"] == 0 and summary["prompt"]["not_sent"] == 1


async def test_the_fixed_guard_still_refuses_a_second_attempt_for_the_same_step():
    from jt_oz_bridge.adapters.opencode.transport import TransportNotSent

    ctx, state = bridge_transport([])
    sid = {"sessionID": REF.upstream_session_id}
    body = tool.prompt_body("x", "a" * 32, "b" * 64)

    def guard():
        tool.need(ctx.wire.attempts["prompt"] <= 1, "second_prompt_for_step")

    first, second = {"sent": False}, {"sent": False}
    try:
        await tool.send_mutation(
            ctx, "prompt", first, "session.prompt", path=sid, body=body, before_send=guard
        )
        with pytest.raises(TransportNotSent):
            await tool.send_mutation(
                ctx, "prompt", second, "session.prompt", path=sid, body=body, before_send=guard
            )
    finally:
        await ctx.transport.close()
    assert first["sent"] is True and second["sent"] is False and len(state.posts) == 1
    assert ctx.wire.sent["prompt"] == 1


class AbortedTailRoot(FakeRoot):
    """The Root's newest entry is a declined permission's aborted assistant."""

    async def request(self, operation, *, path=None, query=None, body=None, before_send=None):
        if operation == "session.message.list":
            self.calls.append(operation)
            error = {"type": "aborted", "message": "Step interrupted"}
            return {"data": [{"id": "msg_aborted", "type": "assistant", "error": error}]}
        return await super().request(operation, path=path, query=query, body=body)


async def test_quiet_root_accepts_an_aborted_tail_only_before_the_first_prompt():
    # A declined ask leaves no Idle; the boundary is its head.
    ctx = turn_context(AbortedTailRoot([]))
    assert await tool.root_quiet(ctx) == "msg_aborted"
    ctx.wire.attempts["prompt"] = 1
    with pytest.raises(tool.CertifyError, match="root_latest_message_not_idle"):
        await tool.root_quiet(ctx)
