"""Synthetic Root trust packets only; no installed/Native qualification claim."""

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from jt_oz_bridge.adapters.opencode.directory_scope import DirectoryScopeRoot
from jt_oz_bridge.adapters.opencode.host_owner import HostOwnerEnrollment
from jt_oz_bridge.domain.checks import CheckCatalog, CheckObservation, check_message_id
from jt_oz_bridge.domain.directory_scope import directory_project_key
from jt_oz_bridge.services import git_evidence_enrollment as enrollment
from jt_oz_bridge.storage.durable import digest
from tests.contract.test_host_owner import CONFIG, evidence
from tests.support import REF
from tests.unit.test_git_evidence import document, pin


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


@pytest.fixture
def installation(monkeypatch):
    assets = {}
    reads = []

    def asset(path, raw):
        assets[Path(path)] = raw
        return dict(path=path, sha256=sha(raw))

    def read(path, expected):
        reads.append(path)
        raw = assets[path]
        if sha(raw) != expected:
            raise ValueError("synthetic_pinned_digest_changed")
        return raw

    monkeypatch.setattr(enrollment, "pinned_root_bytes", read)
    python = "/usr/bin/python3.12"
    monkeypatch.setattr(enrollment, "python_command_target", lambda: Path(python))
    owner = HostOwnerEnrollment.model_validate(
        CONFIG
        | {
            "backend_id": REF.backend_id,
            "backend_identity": REF.backend_identity,
        }
    )
    physical = DirectoryScopeRoot(
        project_key=directory_project_key(REF),
        directory=REF.canonical_directory,
        device=1,
        inode=20,
        uid=owner.native_uid,
        gid=1000,
        mode=0o700,
    )
    script = asset(str(enrollment.SCRIPT), b"# synthetic script, never executed\n")
    py = asset(python, b"\x7fELFsynthetic interpreter")
    git = asset("/usr/bin/git", b"\x7fELFsynthetic git")
    catalog = CheckCatalog(reference=REF, contract_sha256="c" * 64, checks=(pin().check,))
    plugin = asset(
        "/etc/jt-oz-bridge/evidence-plugin.json",
        encoded(
            dict(
                format="git-evidence-reviewed-plugin-policy-v1",
                reviewed=True,
                reference=REF.model_dump(mode="json"),
                native_policy_sha256="d" * 64,
                script_sha256=script["sha256"],
                check_command_sha256=sha(pin().check.command.encode()),
            )
        ),
    )
    p = pin(
        catalog_sha256=digest(catalog.model_dump(mode="json")),
        contract_sha256=catalog.contract_sha256,
        qualification_sha256="e" * 64,
        script_sha256=script["sha256"],
        python_binary_sha256=py["sha256"],
        git_binary_sha256=git["sha256"],
        physical_scope_sha256=digest(physical.model_dump(mode="json")),
        native_policy_sha256="d" * 64,
        plugin_policy_sha256=plugin["sha256"],
    )

    def identity(path, inode):
        return dict(path=path, dev=1, ino=inode, uid=1000, gid=1000, mode=0o700)

    common = REF.canonical_directory + "/.git"
    entry = dict(
        reference=REF.model_dump(mode="json"),
        cwd=identity(REF.canonical_directory, 20),
        git_dir=identity(common, 21),
        common_dir=identity(common, 21),
        object_dir=identity(common + "/objects", 22),
        home=identity("/home/example", 23),
        index_uid=1000,
        configs={},
        qualification={
            key: getattr(p, key)
            for key in (
                "physical_scope_sha256",
                "native_policy_sha256",
                "plugin_policy_sha256",
                "installed_qualification_sha256",
            )
        },
    )
    entry["configs"] = {"system": None, "xdg": None, "global": None}
    entry["configs"]["local"] = identity(common + "/config", 24) | {"sha256": "f" * 64}
    registry = dict(
        format="git-inspect225-root-v1",
        script_sha256=p.script_sha256,
        python=dict(path=python, sha256=p.python_binary_sha256, version=p.python_version),
        git=dict(path="/usr/bin/git", sha256=p.git_binary_sha256, version=p.git_version),
        scopes={p.scope_sha256: entry},
    )
    observed_owner = evidence(
        **{
            key: getattr(owner, key)
            for key in (
                "backend_id",
                "backend_identity",
                "unit",
                "unit_sha256",
                "native_uid",
                "version",
                "url",
                "executable_sha256",
                "dataset_device",
                "dataset_inode",
            )
        }
    )
    checks = []
    for n in (1, 2):
        action = f"installed-check-{n}"
        checks.append(
            CheckObservation(
                reference=REF,
                action_id=action,
                check=p.check,
                message_id=check_message_id(action),
                shell_id=f"shell-{n}",
                status="exited",
                exit_code=0,
                started_at=(100 if n == 1 else 102) * 1000,
                completed_at=(101 if n == 1 else 103) * 1000,
                evidence_sha256="f" * 64,
                qualification_sha256=p.qualification_sha256,
                output=json.dumps(
                    document(
                        script_sha256=p.script_sha256,
                        git_binary_sha256=p.git_binary_sha256,
                        capture_started_at=100 if n == 1 else 102,
                        capture_finished_at=101 if n == 1 else 103,
                    )
                ),
            ).model_dump(mode="json")
        )
    observation = dict(
        format="installed-original-git-evidence-observation-v1",
        passed=True,
        reference=REF.model_dump(mode="json"),
        installation_semantic_sha256="a" * 64,
        owners=[observed_owner, observed_owner | {"observed_at": 104}],
        checks=checks,
        cases={case: True for case in enrollment.CASES},
        repository_unchanged=True,
        native_database_bytes_read=False,
        formal_acceptance=False,
    )
    packet = dict(
        format="installed-original-git-evidence-qualification-v1",
        passed=True,
        pin=p.model_dump(mode="json"),
        script=script,
        registry=asset(str(enrollment.REGISTRY), encoded(registry)),
        python_binary=py,
        git_binary=git,
        plugin_policy=plugin,
        observation=asset("/etc/jt-oz-bridge/evidence-observed.json", encoded(observation)),
        directory_enrollment_sha256="b" * 64,
        physical_root=physical.model_dump(mode="json"),
    )

    def save():
        # Exclude only the observation-hash backlink to avoid a circular hash.
        observation["installation_semantic_sha256"] = enrollment.installation_semantics(
            enrollment.GitEvidenceInstallPacket.model_validate(packet), registry
        )
        packet["observation"] = asset(
            "/etc/jt-oz-bridge/evidence-observed.json", encoded(observation)
        )
        packet["pin"]["installed_qualification_sha256"] = packet["observation"]["sha256"]
        entry["qualification"]["installed_qualification_sha256"] = packet["observation"]["sha256"]
        packet["registry"] = asset(str(enrollment.REGISTRY), encoded(registry))
        return encoded(packet)

    def qualify(raw=None):
        return enrollment.qualify_git_evidence(
            raw or save(),
            reference=REF,
            catalog=catalog,
            contract_sha256=catalog.contract_sha256,
            check_qualification_sha256="e" * 64,
            native_policy_sha256="d" * 64,
            owner=owner,
            physical_root=physical,
            directory_enrollment_sha256="b" * 64,
        )

    save()
    return SimpleNamespace(
        assets=assets,
        reads=reads,
        packet=packet,
        entry=entry,
        registry=registry,
        observation=observation,
        save=save,
        qualify=qualify,
        asset=asset,
        owner=owner,
        physical=physical,
        catalog=catalog,
    )


def test_complete_synthetic_packet_binds_assets_without_workspace_reads(installation):
    x = installation
    result = x.qualify()
    assert (
        result.reference == REF
        and result.installed_qualification_sha256 == x.packet["observation"]["sha256"]
    )
    assert len(x.reads) == 6
    assert all(not str(path).startswith(REF.canonical_directory) for path in x.reads)


def test_old_raw_packet_is_refused_before_any_asset_read(installation):
    x = installation
    packet = json.loads(x.save())
    packet["pin"]["git_version"] = "2.56.0"
    x.reads.clear()
    with pytest.raises(ValueError, match="git_version"):
        x.qualify(encoded(packet))
    assert x.reads == []


@pytest.mark.parametrize(
    "field", ["script", "registry", "python_binary", "git_binary", "plugin_policy", "observation"]
)
def test_every_installed_asset_is_actually_hash_read(installation, field):
    x = installation
    raw = x.save()
    x.assets[Path(x.packet[field]["path"])] += b"changed"
    with pytest.raises(ValueError):
        x.qualify(raw)


@pytest.mark.parametrize(
    "field", ["passed", "repository_unchanged", "native_database_bytes_read", "formal_acceptance"]
)
def test_observation_requires_safe_strict_terminal_claims(installation, field):
    x = installation
    x.observation[field] = not x.observation[field]
    with pytest.raises(ValueError):
        x.qualify()


@pytest.mark.parametrize("case", sorted(enrollment.CASES))
def test_every_installed_functional_case_is_required(installation, case):
    x = installation
    x.observation["cases"][case] = False
    with pytest.raises(ValueError):
        x.qualify()


@pytest.mark.parametrize(
    "path", ["/tmp/unsafe", "/etc/jt-oz-bridge/../unsafe", "/home/example/file"]
)
def test_root_config_assets_cannot_select_arbitrary_paths(installation, path):
    x = installation
    x.packet["observation"]["path"] = path
    with pytest.raises((ValueError, KeyError)):
        x.qualify(encoded(x.packet))


@pytest.mark.parametrize(
    "key,value",
    [
        ("path", "/a/../b"),
        ("path", "//alias"),
        ("path", "/a\x00b"),
        ("path", "/"),
        ("dev", True),
        ("ino", 0),
        ("uid", -1),
        ("mode", 0o777),
        ("mode", 0o170000),
    ],
)
def test_full_declared_directory_identity_is_validated(installation, key, value):
    x = installation
    x.entry["object_dir"][key] = value
    with pytest.raises(ValueError):
        x.qualify()


@pytest.mark.parametrize(
    "fault",
    [
        "same_action",
        "changed_index",
        "truncated",
        "failed",
        "owner",
        "check",
        "physical",
        "backlink",
        "plugin",
        "registry",
    ],
)
def test_installed_original_samples_and_physical_scope_cannot_drift(installation, fault):
    x = installation
    if fault == "same_action":
        x.observation["checks"][1] = copy.deepcopy(x.observation["checks"][0])
    elif fault == "changed_index":
        doc = json.loads(x.observation["checks"][1]["output"])
        doc["index_sha256"] = "0" * 64
        x.observation["checks"][1]["output"] = json.dumps(doc)
    elif fault == "truncated":
        x.observation["checks"][1]["output_truncated"] = True
    elif fault == "failed":
        x.observation["checks"][1]["exit_code"] = 1
    elif fault == "owner":
        x.observation["owners"][1] = evidence(
            backend_id=REF.backend_id, backend_identity=REF.backend_identity, pid=999
        )
    elif fault == "check":
        x.observation["checks"][1]["check"]["command"] = "git status"
    elif fault == "physical":
        x.packet["physical_root"]["inode"] += 1
    elif fault == "backlink":
        x.entry["qualification"]["physical_scope_sha256"] = "0" * 64
    elif fault == "plugin":
        path = Path(x.packet["plugin_policy"]["path"])
        value = json.loads(x.assets[path])
        value["reviewed"] = 1
        x.packet["plugin_policy"] = x.asset(str(path), encoded(value))
        x.packet["pin"]["plugin_policy_sha256"] = x.packet["plugin_policy"]["sha256"]
        x.entry["qualification"]["plugin_policy_sha256"] = x.packet["plugin_policy"]["sha256"]
    elif fault == "registry":
        x.registry["python"]["version"] = "unknown"
    with pytest.raises(ValueError):
        x.qualify()


def test_semantic_digest_detects_registry_changes_even_if_asset_hash_is_refreshed(installation):
    x = installation
    x.save()
    x.entry["home"]["ino"] += 1
    x.packet["registry"] = x.asset(str(enrollment.REGISTRY), encoded(x.registry))
    with pytest.raises(ValueError, match="registry_or_pins_changed"):
        x.qualify(encoded(x.packet))


@pytest.mark.parametrize(
    "fault",
    ["same_shell", "capture_before", "capture_after", "owner_before", "owner_after", "overlap"],
)
def test_original_shell_and_owner_must_bracket_each_capture(installation, fault):
    x = installation
    if fault == "same_shell":
        x.observation["checks"][1]["shell_id"] = x.observation["checks"][0]["shell_id"]
    elif fault.startswith("capture_"):
        raw = json.loads(x.observation["checks"][0]["output"])
        raw["capture_started_at"] = 99 if fault == "capture_before" else 101
        raw["capture_finished_at"] = 100 if fault == "capture_before" else 102
        x.observation["checks"][0]["output"] = json.dumps(raw)
    elif fault == "owner_before":
        x.observation["owners"][0]["observed_at"] = 100.5
    elif fault == "owner_after":
        x.observation["owners"][1]["observed_at"] = 102.5
    else:
        x.observation["checks"][1]["started_at"] = 100000
    with pytest.raises(ValueError):
        x.qualify()
