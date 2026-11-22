"""Zulip upgrade check: the runtime's own release rule, read from a manifest and a tree."""

import hashlib
import importlib.util
import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
TOOL = ROOT / "ops/server/check_zulip_upgrade.py"
SPEC = importlib.util.spec_from_file_location("check_zulip_upgrade", TOOL)
assert SPEC is not None and SPEC.loader is not None
tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tool
SPEC.loader.exec_module(tool)

UPLOAD = b"# synthetic zerver/lib/upload/__init__.py\n"
VIEWS = b"# synthetic zerver/views/upload.py\n"


def config(tmp_path, version="12.3", level=500):
    manifest = tmp_path / "runtime.json"
    manifest.write_text(
        json.dumps(
            {
                "realm": {
                    "realm_id": "2",
                    "url": "https://chat.invalid",
                    "bot_email": "bot@chat.invalid",
                    "bot_user_id": 11,
                    "bot_owner_id": 8,
                    "zulip_version": version,
                    "feature_level": level,
                    "message_limit": 10000,
                    "topic_limit": 60,
                    "evidence": [{"path": "/etc/synthetic/zulip.json", "sha256": "a" * 64}],
                }
            }
        )
    )
    path = tmp_path / "config.toml"
    path.write_text(f'[runtime]\nenabled = true\nenrollment_file = "{manifest}"\n')
    return path


@pytest.fixture
def pinned(monkeypatch):
    """Pin the synthetic upload sources the way file_upload.py pins Zulip 12.3's."""
    monkeypatch.setattr(
        tool,
        "UPLOAD_SOURCES",
        {
            "zulip-12.3-upload.py": hashlib.sha256(UPLOAD).hexdigest(),
            "zulip-12.3-upload-views.py": hashlib.sha256(VIEWS).hexdigest(),
        },
    )


def release_files(version, level, upload=UPLOAD):
    return {
        "version.py": (
            f'ZULIP_VERSION = "{version}"\nLATEST_MAJOR_VERSION = "12.0"\n'
            f"API_FEATURE_LEVEL = {level}\n"
        ).encode(),
        "zerver/lib/upload/__init__.py": upload,
        "zerver/views/upload.py": VIEWS,
    }


def tarball(tmp_path, files, top="zulip-server-12.6"):
    path = tmp_path / f"{top}.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(f"{top}/{name}")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return path


def tree(tmp_path, files):
    for name, data in files.items():
        (tmp_path / "tree" / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "tree" / name).write_bytes(data)
    return tmp_path / "tree"


def test_the_pins_this_tool_maps_are_the_ones_file_upload_has():
    assert set(tool.SOURCE_PATHS) == set(tool.UPLOAD_SOURCES)


@pytest.mark.parametrize(
    ("version", "level", "code"),
    [
        ("12.3", 500, 0),
        ("12.5", 501, 0),  # A later maintenance release of the same series.
        ("12.6", 502, 0),
        ("13.0", 510, 2),
        ("12.2", 499, 2),
        ("12.5", 499, 2),
        ("12.5-dev+git", 501, 2),
    ],
)
def test_a_given_release_follows_the_runtime_rule(tmp_path, capsys, version, level, code):
    args = ["--config", str(config(tmp_path)), "--version", version, "--feature-level", str(level)]
    assert tool.main(args) == code
    out = capsys.readouterr().out
    assert ("bridge: accepts" in out) is (code == 0)
    assert "qualified: 12.3/500" in out


def test_a_release_tarball_names_its_release_and_upload_code(tmp_path, capsys, pinned):
    cfg = config(tmp_path)
    assert (
        tool.main(
            ["--config", str(cfg), "--sources", str(tarball(tmp_path, release_files("12.6", 502)))]
        )
        == 0
    )
    assert "candidate: 12.6/502 (sources)" in capsys.readouterr().out
    changed = tarball(
        tmp_path, release_files("12.6", 502, upload=b"# changed\n"), "zulip-server-12.7"
    )
    assert tool.main(["--config", str(cfg), "--sources", str(changed), "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["accepted"] is True
    assert report["uploads"] == {
        "zerver/lib/upload/__init__.py": "changed",
        "zerver/views/upload.py": "unchanged",
    }
    major = tarball(tmp_path, release_files("13.0", 510), "zulip-server-13.0")
    assert tool.main(["--config", str(cfg), "--sources", str(major)]) == 2


def test_an_unpacked_deployment_is_read_the_same_way(tmp_path, capsys, pinned):
    files = release_files("12.5", 501)
    del files["zerver/views/upload.py"]
    assert (
        tool.main(["--config", str(config(tmp_path)), "--sources", str(tree(tmp_path, files))]) == 1
    )
    assert "upload code missing: zerver/views/upload.py" in capsys.readouterr().out


def test_the_live_server_is_asked_without_a_credential(tmp_path, monkeypatch, capsys):
    seen = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self, limit):
            return json.dumps(
                {"result": "success", "zulip_version": "12.5", "zulip_feature_level": 501}
            ).encode()

    def urlopen(request, timeout):
        seen.append(request)
        return Response()

    monkeypatch.setattr(tool.urllib.request, "urlopen", urlopen)
    assert tool.main(["--config", str(config(tmp_path))]) == 0
    assert seen[0].full_url == "https://chat.invalid/api/v1/server_settings"
    assert seen[0].get_method() == "GET" and "Authorization" not in seen[0].headers
    assert "candidate: 12.5/501 (live)" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("args", "reason"),
    [
        (["--version", "12.6"], "version_and_feature_level_go_together"),
        (["--sources", "/nonexistent/zulip.tar.gz"], "sources_not_a_directory_or_tarball"),
    ],
)
def test_what_cannot_be_evaluated_exits_3_never_as_accepted(tmp_path, capsys, args, reason):
    assert tool.main(["--config", str(config(tmp_path)), *args]) == 3
    assert reason in capsys.readouterr().err


def test_an_unreadable_manifest_or_version_file_exits_3(tmp_path, capsys, pinned):
    missing = tmp_path / "missing.toml"
    missing.write_text('[runtime]\nenabled = true\nenrollment_file = "/nonexistent/runtime.json"\n')
    assert tool.main(["--config", str(missing), "--version", "12.5", "--feature-level", "501"]) == 3
    assert "runtime_manifest_unreadable" in capsys.readouterr().err
    files = release_files("12.5", 501)
    files["version.py"] = b"ZULIP_VERSION = lines.pop(0)\n"
    assert (
        tool.main(["--config", str(config(tmp_path)), "--sources", str(tree(tmp_path, files))]) == 3
    )
    assert "version_file_unrecognized" in capsys.readouterr().err


def test_a_tarball_with_more_than_one_top_directory_is_not_guessed(tmp_path, capsys):
    path = tmp_path / "mixed.tar"
    with tarfile.open(path, "w") as archive:
        for name in ("a/version.py", "b/version.py"):
            member = tarfile.TarInfo(name)
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
    assert tool.main(["--config", str(config(tmp_path)), "--sources", str(path)]) == 3
    assert "tarball_needs_one_top_directory" in capsys.readouterr().err
