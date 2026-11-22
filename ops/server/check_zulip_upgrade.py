"""Say whether this Bridge keeps running on a Zulip release, before or after upgrading Zulip.

Read-only operator tool. It never needs the Bot credential: the live check is the public
``GET /api/v1/server_settings``, and a release tarball or unpacked deployment is only read,
never extracted or run. It writes nothing.

    python check_zulip_upgrade.py                                    # the live server
    python check_zulip_upgrade.py --sources zulip-server-12.6.tar.gz # before upgrading
    python check_zulip_upgrade.py --version 13.0 --feature-level 510 # from release notes
    python check_zulip_upgrade.py --sources /srv/zulip-deployment --json

Bridge accepts the release it was qualified on and later maintenance releases of the
same series (12.3 to 12.5): the same check `ZulipRuntimeIdentity` makes on every start.
With ``--sources`` it also compares the Zulip upload code that Bridge's file transfer
was qualified against.

Exit codes: 0 accepted, and the upload code is unchanged or was not given; 1 accepted,
but the upload code changed, so review file transfer before upgrading; 2 refused, so
Bridge stops on this release until it is qualified (or Zulip is rolled back); 3 could
not evaluate (never read 3 as accepted).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tarfile
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import NoReturn

EXIT_ACCEPTED, EXIT_REVIEW_UPLOADS, EXIT_REFUSED, EXIT_UNEVALUATED = 0, 1, 2, 3
try:
    from jt_oz_bridge.adapters.zulip.file_upload import UPLOAD_SOURCES
    from jt_oz_bridge.adapters.zulip.server_release import same_release_line
    from jt_oz_bridge.config import load_settings
    from jt_oz_bridge.security.json_data import strict_loads
    from jt_oz_bridge.services.runtime_enrollment import RealmQualification
except Exception as error:
    # Python's own failure exit is 1, which here would read as "accepted".
    print(f"could not evaluate: project_import_failed_{type(error).__name__}", file=sys.stderr)
    raise SystemExit(EXIT_UNEVALUATED) from None

DEFAULT_CONFIG = Path("/etc/jt-oz-bridge/config.toml")
# Where each pinned upload source sits in a Zulip tree (docs/UPLOAD_ASSOCIATION.md).
SOURCE_PATHS = {
    "zulip-12.3-upload.py": "zerver/lib/upload/__init__.py",
    "zulip-12.3-upload-views.py": "zerver/views/upload.py",
}
VERSION_FILE = "version.py"
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_SETTINGS_BYTES = 256 * 1024
VERSION = re.compile(r'^ZULIP_VERSION = "([0-9A-Za-z.+-]{1,32})"$', re.MULTILINE)
LEVEL = re.compile(r"^API_FEATURE_LEVEL = ([0-9]{1,6})$", re.MULTILINE)


class Unevaluated(Exception):
    pass


@dataclass
class Report:
    qualified: str
    candidate: str
    feature_level: int | None
    source: str
    accepted: bool
    uploads: dict[str, str] = field(default_factory=dict)
    advice: list[str] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        if not self.accepted:
            return EXIT_REFUSED
        if any(state != "unchanged" for state in self.uploads.values()):
            return EXIT_REVIEW_UPLOADS
        return EXIT_ACCEPTED


def fail(reason: str) -> NoReturn:
    raise Unevaluated(reason)


def qualification(config: Path) -> RealmQualification:
    """The Zulip release the running runtime manifest was qualified on."""
    try:
        settings = load_settings(config)
    except Exception:
        fail("bridge_config_unreadable")
    manifest = settings.runtime.enrollment_file
    if manifest is None:
        fail("runtime_manifest_not_configured")
    try:
        return RealmQualification.model_validate(strict_loads(manifest.read_bytes())["realm"])
    except Exception:
        fail("runtime_manifest_unreadable")


class Tree:
    """A Zulip release tarball or an unpacked tree, read member by member."""

    def __init__(self, path: Path) -> None:
        self.path, self.tar, self.prefix = path, None, PurePosixPath()
        if path.is_dir():
            return
        try:
            self.tar = tarfile.open(path, "r:*")
        except (OSError, tarfile.TarError):
            fail("sources_not_a_directory_or_tarball")
        # Release tarballs hold one top directory such as zulip-server-12.5/.
        tops = {PurePosixPath(m.name).parts[0] for m in self.tar.getmembers() if m.name}
        if len(tops) != 1:
            fail("tarball_needs_one_top_directory")
        self.prefix = PurePosixPath(tops.pop())

    def read(self, relative: str) -> bytes | None:
        if self.tar is None:
            target = self.path / relative
            if target.is_symlink() or not target.is_file():
                return None
            if target.stat().st_size > MAX_SOURCE_BYTES:
                fail("source_too_large")
            return target.read_bytes()
        try:
            member = self.tar.getmember(str(self.prefix / relative))
        except KeyError:
            return None
        if not member.isfile():
            return None
        if member.size > MAX_SOURCE_BYTES:
            fail("source_too_large")
        handle = self.tar.extractfile(member)
        return None if handle is None else handle.read()


def tree_release(tree: Tree) -> tuple[str, int]:
    data = tree.read(VERSION_FILE)
    if data is None:
        fail("version_file_missing")
    text = data.decode("utf-8", "replace")
    version, level = VERSION.search(text), LEVEL.search(text)
    if version is None or level is None:
        fail("version_file_unrecognized")
    return version[1], int(level[1])


def upload_changes(tree: Tree) -> dict[str, str]:
    if set(SOURCE_PATHS) != set(UPLOAD_SOURCES):
        fail("upload_source_pins_changed_update_this_tool")
    states = {}
    for name, relative in SOURCE_PATHS.items():
        data = tree.read(relative)
        if data is None:
            states[relative] = "missing"
        elif hashlib.sha256(data).hexdigest() == UPLOAD_SOURCES[name]:
            states[relative] = "unchanged"
        else:
            states[relative] = "changed"
    return states


def live_release(url: str) -> tuple[object, object]:
    request = urllib.request.Request(
        url.rstrip("/") + "/api/v1/server_settings", headers={"Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = strict_loads(response.read(MAX_SETTINGS_BYTES + 1))
    except Exception:
        fail("server_settings_unavailable")
    if not isinstance(body, dict) or body.get("result") != "success":
        fail("server_settings_unrecognized")
    return body.get("zulip_version"), body.get("zulip_feature_level")


def evaluate(
    q: RealmQualification,
    version: object,
    level: object,
    source: str,
    uploads: dict[str, str] | None = None,
) -> Report:
    accepted = same_release_line(q.zulip_version, q.feature_level, version, level)
    report = Report(
        qualified=f"{q.zulip_version}/{q.feature_level}",
        candidate=str(version)[:32],
        feature_level=level if type(level) is int else None,
        source=source,
        accepted=accepted,
        uploads=uploads or {},
    )
    if not accepted:
        report.advice += [
            "Bridge stops on this release: do not upgrade Zulip until Bridge is qualified on it.",
            "If Zulip is already on it, roll Zulip back or qualify and deploy a new Bridge.",
        ]
    elif report.exit_code == EXIT_REVIEW_UPLOADS:
        report.advice.append(
            "Bridge keeps running, but the Zulip upload code changed: review file transfer "
            "(docs/UPLOAD_ASSOCIATION.md) before upgrading."
        )
    else:
        report.advice.append(
            "Bridge keeps running on this release. Avoid the Bridge cutover window and "
            "check Bridge's readiness after the upgrade."
        )
    return report


def text(report: Report) -> str:
    level = "-" if report.feature_level is None else report.feature_level
    lines = [
        f"qualified: {report.qualified}",
        f"candidate: {report.candidate}/{level} ({report.source})",
        f"bridge: {'accepts' if report.accepted else 'refuses'}",
    ]
    lines += [f"upload code {state}: {path}" for path, state in report.uploads.items()]
    return "\n".join(lines + report.advice)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    candidate = parser.add_mutually_exclusive_group()
    candidate.add_argument("--sources", type=Path, help="release tarball or unpacked tree")
    candidate.add_argument("--version", help="candidate release, e.g. 12.6 (needs --feature-level)")
    candidate.add_argument("--url", help="Zulip server to ask (default: the configured realm)")
    parser.add_argument("--feature-level", type=int)
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)
    try:
        if (args.version is None) != (args.feature_level is None):
            fail("version_and_feature_level_go_together")
        q = qualification(args.config)
        if args.sources is not None:
            tree = Tree(args.sources)
            version, level = tree_release(tree)
            report = evaluate(q, version, level, "sources", upload_changes(tree))
        elif args.version is not None:
            report = evaluate(q, args.version, args.feature_level, "given")
        else:
            report = evaluate(q, *live_release(args.url or q.url), "live")
    except Unevaluated as error:
        print(f"could not evaluate: {error}", file=sys.stderr)
        return EXIT_UNEVALUATED
    print(json.dumps(asdict(report), indent=2) if args.json else text(report))
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
