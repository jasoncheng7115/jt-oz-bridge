"""Git hooks of the public repository: no commit or push carries anything private.

Installed with `git config core.hooksPath tools/git-hooks`; each hook there runs this.
The owner's private terms, the original specification and the one identity the
repository publishes under come from the environment, and every hook refuses to run
without them, so a hook that cannot check never passes by default:

  JTOZ_PUBLIC_TERMS     owner-only word list (`scripts.public_gate --private-terms`)
  JTOZ_PUBLIC_SPEC      directory of the original specification (never published)
  JTOZ_PUBLIC_IDENTITY  `Name <e-mail>` of every author, committer and tagger
  JTOZ_PUBLIC_ALLOWLIST the private repository's `publish/allowlist.txt`

`pre-commit` scans the staged tree, `commit-msg` the message, and `pre-push` every
commit and tag the push would add: identity, message, the whole tree, and that each
path is published both by that commit's allowlist and by the private repository's,
so a commit made here cannot widen its own allowlist.
"""

import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from collections.abc import Set as AbstractSet
from pathlib import Path
from typing import NamedTuple

from scripts.public_export import ALLOWLIST, AUTHOR, patterns, selected
from scripts.public_gate import Finding, load_terms, scan, scan_text, spec_windows

# What only the public repository has (publish/overlay/ of the private one).
OVERLAY = [".gitignore", ".github/**", "tools/git-hooks/*"]
ZERO = "0" * 40


class Refused(Exception):
    pass


class Checks(NamedTuple):
    terms: list[re.Pattern[str]]
    spec: AbstractSet[int]
    identity: str
    allowlist: list[str]


def git(*args: str, data: bytes | None = None) -> str:
    return subprocess.run(
        ["git", *args], input=data, check=True, capture_output=True
    ).stdout.decode()


def settings() -> Checks:
    terms_file, spec_dir = os.environ.get("JTOZ_PUBLIC_TERMS"), os.environ.get("JTOZ_PUBLIC_SPEC")
    identity = os.environ.get("JTOZ_PUBLIC_IDENTITY", "")
    if not terms_file or not Path(terms_file).is_file():
        raise Refused("JTOZ_PUBLIC_TERMS is not a file; private terms cannot be checked")
    if not spec_dir or not Path(spec_dir).is_dir():
        raise Refused("JTOZ_PUBLIC_SPEC is not a directory; copied text cannot be checked")
    if not AUTHOR.fullmatch(identity):
        raise Refused("JTOZ_PUBLIC_IDENTITY must be 'Name <e-mail>'")
    allowlist_file = os.environ.get("JTOZ_PUBLIC_ALLOWLIST")
    if not allowlist_file or not Path(allowlist_file).is_file():
        raise Refused("JTOZ_PUBLIC_ALLOWLIST is not a file; published paths cannot be checked")
    allowlist = patterns(Path(allowlist_file).read_text())
    terms = load_terms(Path(terms_file))
    spec = spec_windows(Path(spec_dir))
    if not terms or not spec:
        raise Refused("the private terms list or the specification is empty")
    return Checks(terms, spec, identity, allowlist)


def allowed(name: str, globs: list[str]) -> bool:
    return selected(name, globs) or selected(name, OVERLAY)


def report(findings: list[Finding], where: str) -> None:
    if findings:
        for finding in findings:
            print(finding, file=sys.stderr)
        raise Refused(f"{len(findings)} findings in {where}")


def scan_tree(treeish: str, checks: Checks) -> None:
    """The whole tree of a commit, as the public will see it."""
    with tempfile.TemporaryDirectory() as directory:
        archive = subprocess.run(
            ["git", "archive", treeish], check=True, capture_output=True
        ).stdout
        subprocess.run(["tar", "-x", "-C", directory], input=archive, check=True)
        report(scan(Path(directory), checks.terms, checks.identity, checks.spec), treeish)


def pre_commit() -> None:
    checks = settings()
    with tempfile.TemporaryDirectory() as directory:
        git("checkout-index", "-a", f"--prefix={directory}/")
        globs = patterns((Path(directory) / ALLOWLIST).read_text())
        outside = [
            name
            for name in git("ls-files").splitlines()
            if not (allowed(name, globs) and allowed(name, checks.allowlist))
        ]
        if outside:
            raise Refused(f"not on the allowlist: {outside[:5]}")
        report(scan(Path(directory), checks.terms, checks.identity, checks.spec), "the staged tree")


def commit_msg(path: str) -> None:
    terms, spec, *_ = settings()
    report(list(scan_text("commit message", Path(path).read_text(), terms, spec)), "the message")


def check_commit(sha: str, checks: Checks) -> None:
    terms, spec, identity, private = checks
    people = git("log", "-1", "--format=%an <%ae>%n%cn <%ce>", sha).splitlines()
    if any(person != identity for person in people):
        raise Refused(f"{sha[:12]}: author or committer is not {identity}")
    report(
        list(scan_text(f"{sha[:12]} message", git("log", "-1", "--format=%B", sha), terms, spec)),
        sha[:12],
    )
    globs = patterns(git("show", f"{sha}:{ALLOWLIST}"))
    changed = git("diff-tree", "--root", "--no-commit-id", "--name-only", "-r", sha).splitlines()
    outside = [n for n in changed if not (allowed(n, globs) and allowed(n, private))]
    if outside:
        raise Refused(f"{sha[:12]}: not on the allowlist: {outside[:5]}")
    scan_tree(sha, checks)


def check_tag(ref: str, checks: Checks) -> None:
    terms, spec, identity, _ = checks
    if git("cat-file", "-t", ref).strip() != "tag":
        raise Refused(f"{ref}: only annotated tags are published")
    body = git("cat-file", "tag", ref)
    tagger = next((line[7:] for line in body.splitlines() if line.startswith("tagger ")), "")
    if not tagger.startswith(identity + " "):
        raise Refused(f"{ref}: tagger is not {identity}")
    message = body.partition("\n\n")[2]
    report(list(scan_text(f"{ref} message", message, terms, spec)), ref)


def pre_push(lines: list[str]) -> None:
    current = settings()
    for line in lines:
        local_ref, local_sha, _, remote_sha = line.split()
        if local_sha == ZERO:
            continue  # Deleting a remote ref adds nothing.
        if local_ref.startswith("refs/tags/"):
            check_tag(local_ref, current)
        span = local_sha if remote_sha == ZERO else f"{remote_sha}..{local_sha}"
        for sha in git("rev-list", "--reverse", span).splitlines():
            check_commit(sha, current)


def main(argv: list[str]) -> int:
    hooks: dict[str, Callable[[], None]] = {
        "pre-commit": pre_commit,
        "commit-msg": lambda: commit_msg(argv[2]),
        "pre-push": lambda: pre_push([line for line in sys.stdin.read().splitlines() if line]),
    }
    try:
        hooks[argv[1]]()
    except Refused as error:
        print(f"REFUSED ({argv[1]}): {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
