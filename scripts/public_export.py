"""Build the public repository from one commit of this private one.

Only files that `publish/allowlist.txt` names are copied, from the commit itself
(never the working tree), then `publish/overlay/` is laid over the result. The
allowlist only includes; nothing private is named in it. The new repository has
one commit by the given author and no history of this one; that author line
is the only thing the gate lets through unchecked. `scripts.public_gate`
must pass on the tree before the commit and on the repository after it.

  python -m scripts.public_export --out <new dir> --private-terms <owner-only file> \\
      --author "Name <e-mail>" [--spec-dir DIR] [--rev HEAD] [--message ...]

The original specification (default `docs/specifications` of this checkout) is never
exported; the gate refuses any run of its text that turns up in the tree.
"""

import argparse
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath

from scripts.public_gate import load_terms, scan, spec_windows

ALLOWLIST = "publish/allowlist.txt"
OVERLAY = "publish/overlay/"
AUTHOR = re.compile(r"^[^<>@\n]+ <[^<>\s@]+@[^<>\s@]+\.[A-Za-z]{2,}>$")


def patterns(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


def selected(name: str, globs: list[str]) -> bool:
    """Named by an include glob and by no `!` exclude glob, whatever their order.

    A `=` glob includes a path whose public copy must come from the overlay (see build).
    """
    path = PurePosixPath(name)
    return any(
        path.full_match(g.removeprefix("=")) for g in globs if not g.startswith("!")
    ) and not any(path.full_match(g[1:]) for g in globs if g.startswith("!"))


def replaced(name: str, globs: list[str]) -> bool:
    return any(PurePosixPath(name).full_match(g[1:]) for g in globs if g.startswith("="))


def commit_files(root: Path, rev: str) -> dict[str, tuple[bytes, int]]:
    """Every regular file of the commit with its bytes and mode; links are refused."""
    archive = subprocess.run(
        ["git", "-C", str(root), "archive", "--format=tar", rev], check=True, capture_output=True
    ).stdout
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in tar.getmembers():
            if member.issym() or member.islnk():
                raise ValueError(f"link in commit: {member.name}")
            if member.isfile():
                extracted = tar.extractfile(member)
                assert extracted is not None
                files[member.name] = (extracted.read(), member.mode)
    return files


def build(root: Path, rev: str, out: Path) -> list[str]:
    files = commit_files(root, rev)
    globs = patterns(files[ALLOWLIST][0].decode())
    overlay = {
        name.removeprefix(OVERLAY): content
        for name, content in files.items()
        if name.startswith(OVERLAY)
    }
    # A `=` path is never copied itself: its sanitized copy comes from the overlay, and
    # a path with no copy there stops the export instead of falling back to the original.
    missing = [
        name
        for name in files
        if not name.startswith(OVERLAY) and replaced(name, globs) and name not in overlay
    ]
    if missing:
        raise ValueError(f"replace-only paths have no overlay copy: {missing[:5]}")
    chosen = {
        name: content
        for name, content in files.items()
        if selected(name, globs) and not replaced(name, globs) and not name.startswith(OVERLAY)
    }
    # The overlay holds what only the public repository has, such as its own CI.
    chosen.update(overlay)
    unused = [
        glob
        for glob in globs
        if not any(PurePosixPath(name).full_match(glob.lstrip("!=")) for name in files)
    ]
    if unused:
        raise ValueError(f"allowlist entries match nothing: {unused}")
    out.mkdir(mode=0o755)
    for name, (data, mode) in sorted(chosen.items()):
        target = out / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        os.chmod(target, 0o755 if mode & 0o111 else 0o644)
    return sorted(chosen)


def commit(out: Path, author: str, message: str) -> None:
    name, _, email = author.partition(" <")
    identity = {
        "GIT_AUTHOR_NAME": name,
        "GIT_AUTHOR_EMAIL": email.rstrip(">"),
        "GIT_COMMITTER_NAME": name,
        "GIT_COMMITTER_EMAIL": email.rstrip(">"),
    }
    environment = {**os.environ, **identity, "GIT_CONFIG_GLOBAL": os.devnull}
    run = {"cwd": out, "check": True, "env": environment, "capture_output": True}
    subprocess.run(["git", "init", "-q", "-b", "main"], **run)  # type: ignore[call-overload]
    subprocess.run(["git", "add", "-A"], **run)  # type: ignore[call-overload]
    subprocess.run(["git", "commit", "-q", "-m", message], **run)  # type: ignore[call-overload]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--private-terms", type=Path, required=True)
    parser.add_argument("--author", required=True)
    parser.add_argument("--rev", default="HEAD")
    parser.add_argument("--message", default="jt-oz-bridge public source")
    parser.add_argument("--spec-dir", type=Path, help="default: docs/specifications here")
    args = parser.parse_args()
    if not AUTHOR.fullmatch(args.author):
        print("FAIL: --author must be 'Name <e-mail>'")
        return 1
    if args.out.exists():
        print(f"FAIL: {args.out} exists; the export is always built fresh")
        return 1
    root = Path(__file__).resolve().parents[1]
    terms = load_terms(args.private_terms)
    if not terms:
        print("FAIL: the private terms list is empty")
        return 1
    spec_dir = args.spec_dir or root / "docs/specifications"
    spec = spec_windows(spec_dir) if spec_dir.is_dir() else set()
    if not spec:
        print(f"FAIL: no specification text under {spec_dir}; copied text could not be checked")
        return 1
    names = build(root, args.rev, args.out)
    for stage in ("tree", "repository"):
        if stage == "repository":
            commit(args.out, args.author, args.message)
        # The author is published by the owner's choice; nothing else in history is exempt.
        findings = scan(args.out.resolve(), terms, args.author, spec)
        for finding in findings:
            print(finding)
        if findings:
            shutil.rmtree(args.out)
            print(f"FAIL: {len(findings)} findings in the {stage}; the export was removed")
            return 1
    head = subprocess.run(
        ["git", "-C", str(args.out), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    print(f"PASS: {len(names)} files, one commit {head[:12]} in {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
