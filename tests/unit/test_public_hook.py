"""Public repository hooks: a commit or push with anything private never gets through."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
IDENTITY = "Pat Example <pat@example.com>"
# The source repository keeps the hooks under publish/overlay/; a published one at their own path.
HOOKS = next(
    path
    for path in (ROOT / "publish/overlay/tools/git-hooks", ROOT / "tools/git-hooks")
    if path.is_dir()
)


def git(repo, *args, env=None, check=True):
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, env=env, check=check
    )


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


@pytest.fixture
def public(tmp_path):
    owner = tmp_path / "owner"
    write(owner, "terms.txt", "zorblax\n")
    write(
        owner,
        "spec/SPEC.md",
        "The lighthouse keeper must never relight a lantern with a trimmed wick.\n",
    )
    repo = tmp_path / "public"
    for name in ("public_gate.py", "public_export.py", "public_hook.py"):
        write(repo, f"scripts/{name}", (ROOT / "scripts" / name).read_text())
    write(repo, "scripts/__init__.py", "")
    for hook in ("pre-commit", "commit-msg", "pre-push"):
        target = repo / "tools/git-hooks" / hook
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(HOOKS / hook, target)
        target.chmod(0o755)
    allowlist = "scripts/*.py\npublish/allowlist.txt\nsrc/**\n"
    write(repo, "publish/allowlist.txt", allowlist)
    write(owner, "allowlist.txt", allowlist)
    write(repo, ".gitignore", "__pycache__/\n")
    write(repo, "src/app.py", "print('hi')\n")
    name, _, email = IDENTITY.partition(" <")
    git(repo.parent, "init", "-q", "-b", "main", str(repo))
    for key, value in (
        ("user.name", name),
        ("user.email", email.rstrip(">")),
        ("core.hooksPath", "tools/git-hooks"),
    ):
        git(repo, "config", key, value)
    env = {
        **os.environ,
        "JTOZ_PUBLIC_TERMS": str(owner / "terms.txt"),
        "JTOZ_PUBLIC_SPEC": str(owner / "spec"),
        "JTOZ_PUBLIC_IDENTITY": IDENTITY,
        "JTOZ_PUBLIC_ALLOWLIST": str(owner / "allowlist.txt"),
        "JTOZ_PUBLIC_PYTHON": sys.executable,
        "GIT_CONFIG_GLOBAL": os.devnull,
    }
    git(repo, "add", "-A", env=env)
    assert git(repo, "commit", "-qm", "first", env=env).returncode == 0
    return repo, env


def commit(repo, env, message="change"):
    git(repo, "add", "-A", env=env)
    return git(repo, "commit", "-qm", message, env=env, check=False)


def test_a_clean_change_commits_and_a_private_one_is_refused(public):
    repo, env = public
    write(repo, "src/app.py", "print('hello')\n")
    assert commit(repo, env).returncode == 0
    write(repo, "src/app.py", "host = 'zorblax'\n")
    refused = commit(repo, env)
    assert refused.returncode != 0 and "private-term-1" in refused.stderr
    write(
        repo,
        "src/app.py",
        "# The lighthouse keeper must never relight a lantern with a trimmed wick.\n",
    )
    assert "spec-text" in commit(repo, env).stderr
    write(repo, "src/app.py", "print('hello')\n")
    write(repo, "notes/extra.md", "not on the allowlist\n")
    assert "not on the allowlist" in commit(repo, env).stderr


def test_a_message_with_an_assistant_trace_or_term_is_refused(public):
    repo, env = public
    write(repo, "src/app.py", "print(2)\n")
    trailer = "fix\n\nClaude" + "-Session: https://example.com/s"
    assert "assistant-session" in commit(repo, env, trailer).stderr
    assert "private-term-1" in commit(repo, env, "deploy to zorblax").stderr
    assert commit(repo, env, "fix output").returncode == 0


def test_no_hook_passes_without_its_private_inputs(public):
    repo, env = public
    write(repo, "src/app.py", "print(3)\n")
    for key in (
        "JTOZ_PUBLIC_TERMS",
        "JTOZ_PUBLIC_SPEC",
        "JTOZ_PUBLIC_IDENTITY",
        "JTOZ_PUBLIC_ALLOWLIST",
    ):
        refused = commit(repo, {k: v for k, v in env.items() if k != key})
        assert refused.returncode != 0 and "REFUSED" in refused.stderr


def push(repo, env, target, *refs):
    return git(repo, "push", "-q", str(target), *refs, env=env, check=False)


def test_push_checks_every_new_commit_identity_allowlist_and_tag(public, tmp_path):
    repo, env = public
    remote = tmp_path / "remote.git"
    git(tmp_path, "init", "-q", "--bare", str(remote))
    assert push(repo, env, remote, "main").returncode == 0
    # A commit by anyone else is refused, even with clean content.
    write(repo, "src/app.py", "print(4)\n")
    other = {**env, "GIT_AUTHOR_NAME": "Someone", "GIT_AUTHOR_EMAIL": "someone@example.com"}
    git(repo, "add", "-A", env=env)
    git(repo, "commit", "-qm", "other", env=other)
    refused = push(repo, env, remote, "main")
    assert refused.returncode != 0 and "author or committer" in refused.stderr
    git(repo, "reset", "-q", "--hard", "HEAD~1")
    # A commit made here that widens its own allowlist is refused at commit, and at push
    # even when the commit hook was skipped.
    write(repo, "publish/allowlist.txt", "scripts/*.py\npublish/allowlist.txt\nsrc/**\nextra/**\n")
    write(repo, "extra/data.md", "more\n")
    assert "not on the allowlist" in commit(repo, env).stderr
    git(repo, "commit", "-q", "--no-verify", "-m", "widen", env=env)
    refused = push(repo, env, remote, "main")
    assert refused.returncode != 0 and "not on the allowlist" in refused.stderr
    git(repo, "reset", "-q", "--hard", "HEAD~1")
    # Lightweight tags and tags with private words are refused; an annotated clean one passes.
    git(repo, "tag", "v0.0.1")
    assert "annotated" in push(repo, env, remote, "v0.0.1").stderr
    git(repo, "tag", "-d", "v0.0.1")
    git(repo, "tag", "-a", "v0.0.1", "-m", "release for zorblax", env=env)
    assert "private-term-1" in push(repo, env, remote, "v0.0.1").stderr
    git(repo, "tag", "-d", "v0.0.1")
    git(repo, "tag", "-a", "v0.0.1", "-m", "jt-oz-bridge 0.0.1", env=env)
    assert push(repo, env, remote, "main", "v0.0.1").returncode == 0
