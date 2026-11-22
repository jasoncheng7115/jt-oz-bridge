import subprocess
import sys
import zlib

import pytest

from scripts.public_export import AUTHOR, build, commit, selected
from scripts.public_gate import line_digest, load_terms, main, scan, spec_windows


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def rules(root, terms=()):
    return sorted(finding.rule for finding in scan(root, list(terms)))


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ("url = 'http://192.168" + ".7.21:4096'", "ip-address"),
        ("peer 172.20" + ".1.5", "ip-address"),
        ("public 8.8" + ".4.4", "ip-address"),
        ("mail owner" + "@" + "zorblax" + ".com.tw", "email"),
        ("-----BEGIN OPENSSH " + "PRIVATE KEY-----", "private-key"),
        ("token ghp_" + "a" * 36, "github-token"),
        ("key = sk-" + "b" * 30, "api-key"),
        ("https://admin:" + "hunter22@chat.example.com/", "url-credentials"),
        ("see /" + "root/archive/run", "home-directory"),
        ("see /" + "Users/someone/project", "home-directory"),
        ("see /" + "home/alice/work", "home-directory"),
        ("root ses_" + "3a9f02c1d4e5Ab12Cd34Ef56Gh", "opencode-session-id"),
        ("Claude" + "-Session: https://example.com/x", "assistant-session"),
        ("read claude" + ".md first", "assistant-session"),
        ("<system" + "-reminder>context</system-reminder>", "assistant-session"),
        ('"origin' + 'SessionId": "x"', "assistant-session"),
        ("then run codex" + " exec -s read-only", "assistant-session"),
        ("bridge at chat01.office" + ".lan:9991", "internal-host"),
        ("dns nas" + ".internal", "internal-host"),
        ("peer fd12" + ":3456:789a::1", "ipv6-ula"),
        ("token eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc", "jwt"),
        ('password = "Wint' + 'er2026!"', "password"),
        ("身分證 A1234" + "56789", "national-id"),
        ("call 0912" + "-345-678", "phone-number"),
        ("call +886 912" + " 345 678", "phone-number"),
        ("card 4111 1111" + " 1111 1111", "card-number"),
    ],
)
def test_each_rule_finds_what_must_stay_private(tmp_path, text, rule):
    write(tmp_path, "notes.txt", text + "\n")
    assert rule in rules(tmp_path)


@pytest.mark.parametrize(
    "text",
    [
        "server = 'http://192.0.2.10:4096'",
        "deny ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')",
        "a private example 10.0.0.7",
        "listen 127.0.0.1:8080",
        "bot@chat.example.com",
        "fixture ses_000000000001FixtureRootA1",
        "/home/opencode/workspaces/example-project",
        "version 1.2.3",
        "deny fc00::/7 and fd00::/8",
        "copy config.local.toml and a/.env.local.sample",
        'password = "<your password>"',
        'password = "${JTOZ_PASSWORD}"',
        "id A123456780 fails its checksum",
        "card 4111 1111 1111 1112 fails Luhn",
        "timestamp 1700000000000000",
        "OpenCode reads AGENTS" + ".md in the project",
    ],
)
def test_examples_and_whole_blocks_pass(tmp_path, text):
    write(tmp_path, "notes.txt", text + "\n")
    assert rules(tmp_path) == []


def test_private_terms_match_whole_words_and_regexes_and_file_names(tmp_path):
    terms = write(tmp_path / "owner", "terms.txt", "# hosts\nzorblax\nre:\\bacme-[a-z]+\n")
    tree = tmp_path / "tree"
    write(tree, "ops/zorblax.conf", "x\n")
    write(tree, "a.md", "Built for Acme-Retail on ZORBLAX, not zorblax0.\n")
    assert rules(tree, load_terms(terms)) == ["private-term-1", "private-term-1", "private-term-2"]


def test_forbidden_files_links_and_broken_markdown_links(tmp_path):
    write(tmp_path, "state/bridge.db", "x")
    write(tmp_path, "secret.pem", "x")
    (tmp_path / "link").symlink_to(tmp_path / "secret.pem")
    write(tmp_path, "docs/A.md", "[ok](B.md) [gone](private.md) [web](https://example.com)\n")
    write(tmp_path, "docs/B.md", "[back](A.md#top)\n")
    assert rules(tmp_path) == [
        "broken-link",
        "forbidden-file-type",
        "forbidden-file-type",
        "symlink",
    ]


def test_a_reviewed_line_passes_until_it_changes_and_terms_cannot_be_reviewed(tmp_path):
    line = 'FAKE = "-----BEGIN ' + 'PRIVATE KEY-----"'
    write(tmp_path, "tests/test_x.py", line + "\n")
    review = f"tests/test_x.py\tprivate-key\t{line_digest(line)}\tfake key for redaction\n"
    write(tmp_path, "publish/reviewed-findings.txt", review)
    assert rules(tmp_path) == []
    write(tmp_path, "tests/test_x.py", line + "  # changed\n")
    assert rules(tmp_path) == ["private-key"]
    write(tmp_path, "publish/reviewed-findings.txt", "a\tprivate-term-1\tdeadbeef\twhy\n")
    with pytest.raises(ValueError):
        scan(tmp_path, [])
    write(
        tmp_path, "publish/reviewed-findings.txt", f"tests/test_x.py\tprivate-key\t{'0' * 16}\t\n"
    )
    with pytest.raises(ValueError):
        scan(tmp_path, [])


def git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True, text=True
    ).stdout


def private_repo(tmp_path):
    root = tmp_path / "private"
    write(root, "publish/allowlist.txt", "src/**\npublish/allowlist.txt\n")
    write(root, "publish/overlay/.gitignore", "dist/\n")
    write(root, "src/app.py", "print('hi')\n")
    write(root, "private/notes.md", "host zorblax at 192.168" + ".9.9\n")
    write(root, ".gitignore", "private-only\n")
    git(root, "init", "-q", "-b", "main")
    git(root, "-c", "user.name=Owner", "-c", "user.email=o@example.com", "add", "-A")
    git(root, "-c", "user.name=Owner", "-c", "user.email=o@example.com", "commit", "-qm", "x")
    return root


def test_export_copies_only_the_allowlist_and_overlay_from_the_commit(tmp_path):
    root = private_repo(tmp_path)
    write(root, "src/uncommitted.py", "never exported\n")
    out = tmp_path / "public"
    names = build(root, "HEAD", out)
    assert names == [".gitignore", "publish/allowlist.txt", "src/app.py"]
    assert (out / ".gitignore").read_text() == "dist/\n"
    author = "Owner <1+owner" + "@users.noreply.github.com>"
    commit(out, author, "public source")
    assert git(out, "log", "--format=%an <%ae>%n%B").splitlines()[0] == author
    assert git(out, "rev-list", "--count", "HEAD").strip() == "1"
    assert rules(out) == []
    with pytest.raises(FileExistsError):
        build(root, "HEAD", out)


def test_export_refuses_an_allowlist_entry_that_matches_nothing(tmp_path):
    root = private_repo(tmp_path)
    write(root, "publish/allowlist.txt", "src/**\nmissing/*.md\n")
    git(root, "-c", "user.name=O", "-c", "user.email=o@example.com", "commit", "-qam", "y")
    with pytest.raises(ValueError, match="match nothing"):
        build(root, "HEAD", tmp_path / "public")


def test_export_author_is_one_name_and_address_and_only_it_skips_the_history_check(tmp_path):
    assert AUTHOR.fullmatch("Jane Doe <jane@example.com>")
    assert not AUTHOR.fullmatch("Jane Doe jane@example.com")
    assert not AUTHOR.fullmatch("<jane@example.com>")
    assert selected("src/a/b.py", ["src/**"]) and not selected("srcx/a.py", ["src/**"])
    root = private_repo(tmp_path)
    out = tmp_path / "public"
    build(root, "HEAD", out)
    # A domain outside the reserved examples, so the e-mail rule still applies to it.
    author = "Jane Doe <jane" + "@" + "zorblax" + ".com.tw>"
    commit(out, author, "public source for zorblax")
    terms = load_terms(write(tmp_path / "owner", "terms.txt", "zorblax\n"))
    # The chosen author and committer lines pass; the same word in the message does not.
    assert [f.rule for f in scan(out, terms, author)] == ["private-term-1"]
    assert sorted(f.rule for f in scan(out, terms)) == ["email", "email", *["private-term-1"] * 3]


def test_ci_passes_the_published_identity_through_the_environment(tmp_path, monkeypatch, capsys):
    root = private_repo(tmp_path)
    out = tmp_path / "public"
    build(root, "HEAD", out)
    author = "Jane Doe <jane" + "@" + "zorblax" + ".com.tw>"
    commit(out, author, "public source")
    argv = ["public_gate", str(out)]
    monkeypatch.delenv("JTOZ_PUBLIC_IDENTITY", raising=False)
    # Without the identity the author's address in the history is a finding, with a hint.
    monkeypatch.setattr(sys, "argv", argv)
    assert main() == 1
    assert "HINT: pass --identity or set JTOZ_PUBLIC_IDENTITY" in capsys.readouterr().out
    # An empty repository variable is no identity.
    monkeypatch.setenv("JTOZ_PUBLIC_IDENTITY", "")
    assert main() == 1
    monkeypatch.setenv("JTOZ_PUBLIC_IDENTITY", author)
    assert main() == 0
    # Another address is still refused.
    monkeypatch.setenv("JTOZ_PUBLIC_IDENTITY", "Jane Doe <jane@example.org>")
    assert main() == 1
    monkeypatch.delenv("JTOZ_PUBLIC_IDENTITY")
    monkeypatch.setattr(sys, "argv", [*argv, "--identity", author])
    assert main() == 0


def png(*chunks):
    def chunk(kind, data):
        return (
            len(data).to_bytes(4, "big") + kind + data + zlib.crc32(kind + data).to_bytes(4, "big")
        )

    body = chunk(b"IHDR", bytes(13)) + b"".join(chunk(k, d) for k, d in chunks)
    return b"\x89PNG\r\n\x1a\n" + body + chunk(b"IEND", b"")


def test_every_picture_needs_a_person_and_metadata_is_never_accepted(tmp_path):
    (tmp_path / "docs").mkdir()
    clean = tmp_path / "docs/shot.png"
    clean.write_bytes(png())
    found = scan(tmp_path, [])
    assert [f.rule for f in found] == ["image-review"]
    review = f"docs/shot.png\timage-review\t{found[0].digest}\tlooked: a menu with example names\n"
    write(tmp_path, "publish/reviewed-findings.txt", review)
    assert rules(tmp_path) == []
    # Changing the picture voids the review; a screenshot tool's text chunk is refused outright.
    clean.write_bytes(png((b"tEXt", b"Software\x00Shot 1.0")))
    assert rules(tmp_path) == ["image-metadata", "image-review"]
    (tmp_path / "docs/photo.jpg").write_bytes(b"\xff\xd8\xff\xe1\x00\x10Exif\x00\x00MM")
    assert rules(tmp_path).count("image-metadata") == 2
    write(
        tmp_path, "publish/reviewed-findings.txt", "docs/shot.png\timage-metadata\tdeadbeef\twhy\n"
    )
    with pytest.raises(ValueError):
        scan(tmp_path, [])


def test_svg_embedded_pictures_and_editor_metadata_are_refused(tmp_path):
    write(tmp_path, "a.svg", '<svg><image href="data:image/png;base64,AAAA"/></svg>\n')
    write(tmp_path, "b.svg", '<svg sodipodi:docname="desk.svg"><metadata/></svg>\n')
    write(tmp_path, "c.svg", '<svg><rect width="1" height="1"/></svg>\n')
    assert rules(tmp_path) == ["svg-metadata"] * 3


def test_private_paths_data_exports_and_utf16_text_are_caught(tmp_path):
    write(tmp_path, "docs/specifications/v1/README.md", "x\n")
    write(tmp_path, "CLAUDE" + ".md", "x\n")
    write(tmp_path, "." + "codex/config.toml", "x\n")
    write(tmp_path, "AGENTS" + ".md", "x\n")
    write(tmp_path, "customers.csv", "name\n")
    write(tmp_path, "capture.har", "{}\n")
    (tmp_path / "notes.txt").write_bytes(("peer 192.168" + ".5.5\n").encode("utf-16"))
    found = rules(tmp_path)
    assert found.count("private-path") == 4
    assert found.count("forbidden-file-type") == 2
    assert "ip-address" in found
    write(tmp_path, "publish/reviewed-findings.txt", "AGENTS.md\tprivate-path\t0\twhy\n")
    with pytest.raises(ValueError):
        scan(tmp_path, [])


def test_text_copied_from_the_specification_is_refused_but_its_identifiers_are_not(tmp_path):
    spec = tmp_path / "spec"
    write(
        spec,
        "SPEC.md",
        "## 9.4 Lanterns\nThe lighthouse keeper must never relight a lantern whose wick "
        "was trimmed after the storm began.\nSet `lantern_glow_mode = "
        '"amber_with_reviewed_full_glow"` and see https://example.com/a/very/long/path.\n',
    )
    windows = spec_windows(spec)
    tree = tmp_path / "tree"
    copied = "# The lighthouse keeper must never relight a lantern whose wick was trimmed.\n"
    write(tree, "a.py", copied)
    write(tree, "b.toml", 'lantern_glow_mode = "amber_with_reviewed_full_glow"\n')
    write(
        tree,
        "c.md",
        "Lanterns stay dark once their wick is gone (see https://example.com/a/very/long/path).\n",
    )
    assert [f.rule for f in scan(tree, [], spec=windows)] == ["spec-text"]
    write(tree, "publish/reviewed-findings.txt", "a.py\tspec-text\t0\twhy\n")
    with pytest.raises(ValueError):
        scan(tree, [], spec=windows)


def test_a_replace_only_path_goes_out_only_as_its_overlay_copy(tmp_path):
    root = private_repo(tmp_path)
    write(root, "publish/allowlist.txt", "src/**\npublish/allowlist.txt\n=rec/**\n")
    write(root, "rec/live.json", '{"prompt": "real words"}\n')
    git(root, "-c", "user.name=O", "-c", "user.email=o@example.com", "add", "-A")
    git(root, "-c", "user.name=O", "-c", "user.email=o@example.com", "commit", "-qm", "rec")
    with pytest.raises(ValueError, match="no overlay copy"):
        build(root, "HEAD", tmp_path / "public")
    write(root, "publish/overlay/rec/live.json", '{"prompt": "synthetic"}\n')
    git(root, "-c", "user.name=O", "-c", "user.email=o@example.com", "add", "-A")
    git(root, "-c", "user.name=O", "-c", "user.email=o@example.com", "commit", "-qm", "copy")
    out = tmp_path / "public2"
    assert "rec/live.json" in build(root, "HEAD", out)
    assert (out / "rec/live.json").read_text() == '{"prompt": "synthetic"}\n'
    assert selected("rec/live.json", ["=rec/**"])


def test_a_site_page_may_link_only_to_published_files(tmp_path):
    write(tmp_path, "docs/INSTALL.md", "x\n")
    write(tmp_path, "site/style.css", "x\n")
    page = (
        '<a href="https://github.com/someone/jt-oz-bridge/blob/main/docs/INSTALL.md">ok</a>\n'
        '<link href="style.css"><a href="#top">top</a><a href="https://example.com/x">web</a>\n'
        '<a href="https://github.com/someone/jt-oz-bridge/blob/main/docs/PRIVATE.md">gone</a>\n'
        '<img src="assets/missing.svg">\n'
        "<a href=\"{{ url_for('x') }}\">template</a>\n"
    )
    write(tmp_path, "site/index.html", page)
    assert rules(tmp_path) == ["broken-link", "broken-link"]
