"""Refuse a public export that still carries anything private.

Every file of the tree is checked against fixed rules: private and unknown IP
addresses, e-mail addresses, keys and tokens, home directories, real OpenCode
session identifiers, assistant session traces, files that are databases, keys,
archives or links, and Markdown links to files the tree does not have. An owner
keeps a second list of exact words (host names, accounts, customers, projects)
outside the repository and passes it with `--private-terms`; that list is never
published. A git repository in the tree has its commit messages and identities
checked the same way.

It also refuses personal data (Taiwan national IDs, mobile numbers, card numbers),
JWTs and written-out passwords, internal host names and IPv6 ULAs, AI assistant
and Codex traces, private paths such as the original specification, and any run of
text copied from that specification (`--spec-dir`, kept outside the tree). Raster
images carry no metadata, and each needs a review by its own digest, since what a
picture shows cannot be read by a rule.

A line that must keep a match on purpose, such as a fake key a redaction test
feeds in, is listed by path, rule and line digest in `publish/reviewed-findings.txt`
with the reason. Changing the line voids the review. Private terms, specification
text, assistant traces, private paths and image metadata cannot be reviewed away.

  python -m scripts.public_gate <tree> --private-terms <owner-only file> --spec-dir <dir>

Exit 0 only when nothing unreviewed matched. Findings mask the matched text.
"""

import argparse
import hashlib
import ipaddress
import re
import subprocess
import sys
import zipfile
from collections.abc import Iterable, Iterator
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from pathlib import Path

REVIEWED = Path("publish/reviewed-findings.txt")
MAX_BYTES = 2 * 1024 * 1024
FORBIDDEN_SUFFIXES = {
    ".db",
    ".sqlite",
    ".sqlite3",
    ".db-wal",
    ".db-shm",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".crt",
    ".csr",
    ".kdbx",
    ".bundle",
    ".tgz",
    ".gz",
    ".zst",
    ".zip",
    ".tar",
    ".whl",
    ".jsonl",
    ".log",
    ".env",
    # Exports of data: customer lists, captures, dumps, notebooks and office files.
    ".csv",
    ".tsv",
    ".xls",
    ".xlsx",
    ".docx",
    ".pdf",
    ".har",
    ".pcap",
    ".pcapng",
    ".dump",
    ".bak",
    ".sql",
    ".ipynb",
}
FORBIDDEN_NAMES = {".env", "id_rsa", "id_ed25519", "known_hosts", "authorized_keys", ".netrc"}
RASTER_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".bmp",
    ".tif",
    ".tiff",
    ".avif",
    ".heic",
}
# Paths that are private by what they are: the original specification and the files and
# directories AI assistants keep their instructions and sessions in.
PRIVATE_PATH = re.compile(
    r"(?:^|/)(?:docs/specifications|\.claude|\.codex|\.cursor|\.aider[^/]*)(?:/|$)"
    r"|(?:^|/)(?:CLAUDE|AGENTS|GEMINI)\." + "md$",
    re.IGNORECASE,
)
# A finding of these rules is never accepted by a review.
UNREVIEWABLE = ("private-term", "spec-text", "assistant-session", "private-path", "image-metadata")

IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?(?![\w.]*\d)")
# Address blocks that documentation and tests may name: the RFC 5737 examples,
# loopback, unspecified, and one private block for examples where privacy is the point.
EXAMPLES = [
    ipaddress.ip_network(net)
    for net in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "127.0.0.0/8",
        "0.0.0.0/32",
        "10.0.0.0/24",
        # A well-known global address and a multicast one, for code that tells them apart.
        "8.8.8.8/32",
        "224.0.0.1/32",
    )
]
# Whole private blocks, as code that refuses them names them.
WHOLE_BLOCKS = {
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "169.254.169.254/32",
    "169.254.169.254",
    "0.0.0.0/0",
    "127.0.0.1/32",
    "255.255.255.255",
}
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})")
EMAIL_DOMAINS = re.compile(r"(?:^|\.)(?:example\.(?:com|org|net)|example|invalid|test|localhost)$")
SECRETS = {
    "private-key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "github-token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})"),
    "aws-key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "slack-token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "api-key": re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{24,}"),
    "bearer": re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{24,}"),
    "url-credentials": re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]{6,}@"),
}
HOME = re.compile(
    r"(?<![\w.-])(?:/Users/[A-Za-z0-9._-]+|/root/[A-Za-z0-9._-]|/home/([A-Za-z0-9._-]+))"
)
HOME_USERS = {"opencode", "user", "example", "jtoz", "bridge"}
# Host names on internal-only domains; `config.local.toml` is a file name, not a host.
INTERNAL_HOST = re.compile(
    r"(?<![\w.-])[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:lan|local|internal|intranet|corp|localdomain|home\.arpa)"
    r"(?![\w.-])",
    re.IGNORECASE,
)
# A ULA host address; the blocks themselves (fc00::/7, fd00::/8) are what refusing code names.
IPV6_ULA = re.compile(r"(?<![\w:])f[cd][0-9a-f]{2}:(?!:/)[0-9a-f]{0,4}:[0-9a-f:]*", re.IGNORECASE)
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.")
PASSWORD = re.compile(
    r"\b(?:password|passwd|pwd|passphrase)\b\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]", re.IGNORECASE
)
PASSWORD_EXAMPLES = re.compile(
    r"^(?:x+|\*+|<[^>]*>|\$\{?\w+\}?|changeme|example\w*|secret|password)$", re.I
)
TW_ID = re.compile(r"(?<![A-Za-z0-9])([A-Z][12][0-9]{8})(?![A-Za-z0-9])")
MOBILE = re.compile(r"(?<![\d+])(?:\+886[-\s]?9|09)[0-9]{2}[-\s]?[0-9]{3}[-\s]?[0-9]{3}(?!\d)")
CARD = re.compile(r"(?<![\d-])([3-6][0-9]{3}(?:[ -]?[0-9]{4}){3})(?![\d-])")
# An OpenCode session id as the server issues it: `ses_`, 12 hex digits, 14 letters/digits.
# Test fixtures use made-up ids that start with six zeros.
SESSION = re.compile(r"\bses_(?!000000)[0-9a-f]{12}[A-Za-z0-9]{14}\b")
# Written in pieces so that this file does not match its own rule.
ASSISTANT = re.compile(
    "|".join(
        (
            "Claude" + "-Session",
            r"claude\.ai/(?:code|chat|share)",
            r"\bsession_01[A-Za-z0-9]{16,}",
            r"(?<![\w-])\." + "claude/",
            r"(?<![\w/-])claude\." + "md\\b",
            r"Co-Authored-By:\s*Claude",
            "<system" + "-reminder>",
            r"\bantml" + ":",
            "origin" + "SessionId",
            r"(?<![\w-])\." + "codex/",
            r"\bcodex" + r"\s+(?:exec|review)\b",
            r"Generated with \[Claude",
        )
    ),
    re.IGNORECASE,
)
SVG_METADATA = re.compile(
    r"data:image/|sodipodi:docname|inkscape:export-filename|<metadata\b", re.I
)
SPEC_WINDOW = 48
LINK = re.compile(r"\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
# A page's link into this repository's own files on GitHub, or a relative one.
HREF = re.compile(r"""(?:href|src)=["']([^"'#?]+)""")
REPO_FILE = re.compile(r"^https://github\.com/[\w.-]+/jt-oz-bridge/(?:blob|tree)/main/(.+)$")


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    text: str
    digest: str = ""  # Of the whole line, so a reviewed line stops matching once it changes.

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.rule}: {mask(self.text)} [{self.digest}]"

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.path, self.rule, self.digest)


def mask(text: str) -> str:
    """Enough to find the match again, not enough to republish it."""
    return text if len(text) <= 4 else text[:2] + "…" + text[-1]


def load_terms(path: Path | None) -> list[re.Pattern[str]]:
    if path is None:
        return []
    terms = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        term = raw.strip()
        if not term or term.startswith("#"):
            continue
        if term.startswith("re:"):
            terms.append(re.compile(term[3:], re.IGNORECASE))
        else:
            terms.append(re.compile(r"(?<![\w])" + re.escape(term) + r"(?![\w])", re.IGNORECASE))
    return terms


def tw_id_valid(value: str) -> bool:
    """The checksum a real national ID carries, so a random test token rarely matches."""
    letters = "ABCDEFGHJKLMNPQRSTUVXYWZIO"
    code = letters.index(value[0]) + 10
    digits = [code // 10, code % 10, *map(int, value[1:])]
    weights = [1, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1]
    return sum(d * w for d, w in zip(digits, weights, strict=True)) % 10 == 0


def luhn(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()][::-1]
    total = sum(d if i % 2 == 0 else (d * 2 - 9 if d > 4 else d * 2) for i, d in enumerate(digits))
    return total % 10 == 0


def normalize(text: str) -> str:
    """Prose only: URLs, code spans and punctuation are shared with any OpenCode/Zulip text."""
    text = re.sub(r"[a-z][a-z0-9+.-]*://\S+|`[^`\n]*`", " ", text, flags=re.IGNORECASE)
    # Identifiers such as `long_output_mode` are the code's own names, not copied prose.
    text = re.sub(r"[\w.:-]*_[\w.:-]*|\{\w*\}", " ", text)
    text = re.sub(r"[^\w\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip().casefold()


def spec_windows(spec_dir: Path | None) -> set[int]:
    """Every run of SPEC_WINDOW characters of the original specification, hashed."""
    if spec_dir is None:
        return set()
    windows: set[int] = set()
    for path in sorted(spec_dir.rglob("*")):
        if not path.is_file():
            continue
        texts = []
        if path.suffix.lower() == ".zip":
            with zipfile.ZipFile(path) as archive:
                texts = [archive.read(n).decode("utf-8", "ignore") for n in archive.namelist()]
        else:
            texts = [path.read_bytes().decode("utf-8", "ignore")]
        for text in texts:
            flat = normalize(text)
            windows.update(
                hash(flat[i : i + SPEC_WINDOW]) for i in range(len(flat) - SPEC_WINDOW + 1)
            )
    return windows


def load_reviewed(path: Path) -> set[tuple[str, str, str]]:
    """`path<TAB>rule<TAB>digest<TAB>reason` lines; a review without a reason is no review."""
    if not path.is_file():
        return set()
    reviewed = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.startswith("#"):
            continue
        fields = raw.split("\t")
        if len(fields) != 4 or not fields[3].strip() or fields[1].startswith(UNREVIEWABLE):
            raise ValueError(f"invalid review line: {raw[:80]}")
        reviewed.add((fields[0], fields[1], fields[2]))
    return reviewed


def address_allowed(address: str, prefix: str | None) -> bool:
    written = address + (f"/{prefix}" if prefix else "")
    if written in WHOLE_BLOCKS:
        return True
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True  # A version number such as 1.2.3.400 is not an address.
    return any(ip in net for net in EXAMPLES)


def line_digest(line: str) -> str:
    return hashlib.sha256(line.encode()).hexdigest()[:16]


def spec_match(line: str, spec: AbstractSet[int]) -> str | None:
    flat = normalize(line)
    for i in range(len(flat) - SPEC_WINDOW + 1):
        if hash(flat[i : i + SPEC_WINDOW]) in spec:
            return flat[i : i + SPEC_WINDOW]
    return None


def line_matches(
    line: str,
    terms: list[re.Pattern[str]],
    spec: AbstractSet[int] = frozenset(),
) -> Iterator[tuple[str, str]]:
    for match in IPV4.finditer(line):
        if not address_allowed(match[1], match[2]):
            yield "ip-address", match[0]
    for match in EMAIL.finditer(line):
        if not EMAIL_DOMAINS.search(match[1].lower()):
            yield "email", match[0]
    for rule, pattern in SECRETS.items():
        for match in pattern.finditer(line):
            yield rule, match[0]
    for match in HOME.finditer(line):
        if match[1] is None or match[1] not in HOME_USERS:
            yield "home-directory", match[0]
    for match in SESSION.finditer(line):
        yield "opencode-session-id", match[0]
    for match in ASSISTANT.finditer(line):
        yield "assistant-session", match[0]
    for match in INTERNAL_HOST.finditer(line):
        yield "internal-host", match[0]
    for match in IPV6_ULA.finditer(line):
        yield "ipv6-ula", match[0]
    for match in JWT.finditer(line):
        yield "jwt", match[0]
    for match in PASSWORD.finditer(line):
        if not PASSWORD_EXAMPLES.match(match[1]):
            yield "password", match[0]
    for match in TW_ID.finditer(line):
        if tw_id_valid(match[1]):
            yield "national-id", match[0]
    for match in MOBILE.finditer(line):
        yield "phone-number", match[0]
    for match in CARD.finditer(line):
        if luhn(match[1]):
            yield "card-number", match[0]
    if spec and (copied := spec_match(line, spec)) is not None:
        yield "spec-text", copied
    for index, term in enumerate(terms, 1):
        for match in term.finditer(line):
            yield f"private-term-{index}", match[0]


def scan_text(
    path: str,
    text: str,
    terms: list[re.Pattern[str]],
    spec: AbstractSet[int] = frozenset(),
) -> Iterator[Finding]:
    for number, line in enumerate(text.splitlines(), 1):
        for rule, matched in line_matches(line, terms, spec):
            yield Finding(path, number, rule, matched, line_digest(line))


def png_metadata(data: bytes) -> bool:
    """Text, EXIF or time chunks: what a screenshot tool or camera writes about itself."""
    position = 8
    while position + 8 <= len(data):
        length = int.from_bytes(data[position : position + 4], "big")
        kind = data[position + 4 : position + 8]
        if kind in {b"tEXt", b"iTXt", b"zTXt", b"eXIf", b"tIME"}:
            return True
        position += 12 + length
    return False


def image_metadata(path: Path, data: bytes) -> bool:
    suffix = path.suffix.lower()
    if suffix == ".png":
        return not data.startswith(b"\x89PNG\r\n\x1a\n") or png_metadata(data)
    # EXIF, XMP and IPTC carry camera, place, software and author.
    return any(
        marker in data for marker in (b"Exif\x00", b"http://ns.adobe.com/xap", b"Photoshop 3.0")
    )


def scan_image(name: str, path: Path) -> Iterator[Finding]:
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()[:16]
    if image_metadata(path, data):
        yield Finding(name, 0, "image-metadata", path.name, digest)
    # A rule cannot see a host name or a face in a picture: a person must have looked.
    yield Finding(name, 0, "image-review", path.name, digest)


def broken_links(root: Path, path: Path, text: str) -> Iterator[Finding]:
    """A relative Markdown link must land on a file this tree publishes."""
    name = path.relative_to(root).as_posix()
    for number, line in enumerate(text.splitlines(), 1):
        for match in LINK.finditer(line):
            link = match[1]
            if "://" in link or link.startswith(("#", "mailto:")):
                continue
            target = (path.parent / link.partition("#")[0]).resolve()
            if not target.is_relative_to(root) or not target.exists():
                yield Finding(name, number, "broken-link", link, line_digest(line))


def broken_page_links(root: Path, path: Path, text: str) -> Iterator[Finding]:
    """A site page's link to a repository file or a relative file must be published."""
    name = path.relative_to(root).as_posix()
    for number, line in enumerate(text.splitlines(), 1):
        for match in HREF.finditer(line):
            link = match[1]
            if repo := REPO_FILE.match(link):
                target = (root / repo[1]).resolve()
            elif "://" in link or link.startswith(("mailto:", "data:", "/")) or "{" in link:
                continue
            else:
                target = (path.parent / link).resolve()
            if not target.is_relative_to(root) or not target.exists():
                yield Finding(name, number, "broken-link", link, line_digest(line))


def scan_file(
    root: Path,
    path: Path,
    terms: list[re.Pattern[str]],
    spec: AbstractSet[int] = frozenset(),
) -> Iterator[Finding]:
    name = path.relative_to(root).as_posix()
    yield from scan_text(name, name, terms)  # File names leak hosts too.
    if PRIVATE_PATH.search(name):
        yield Finding(name, 0, "private-path", name)
        return
    if path.is_symlink():
        yield Finding(name, 0, "symlink", name)
        return
    lowered = path.name.lower()
    suffixes = {suffix.lower() for suffix in path.suffixes}
    if lowered in FORBIDDEN_NAMES or suffixes & FORBIDDEN_SUFFIXES or lowered.startswith(".env"):
        yield Finding(name, 0, "forbidden-file-type", path.name)
        return
    size = path.stat().st_size
    if size > MAX_BYTES:
        yield Finding(name, 0, "file-too-large", str(size))
        return
    if path.suffix.lower() in RASTER_SUFFIXES:
        yield from scan_image(name, path)
        return
    data = path.read_bytes()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        if not data.startswith((b"\xff\xfe", b"\xfe\xff")):
            digest = hashlib.sha256(data).hexdigest()[:16]
            yield Finding(name, 0, "binary-file", path.name, digest)
            return
        text = data.decode("utf-16", "replace")  # Text hidden from a UTF-8 reader.
    yield from scan_text(name, text, terms, spec)
    if path.suffix.lower() == ".svg":
        for number, line in enumerate(text.splitlines(), 1):
            for match in SVG_METADATA.finditer(line):
                yield Finding(name, number, "svg-metadata", match[0], line_digest(line))
    if path.suffix.lower() == ".md":
        yield from broken_links(root, path, text)
    if path.suffix.lower() in {".html", ".htm"}:
        yield from broken_page_links(root, path, text)


def tree_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if ".git" in path.relative_to(root).parts:
            continue
        if path.is_file() or path.is_symlink():
            yield path


def git_history(root: Path) -> str | None:
    if not (root / ".git").exists():
        return None
    return subprocess.run(
        ["git", "-C", str(root), "log", "--all", "--format=%an <%ae>%n%cn <%ce>%n%B"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def scan(
    root: Path,
    terms: list[re.Pattern[str]],
    identity: str | None = None,
    spec: AbstractSet[int] = frozenset(),
) -> list[Finding]:
    """`identity` is the one `Name <e-mail>` the owner chose to publish as commit author."""
    reviewed = load_reviewed(root / REVIEWED)
    findings = [
        finding
        for path in tree_files(root)
        for finding in scan_file(root, path, terms, spec)
        if finding.key not in reviewed
    ]
    history = git_history(root)
    if history is not None:
        if identity is not None:
            history = "\n".join(line for line in history.splitlines() if line != identity)
        noreply = re.compile(r"@users\.noreply\.github\.com$")
        for finding in scan_text(".git (commits)", history, terms):
            if finding.rule == "email" and noreply.search(finding.text):
                continue
            findings.append(finding)
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tree", type=Path)
    parser.add_argument("--private-terms", type=Path)
    parser.add_argument("--spec-dir", type=Path, help="original specification, kept outside")
    args = parser.parse_args()
    terms = load_terms(args.private_terms)
    if args.private_terms is None:
        print("WARNING: no --private-terms; host, account and customer names are not checked")
    if args.spec_dir is None:
        print("WARNING: no --spec-dir; text copied from the specification is not checked")
    root = args.tree.resolve(strict=True)
    findings = scan(root, terms, spec=spec_windows(args.spec_dir))
    for finding in findings:
        print(finding)
    if findings:
        print(f"FAIL: {len(findings)} findings; nothing may be published")
        return 1
    print(f"PASS: {sum(1 for _ in tree_files(root))} files, no private content found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
