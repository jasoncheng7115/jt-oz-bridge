"""Conservative Markdown serialization and bounded, balanced mobile pages."""

import html
import re
import string
from dataclasses import dataclass
from urllib.parse import quote, unquote, urlsplit

from markdown_it import MarkdownIt
from markdown_it.tree import SyntaxTreeNode

from jt_oz_bridge.config import Locale
from jt_oz_bridge.i18n import Translator

ANSI = re.compile(
    r"\x1b\](?:[^\x07\x1b]|\x1b(?!\\))*(?:\x07|\x1b\\|$)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-_]"
)
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")
PUNCTUATION = frozenset(string.punctuation)


def sanitize_controls(source: str) -> tuple[str, int]:
    source, first = ANSI.subn("", source)
    source, second = CONTROL.subn("", source)
    count = first + second + source.count("\r")
    return source.replace("\r\n", "\n").replace("\r", "␍"), count


def literal(source: str) -> str:
    # Zulip deliberately disables Python-Markdown's backslash escape pattern.
    # CommonMark's \\. / \\- serialization therefore exposes the backslashes in
    # real Zulip messages. Entities survive both renderers as visible text and
    # keep mentions, emoji, links and other Zulip-only syntax inert. Encode the
    # original characters, not an already generated entity's punctuation.
    return "".join(
        html.escape(char, quote=False)
        if char in "&<>"
        else f"&#{ord(char)};"
        if char in PUNCTUATION
        else char
        for char in source
    )


def safe_url(source: str) -> str | None:
    decoded = unquote(html.unescape(source)).strip()
    if (
        len(decoded) > 8192
        or "\\" in decoded
        or any(ord(char) <= 32 or ord(char) == 127 for char in decoded)
    ):
        return None
    try:
        parsed = urlsplit(decoded)
        if parsed.scheme.lower() in {"https", "http"}:
            if not parsed.hostname or parsed.username is not None or parsed.password is not None:
                return None
        elif parsed.scheme.lower() == "mailto":
            if not parsed.path or "@" not in parsed.path or parsed.query or parsed.fragment:
                return None
        else:
            return None
    except ValueError:
        return None
    return quote(decoded, safe="/:#?&=@%+,-._~!$;")


def code_span(source: str) -> str:
    longest = max((len(match.group()) for match in re.finditer(r"`+", source)), default=0)
    fence = "`" * (longest + 1)
    pad = (
        " "
        if source.strip() and (source.startswith(("`", " ")) or source.endswith(("`", " ")))
        else ""
    )
    return fence + pad + source + pad + fence


def _fenced_block(source: str, info: str) -> str:
    longest = {
        char: max((len(m.group()) for m in re.finditer(re.escape(char) + "+", source)), default=0)
        for char in ("`", "~")
    }
    char = min(longest, key=lambda key: longest[key])
    fence = char * max(3, longest[char] + 1)
    return fence + info + "\n" + source + ("" if source.endswith("\n") else "\n") + fence


def code_block(source: str, language: str = "") -> str:
    language = language.split()[0] if language.split() else ""
    # These Zulip fence types render their body as Markdown, not literal code.
    # Code callers and oversized fallbacks must never activate their contents.
    if language.lower() in {"spoiler", "quote"}:
        language = "text"
    if not re.fullmatch(r"[A-Za-z0-9_+.-]{0,40}", language):
        language = ""
    return _fenced_block(source, language)


def spoiler_block(source: str, title: str) -> str:
    """Wrap Markdown for subsequent MobileMarkdown sanitization, not raw delivery."""
    clean, _ = sanitize_controls(title)
    heading = literal(" ".join(html.unescape(clean).split()))
    return _fenced_block(source, "spoiler" + (" " + heading if heading else ""))


@dataclass(frozen=True)
class RenderedOutput:
    pages: tuple[str, ...]
    original_characters: int
    control_normalizations: int
    neutralized_mentions: int
    source_fallback_blocks: int


class MobileMarkdown:
    def __init__(self, *, locale: Locale = "en") -> None:
        self.parser = MarkdownIt("commonmark", {"html": False}).enable("table")
        self.preview_parser = (
            MarkdownIt("commonmark", {"html": False}).enable("table").disable("image")
        )
        self.locale, self.translator = locale, Translator()
        self._mentions = 0

    def inline_children(self, node: SyntaxTreeNode, *, table: bool = False) -> str:
        parts = []
        children = node.children or []
        for index, child in enumerate(children):
            value = self.inline(child, table=table)
            if (
                child.type == "text"
                and child.content.endswith("@")
                and index + 1 < len(children)
                and children[index + 1].type in {"em", "strong"}
            ):
                value += "\u200b"
                self._mentions += 1
            parts.append(value)
        return "".join(parts)

    def inline(self, node: SyntaxTreeNode, *, table: bool = False) -> str:
        if node.type in {"text", "html_inline"}:
            return literal(node.content)
        if node.type == "code_inline":
            result = code_span(node.content)
            return result.replace("|", r"\|") if table else result
        if node.type == "softbreak":
            return "\n"
        if node.type == "hardbreak":
            return "  \n"
        content = self.inline_children(node, table=table)
        if node.type in {"inline", "link", "image"}:
            if node.type == "inline":
                return content
            address = safe_url(str(node.attrs.get("href" if node.type == "link" else "src", "")))
            if node.type == "image":
                content = content or self.translator.render("output.image", self.locale)
            return f"[{content}]({address})" if address else content
        if node.type in {"em", "strong", "s"}:
            delimiter = {"em": "*", "strong": "**", "s": "~~"}[node.type]
            return delimiter + content + delimiter
        raise ValueError("unsupported_inline_markdown")

    def block(self, node: SyntaxTreeNode, *, container_depth: int = 0) -> str:
        if node.type in {"fence", "code_block"}:
            info = (node.token.info if node.token else "").strip()
            pieces = info.split(maxsplit=1)
            if node.type == "fence" and pieces and pieces[0] in {"spoiler", "quote"}:
                if container_depth >= 8:
                    raise ValueError("markdown_container_nesting_limit")
                title = pieces[1] if len(pieces) == 2 else ""
                if len(html.unescape(title)) > 256:
                    raise ValueError("markdown_container_heading_too_large")
                root = SyntaxTreeNode(self.parser.parse(node.content))
                body = "\n\n".join(
                    self.block(child, container_depth=container_depth + 1)
                    for child in root.children or []
                )
                if pieces[0] == "quote":
                    return "\n".join("> " + line for line in body.split("\n"))
                return spoiler_block(body, title)
            return code_block(node.content, info)
        if node.type in {"paragraph", "heading"}:
            content = "".join(self.inline(child) for child in node.children or [])
            return ("#" * int(node.tag[1:]) + " " if node.type == "heading" else "") + content
        if node.type == "hr":
            return "---"
        if node.type == "html_block":
            return literal(node.content)
        if node.type == "blockquote":
            content = "\n\n".join(
                self.block(child, container_depth=container_depth) for child in node.children or []
            )
            return "\n".join("> " + line for line in content.split("\n"))
        if node.type in {"bullet_list", "ordered_list"}:
            rows = []
            start = int(node.attrs.get("start", 1))
            for number, child in enumerate(node.children or [], start):
                prefix = "- " if node.type == "bullet_list" else f"{number}. "
                content = "\n\n".join(
                    self.block(part, container_depth=container_depth)
                    for part in child.children or []
                )
                lines = content.split("\n")
                rows.append(
                    prefix
                    + lines[0]
                    + "".join("\n" + " " * len(prefix) + line for line in lines[1:])
                )
            return "\n".join(rows)
        if node.type == "table":
            rows = []
            for section in node.children or []:
                for row in section.children or []:
                    cells = [
                        "".join(
                            self.inline(child, table=True) for child in cell.children or []
                        ).replace("\n", " ")
                        for cell in row.children or []
                    ]
                    rows.append("| " + " | ".join(cells) + " |")
                    if section.type == "thead":
                        rows.append("| " + " | ".join("---" for _ in cells) + " |")
            return "\n".join(rows)
        raise ValueError("unsupported_block_markdown")

    @staticmethod
    def code_pages(source: str, limit: int, language: str = "") -> list[str]:
        if not source:
            return [code_block("", language)]
        pages = []
        offset = 0
        while offset < len(source):
            size = min(len(source) - offset, limit - 64)
            while True:
                candidate = source[offset : offset + size]
                boundary = candidate.rfind("\n") + 1
                if boundary >= size // 2 and boundary > 0:
                    candidate = candidate[:boundary]
                page = code_block(candidate, language)
                if len(page) <= limit:
                    break
                size //= 2
                if size == 0:
                    raise ValueError("message_limit_too_small")
            pages.append(page)
            offset += len(candidate)
        return pages

    def render(
        self, source: str, message_limit: int, *, reserved_characters: int = 0
    ) -> RenderedOutput:
        if (
            not isinstance(message_limit, int)
            or isinstance(message_limit, bool)
            or not isinstance(reserved_characters, int)
            or isinstance(reserved_characters, bool)
            or reserved_characters < 0
        ):
            raise ValueError("invalid_reported_message_limit")
        if len(source) > 1000000:
            raise ValueError("output_source_too_large")
        limit = message_limit - reserved_characters
        if limit < 128:
            raise ValueError("reported_message_limit_too_small")
        self._mentions = 0
        cleaned, controls = sanitize_controls(source)
        lines = cleaned.splitlines(keepends=True)
        root = SyntaxTreeNode(self.parser.parse(cleaned))
        pages: list[str] = []
        fallbacks = 0
        for node in root.children or []:
            try:
                rendered = self.block(node)
            except (ValueError, TypeError, RecursionError):
                rendered = ""
            if not rendered or len(rendered) > limit:
                info = (node.token.info if node.token else "").split()
                container = node.type == "fence" and info and info[0] in {"spoiler", "quote"}
                if node.type in {"fence", "code_block"} and not container:
                    blocks = self.code_pages(
                        node.content, limit, node.token.info if node.token else ""
                    )
                else:
                    start, end = node.map or (0, len(lines))
                    blocks = self.code_pages("".join(lines[start:end]), limit, "text")
                    fallbacks += 1
            else:
                blocks = [rendered]
            for block in blocks:
                if pages and len(pages[-1]) + 2 + len(block) <= limit:
                    pages[-1] += "\n\n" + block
                else:
                    pages.append(block)
        return RenderedOutput(tuple(pages), len(source), controls, self._mentions, fallbacks)

    def preview_html(self, page: str) -> str:
        # pages already contain serialized safe links, no active HTML or images.
        rendered = self.preview_parser.render(page)
        if not isinstance(rendered, str):
            raise ValueError("invalid_preview_renderer_result")
        return rendered
