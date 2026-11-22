import json
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest
from markdown_it import MarkdownIt

from jt_oz_bridge.presentation.markdown import (
    MobileMarkdown,
    code_block,
    code_span,
    literal,
    safe_url,
)

ZULIP_RENDERING = json.loads(
    (Path(__file__).parents[1] / "fixtures/zulip/rendering-12.3-entities.json").read_text()
)


class Elements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.links, self.text = [], [], []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.links.extend(value for name, value in attrs if name == "href")

    def handle_data(self, data):
        self.text.append(data)


@pytest.mark.parametrize("case", ZULIP_RENDERING["cases"], ids=lambda case: case["name"])
def test_literal_matches_installed_zulip_rendering_without_extra_backslashes(case):
    # The expected HTML follows Zulip 12.3's /messages/render output, not
    # CommonMark's preview. The samples are synthetic text.
    assert ZULIP_RENDERING["synthetic_rendering_samples"]
    assert ZULIP_RENDERING["message_posts"] == 0
    assert literal(case["source"]) == case["wire"]
    rendered = Elements()
    rendered.feed(case["rendered_html"])
    assert set(rendered.tags) <= {"p", "br"}
    assert not rendered.links

    def normalized(text):
        return re.sub(r"\s+", " ", text).strip()

    assert normalized(" ".join(rendered.text)) == normalized(case["source"])


@pytest.mark.parametrize(
    "source",
    [
        "example-provider/example-model-1.2-mini-q4_k [none]",
        r"C:\path\file.py \- \.",
        "@**all** <script> & &#42; :smile:",
    ],
)
def test_literal_remains_literal_after_metadata_and_output_serialization(source):
    renderer = MobileMarkdown()
    first = renderer.render(literal(source), 2000).pages
    second = renderer.render(first[0], 2000).pages
    assert first == second == (literal(source),)
    rendered = Elements()
    rendered.feed(renderer.preview_html(second[0]))
    assert "".join(rendered.text).strip() == source
    assert not rendered.links and set(rendered.tags) == {"p"}


def test_common_blocks_inline_code_language_lists_tables_and_links_survive():
    source = '# Original title\n\nA **bold** and *emphasized* paragraph with `x < y` and [safe](https://example.com/a?q=1).\n\n- first\n- second\n  - nested\n\n> quoted text\n\n| Name | Value |\n| --- | --- |\n| key | `x\\|y` |\n\n```python\nprint("literal <b>")\n```\n'
    renderer = MobileMarkdown()
    result = renderer.render(source, 10000)
    assert len(result.pages) == 1 and result.source_fallback_blocks == 0
    parser = Elements()
    parser.feed(renderer.preview_html(result.pages[0]))
    assert {"h1", "strong", "em", "code", "ul", "li", "blockquote", "table", "pre", "a"} <= set(
        parser.tags
    )
    assert 'print("literal <b>")\n' in parser.text
    assert parser.links == ["https://example.com/a?q=1"]
    assert "x|y" in parser.text


def test_hostile_html_links_images_mentions_and_terminal_controls_stay_inert():
    renderer = MobileMarkdown()
    source = "<script>alert(1)</script>\n\n<img src=x onerror=alert(2)>\n\n[x](javascript:alert(3)) [y](data:text/html,bad) ![remote](https://images.example/pixel)\n\n@**all** @*operators* literal@email.example\n\n\x1b[31mred\x1b[0m\x1b]8;;https://evil.example\x07click\x1b]8;;\x07\x00\u202ehidden\rrewrite"
    result = renderer.render(source, 10000)
    assert result.control_normalizations >= 5 and result.neutralized_mentions == 2
    assert "@**all**" not in result.pages[0]
    assert (
        "\x1b" not in result.pages[0] and "\u202e" not in result.pages[0] and "␍" in result.pages[0]
    )
    parser = Elements()
    parser.feed(renderer.preview_html(result.pages[0]))
    assert not {"script", "img", "iframe", "style"} & set(parser.tags)
    assert all(link.startswith("https://") for link in parser.links)
    assert parser.links == ["https://images.example/pixel"]
    assert "literal@email.example" in "".join(parser.text)
    # Even a caller that skips normal serialization cannot embed a preview image.
    assert "<img" not in renderer.preview_html("![x](http://127.0.0.1/private)")


@pytest.mark.parametrize("source", ["`tick`", " leading", "trailing ", "  ", "a``b", "<b>"])
def test_inline_code_round_trip_is_literal(source):
    parser = MarkdownIt("commonmark")
    token = parser.parseInline(code_span(source))[0].children[0]
    assert token.type == "code_inline" and token.content == source


@pytest.mark.parametrize("source", ['print("x")\n', "```\n~~~\n````\n~~~~", "`" * 200 + "~" * 200])
def test_fences_cannot_be_closed_by_untrusted_content(source):
    tokens = MarkdownIt("commonmark").parse(code_block(source, "python"))
    assert len(tokens) == 1 and tokens[0].type == "fence"
    assert tokens[0].content == source + ("" if source.endswith("\n") else "\n")


def test_large_code_and_nested_blocks_split_with_balanced_fences_and_reserved_footer():
    renderer = MobileMarkdown()
    source = "```diff\n" + "+changed line\n" * 150 + "```\n\n" + "A **long** paragraph " * 100
    result = renderer.render(source, 280, reserved_characters=45)
    assert len(result.pages) > 5 and result.source_fallback_blocks == 1
    for page in result.pages:
        assert len(page) <= 235
        tokens = MarkdownIt("commonmark").parse(page)
        for token in tokens:
            if token.type == "fence":
                assert token.info in {"diff", "text"}
                assert token.map[-1] <= len(page.splitlines())
    # Every data line is still present; no token-delta truncation or silent dropping.
    assert sum(page.count("+changed line") for page in result.pages) == 150


@pytest.mark.parametrize(
    "uri",
    [
        "javascript:alert(1)",
        "jav&#x61;script:alert(1)",
        "data:text/html,bad",
        "file:///etc/passwd",
        "https://user:secret@example.com/",
        "https://example.com/\nheader",
        "//example.com/path",
        "https://bad\\host/path",
    ],
)
def test_unsafe_link_schemes_credentials_and_controls_have_no_active_target(uri):
    assert safe_url(uri) is None


def test_localized_image_label_and_size_errors_are_explicit():
    result = MobileMarkdown(locale="zh-TW").render("![](https://example.com/image)", 1000)
    assert "圖片" in result.pages[0]
    with pytest.raises(ValueError, match="too_small"):
        MobileMarkdown().render("text", 100)
    with pytest.raises(ValueError, match="invalid"):
        MobileMarkdown().render("text", 1000, reserved_characters=-1)


@pytest.mark.parametrize("heading", ["Advanced", "進階指令", "@**all** <img src=x> :smile:"])
def test_named_spoilers_keep_literal_heading_and_sanitize_markdown_body(heading):
    source = "```spoiler " + heading + "\n**Details**\n\n@**all** [bad](javascript:alert(1))\n```"
    renderer = MobileMarkdown()
    result = renderer.render(source, 4000)
    assert len(result.pages) == 1 and result.source_fallback_blocks == 0
    page = result.pages[0]
    token = MarkdownIt("commonmark").parse(page)[0]
    assert token.type == "fence" and token.info.startswith("spoiler ")
    import html

    assert html.unescape(token.info.split(" ", 1)[1]) == heading
    assert "**Details**" in token.content
    assert "@**all**" not in page and "javascript:" not in page
    assert renderer.render(page, 4000).pages == result.pages


@pytest.mark.parametrize("kind", ["spoiler", "quote"])
def test_markdown_container_bodies_do_not_bypass_link_image_or_mention_safety(kind):
    renderer = MobileMarkdown()
    source = (
        "```"
        + kind
        + "\n@**all** ![pixel](https://example.com/pixel)\n\n<script>alert(1)</script>\n```"
    )
    page = renderer.render(source, 4000).pages[0]
    assert "@**all**" not in page and "<script>" not in page
    body = MarkdownIt("commonmark").parse(page)[0].content if kind == "spoiler" else page
    parsed = Elements()
    parsed.feed(renderer.preview_html(body))
    assert not {"img", "script", "iframe"} & set(parsed.tags)
    assert parsed.links == ["https://example.com/pixel"]


@pytest.mark.parametrize("language", ["spoiler", "quote", "SPOILER", "quote ignored-title"])
def test_literal_code_callers_cannot_activate_zulip_markdown_containers(language):
    source = "@**all** <img src=x> [bad](javascript:alert(1))"
    page = code_block(source, language)
    tokens = MarkdownIt("commonmark").parse(page)
    assert len(tokens) == 1 and tokens[0].info == "text"
    assert tokens[0].content.rstrip("\n") == source


@pytest.mark.parametrize("kind", ["spoiler", "quote"])
def test_oversized_markdown_containers_fall_back_to_balanced_literal_source(kind):
    source = "```" + kind + " Important heading\n" + "@**all** line\n" * 100 + "```"
    result = MobileMarkdown().render(source, 260, reserved_characters=40)
    assert len(result.pages) > 1 and result.source_fallback_blocks == 1
    recovered = []
    for page in result.pages:
        assert len(page) <= 220
        tokens = MarkdownIt("commonmark").parse(page)
        assert tokens and all(t.type == "fence" and t.info == "text" for t in tokens)
        recovered.extend(t.content for t in tokens)
    assert "Important heading" in "".join(recovered)
    assert sum(part.count("@**all** line") for part in recovered) == 100


def test_nested_spoilers_are_bounded_and_deep_raw_content_remains_inert():
    from jt_oz_bridge.presentation.markdown import spoiler_block

    source = "@**all** [bad](javascript:alert(1))"
    for index in range(10):
        source = spoiler_block(source, "Details " + str(index))
    result = MobileMarkdown().render(source, 10000)
    assert result.source_fallback_blocks == 1
    tokens = MarkdownIt("commonmark").parse(result.pages[0])
    assert tokens and all(t.type == "fence" and t.info == "text" for t in tokens)
    recovered = "".join(t.content for t in tokens)
    assert "Details 9" in recovered and "@**all**" in recovered


ZULIP_CONTAINERS = json.loads(
    (Path(__file__).parents[1] / "fixtures/zulip/rendering-containers.json").read_text()
)


@pytest.mark.parametrize("case", ZULIP_CONTAINERS["cases"], ids=lambda case: case["name"])
def test_container_serialization_matches_actual_zulip_renderer_and_stays_inert(case):
    assert ZULIP_CONTAINERS["synthetic_rendering_samples"]
    assert ZULIP_CONTAINERS["message_posts"] == ZULIP_CONTAINERS["upload_posts"] == 0
    assert ZULIP_CONTAINERS["Native_requests"] == 0
    assert MobileMarkdown(locale="zh-TW").render(case["source"], 10000).pages == (case["wire"],)
    rendered = Elements()
    rendered.feed(case["rendered_html"])
    assert not {"img", "script", "iframe", "style"} & set(rendered.tags)
    assert not any(
        v in case["rendered_html"] for v in ["user-mention", "data-user-id", 'class="emoji"']
    )
    assert rendered.links in [[], ["https://example.invalid/pixel"]]
    if case["name"] in {"named_en", "named_zh", "nested_json"}:
        heading = {"named_en": "Advanced", "named_zh": "進階指令", "nested_json": "完整連線目標"}[
            case["name"]
        ]
        assert 'class="spoiler-header"' in case["rendered_html"] and heading in rendered.text
    if case["name"] == "literal_reserved":
        assert 'class="spoiler-block"' not in case["rendered_html"] and "code" in rendered.tags


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
def test_advanced_menu_commands_preserve_opaque_token_edges_in_literal_code(locale):
    from jt_oz_bridge.i18n import Translator

    tr = Translator()
    opaque = "_" + "0" * 30 + "_"
    keys = [
        "binding.preview_confirm",
        "discovery.next",
        "discovery.choose",
        "discovery.choose_project",
        "discovery.choose_session",
        "discovery.choose_backend",
    ]
    values = {"token": opaque, "menu_id": opaque, "item_number": 1, "command": "sessions"}
    for key in keys:
        params = {name: values[name] for name in tr.fields(tr.catalogs["en"][key])}
        source = tr.render(key, locale, **params)
        page = MobileMarkdown(locale=locale).render(source, 10000).pages[0]
        containers = [t for t in MarkdownIt("commonmark").parse(page) if t.type == "fence"]
        assert len(containers) == 1 and containers[0].info.startswith("spoiler ")
        children = [
            c
            for t in MarkdownIt("commonmark").parse(containers[0].content)
            for c in t.children or []
        ]
        commands = [c.content for c in children if c.type == "code_inline"]
        assert len(commands) == 1 and opaque in commands[0]
        assert commands[0].startswith(("!oz ", "!ok "))
