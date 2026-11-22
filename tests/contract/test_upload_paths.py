from dataclasses import replace

import httpx
import pytest
from markdown_it import MarkdownIt

from jt_oz_bridge.adapters.zulip.client import ZulipError
from jt_oz_bridge.adapters.zulip.uploads import upload_markdown_link, upload_reference
from jt_oz_bridge.security.downloads import DownloadDenied
from tests.contract.test_zulip_delivery import client


@pytest.mark.parametrize(
    "value",
    [
        "/user_uploads/1/ab/opaque/%E5%9C%96.png",
        "https://zulip.invalid/user_uploads/1/ab/opaque/%E5%9C%96.png",
        "user_uploads/1/ab/opaque/%E5%9C%96.png",
    ],
)
def test_original_upload_paths_preserve_canonical_unicode_filename(value):
    item = upload_reference(value, "https://zulip.invalid")
    assert item.path_id == "1/ab/opaque/%E5%9C%96.png" and item.filename == "圖.png"
    assert item.api_route == "user_uploads/1/ab/opaque/%E5%9C%96.png"


@pytest.mark.parametrize(
    "value",
    [
        "https://evil.example/user_uploads/1/ab/file",
        "//evil.example/user_uploads/1/ab/file",
        "/user_uploads/temporary/token/file",
        "/user_uploads/1/ab/../file",
        "/user_uploads/1/ab/%2e%2e/file",
        "/user_uploads/1/ab/%252e%252e/file",
        "/user_uploads/1/ab/a%2fb",
        "/user_uploads/1/ab/file?next=http://private",
        "/user_uploads/1/ab/file#fragment",
        "/user_uploads/1/ab/file%00bad",
        "/user_uploads/1/ab/bad%FF",
    ],
)
def test_untrusted_urls_and_encoded_path_escapes_are_never_api_routes(value):
    with pytest.raises(DownloadDenied):
        upload_reference(value, "https://zulip.invalid")


@pytest.mark.parametrize(
    "name", ["原始 [file].html", "@**all**.txt", "a&b<test>.html", "one (two)!_*.html"]
)
def test_message_upload_links_keep_unicode_path_and_literal_original_filename(name):
    path = "/user_uploads/1/ab/opaque/%E5%9C%96-file.html"
    result = upload_markdown_link(path, name, "https://zulip.invalid")
    assert result.endswith(")") and "](/user_uploads/1/ab/opaque/圖-file.html)" in result
    assert "\\" not in result and "@**all**" not in result
    # The existing CommonMark serializer also sees a single named local link;
    # actual Zulip collector/claim semantics require separate installed proof.
    inline = MarkdownIt().parse(result)[1].children
    assert inline is not None
    links = [token for token in inline if token.type == "link_open"]
    assert len(links) == 1 and links[0].attrGet("href") == path
    assert "".join(token.content for token in inline if token.type == "text") == name
    assert upload_reference(path, "https://zulip.invalid").path_id.endswith("%E5%9C%96-file.html")


@pytest.mark.parametrize(
    "path",
    [
        "/user_uploads/1/ab/opaque/file%29%28.html",
        "/user_uploads/1/ab/opaque/file%20name.html",
        "/user_uploads/1/ab/opaque/file%23x.html",
        "/user_uploads/1/ab/opaque/file%3Fx.html",
        "/user_uploads/1/ab/opaque/file%3Cscript%3E.html",
        "/user_uploads/1/ab/opaque/file%26x.html",
        "https://foreign.invalid/user_uploads/1/ab/opaque/file.html",
        "/user_uploads/temporary/token/file.html",
    ],
)
def test_message_upload_link_cannot_turn_encoded_punctuation_into_markdown_or_url_syntax(path):
    with pytest.raises(DownloadDenied):
        upload_markdown_link(path, "file.html", "https://zulip.invalid")


@pytest.mark.parametrize("name", ["", ".", "..", "x" * 256, "../x", "a\\b", "a\nuser", "a\x00b"])
def test_message_upload_link_rejects_invalid_display_filenames(name):
    with pytest.raises(DownloadDenied):
        upload_markdown_link("/user_uploads/1/ab/file.html", name, "https://zulip.invalid")


async def test_file_contract_is_separately_gated_and_signed_url_is_only_returned_in_memory():
    requests = []

    def handle(request):
        requests.append(request)
        assert request.url.path == "/api/v1/user_uploads/1/ab/opaque/file.txt"
        return httpx.Response(
            200,
            json={"result": "success", "url": "/user_uploads/temporary/PRIVATE-MARKER/file.txt"},
        )

    c = client(handle)
    try:
        with pytest.raises(ZulipError, match="not_attested"):
            await c.temporary_file_url("/user_uploads/1/ab/opaque/file.txt")
        assert not requests
        c.attestation = replace(c.attestation, verified_file_operations=frozenset({"download"}))
        assert (
            await c.temporary_file_url("/user_uploads/1/ab/opaque/file.txt")
            == "https://zulip.invalid/user_uploads/temporary/PRIVATE-MARKER/file.txt"
        )
        assert len(requests) == 1
    finally:
        await c.close()


@pytest.mark.parametrize(
    "value",
    [
        "//foreign.example/path",
        "/admin/secret",
        "/user_uploads/temporary/token/file#fragment",
        "/user_uploads/temporary/token/file\r\nX-Header: bad",
        "https://user:password@files.example/blob",
        "http://files.example/blob",
        "not-an-absolute-url",
    ],
)
async def test_temporary_url_response_rejects_unsafe_schemes_credentials_and_unrelated_relative_routes(
    value,
):
    c = client(lambda request: httpx.Response(200, json={"result": "success", "url": value}))
    c.attestation = replace(c.attestation, verified_file_operations=frozenset({"download"}))
    try:
        with pytest.raises(ZulipError, match="contract_mismatch"):
            await c.temporary_file_url("/user_uploads/1/ab/opaque/file.txt")
    finally:
        await c.close()


async def test_explicit_absolute_signed_origin_is_left_to_auth_free_download_policy():
    value = "https://files.example/blob?signature=PRIVATE-MARKER"
    c = client(lambda request: httpx.Response(200, json={"result": "success", "url": value}))
    c.attestation = replace(c.attestation, verified_file_operations=frozenset({"download"}))
    try:
        assert await c.temporary_file_url("/user_uploads/1/ab/opaque/file.txt") == value
    finally:
        await c.close()
