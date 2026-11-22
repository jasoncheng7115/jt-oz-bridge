"""Candidate upload paths are syntax, never proof of per-message authorization."""

import re
from urllib.parse import quote, unquote

import httpx

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.presentation.markdown import literal, sanitize_controls
from jt_oz_bridge.security.downloads import DownloadDenied, checked_url, origin_key


class UploadReference(ControlModel):
    path_id: str
    filename: str

    @property
    def api_route(self) -> str:
        return "user_uploads/" + self.path_id


def upload_markdown_link(upload_path: str, filename: str, realm_url: str) -> str:
    """Serialize a named link that Zulip 12.3 can claim as an attachment.

    HTTP requests still use canonical percent-encoded UploadReference paths.
    Zulip's Markdown attachment collector compares its raw URL path to the DB
    path without unquoting it, so message links must retain Unicode characters.
    Only the installed backend's sanitized word/dot/hyphen path alphabet is
    eligible; URI punctuation cannot escape the Markdown destination.
    """
    reference = upload_reference(upload_path, realm_url)
    parts = unquote(reference.path_id, errors="strict").split("/")
    if any(re.fullmatch(r"[\w.-]+", part) is None for part in parts):
        raise DownloadDenied("upload_path_not_safe_for_zulip_markdown")
    if (
        not isinstance(filename, str)
        or not 1 <= len(filename) <= 255
        or filename in {".", ".."}
        or any(char in filename for char in "/\\")
        or any(ord(char) < 32 or ord(char) == 127 for char in filename)
    ):
        raise DownloadDenied("upload_display_filename_invalid")
    label, _ = sanitize_controls(filename)
    if not label:
        raise DownloadDenied("upload_display_filename_invalid")
    # Zulip disables backslash escapes. Entity serialization preserves visible
    # filename punctuation while keeping links/mentions inert inside the label.
    return "[" + literal(label) + "](/user_uploads/" + "/".join(parts) + ")"


def upload_reference(value: str, realm_url: str) -> UploadReference:
    try:
        if len(value) > 4096 or "?" in value or "#" in value or "\\" in value:
            raise ValueError("unsupported source upload link")
        if value.startswith("user_uploads/"):
            value = "/" + value
        if value.startswith("/") and not value.startswith("//"):
            url = httpx.URL(value)
        else:
            url = checked_url(value)
            if origin_key(url) != origin_key(checked_url(realm_url)):
                raise ValueError("foreign upload origin")
        path = url.raw_path.decode("ascii")
        if not path.startswith("/user_uploads/"):
            raise ValueError("not an original upload path")
        parts = path.removeprefix("/user_uploads/").split("/")
        if not 3 <= len(parts) <= 10 or re.fullmatch(r"[1-9][0-9]{0,17}", parts[0]) is None:
            raise ValueError("unsupported upload identity")
        decoded = [unquote(part, errors="strict") for part in parts]
        for part in decoded:
            if (
                not part
                or part in {".", ".."}
                or any(char in part for char in "/\\")
                or any(ord(char) < 32 or ord(char) == 127 for char in part)
                or re.search(r"%[0-9a-fA-F]{2}", part)
            ):
                raise ValueError("ambiguous encoded upload path")
        return UploadReference(
            path_id="/".join(quote(part, safe="-._~") for part in decoded), filename=decoded[-1]
        )
    except (ValueError, UnicodeError, httpx.InvalidURL):
        raise DownloadDenied("invalid_or_unassociated_upload_path") from None
