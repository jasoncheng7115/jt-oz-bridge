"""Original-Root patch pages with fresh VIEW checks and no Git mutations.

Tokens retain only selection, issuer and content digests. Each continuation
re-reads the same Native comparison; a changed patch requires a new request.
"""

import re
from typing import TYPE_CHECKING, Literal

from pydantic import Field, StrictInt, field_validator, model_validator

from jt_oz_bridge.adapters.opencode.git_review import explicit_base
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.git_review import NativeGitPatch, NativeGitPatchReader
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.presentation.git_review import visible
from jt_oz_bridge.presentation.markdown import MobileMarkdown, sanitize_controls
from jt_oz_bridge.security.redaction import redact_text
from jt_oz_bridge.security.workspace_paths import disclosed_path
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest

if TYPE_CHECKING:
    from jt_oz_bridge.services.git_review_commands import NativeGitReviewCommands

KIND = "native-git-patch-page"
RENDERER: Literal["native-git-patch-page-v1"] = "native-git-patch-page-v1"


class PatchPage(ControlModel):
    reference: SessionRef
    path: str = Field(min_length=1, max_length=4096)
    mode: Literal["working", "branch", "committed"] = "working"
    base: str | None = Field(default=None, max_length=255)
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    offset: StrictInt = Field(ge=1, le=65536)
    issuer: HumanMessage
    message_limit: StrictInt = Field(ge=512, le=1000000)
    locale: Locale
    renderer: Literal["native-git-patch-page-v1"] = RENDERER

    @field_validator("path")
    @classmethod
    def disclosed(cls, value: str) -> str:
        return disclosed_path(value)

    @model_validator(mode="after")
    def comparison(self) -> "PatchPage":
        if (self.mode == "working") != (self.base is None):
            raise ValueError("git_patch_explicit_comparison_required")
        if self.base is not None:
            explicit_base(self.base)
        return self


def patch_query(value: str) -> tuple[str, Literal["working", "branch", "committed"], str | None]:
    # Split comparison syntax only; preserve a path containing ordinary spaces.
    parts = value.split(maxsplit=1)
    if not parts:
        raise ValueError("git_patch_path_required")
    if parts[0] in {"working", "branch", "committed"}:
        mode = parts[0]
        tail = parts[1] if len(parts) == 2 else ""
        if mode == "working":
            return disclosed_path(tail), "working", None
        comparison = tail.split(maxsplit=1)
        if len(comparison) != 2:
            raise ValueError("git_patch_comparison_path_required")
        return (
            disclosed_path(comparison[1]),
            "branch" if mode == "branch" else "committed",
            explicit_base(comparison[0]),
        )
    return disclosed_path(value), "working", None


async def patch_route(
    commands: "NativeGitReviewCommands",
    binding: Binding,
    source: HumanMessage,
    locale: Locale,
    arguments: str,
) -> str:
    await commands._current(binding, source, arguments)
    await commands._authority(binding)
    selected = commands.readers.get(reference(binding))
    if (
        not commands.available(binding)
        or not isinstance(selected, NativeGitPatchReader)
        or not selected.qualified_patch(reference(binding))
        or selected.patch_contract_for(reference(binding))
        != commands.bindings.control.contract_for(reference(binding))
    ):
        # No Native request, token or raw content when separate opt-in is absent.
        await commands._current(binding, source, arguments)
        await commands._authority(binding)
        return commands.tr.render("git_patch.unavailable", locale)
    value = arguments.split(maxsplit=1)[1] if len(arguments.split(maxsplit=1)) == 2 else ""
    saved = None
    state = None
    if value.startswith("page:"):
        raw = value.removeprefix("page:")
        if re.fullmatch(r"[A-Za-z0-9_-]{32}", raw) is None:
            raise ValueError("git_patch_opaque_page_required")
        saved = await commands.tokens.inspect(raw, KIND, source.realm_id, source.author_id)
        state = PatchPage.model_validate(saved.context)
        if (
            saved.binding_id != binding.id
            or saved.binding_revision != binding.revision
            or state.reference != reference(binding)
            or state.message_limit != commands.message_limit
            or (
                state.issuer.realm_id,
                state.issuer.channel_id,
                state.issuer.topic,
                state.issuer.author_id,
            )
            != (source.realm_id, source.channel_id, source.topic, source.author_id)
        ):
            raise Conflict("git_patch_page_original_scope_changed")
        await commands._current(
            binding, state.issuer, parse_input(state.issuer.text, bound=True).arguments
        )
        path, mode, base = state.path, state.mode, state.base
    else:
        path, mode, base = patch_query(value)
    snapshot = await selected.read_patch(reference(binding), path=path, mode=mode, base=base)
    NativeGitPatch.model_validate(snapshot.model_dump(mode="json"))
    if (snapshot.reference, snapshot.file.path, snapshot.mode, snapshot.requested_base) != (
        reference(binding),
        path,
        mode,
        base,
    ):
        raise Conflict("git_patch_original_selection_changed")
    fingerprint = digest(snapshot.model_dump(mode="json"))
    if state is not None and state.snapshot_sha256 != fingerprint:
        raise Conflict("git_patch_original_content_changed")
    await commands._current(binding, source, arguments)
    if not commands._snapshot_current(binding, selected, snapshot):
        raise Conflict("git_patch_original_snapshot_expired")
    # Normalize/redact before pagination, so credential boundaries never split
    # across pages. Do not put untrusted names or patch bytes in metadata fields.
    normalized, controls = sanitize_controls(snapshot.patch)
    displayed, redactions = redact_text(normalized)
    render_locale = state.locale if state is not None else locale
    tr, maximum = commands.tr, commands.message_limit
    title = tr.render("git_patch.title", render_locale, path=visible(path, 48))
    scope = tr.render("git_patch.scope", render_locale)
    notice = tr.render("filemenu.sanitized", render_locale) if controls or redactions else ""
    longest_footer = tr.render("git_patch.next", render_locale, token="_" * 32)
    reserve = 100 + sum(map(len, (title, scope, notice, longest_footer))) + 24
    if maximum - reserve < 128:
        raise ValueError("git_patch_message_limit_too_small")
    pages = MobileMarkdown.code_pages(displayed, maximum - reserve, "diff")
    offset = state.offset if state is not None else 0
    if offset >= len(pages):
        raise Conflict("git_patch_original_page_changed")
    # Plan tokens first, then commit issuance/consumption with final bound scope.
    # A failed source/lease/snapshot check leaves no usable orphan continuation.
    with commands.tokens.planning() as plan:
        lines = [title, f"{offset + 1}/{len(pages)}", pages[offset], scope]
        if notice:
            lines.append(notice)
        if offset + 1 < len(pages):
            next_state = PatchPage(
                reference=reference(binding),
                path=path,
                mode=mode,
                base=base,
                snapshot_sha256=fingerprint,
                offset=offset + 1,
                issuer=state.issuer if state is not None else source,
                message_limit=maximum,
                locale=render_locale,
            )
            token = await commands.tokens.issue(
                KIND,
                source.realm_id,
                source.author_id,
                next_state.model_dump(mode="json"),
                binding_id=binding.id,
                binding_revision=binding.revision,
            )
            lines.append(tr.render("git_patch.next", render_locale, token=token))
        result = "\n\n".join(lines)
        result = await commands._finish(binding, source, arguments, result, selected, snapshot)
        if state is not None:
            parsed = parse_input(state.issuer.text, bound=True)
            await commands._current(binding, state.issuer, parsed.arguments)
        async with commands.db.sessions.begin() as session:
            await commands.fence.lock(session)
            from jt_oz_bridge.services.scope_lock import lock_output_scope

            await lock_output_scope(commands.bindings, session, binding)
            await commands.fence.lock(session)
            if not commands._snapshot_current(binding, selected, snapshot):
                raise Conflict("git_patch_snapshot_changed_before_page_commit")
            if saved is not None:
                await commands.tokens.consume_in_session(session, saved)
            await plan.commit(session)
        # The live five-second snapshot and actual lease must survive the commit.
        await commands._locked_scope(binding, selected, snapshot)
        return result
