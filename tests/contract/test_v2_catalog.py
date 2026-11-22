from pathlib import Path

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.catalog import V2CatalogProject, V2SessionCatalog
from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile
from jt_oz_bridge.adapters.opencode.transport import (
    ContractAttestation,
    TransportError,
    V2HTTPTransport,
)
from jt_oz_bridge.domain.catalog import ProjectScope
from jt_oz_bridge.domain.control import ExecutionState

SCOPE = ProjectScope(
    backend_id="backend",
    backend_identity="synthetic-installation",
    project_id="bridge-project-alias",
    canonical_directory="/workspace/approved",
)


@pytest.fixture(params=["opencode-v2-openapi.json", "opencode-v2.0.30-openapi.json"])
def profile(request):
    return OpenAPIProfile.from_file(Path("tests/fixtures/contracts") / request.param)


def native(**changes):
    return {
        "id": "ses_original",
        "projectID": "native-project-id",
        "cost": 0,
        "tokens": {"input": 0, "output": 0, "reasoning": 0, "cache": {"read": 0, "write": 0}},
        "time": {"created": 1, "updated": 2},
        "location": {"directory": SCOPE.canonical_directory},
        "title": "Original native title",
        **changes,
    }


async def identity():
    return True


def catalog(profile, handle, *, attested=True, verified=identity):
    transport = V2HTTPTransport(
        "https://private.invalid",
        profile,
        attestation=ContractAttestation(
            profile.sha256, SCOPE.backend_identity, "synthetic-fixture", frozenset({"session.list"})
        )
        if attested
        else None,
        verify_identity=verified,
        transport=httpx.MockTransport(handle),
    )
    return V2SessionCatalog(
        transport, {SCOPE.project_id: V2CatalogProject(SCOPE, "native-project-id")}
    ), transport


async def test_exact_readonly_query_uses_native_project_id_string_limit_and_literal_search(profile):
    seen = []

    def handle(request):
        seen.append(request)
        assert request.method == "GET" and request.url.path == "/api/session"
        assert dict(request.url.params) == {
            "directory": SCOPE.canonical_directory,
            "project": "native-project-id",
            "limit": "10",
            "order": "desc",
            "search": "!oz exact search",
            "cursor": "opaque:from-native",
        }
        return httpx.Response(
            200, json={"data": [native()], "cursor": {"previous": None, "next": "opaque:next"}}
        )

    client, transport = catalog(profile, handle)
    try:
        page = await client.list_sessions(
            SCOPE, search="!oz exact search", cursor="opaque:from-native", limit=10
        )
        assert page.items[0].reference.project_id == SCOPE.project_id
        assert page.items[0].reference.upstream_session_id == "ses_original"
        assert page.items[0].reference.canonical_directory == SCOPE.canonical_directory
        assert page.items[0].state == ExecutionState.UNKNOWN
        # Native time.updated is milliseconds; it only labels and orders the chooser.
        assert page.items[0].updated_at == 0.002
        assert page.next_cursor == "opaque:next" and len(seen) == 1
    finally:
        await transport.close()


@pytest.mark.parametrize("foreign_child", [False, True])
async def test_opt_in_adoption_root_query_is_explicit_and_never_accepts_a_child(foreign_child):
    profile = OpenAPIProfile.from_file(
        Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json")
    )
    seen = []

    def handle(request):
        seen.append(request)
        assert request.url.params["parentID"] == "null"
        assert request.url.params["directory"] == SCOPE.canonical_directory
        assert request.url.params["project"] == "native-project-id"
        return httpx.Response(
            200,
            json={
                "data": [native(**({"parentID": "ses_parent"} if foreign_child else {}))],
                "cursor": {"next": "native-next"},
            },
        )

    original, transport = catalog(profile, handle)
    roots = V2SessionCatalog(
        transport, original.projects, root_projects=frozenset({SCOPE.project_id})
    )
    try:
        if foreign_child:
            with pytest.raises(ContractError, match="foreign_project"):
                await roots.list_sessions(SCOPE, search="literal", cursor=None, limit=10)
        else:
            page = await roots.list_sessions(SCOPE, search="literal", cursor=None, limit=10)
            assert len(page.items) == 1 and page.next_cursor == "native-next"
            assert page.items[0].selection is None  # Listing is not a current identity proof.
        assert len(seen) == 1 and seen[0].method == "GET"
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "change", ["unattested", "unverified", "missing_verifier", "wrong_scope", "wrong_identity"]
)
async def test_missing_installed_contract_or_identity_never_reaches_transport(profile, change):
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(200, json={"data": [], "cursor": {}})

    async def unverified():
        return False

    client, transport = catalog(
        profile,
        handle,
        attested=change != "unattested",
        verified=unverified
        if change == "unverified"
        else None
        if change == "missing_verifier"
        else identity,
    )
    scope = (
        SCOPE.model_copy(update={"canonical_directory": "/workspace/unapproved"})
        if change == "wrong_scope"
        else SCOPE
    )
    if change == "wrong_identity":
        transport.attestation = ContractAttestation(
            profile.sha256, "other-instance", "synthetic", frozenset({"session.list"})
        )
    try:
        with pytest.raises(ContractError):
            await client.list_sessions(scope, search="", cursor=None, limit=10)
        assert not seen
    finally:
        await transport.close()


@pytest.mark.parametrize("change", ["project", "directory", "duplicate", "too_many", "cursor"])
async def test_schema_valid_but_semantically_foreign_or_unbounded_response_is_refused(
    profile, change
):
    data = [native()]
    cursor = {}
    if change == "project":
        data = [native(projectID="foreign-native-project")]
    elif change == "directory":
        data = [native(location={"directory": "/workspace/approved/../other"})]
    elif change == "duplicate":
        data *= 2
    elif change == "too_many":
        data = [native(id=f"ses_{i}") for i in range(11)]
    else:
        cursor = {"next": "repeat"}
    client, transport = catalog(
        profile, lambda request: httpx.Response(200, json={"data": data, "cursor": cursor})
    )
    try:
        with pytest.raises(ValueError):
            await client.list_sessions(
                SCOPE, search="", cursor="repeat" if change == "cursor" else None, limit=10
            )
    finally:
        await transport.close()


async def test_connection_change_during_read_discards_result_without_inventing_another_owner(
    profile,
):
    checks = 0

    async def changed():
        nonlocal checks
        checks += 1
        return checks == 1

    client, transport = catalog(
        profile,
        lambda request: httpx.Response(200, json={"data": [native()], "cursor": {}}),
        verified=changed,
    )
    try:
        with pytest.raises(ContractError, match="identity_unverified"):
            await client.list_sessions(SCOPE, search="", cursor=None, limit=10)
        assert checks == 2
    finally:
        await transport.close()


async def test_missing_title_uses_native_id_without_inventing_title_and_zero_archive_is_preserved(
    profile,
):
    row = native(time={"created": 0, "updated": 0, "archived": 0})
    row.pop("title")
    client, transport = catalog(
        profile, lambda request: httpx.Response(200, json={"data": [row], "cursor": {}})
    )
    try:
        page = await client.list_sessions(SCOPE, search="", cursor=None, limit=10)
        assert page.items[0].title == "ses_original" and page.items[0].archived is True
        assert page.items[0].state == ExecutionState.UNKNOWN
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "invalid",
    [
        b'{"data":[],"data":[],"cursor":{}}',
        b'{"data":[],"cursor":{},"PRIVATE_MARKER":NaN}',
        b'{"data":[],"cursor":{},"PRIVATE_MARKER":1e999}',
    ],
)
async def test_ambiguous_or_nonfinite_json_is_rejected_before_contract_normalization_without_echo(
    profile, invalid
):
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(200, content=invalid, headers={"content-type": "application/json"})

    client, transport = catalog(profile, handle)
    try:
        with pytest.raises(TransportError) as error:
            await client.list_sessions(SCOPE, search="", cursor=None, limit=10)
        assert "PRIVATE_MARKER" not in str(error.value) and len(seen) == 1
    finally:
        await transport.close()


async def test_upstream_error_is_one_read_without_version_or_protocol_fallback(profile):
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(401, json={"_tag": "UnauthorizedError"})

    client, transport = catalog(profile, handle)
    try:
        with pytest.raises(ValueError):
            await client.list_sessions(SCOPE, search="", cursor=None, limit=10)
        assert len(seen) == 1 and seen[0].method == "GET"
    finally:
        await transport.close()


@pytest.mark.parametrize("native_id", ["ses_bad/path", "ses_bad?query"])
async def test_unusable_native_session_path_cannot_be_published_as_selection(profile, native_id):
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(200, json={"data": [native(id=native_id)], "cursor": {}})

    client, transport = catalog(profile, handle)
    try:
        with pytest.raises(ContractError, match="path_parameter"):
            await client.list_sessions(SCOPE, search="", cursor=None, limit=10)
        assert len(seen) == 1 and seen[0].url.path == "/api/session"
    finally:
        await transport.close()


async def test_attestation_replaced_during_peer_verification_does_not_escape_final_check(profile):
    client, transport = catalog(
        profile, lambda request: httpx.Response(200, json={"data": [native()], "cursor": {}})
    )
    checks = 0

    async def replaced():
        nonlocal checks
        checks += 1
        if checks == 2:
            transport.attestation = None
        return True

    transport.verify_identity = replaced
    try:
        with pytest.raises(ContractError, match="not_attested"):
            await client.list_sessions(SCOPE, search="", cursor=None, limit=10)
    finally:
        await transport.close()
