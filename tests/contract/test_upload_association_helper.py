"""Isolated request/policy/ORM model fixtures; no production rows are created."""

import copy
import hashlib
import json
import sys
import types
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from ops.zulip import upload_association as h


def data(tmp_path):
    policy = {
        "format": h.FORMAT,
        "realm_id": "realm",
        "numeric_realm_id": 2,
        "channel_ids": [10],
        "zulip_root": str(tmp_path),
        "zulip_version": "12.3",
        "source_sha256": {},
    }
    for relative in h.REQUIRED_SOURCES:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"isolated source pin")
        policy["source_sha256"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    source = {
        "realm_id": "realm",
        "channel_id": 10,
        "topic": "Docs",
        "message_id": 100,
        "revision": 0,
        "author_id": 7,
        "text": "original file link",
        "deleted": False,
        "is_bot": False,
    }
    request = {
        "format": h.FORMAT,
        "nonce": "a" * 32,
        "source": source,
        "upload_paths": ["/user_uploads/2/opaque/file.txt"],
    }
    return request, policy


@pytest.mark.parametrize(
    "change",
    [
        {"realm_id": "other"},
        {"channel_id": 99},
        {"message_id": True},
        {"author_id": 0},
        {"revision": True},
        {"revision": -1},
        {"is_bot": True},
        {"is_bot": 0},
        {"deleted": True},
        {"text": None},
        {"topic": ""},
    ],
)
def test_source_claims_are_exact_and_fail_before_database_access(tmp_path, change):
    request, policy = data(tmp_path)
    request["source"].update(change)
    with pytest.raises(ValueError):
        h.validate(request, policy)


@pytest.mark.parametrize(
    "path",
    [
        "https://foreign/user_uploads/2/a/file",
        "/user_uploads/3/a/file",
        "/user_uploads/2/a/../file",
        "/user_uploads/2/a/%2e%2e",
        "/user_uploads/2/a/%252e%252e",
        "/user_uploads/2/a/%2Fsecret",
        "/user_uploads/2/a/file?query",
        "/user_uploads/2/a/file%00name",
        "/user_uploads/2/a/%ff",
    ],
)
def test_noncanonical_cross_realm_or_encoded_escapes_never_reach_orm(tmp_path, path):
    request, policy = data(tmp_path)
    request["upload_paths"] = [path]
    with pytest.raises(ValueError):
        h.validate(request, policy)


def test_no_remote_sql_command_operator_flag_or_duplicate_nonfinite_json(tmp_path):
    request, policy = data(tmp_path)
    for field in ("sql", "command", "operator_bot"):
        with pytest.raises(ValueError):
            h.validate({**request, field: True}, policy)
    for raw in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'):
        with pytest.raises(ValueError):
            h.strict_json(raw)
    assert h.validate(request, policy)[1] == ["2/opaque/file.txt"]


@pytest.fixture
def orm(tmp_path, monkeypatch):
    request, policy = data(tmp_path)
    sender = SimpleNamespace(
        id=7, realm_id=2, is_active=True, is_bot=False, can_access_public_streams=lambda: True
    )
    recipient = SimpleNamespace(type=2, type_id=10)
    message = SimpleNamespace(
        id=100,
        realm_id=2,
        sender_id=7,
        sender=sender,
        recipient=recipient,
        is_channel_message=True,
        content="original file link",
        edit_history=None,
        topic_name=lambda: "Docs",
    )
    rows = [
        {
            "id": 55,
            "path_id": "2/opaque/file.txt",
            "owner_id": 99,
            "size": 23,
            "content_type": "text/plain; charset=UTF-8",
            "file_name": "原始 [file].txt",
        }
    ]
    statements = []
    filters = []
    authorization = {"allowed": True, "attachment_id": 55}

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def execute(self, sql):
            statements.append(sql)

        def fetchone(self):
            return (authorization.get("read_only", "on"),)

    @contextmanager
    def atomic():
        yield

    class MessageManager:
        def select_related(self, *fields):
            assert fields == ("sender", "recipient")
            return self

        def get(self, **keys):
            assert keys == {"id": 100}
            assert statements[0] == "SET TRANSACTION READ ONLY"
            return message

    class AttachmentManager:
        def filter(self, **keys):
            filters.append(keys)
            return self

        def values(self, *names):
            assert set(names) == set(rows[0]) if rows else True
            return rows

        def get(self, **keys):
            assert keys == {"id": 55}
            return SimpleNamespace(
                id=authorization["attachment_id"],
                path_id=rows[0]["path_id"] if authorization["attachment_id"] == 55 else "wrong",
                realm_id=2,
                owner_id=99,
                is_realm_public=authorization["allowed"],
                messages=SimpleNamespace(all=lambda: EmptyQuery()),
            )

    class EmptyQuery(list):
        def select_related(self, *args):
            return self

        def values_list(self, *args, **kwargs):
            return self

    django = types.ModuleType("django")
    django.setup = lambda: None
    db = types.ModuleType("django.db")
    db.transaction = SimpleNamespace(atomic=atomic)
    db.connection = SimpleNamespace(cursor=Cursor)
    version = types.ModuleType("version")
    version.ZULIP_VERSION = "12.3"
    zerver = types.ModuleType("zerver")
    zerver.__path__ = []
    models = types.ModuleType("zerver.models")
    models.Message = SimpleNamespace(objects=MessageManager())
    models.Attachment = SimpleNamespace(objects=AttachmentManager())
    models.Recipient = SimpleNamespace(STREAM=2)
    lib = types.ModuleType("zerver.lib")
    lib.__path__ = []
    attachments = types.ModuleType("zerver.lib.attachments")

    attachments.UserMessage = SimpleNamespace(
        objects=SimpleNamespace(filter=lambda **kw: EmptyQuery())
    )
    attachments.Subscription = SimpleNamespace(
        objects=SimpleNamespace(filter=lambda **kw: EmptyQuery())
    )
    attachments.Recipient = models.Recipient
    for name, module in [
        ("django", django),
        ("django.db", db),
        ("version", version),
        ("zerver", zerver),
        ("zerver.models", models),
        ("zerver.lib", lib),
        ("zerver.lib.attachments", attachments),
    ]:
        monkeypatch.setitem(sys.modules, name, module)
    original = list(sys.path)
    yield request, policy, message, rows, authorization, statements, filters, version
    sys.path[:] = original


def test_per_path_claim_and_sender_access_use_read_only_transaction_and_preserve_original_metadata(
    orm,
):
    request, policy, message, rows, auth, statements, filters, version = orm
    result = h.observe(request, policy)
    assert result["allowed"] is True and result["source_sha256"] == h.sha(request["source"])
    assert result["files"] == [
        {
            "upload_path": "/user_uploads/2/opaque/file.txt",
            "filename": "原始 [file].txt",
            "mime_type": "text/plain",
            "size": 23,
        }
    ]
    assert "original file link" not in json.dumps(result)
    assert result["nonce"] == request["nonce"] and result["mode"] == "human-source"
    assert statements == [
        "SET TRANSACTION READ ONLY",
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ",
        "SET LOCAL statement_timeout = '2000ms'",
        "SHOW transaction_read_only",
    ]
    assert filters == [{"realm_id": 2, "path_id__in": ["2/opaque/file.txt"], "messages__id": 100}]
    assert (
        rows[0]["owner_id"] == 99
    )  # Authorized forwarding need not be original uploader ownership.


@pytest.mark.parametrize(
    "kind",
    [
        "actor",
        "realm",
        "topic",
        "body",
        "revision",
        "channel",
        "inactive",
        "bot",
        "missing-claim",
        "duplicate-claim",
        "no-access",
        "different-attachment",
        "version",
        "source-pin",
        "read-write-transaction",
    ],
)
def test_orm_changes_never_return_positive_association(orm, kind, tmp_path):
    request, policy, message, rows, auth, statements, filters, version = orm
    if kind == "actor":
        message.sender_id = 8
    elif kind == "realm":
        message.realm_id = 3
    elif kind == "topic":
        message.topic_name = lambda: "Other"
    elif kind == "body":
        message.content = "edited"
    elif kind == "revision":
        message.edit_history = '[{"prev_content":"old"}]'
    elif kind == "channel":
        message.recipient.type_id = 11
    elif kind == "inactive":
        message.sender.is_active = False
    elif kind == "bot":
        message.sender.is_bot = True
    elif kind == "missing-claim":
        rows.clear()
    elif kind == "duplicate-claim":
        rows.append(copy.deepcopy(rows[0]))
    elif kind == "no-access":
        auth["allowed"] = False
    elif kind == "different-attachment":
        auth["attachment_id"] = 56
    elif kind == "version":
        version.ZULIP_VERSION = "changed"
    elif kind == "source-pin":
        (tmp_path / "zerver/lib/attachments.py").write_text("changed source")
    elif kind == "read-write-transaction":
        auth["read_only"] = "off"
    with pytest.raises(ValueError):
        h.observe(request, policy)


def test_operator_bot_probe_is_not_a_remote_or_normal_human_authorization_path(orm):
    request, policy, message, rows, auth, statements, filters, version = orm
    request["source"]["is_bot"] = True
    message.sender.is_bot = True
    with pytest.raises(ValueError):
        h.observe(request, policy)
    operator = h.observe(request, policy, operator_bot=True)
    assert operator["mode"] == "operator-bot-only"


@pytest.mark.parametrize(
    "changes, expected",
    [
        ({"owner_id": 7}, True),
        ({"public": True}, True),
        ({"public": None, "computed_public": True}, True),
        ({"public": None, "computed_public": False}, False),
        ({"public": True, "attachment_realm": 3}, False),
        ({"public": True, "can_public": False}, False),
        ({"dm": True, "received": True}, True),
        ({"dm": True}, False),
        ({"received": True, "subscribed": True}, True),
        ({"subscribed": True, "history_public": True}, True),
        ({"subscribed": True}, False),
        ({"received": True}, False),
        ({"group_access": True, "history_public": True}, True),
        ({"group_access": True, "received": True}, True),
        ({"group_access": True}, False),
        ({"history_public": True}, False),
        ({}, False),
    ],
)
def test_upstream_sender_permission_branches_are_preserved_without_any_write(changes, expected):
    state = {
        "owner_id": 99,
        "public": False,
        "computed_public": False,
        "attachment_realm": 2,
        "can_public": True,
        "dm": False,
        "received": False,
        "subscribed": False,
        "history_public": False,
        "group_access": False,
        **changes,
    }
    calls = []

    class Query(list):
        # No update/save/delete/refresh method exists: a write fails the test.
        def select_related(self, *fields):
            calls.append(("select_related", fields))
            return self

        def values_list(self, name, *, flat):
            assert flat is True and name in {"recipient__type_id", "id"}
            calls.append(("values_list", name))
            return self

        def exists(self):
            calls.append(("exists",))
            return state["computed_public"]

    user = SimpleNamespace(id=7, realm_id=2, can_access_public_streams=lambda: state["can_public"])
    message = SimpleNamespace(
        is_channel_message=not state["dm"], recipient=SimpleNamespace(type_id=10), recipient_id=77
    )
    messages = Query([message])
    attachment = SimpleNamespace(
        owner_id=state["owner_id"],
        realm_id=state["attachment_realm"],
        is_realm_public=state["public"],
        messages=SimpleNamespace(all=lambda: messages),
    )
    channel = SimpleNamespace(
        id=10, is_history_public_to_subscribers=lambda: state["history_public"]
    )

    def public_filter(**keys):
        assert keys == {
            "realm_id": 2,
            "attachment": attachment,
            "recipient__stream__invite_only": False,
        }
        calls.append(("public_filter",))
        return Query()

    def received_filter(**keys):
        assert keys == {"user_profile": user, "message__in": messages}
        return Query([SimpleNamespace(message=message)] if state["received"] else [])

    def subscriptions(**keys):
        assert keys == {
            "user_profile": user,
            "active": True,
            "recipient__type": 2,
            "recipient__in": [77],
        }
        return Query([10] if state["subscribed"] else [])

    def channels(**keys):
        assert keys == {"id__in": {10}}
        return Query([channel])

    def groups(actor):
        assert actor is user
        return Query([42])

    def group_access(candidate, ids):
        assert candidate is channel and ids == {42}
        return state["group_access"]

    access = SimpleNamespace(
        Message=SimpleNamespace(objects=SimpleNamespace(filter=public_filter)),
        UserMessage=SimpleNamespace(objects=SimpleNamespace(filter=received_filter)),
        Subscription=SimpleNamespace(objects=SimpleNamespace(filter=subscriptions)),
        Recipient=SimpleNamespace(STREAM=2),
        Stream=SimpleNamespace(objects=SimpleNamespace(filter=channels)),
        get_recursive_membership_groups=groups,
        is_user_in_groups_granting_content_access=group_access,
    )
    assert h.readonly_sender_access(user, attachment, access) is expected
    assert attachment.is_realm_public is state["public"]
    assert (("public_filter",) in calls) is (state["public"] is None)
