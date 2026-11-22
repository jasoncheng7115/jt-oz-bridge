"""Fixed-policy read-only metadata helper for self-hosted Zulip 12.3.

Install with a restricted SSH forced command; normal stdin accepts Human source
checks only. No arbitrary SQL, shell, file retrieval or message mutation API.
"""

import hashlib
import json
import os
import re
import signal
import stat
import sys
import time
from pathlib import Path
from urllib.parse import quote, unquote

FORMAT = "jt-oz-upload-association-v1"
SOURCE_KEYS = {
    "realm_id",
    "channel_id",
    "topic",
    "message_id",
    "revision",
    "author_id",
    "text",
    "deleted",
    "is_bot",
}
REQUIRED_SOURCES = frozenset(
    {
        "zerver/lib/attachments.py",
        "zerver/actions/uploads.py",
        "zerver/lib/upload/__init__.py",
        "zerver/models/messages.py",
        "zerver/views/upload.py",
        "zerver/lib/streams.py",
        "zerver/lib/user_groups.py",
        "zerver/models/streams.py",
        "zerver/models/users.py",
    }
)


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    return json.loads(
        data,
        object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")),
    )


def sha(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def positive(value):
    return type(value) is int and 0 < value < 10**18


def validate(request, policy, *, operator_bot=False):
    if (
        not isinstance(request, dict)
        or set(request) != {"format", "nonce", "source", "upload_paths"}
        or request["format"] != FORMAT
    ):
        raise ValueError("invalid request")
    source = request["source"]
    nonce = request["nonce"]
    paths = request["upload_paths"]
    if (
        not isinstance(nonce, str)
        or len(nonce) != 32
        or any(c not in "0123456789abcdef" for c in nonce)
    ):
        raise ValueError("invalid nonce")
    if not isinstance(source, dict) or set(source) != SOURCE_KEYS:
        raise ValueError("invalid source")
    if (
        source["realm_id"] != policy["realm_id"]
        or source["channel_id"] not in policy["channel_ids"]
        or not all(positive(source[k]) for k in ("message_id", "author_id", "channel_id"))
    ):
        raise ValueError("source scope denied")
    if (
        source["deleted"] is not False
        or type(source["is_bot"]) is not bool
        or (source["is_bot"] and not operator_bot)
    ):
        raise ValueError("human source required")
    if (
        type(source["revision"]) is not int
        or not 0 <= source["revision"] <= 10000
        or not isinstance(source["text"], str)
        or len(source["text"]) > 1000000
        or not isinstance(source["topic"], str)
        or not 1 <= len(source["topic"]) <= 10000
    ):
        raise ValueError("invalid source fields")
    if (
        not isinstance(paths, list)
        or not 1 <= len(paths) <= 10
        or any(not isinstance(p, str) or len(p) > 4096 for p in paths)
        or len(set(paths)) != len(paths)
    ):
        raise ValueError("invalid upload paths")
    decoded = []
    for path in paths:
        if not path.startswith("/user_uploads/"):
            raise ValueError("invalid upload route")
        components = path.removeprefix("/user_uploads/").split("/")
        if not 3 <= len(components) <= 10 or components[0] != str(policy["numeric_realm_id"]):
            raise ValueError("invalid upload realm")
        parts = [unquote(part, errors="strict") for part in components]
        if any(
            not part
            or part in {".", ".."}
            or any(c in part for c in "/\\")
            or any(ord(c) < 32 or ord(c) == 127 for c in part)
            or re.search(r"%[0-9a-fA-F]{2}", part)
            for part in parts
        ):
            raise ValueError("noncanonical upload component")
        if "/user_uploads/" + "/".join(quote(part, safe="-._~") for part in parts) != path:
            raise ValueError("noncanonical upload encoding")
        decoded.append("/".join(parts))
    return source, decoded


def readonly_sender_access(user, attachment, access):
    """Read-only projection of Zulip 12.3 validate_attachment_request.

    Adapted from Zulip's Apache-2.0 implementation; see NOTICE/LICENSE.zulip.
    The original function may UPDATE a nullable cache before checking access.
    Here that value is computed in memory, with all permission branches kept.
    """
    realm_public = attachment.is_realm_public
    if realm_public is None:
        realm_public = access.Message.objects.filter(
            realm_id=user.realm_id,
            attachment=attachment,
            recipient__stream__invite_only=False,
        ).exists()
    if user.id == attachment.owner_id:
        return True
    if realm_public and attachment.realm_id == user.realm_id and user.can_access_public_streams():
        return True
    messages = attachment.messages.all().select_related("recipient")
    received_channels = set()
    for row in access.UserMessage.objects.filter(
        user_profile=user, message__in=messages
    ).select_related("message", "message__recipient"):
        if not row.message.is_channel_message:
            return True
        received_channels.add(row.message.recipient.type_id)
    subscribed = set(
        access.Subscription.objects.filter(
            user_profile=user,
            active=True,
            recipient__type=access.Recipient.STREAM,
            recipient__in=[message.recipient_id for message in messages],
        ).values_list("recipient__type_id", flat=True)
    )
    if received_channels.intersection(subscribed):
        return True
    channel_ids = {message.recipient.type_id for message in messages if message.is_channel_message}
    if not channel_ids:
        return False
    channels = access.Stream.objects.filter(id__in=channel_ids)
    for channel in channels:
        if channel.id in subscribed and channel.is_history_public_to_subscribers():
            return True
    groups = set(access.get_recursive_membership_groups(user).values_list("id", flat=True))
    for channel in channels:
        if access.is_user_in_groups_granting_content_access(channel, groups):
            if channel.is_history_public_to_subscribers() or channel.id in received_channels:
                return True
    return False


def observe(request, policy, *, operator_bot=False):
    source, paths = validate(request, policy, operator_bot=operator_bot)
    root = Path(policy["zulip_root"])
    assert root.is_absolute()
    for relative, expected in policy["source_sha256"].items():
        if relative.startswith("/") or ".." in Path(relative).parts:
            raise ValueError("invalid trusted source path")
        if hashlib.sha256((root / relative).read_bytes()).hexdigest() != expected:
            raise ValueError("installed Zulip source changed")
    sys.path.insert(0, str(root))
    os.environ["DJANGO_SETTINGS_MODULE"] = "zproject.settings"
    import django

    django.setup()
    from django.db import connection, transaction
    from version import ZULIP_VERSION
    from zerver.lib import attachments as access
    from zerver.models import Attachment, Message, Recipient

    if ZULIP_VERSION != policy["zulip_version"]:
        raise ValueError("Zulip version changed")
    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute("SET TRANSACTION READ ONLY")
            cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            cursor.execute("SET LOCAL statement_timeout = '2000ms'")
            cursor.execute("SHOW transaction_read_only")
            if cursor.fetchone() != ("on",):
                raise ValueError("read-only transaction not established")
        message = Message.objects.select_related("sender", "recipient").get(id=source["message_id"])
        sender = message.sender
        if (
            message.realm_id != policy["numeric_realm_id"]
            or message.sender_id != source["author_id"]
            or sender.realm_id != policy["numeric_realm_id"]
            or sender.is_active is not True
            or sender.is_bot != source["is_bot"]
            or (sender.is_bot and not operator_bot)
            or not message.is_channel_message
            or message.recipient.type != Recipient.STREAM
            or message.recipient.type_id != source["channel_id"]
            or message.topic_name() != source["topic"]
            or message.content != source["text"]
        ):
            raise ValueError("original message changed or denied")
        history = [] if message.edit_history is None else strict_json(message.edit_history)
        if not isinstance(history, list) or len(history) != source["revision"]:
            raise ValueError("original message revision changed")
        rows = list(
            Attachment.objects.filter(
                realm_id=policy["numeric_realm_id"], path_id__in=paths, messages__id=message.id
            ).values("id", "path_id", "owner_id", "size", "content_type", "file_name")
        )
        by_path = {row["path_id"]: row for row in rows}
        if len(rows) != len(paths) or len(by_path) != len(paths) or set(by_path) != set(paths):
            raise ValueError("per-path original message association missing")
        for path in paths:
            attachment = Attachment.objects.get(id=by_path[path]["id"])
            if (
                attachment.path_id != path
                or attachment.realm_id != policy["numeric_realm_id"]
                or not readonly_sender_access(sender, attachment, access)
            ):
                raise ValueError("original sender cannot access attachment")
        snapshot = sha(
            {"source_sha256": sha(source), "attachments": [by_path[path] for path in paths]}
        )
    return {
        "format": FORMAT,
        "nonce": request["nonce"],
        "allowed": True,
        "source_sha256": sha(source),
        "upload_paths": request["upload_paths"],
        "files": [
            {
                "upload_path": original,
                "filename": by_path[path]["file_name"],
                "mime_type": (by_path[path]["content_type"] or "application/octet-stream")
                .partition(";")[0]
                .strip()
                .lower(),
                "size": by_path[path]["size"],
            }
            for original, path in zip(request["upload_paths"], paths, strict=True)
        ],
        "observation_sha256": snapshot,
        "helper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "policy_sha256": sha(policy),
        "observed_at": time.time(),
        "mode": "operator-bot-only" if operator_bot else "human-source",
        "transaction_read_only": True,
    }


def read_policy(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("invalid policy path")
    for parent in reversed(path.parents):
        item = parent.lstat()
        if not stat.S_ISDIR(item.st_mode) or item.st_uid != 0 or item.st_mode & 0o022:
            raise ValueError("untrusted policy parent")
    item = path.lstat()
    if (
        not stat.S_ISREG(item.st_mode)
        or item.st_uid != 0
        or item.st_mode & 0o022
        or item.st_size > 65536
    ):
        raise ValueError("untrusted policy")
    policy = strict_json(path.read_bytes())
    if (
        set(policy)
        != {
            "format",
            "realm_id",
            "numeric_realm_id",
            "channel_ids",
            "zulip_root",
            "zulip_version",
            "source_sha256",
        }
        or policy["format"] != FORMAT
    ):
        raise ValueError("invalid policy schema")
    if (
        not positive(policy["numeric_realm_id"])
        or not isinstance(policy["realm_id"], str)
        or not policy["realm_id"]
    ):
        raise ValueError("invalid realm policy")
    if (
        not isinstance(policy["channel_ids"], list)
        or not policy["channel_ids"]
        or any(not positive(x) for x in policy["channel_ids"])
    ):
        raise ValueError("invalid channels policy")
    if (
        not isinstance(policy["source_sha256"], dict)
        or set(policy["source_sha256"]) != REQUIRED_SOURCES
        or any(
            not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
            for value in policy["source_sha256"].values()
        )
    ):
        raise ValueError("complete installed source pins required")
    return policy


def main():
    signal.alarm(8)
    response = {"format": FORMAT, "allowed": False, "reason": "not_authorized"}
    try:
        if len(sys.argv) != 2:
            raise ValueError("fixed policy argument required")
        data = sys.stdin.buffer.read(4 * 1024**2 + 1)
        if len(data) > 4 * 1024**2:
            raise ValueError("oversized request")
        request = strict_json(data)
        policy = read_policy(sys.argv[1])
        # There is no remote/stdin switch for the privileged operator Bot probe.
        response = observe(request, policy, operator_bot=False)
    except Exception:
        pass
    sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
