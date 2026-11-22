"""A confirmed Git request is one ordinary queued prompt on the wire; mocks only."""

import json
import time

import pytest

from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.execution import MutationNotSent
from jt_oz_bridge.domain.git_publish import GitPublishPlan, GitPublishRequest, GitPublishState
from jt_oz_bridge.security.admin import token_hash
from jt_oz_bridge.storage.durable import digest
from tests.contract.test_v2_execution import REF, profile, setup  # noqa: F401
from tests.integration.test_dispatch import message


def request(**changes):
    before = GitPublishState(
        reference=REF,
        branch="main",
        files=(),
        hidden_files=0,
        conflict_files=0,
        remote="origin",
        tracking_present=True,
        comparison="origin/main",
        ahead=(),
    )
    plan = GitPublishPlan(
        kind="push",
        directory=REF.canonical_directory,
        branch="main",
        remote="origin",
        state_sha256=digest(before.model_dump(mode="json")),
    )
    value = GitPublishRequest(
        reference=REF,
        source=message(message_id=102, revision=0, text="!confirm token-1"),
        preview=message(message_id=101, revision=0, text="!oz git push"),
        plan=plan,
        before=before,
        text=plan.prompt(),
        reply_locale="en",
        confirm_expires_at=time.time() + 60,
        confirmation_token_sha256=token_hash("token-1"),
    ).model_dump(mode="json")
    return {**value, **changes}


async def test_git_publish_is_one_queued_prompt_with_only_the_fixed_text(profile):  # noqa: F811
    client, transport, proof, data, seen = setup(profile)
    sent_request = request()
    try:
        assert client.capabilities(REF)["git.publish"].supported
        result = await client.submit(REF, sent_request, "action-git")
        assert result.status == "admitted" and result.upstream_id == "msg_original"
        assert result.details == {
            "operation": "git.publish",
            "delivery": "queue",
            "turn_completed": False,
            "git_verified": False,
        }
        posts = [r for r in seen if r.method != "GET"]
        assert len(posts) == 1 and posts[0].url.path == "/api/session/ses_original/prompt"
        wire = json.loads(posts[0].content)
        assert set(wire) == {"text", "delivery", "metadata"}
        assert wire["text"] == sent_request["text"] and wire["delivery"] == "queue"
        assert "push origin main" in wire["text"] and "--force" not in wire["text"].split("\n")[2]
    finally:
        await transport.close()


@pytest.mark.parametrize("change", ["busy", "expired", "text", "source", "reference"])
async def test_git_publish_preflight_never_sends_a_changed_request(profile, change):  # noqa: F811
    client, transport, proof, data, seen = setup(profile)
    sent_request = request()
    if change == "busy":
        proof.state = ExecutionState.RUNNING
    elif change == "expired":
        sent_request["confirm_expires_at"] = time.time() - 1
    elif change == "text":
        sent_request["text"] += "\nrm -rf /"
    elif change == "source":
        sent_request["source"]["text"] = "please push"
    else:
        sent_request["reference"]["upstream_session_id"] = "ses_other"
    try:
        with pytest.raises(MutationNotSent):
            await client.submit(REF, sent_request, "action-git")
        assert all(r.method == "GET" for r in seen)
    finally:
        await transport.close()
