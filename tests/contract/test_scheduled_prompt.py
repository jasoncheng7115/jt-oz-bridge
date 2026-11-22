"""Actual V2 prompt preflight and durable correlation for a timed send; synthetic peers only."""

import copy
import json
from uuid import uuid4

import httpx
import pytest

from jt_oz_bridge.domain.execution import Admission, MutationNotSent
from jt_oz_bridge.domain.schedules import ScheduleFire, detect
from jt_oz_bridge.services.execution_receipts import ExecutionReceipt
from jt_oz_bridge.services.resource_execution_results import correlation
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action
from tests.contract.test_leaf_resources import REF, finish
from tests.contract.test_native_project_policy import setup as policy_setup
from tests.integration.test_dispatch import message

ASK = "每半小時檢查一下建置佇列的狀態, 直到 13:00 為止"
TASK = "檢查一下建置佇列的狀態"


def payload(text=ASK):
    source = message(text=text)
    fire = ScheduleFire(id=str(uuid4()), index=1, total=8, ask=detect(ASK))
    data = {
        "operation": "prompt",
        "reference": REF.model_dump(mode="json"),
        "text": TASK,
        "source": source.model_dump(mode="json"),
        "reply_locale": "zh-TW",
        "schedule": fire.model_dump(mode="json"),
    }
    return source, data, str(uuid4())


async def setup():
    p, t, d, g, client, policy_calls, writes = await policy_setup()
    original = t.client._transport

    def handler(request):
        if request.method != "POST" or not request.url.path.endswith("/prompt"):
            return original.handler(request)
        writes.append(request)
        body = json.loads(request.content)
        ack = {
            "id": "msg_scheduled",
            "sessionID": REF.upstream_session_id,
            "time": {"created": 1},
            "type": "user",
            "payload": {k: copy.deepcopy(v) for k, v in body.items() if k != "delivery"},
            "delivery": "queue",
        }
        return httpx.Response(200, json={"data": ack})

    t.client._transport = httpx.MockTransport(handler)
    return p, t, client, writes


async def test_a_timed_send_posts_only_the_task_its_source_asks_for():
    p, t, client, writes = await setup()
    source, frozen, action = payload()
    try:
        admission = await client.submit(REF, frozen, action)
        assert admission.status == "admitted" and admission.upstream_id == "msg_scheduled"
        (write,) = writes
        body = json.loads(write.content)
        assert body["text"] == TASK and body["delivery"] == "queue"
        assert not any(k in body for k in ("files", "agents", "skills", "schedule"))
    finally:
        await finish(p, t)


@pytest.mark.parametrize("change", ["text", "source", "fire", "attachments", "plain"])
async def test_a_changed_timed_send_is_refused_before_any_post(change):
    p, t, client, writes = await setup()
    source, frozen, action = payload()
    if change == "text":
        frozen["text"] = ASK
    elif change == "source":
        frozen["source"]["text"] = ASK.replace("13:00", "12:00")
    elif change == "fire":
        frozen["schedule"]["ask"]["interval_seconds"] = 600
    elif change == "attachments":
        frozen["attachments"] = {"files": []}
    else:
        frozen.pop("schedule")
    try:
        with pytest.raises(MutationNotSent):
            await client.submit(REF, frozen, action)
        assert not writes
    finally:
        await finish(p, t)


def admitted(frozen, action):
    receipt = ExecutionReceipt(
        action_id=action,
        operation_digest=digest(frozen),
        reference=REF,
        contract_sha256="a" * 64,
        admission=Admission(status="admitted", upstream_id="msg_scheduled"),
    )
    return Action(
        id=action,
        operation="prompt",
        owner="opencode",
        actor_id=7,
        payload=frozen,
        operation_digest=digest(frozen),
        upstream_id="msg_scheduled",
        admission=receipt.model_dump(mode="json"),
    )


def test_durable_correlation_expects_the_task_not_the_whole_message():
    source, frozen, action = payload()
    assert correlation(admitted(frozen, action)).text == TASK
    changed = copy.deepcopy(frozen)
    changed["source"]["text"] = ASK.replace("13:00", "12:00")
    with pytest.raises(Conflict):
        correlation(admitted(changed, action))
    plain = copy.deepcopy(frozen)
    plain.pop("schedule")
    with pytest.raises(Conflict):
        correlation(admitted(plain, action))
