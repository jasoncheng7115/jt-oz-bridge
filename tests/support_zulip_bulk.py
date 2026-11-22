"""Synthetic official batch routes over the same original server metadata."""

import json

import httpx


def batch_transport(original):
    """Same synthetic underlying metadata, exposed through official batch APIs."""

    def peer(request):
        route = request.url.path.removeprefix("/api/v1/")
        base = str(request.url).split("/api/v1/")[0] + "/api/v1/"
        if route == "users/me/subscriptions":
            assert dict(request.url.params) == {"include_subscribers": "true"}
            raw = original(httpx.Request("GET", base + "streams/10")).json()["stream"]
            members = original(httpx.Request("GET", base + "streams/10/members")).json()[
                "subscribers"
            ]
            return httpx.Response(
                200,
                json={
                    "result": "success",
                    "subscriptions": [{**raw, "is_archived": False, "subscribers": members}],
                },
            )
        if route == "users":
            assert (
                request.url.params["client_gravatar"]
                == request.url.params["include_custom_profile_fields"]
                == "false"
            )
            ids = json.loads(request.url.params["user_ids"])
            profiles = [
                original(httpx.Request("GET", base + "users/" + str(uid))).json()["user"]
                for uid in ids
            ]
            return httpx.Response(200, json={"result": "success", "members": profiles})
        return original(request)

    return peer
