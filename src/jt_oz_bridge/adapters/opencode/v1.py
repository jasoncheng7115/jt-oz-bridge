from jt_oz_bridge.adapters.opencode.base import ReadOnlyTransport, UpstreamError


class OpenCodeV1Adapter(ReadOnlyTransport):
    async def probe(self) -> dict[str, object]:
        data = await self.get_object("global/health")
        if data.get("healthy") is not True or not isinstance(data.get("version"), str):
            raise UpstreamError("schema_mismatch")
        return {
            "generation": "v1",
            "version": data["version"],
            "healthy": True,
            "identity_verified": False,
            "certified": False,
        }
