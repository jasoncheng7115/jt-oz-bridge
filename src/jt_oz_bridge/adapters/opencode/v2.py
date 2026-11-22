from jt_oz_bridge.adapters.opencode.base import ReadOnlyTransport


class OpenCodeV2Adapter(ReadOnlyTransport):
    async def probe(self) -> dict[str, object]:
        # Route documented in the supplied inventory; shape is not installation-certified.
        await self.get_object("api/info")
        return {
            "generation": "v2",
            "identity_verified": False,
            "certified": False,
            "status": "requires_installed_contract",
        }
