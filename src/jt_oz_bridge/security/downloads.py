"""Explicit HTTPS origins and DNS pinning for untrusted attachment URLs."""

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import unquote

import httpx

PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)
TRANSITION_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32")
)


class DownloadDenied(ValueError):
    pass


def checked_url(value: str) -> httpx.URL:
    if (
        len(value) > 16384
        or "\\" in value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise DownloadDenied("invalid_download_url")
    try:
        url = httpx.URL(value)
        if (
            url.scheme != "https"
            or not url.host
            or url.userinfo
            or "#" in value
            or url.port == 0
            or "%" in url.host
            or unquote(url.path).startswith("//")
        ):
            raise ValueError("invalid origin")
        return url
    except (ValueError, httpx.InvalidURL):
        raise DownloadDenied("invalid_download_url") from None


def origin_key(url: httpx.URL) -> tuple[str, int]:
    return url.raw_host.decode("ascii"), 443 if url.port is None else url.port


def private_subnet(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    allowed: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> bool:
    if isinstance(network, ipaddress.IPv4Network) and isinstance(allowed, ipaddress.IPv4Network):
        return network.subnet_of(allowed)
    if isinstance(network, ipaddress.IPv6Network) and isinstance(allowed, ipaddress.IPv6Network):
        return network.subnet_of(allowed)
    return False


@dataclass(frozen=True)
class DownloadOrigin:
    url: str
    private_networks: tuple[str, ...] = ()
    path_prefixes: tuple[str, ...] = ("/",)

    def __post_init__(self) -> None:
        url = checked_url(self.url)
        if url.path not in {"", "/"} or url.query:
            raise DownloadDenied("download_origin_must_not_include_path_or_query")
        try:
            for value in self.private_networks:
                network = ipaddress.ip_network(value)
                if not any(private_subnet(network, allowed) for allowed in PRIVATE_NETWORKS):
                    raise ValueError("not an ordinary private unicast range")
        except ValueError:
            raise DownloadDenied("private_download_network_not_allowed") from None
        if not self.path_prefixes or any(
            not prefix.startswith("/")
            or any(char in prefix for char in "\\%?#")
            or any(segment in {".", ".."} for segment in prefix.split("/"))
            for prefix in self.path_prefixes
        ):
            raise DownloadDenied("download_path_prefix_invalid")

    @property
    def key(self) -> tuple[str, int]:
        return origin_key(checked_url(self.url))

    def allows(self, value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
            if isinstance(address, ipaddress.IPv6Address) and any(
                address in network for network in TRANSITION_NETWORKS
            ):
                return False
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            if (
                address.is_loopback
                or address.is_link_local
                or address.is_multicast
                or address.is_unspecified
                or address.is_reserved
            ):
                return False
            if address.is_global and not self.private_networks:
                return True
            return any(
                address.version == network.version and address in network
                for network in (ipaddress.ip_network(item) for item in self.private_networks)
            )
        except ValueError:
            return False


class Resolver(Protocol):
    async def resolve(self, host: str, port: int) -> tuple[str, ...]: ...


class SystemResolver:
    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        try:
            address = ipaddress.ip_address(host)
            return (str(address),)
        except ValueError:
            pass
        try:
            rows = await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM), 10
            )
            addresses = tuple(dict.fromkeys(str(row[4][0]) for row in rows))
            if not addresses or len(addresses) > 32:
                raise DownloadDenied("download_dns_answer_rejected")
            return addresses
        except (OSError, TimeoutError):
            raise DownloadDenied("download_dns_unavailable") from None


class DownloadPolicy:
    def __init__(
        self, origins: tuple[DownloadOrigin, ...], resolver: Resolver | None = None
    ) -> None:
        self.origins = {item.key: item for item in origins}
        if not origins or len(self.origins) != len(origins):
            raise DownloadDenied("unique_explicit_download_origins_required")
        self.resolver = resolver or SystemResolver()

    async def pin(self, value: str) -> tuple[httpx.URL, httpx.URL]:
        original = checked_url(value)
        origin = self.origins.get(origin_key(original))
        if origin is None:
            raise DownloadDenied("download_origin_not_enrolled")
        path = unquote(original.path)
        if any(segment in {".", ".."} for segment in path.split("/")) or not any(
            path.startswith(prefix) for prefix in origin.path_prefixes
        ):
            raise DownloadDenied("download_path_not_enrolled")
        host, port = origin_key(original)
        addresses = await self.resolver.resolve(host, port)
        if (
            not addresses
            or len(addresses) > 32
            or any(not origin.allows(item) for item in addresses)
        ):
            raise DownloadDenied("download_dns_address_not_allowed")
        # No second DNS lookup at connect: the URL carries the validated IP.
        return original, original.copy_with(host=str(ipaddress.ip_address(addresses[0])))
