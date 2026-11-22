"""Real TLS/SNI; the test backend maps a validated public IP onto loopback."""

import asyncio
import contextlib
import ssl
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from httpcore._backends.anyio import AnyIOBackend

from jt_oz_bridge.adapters.zulip.download import SafeDownloader
from jt_oz_bridge.security.downloads import DownloadDenied, DownloadOrigin, DownloadPolicy
from tests.contract.test_safe_download import DNS


def certificates(root, hostname):
    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Ephemeral test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    ca_file, cert_file, key_file = root / "ca.pem", root / "leaf.pem", root / "leaf-key.pem"
    ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_file.chmod(0o600)
    return ca_file, cert_file, key_file


@pytest.mark.parametrize("mode", ["valid", "wrong-hostname", "untrusted-ca"])
async def test_pinned_ip_still_uses_original_tls_hostname_and_ca_verification(tmp_path, mode):
    hostname = "other.example" if mode == "wrong-hostname" else "files.example"
    ca_file, cert_file, key_file = certificates(tmp_path, hostname)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    observed_sni, requests, connections = [], [], []
    context.set_servername_callback(lambda ssl_object, name, ssl_context: observed_sni.append(name))

    async def serve(reader, writer):
        try:
            request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)
            requests.append(request)
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 10\r\nConnection: close\r\n\r\nTLS bytes!"
            )
            await writer.drain()
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

    server = await asyncio.start_server(serve, "127.0.0.1", 0, ssl=context)
    listening_port = server.sockets[0].getsockname()[1]

    class MappedBackend:
        async def connect_tcp(self, host, port, **kwargs):
            connections.append((host, port))
            assert host == "8.8.8.8" and port == 443
            return await AnyIOBackend().connect_tcp("127.0.0.1", listening_port, **kwargs)

    verify = ssl.create_default_context(cafile=None if mode == "untrusted-ca" else str(ca_file))
    transport = httpx.AsyncHTTPTransport(
        verify=verify, limits=httpx.Limits(max_keepalive_connections=0)
    )
    transport._pool._network_backend = MappedBackend()
    downloader = SafeDownloader(
        DownloadPolicy((DownloadOrigin("https://files.example"),), DNS()), transport=transport
    )
    try:
        if mode == "valid":
            async with downloader.open(
                "https://files.example/file?signature=ephemeral"
            ) as download:
                assert b"".join([chunk async for chunk in download.chunks()]) == b"TLS bytes!"
            assert b"Host: files.example" in requests[0] or b"host: files.example" in requests[0]
        else:
            with pytest.raises(DownloadDenied, match="tls"):
                async with downloader.open("https://files.example/file"):
                    pytest.fail("TLS accepted")
            assert not requests
        assert connections == [("8.8.8.8", 443)]
        assert observed_sni == ["files.example"]
    finally:
        await downloader.close()
        server.close()
        await server.wait_closed()
