"""Default bridge file disclosure policy; not a Native process sandbox."""

from jt_oz_bridge.security.policy import AccessDenied

DENIED_COMPONENTS = frozenset(
    {
        ".git",
        ".ssh",
        ".aws",
        ".azure",
        ".docker",
        ".gnupg",
        ".kube",
        ".pki",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".pgpass",
        ".git-credentials",
        "auth.json",
        "credentials.json",
        "secrets.json",
        "secrets",
        "credentials",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
    }
)
MANAGED_PREFIXES = (".jt-oz-incoming-", ".jt-oz-preview-")


def canonical_relative(value: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value.encode("utf-8")) <= 4096
        or value.startswith("/")
        or "\\" in value
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
        or any(not p or p in {".", ".."} or len(p.encode("utf-8")) > 255 for p in value.split("/"))
    ):
        raise ValueError("workspace_canonical_relative_path_required")
    return value


def disclosed_path(value: str) -> str:
    value = canonical_relative(value)
    parts = value.casefold().split("/")
    if any(
        p in DENIED_COMPONENTS
        or p == ".env"
        or p.startswith(".env.")
        or p.startswith(MANAGED_PREFIXES)
        for p in parts
    ) or parts[-1].endswith((".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx", ".tfstate")):
        raise AccessDenied("file_return_sensitive_path_disabled")
    return value
