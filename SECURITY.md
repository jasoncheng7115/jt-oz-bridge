# Security policy and verification

[繁體中文](SECURITY_zh-tw.md) · [Testing](docs/TESTING.md)

`jt-oz-bridge` is a development build. Passing automated tests does not certify a public deployment, and acceptance by real people and on phones is not complete. Report suspected vulnerabilities privately to the project owner, with redacted reproduction steps. Do not publish credentials, pairing links, private attachment URLs, conversation contents or connection SOPs in an issue.

## Trust boundaries

- Authorize the verified Human, realm and project, then the exact channel/topic, binding revision and original backend/session. Channel membership alone does not grant operation rights. Bots and model output cannot grant permissions or approve their own requests.
- Recheck the source message, audience, grants and current upstream scope before effects and delivery. Edited/deleted messages, revoked access, moved topics, expired choices and changed state must invalidate the affected operation. A response with an unknown outcome must not be blindly retried.
- Preserve the original OpenCode tool/MCP permissions. Bridge confirmations and disclosure rules cannot constrain an unrestricted upstream shell. An owner-authorized Native account with sudo can administer its container and read container secrets; Bridge process isolation does not change that authority. Prompt-injection resistance is not a claim that such an agent is sandboxed.
- Run Bridge and metadata helpers separately with their own service accounts and filesystem limits. Never mount an entire Native home directory or a container-management socket into Bridge for convenience.

## Files and generated pages

1. Accept only attachments associated with the verified original authorized message. Use the explicit HTTPS storage origin, a narrow private-IP exception where needed, DNS-pinned connections and independently checked redirects. Never forward Bot credentials or cookies to a download endpoint.
2. Enforce per-file, batch, response and storage limits. Verify received size and SHA-256, use encrypted Bridge storage, and bind the result to the original session/topic. Recognizable-secret checks supplement path authorization; they are neither complete data-loss prevention nor an antivirus scanner.
3. Reject traversal, absolute paths, sensitive/managed names and unproved physical directory boundaries. A syntactically relative path is not proof that its ancestor is inside the project. Recheck current filesystem identity; do not follow a symlink merely because an upstream catalog lists it. Nonempty session diffs need separate boundary qualification before enablement.
4. Preserve downloadable original bytes, including HTML. Bridge must not turn a returned HTML/JavaScript file into executable markup in its admin UI or a trusted chat control. Verify the installed download response, including attachment disposition and `nosniff`; do not infer this from the filename or upload success.
5. **Interactive HTML preview is not implemented.** Before adding it, require separately authenticated authorization for the same actor/session, a distinct origin without Zulip/Native credentials, and isolated execution. Untrusted pages must not receive host paths, service credentials, unrestricted network access or control APIs. Bound browser resources, lifetime and cleanup. A screenshot renderer needs the same isolation. A secret link alone is not Human authentication.

## Authentication and exposure

Keep the committed dependency lock and audit the actual installed set. Every release has an SBOM, `jt-oz-bridge-<version>.sbom.cdx.json` (CycloneDX 1.5): the runtime dependencies from the lock, each with the license of the exact version the full gate tested, and the wheel's SHA-256. The gate fails if the SBOM differs from the tested environment or misses a wheel requirement. Certifi must be at least `2026.10.19`, following the [emSign trust-store security advisory](https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2). Do not suppress the advisory or disable TLS verification to make an installation pass; rebuilding an artifact requires a fresh full test and installed qualification.

Use trusted HTTPS and verify the hostname/certificate. Restrict access at the real network/proxy boundary; an absent public DNS record does not block clients that supply Host/SNI themselves. Trust forwarded client identity only from explicitly trusted proxies, and test the actual route. A gateway that replaces external source addresses with an allowed LAN address needs enforcement at that gateway.

Keep Native authentication, Bridge administrator authentication and Zulip authentication separate. Admin mutations require server-side authentication and CSRF checks; GET and link previews must not approve operations. Secure/HttpOnly/SameSite cookies, no-store responses, bounded requests and login throttling remain required. TOTP does not replace protection of Bot API keys, service credentials or an already authenticated device.

Keep keys outside the source tree and separate from database backups. Do not log passwords, one-time links, signed download URLs or raw sensitive exception bodies. Public export review must exclude private deployment records and connection SOPs; `.gitignore` alone is insufficient.

## Required verification

| Area | Required evidence |
|---|---|
| Authorization | Wrong user/realm/project/topic/session, changed audience, Bot messages, revoked grants, edited source and expired/replayed tokens fail without side effects. |
| Files | SSRF/DNS/redirect failures, size/hash mismatch, symlink/path changes, quota exhaustion and ambiguous uploads cannot become a successful transfer or duplicate send. |
| Web/admin | Authentication, CSRF, throttling, cookie/header behavior, escaped hostile content and GET/link-preview safety. |
| Deployment | Actual service identity/permissions, listeners, active firewall, proxy peer handling, trusted TLS, unauthenticated API rejection and the complete WAN/NAT path. |
| Recovery/export | Crash/restart and backup/restore preserve authorization and uncertainty; logs, exports and public packages omit credentials and private operational material. |
| Human/mobile | Real authorized upload/download, exact bytes and topic/session mapping on supported clients. Automated peers cannot replace these cases. |

Every feature or version change runs the complete test suite against the exact source and wheel. Failed results are kept, and synthetic, installed, external-network and real-person results are told apart. A check of one installation is an observation on that date, not a statement that every item above has passed.
