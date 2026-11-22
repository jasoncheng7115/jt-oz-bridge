# Changelog

English · [繁體中文](CHANGELOG_zh-tw.md) · [日本語](CHANGELOG_ja.md)

Versions follow [Semantic Versioning](https://semver.org/). Before 1.0.0 a minor version may change configuration or behaviour; the notes say how to upgrade.

## 0.1.1

- The public CI gate reads the one published commit author from the repository variable `JTOZ_PUBLIC_IDENTITY` (or `--identity`). Without it the gate refused that author's address, so 0.1.0 was tagged but never released.

## 0.1.0

First public preview. It is not a finished production release: see the status note in the [README](README.md).

- Chat with an existing OpenCode session from a Zulip topic: the same session you use at your desk, never a copy or a fork.
- Progress while the agent works, edited in place, and a note when a reply waits on a tool or on the model.
- Messages sent while the agent is busy join the running turn, or wait for their own turn when they cannot.
- Permission requests and questions answered from the phone with a short command, or a button on the desktop.
- Start a new conversation from chat, choose the model from OpenCode's own catalog, and schedule prompts.
- File transfer in both directions in projects that enable it; HTML is offered as a download only.
- Automatic recovery after a restart of the bridge, OpenCode or the host, with one notice in the status topic when something needs an administrator.
- Upgrade checks before an OpenCode or Zulip upgrade, and a daily notice of new releases.
- Python 3.13, SQLite by default, CycloneDX SBOM for each release, GPL-3.0-only.
