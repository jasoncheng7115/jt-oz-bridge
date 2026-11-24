# Changelog

English · [繁體中文](CHANGELOG_zh-tw.md) · [日本語](CHANGELOG_ja.md)

Versions follow [Semantic Versioning](https://semver.org/). Before 1.0.0 a minor version may change configuration or behaviour; the notes say how to upgrade.

## Unreleased

- The project site gets colour while staying light: a tinted hero, alternating section bands, numbered cards with coloured edges, green and red fit lists, and a diagram coloured by role (Zulip, the bridge, OpenCode, storage).

## 0.1.1

- The public CI gate reads the one published commit author from the repository variable `JTOZ_PUBLIC_IDENTITY` (or `--identity`). Without it the gate refused that author's address, so 0.1.0 was tagged but never released.
- The Traditional Chinese and Japanese README tables show the offline install in bold instead of literal asterisks; a test now renders every project document and refuses emphasis markers left as text.
- The project site is rewritten in plain words around a sample topic, with when the bridge fits and when it does not; the home page opens in the visitor's language. It stays light whatever the system theme.
- CI lists each failed test as an annotation on the run page, which anyone can read, since the job log needs admin rights. Each annotation carries the end of the traceback.
- `jt-oz-bridge sessions` and the other local inspection commands report a peer the observer does not allow as `unauthorized` (exit 4) every time. The observer closed such a connection before reading the request, so a client that wrote a moment later saw a failed write and reported the observer as unavailable (exit 2).

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
