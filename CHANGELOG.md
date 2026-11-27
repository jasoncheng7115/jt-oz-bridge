# Changelog

English · [繁體中文](CHANGELOG_zh-tw.md) · [日本語](CHANGELOG_ja.md)

Versions follow [Semantic Versioning](https://semver.org/). Before 1.0.0 a minor version may change configuration or behaviour; the notes say how to upgrade.

## 0.1.2

- `!export` works again for real conversations. Its safety check refused any finished step with token counts, the time OpenCode started streaming, a tool's start time or a code-mode step's tool names, so every export of a session with a finished reply was refused.
- A turn's reply says what changed and how long the conversation is. It ends with one line naming the files the turn's steps changed (`Changed 3 files: a.py, b.py, c.py`, at most five names, then "… and N more", and a pointer to `!diff` where it works); paths come only from OpenCode's list of changed files, a secret such as `.env` is counted but not named, and a turn that changed nothing gets no line. Once a reply's step read 60,000 tokens or more it also ends with `Context: about 120k tokens`. In the progress message, a command that ended with a non-zero exit code says so (`🔧 bash (exit 1)`).
- The topic says why OpenCode is slow or failed instead of "model thinking" or a bare "Run failed.". While OpenCode retries a failed model call, the "still working" line and `!status` say so with the attempt and the reason (for example too many requests); a failed run or compaction names the cause (authentication, rate limit, timeout, service error, conversation too long, or the error type) without the error's own message; and compaction gets its own 🗜️ lines ("The conversation is long; OpenCode is compacting it", "Conversation compacted") instead of "Setting changed".
- After a restart, messages Bridge missed more than a day ago are no longer reported in the topic again. A restart on 11-25 told a topic about two messages missed in an outage eleven days earlier.
- `!status` sent while a tool runs answers again. When the OpenCode server could not confirm its live state, the fallback asked the same check again and the reply was "This request has expired or is no longer valid". It now says the live state could not be confirmed, names a tool that is still running, and lists the waiting messages.
- A message sent while OpenCode is working joins the running turn again. The Zulip formatting wrapper around the dispatcher dropped the steer flag, so every such message failed before it was sent and was reported as not sent.
- The project site gets colour while staying light: a tinted hero, alternating section bands, numbered cards with coloured edges, green and red fit lists, and a diagram coloured by role (Zulip, the bridge, OpenCode, storage).
- The project site puts the self-hosted, on-premises setup first: a hero that says so, a new section showing the chain from Zulip on your phone through your own Zulip, the bridge and OpenCode to a local model with MCP, and a diagram that marks everything inside your server room. The wording follows the talk that introduced jt-oz-bridge.
- The project site's language choice is one button with a menu instead of three buttons side by side; it closes on a click elsewhere or Esc.

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
