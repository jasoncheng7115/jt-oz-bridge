# Operations SOP

[繁體中文](OPERATIONS_SOP_zh-tw.md) · [Install](INSTALL.md) · [Upgrade](UPGRADE.md) · [Testing](TESTING.md)

How to run jt-oz-bridge on a Linux host next to an existing OpenCode. Paths are the defaults: `/etc/jt-oz-bridge` for config, `/var/lib/jt-oz-bridge/service` for state, `/opt/jt-oz-bridge/releases/<wheel-sha256>` for releases. This is a development build (0.1.2) with no formal release yet; following these steps does not by itself make a deployment production-ready.

## Rules that always apply

- **Never restart OpenCode as part of a Bridge operation.** Bridge has its own lifecycle. A restart ends the live feed of active conversations and needs approval from whoever runs OpenCode.
- **Never read or copy the OpenCode database.** Bridge uses its API only. Checking the file's metadata with `stat` is fine.
- Never create, fork or copy a conversation to get past a problem.
- Never restore an older Bridge database over newer data, and never downgrade past a schema that already migrated. Fix forward.
- Never resume held work for someone. Resuming (`!go`) belongs to the person in that topic. A Bridge restart sends messages from the last 10 minutes by itself (also ones sent while it was offline) and replies once where older ones wait. A restart or outage pause also continues when that person sends a new message, unless work is running, unclear or held for another reason. A pause someone chose is never lifted automatically.
- Keep secrets in owner-only files. Commands below take references to them, never values.
- Bridge rules do not contain a privileged OpenCode. If OpenCode has sudo, Bridge approvals are not a sandbox.

## Install

Follow [Install](INSTALL.md) for the configuration, secret files, key and first migration. In short:

1. Create the service user and an owner-only state directory.
2. Build a release directory (see step 2 of the next section).
3. Write `/etc/jt-oz-bridge/config.toml` from `config.example.toml`, then run `jt-oz-bridge --config <config> validate`, which opens no connection.
4. As the service user, run `generate-key` once and back the key up separately. Then run `migrate`.
5. Install the units from `ops/server/`: `jt-oz-bridge.service`, `jt-oz-observer.service` and the helper sockets. Add drop-ins that point `ExecStart` at the release.
6. Onboard at least one project (below), then start the services.

## Deploy a new release

Features go out as one batch: full gate, inactive install, then a short switch with an automatic rollback.

### 1. Run the full test suite

Take the wheel and its SBOM (`jt-oz-bridge-<version>.sbom.cdx.json`) from the GitHub release, or build both from the same checkout. Run the whole suite on that checkout first, as a non-root user on a host with a real CPU: running as root fails the file permission tests, and a slow virtual CPU misses the time limits.

```sh
uv sync --locked
uv run ruff check src tests scripts && uv run mypy src
uv run pytest -q -p no:cacheprovider tests
uv build --wheel --out-dir dist
uv run python -m scripts.make_sbom --uv uv --wheel dist/<wheel> --output dist/jt-oz-bridge-<version>.sbom.cdx.json
```

Every test must pass with zero skips. A pass belongs only to the wheel built from that checkout, so install that wheel and that SBOM together. Do not change the checkout while the suite runs. Before large runs, check free disk: at least 12 GiB, and stop if the disk would pass 80%.

### 2. Install the release inactive

```sh
R=/opt/jt-oz-bridge/releases/<wheel-sha256>
install -d -o root -g <service-group> -m 755 "$R"
cp <wheel> uv.lock pyproject.toml "$R/"
uv export --frozen --no-dev --no-emit-project --format requirements-txt -o "$R/requirements.txt"
uv venv --python <python3.13> "$R/venv"
uv pip install --python "$R/venv/bin/python" --require-hashes -r "$R/requirements.txt"
uv pip install --python "$R/venv/bin/python" --no-deps "$R/<wheel>"
runuser -u <service-user> -- "$R/venv/bin/jt-oz-bridge" --config /etc/jt-oz-bridge/config.toml validate
```

The running service is not touched by this. Files must be readable by the service group.

### 3. Switch, with automatic rollback

Script these steps so that any failure after step 4 runs the rollback, up to a schema migration (step 7). Save everything to a new root-only control directory.

1. Check that the current drop-ins name the old release, that the wheel hash matches, and that `/etc/jt-oz-bridge/promotion-active` does not exist. That file blocks service start.
2. Record the OpenCode identity: `systemctl show opencode -p MainPID -p ExecMainStartTimestampMonotonic -p NRestarts -p InvocationID`.
3. Save both drop-ins and the CLI symlink target.
4. `systemctl stop jt-oz-bridge jt-oz-observer`
5. Back up the Bridge database with the SQLite backup API into the control directory, mode 600. This copy is only for going back. Take a full snapshot for real backups.
6. Note unfinished deliveries and open actions. Stop here if unfinished output depends on something the release changes.
7. If the schema changes, run `migrate` as the service user. **From here, code rollback no longer applies**, because the older release cannot read the newer database. Fix forward.
8. Point both drop-ins and the CLI symlink at the new release, then run `systemctl daemon-reload` and start both services.
9. Smoke test after 30 seconds. Both units are active with `NRestarts=0`, `ExecStart` names the new release, the OpenCode identity is unchanged, the schema is the expected one, `/readyz` says ready, and `journalctl -p warning` shows nothing new.
10. Any failure rolls back, unless step 7 migrated the database (then fix forward): restore the drop-ins and the CLI symlink, `daemon-reload`, restart both services, and check again.

The smoke test only proves the service started. Chat, buttons, files and phones still need a person to try them in the official desktop and phone apps.

Rolling back to a release older than button-saved queue replies leaves receipts that older code cannot replay: a closed-queue reply saved with buttons has a `widget` field, and a bare "ok" Bridge asked about has a `bare-answer` receipt. Only a redelivered event of such a message is affected; it is held instead of replayed.

## Onboard a project

Run `ops/server/onboard_root.py` with the selected release's Python, as root. It proves one existing conversation against this host using read-only requests and controlled test files. It never opens the OpenCode database and never restarts OpenCode.

The spec file names `tag`, `release`, `project_id`, `directory`, `session_id`, `native_project_id` and `probe_socket`.

```sh
PY="<release>/venv/bin/python -I -B"
$PY onboard_root.py prepare   --spec spec.json
$PY onboard_root.py directory --spec spec.json
# Run a private directory helper on probe_socket, using the generated helper config
$PY onboard_root.py probe     --spec spec.json
$PY onboard_root.py cleanup   --spec spec.json
$PY onboard_root.py seal      --spec spec.json
runuser -u <service-user> -- <release>/venv/bin/jt-oz-bridge --config <sealed-config> validate
```

Run `cleanup` even if `probe` fails. These steps run beside the live service. Then activate in one short window, keeping copies of the helper config, main config and observer file for rollback:

1. Stop the observer and Bridge. Back up the Bridge database as above.
2. Install the new helper config and restart only the directory helper.
3. Run `enroll-runtime` with the sealed config, as the service user.
4. Install the sealed config and observer file, then start Bridge and the observer.
5. Confirm OpenCode's identity is unchanged. On any failure, restore the copies and restart.

Grant only the people who should use that project. Check what the conversation's agent can do before you grant anyone. A conversation with broad tools gives that reach to everyone granted.

## Allow new conversations in a project

Run `ops/server/certify_creation.py` as root with the selected release's Python. `plan` sends only GET requests. It prints the request it would send and the policy-template checksum. `certify` sends exactly one `session.create`, and only with `--template-sha256 <checksum from plan> --i-understand-this-creates-a-permanent-native-session`. That leaves a permanent OpenCode conversation; chat cannot delete it. Use the agent's own permission rules as the new conversation's rules, so new conversations get exactly the permissions existing ones have. The tool writes the evidence and a `creation_projects` entry. Then:

1. Add that entry to a new runtime manifest. Add `session.create` and `session.get` to `verified_operations` of every Root on that backend.
2. Point a copy of the config at it and set `session_creation_enabled = true`. Update `runtime_enrollment_sha256` in a copy of the observer file.
3. Validate the copy as the service user. Then switch in one short window, the same way as a release switch. Keep the old config and observer files so a rollback restores them.

New conversations can use `!files` and `!file` when their rules equal the source conversation's and the project has no saved approvals. Copying the agent's own rules, as above, meets that.

Once a conversation has been created through chat, do not roll back to a release without creation support: its startup restoration rejects the newer creation records and Bridge stops. Fix forward instead.

## One private channel per project

`[[zulip_realms.channel_projects]]` maps a channel to the projects it serves. A new topic in a listed channel offers only those projects, including **Start a new conversation**. Unlisted channels keep offering every project. The listed channel must already be in `allowed_channel_ids`. Bindings made from a listed channel cannot reach other projects through any menu or token.

1. In Zulip, create a private channel with protected history. Add the bot and only the people granted that project.
2. Add the channel ID to `allowed_channel_ids`, and add a `channel_projects` entry with `channel_id` and `projects`.
3. Run `enroll-runtime` with the new config as the service user, with Bridge stopped. It checks that the channel is private and that every member is approved.
4. Switch as above, keeping the old config for rollback.

## Enable file transfer

Downloads with `!file` come with onboarding. Uploads are off until you run `ops/server/enable_file_transfer.py`, one conversation at a time. Automatic return of generated files is separate (see [below](#allow-automatic-return-of-generated-files)).

```sh
PY="<release>/venv/bin/python -I -B"
$PY enable_file_transfer.py preflight --spec spec.json     # writes nothing
$PY enable_file_transfer.py prepare   --spec spec.json     # exit 3 means: waiting for a real upload
# A person uploads one real file in that conversation's topic, then:
$PY enable_file_transfer.py scan-source --spec spec.json
$PY enable_file_transfer.py prepare   --spec spec.json --message-id <id>
$PY enable_file_transfer.py activate  --spec spec.json     # short stop, rolls back on failed smoke test
$PY enable_file_transfer.py status    --spec spec.json
```

The selected release must support per-conversation file scope; otherwise the tool reports `release_lacks_workspace_roots_scope`, and you deploy a newer release first. The tool needs one real upload from a person. It never posts to Zulip and never fabricates one. Other conversations' entries stay identical. A project under `/home` is refused because the service cannot see that path. Use `rollback` and `namespace-remove` to go back. Then have a person try an upload and a `!file` download in that topic, on desktop and on a phone.

## Allow automatic return of generated files

Automatic return of files the AI creates is off by default and is enabled one enrolled Root at a time. [`certify_generated.py`](../ops/server/certify_generated.py) issues that Root's scoped `qualified-generated-outputs-v2` bundle and stages the switch. The bundle qualifies only the output origins and the largest size its real cases read; every other output counts as unsupported (see scoped qualification). Run it as root with the selected release's Python, one step at a time:

```sh
$PY certify_generated.py plan    --spec spec.json   # GET only, writes nothing
$PY certify_generated.py certify --spec spec.json --plan-sha256 <from plan> \
    --i-understand-this-sends-operator-prompts-to-the-original-root
$PY certify_generated.py stage   --spec spec.json   # no OpenCode request
```

`spec.json` names `tag` and exactly one of `project_id` or `session_id`; `config`, `observer`, `output` and `stage` are optional absolute paths, and the two output directories must not exist.

- `certify` sends at most 2 operator prompts and at most 12 permission replies to that Root. It answers `once` only for the planned files inside `<directory>/jt-oz-generated-<tag>` and the one planned command, `reject` for anything else, never `always`. Every other mutation, and anything over 8000 GETs or 2 GiB of responses, is refused. No interrupt, form reply or retry is sent.
- The worker runs as the Bridge service user in a transient unit. It never opens the OpenCode database and never restarts OpenCode; OpenCode's PID, restart count and binary SHA-256 must be identical before and after.
- Six negative checks run against the real reader with the real captured outputs. The bundle is written only if every field was observed and the runtime validator accepts it; otherwise `FAILED.json` and the rejected bundle stay in the output directory.
- The planned files stay in the Root's workspace, and the operator turns become part of its history (and may be mirrored into a bound topic). These operator prompts do not replace a person trying the feature in chat and on a phone.
- `stage` writes a new `runtime.json`, a `config.toml` with only `enrollment_file` and `generated_returns_enabled = true` changed, and an observer file with only `runtime_enrollment_sha256` repinned, after the runtime's own loaders accept them. Nothing is active until you switch to the staged files as above.

## Allow subagents (tree lineage)

A leaf-qualified Root refuses all work once its agent starts a subagent (`leaf_descendants_require_qualification`). [`certify_lineage.py`](../ops/server/certify_lineage.py) issues the operator-reviewed `installed-original-lineage-resource-observation-v1` document (`qualification_scope: "tree"`) and stages the `adoption_projects` entry that switches one enrolled Root to the tree provider (see explicit runtime pins). Run it as root with the selected release's Python, one step at a time:

```sh
$PY certify_lineage.py plan    --spec spec.json   # GET only, writes nothing
$PY certify_lineage.py certify --spec spec.json --plan-sha256 <from plan> \
    --i-understand-this-sends-operator-prompts-to-the-target-session
$PY certify_lineage.py stage   --spec spec.json   # GET only, then writes the stage
```

`spec.json` names `tag`, the anchor Root by exactly one of `project_id` or `session_id`, and `target_session_id`: a disposable, childless top-level session in the anchor's project and directory that Bridge does not know (not enrolled, not chat-created or forked), for example one opened in the TUI for this purpose. `config`, `observer`, `output` and `stage` are optional absolute paths; the two output directories must not exist.

- The observation is taken on the target, never on the anchor, because a subagent can never be removed from a session. The runtime records a first tree baseline for the anchor and each chat-created Root of its project only while that Root has no child. `plan` lists any Root that already has one as `activation_blockers`, and `stage` refuses while any remains.
- `certify` sends at most 2 operator prompts to the target (one starts a `general` subagent that writes `<directory>/jt-oz-lineage-<tag>/child.txt`, the other a subagent that starts one more) and answers at most 6 permission requests of the target and its verified descendants: `once` only for the planned `task` start and that one file, `reject` for anything else, never `always`. Anything over 12000 GETs is refused; no interrupt, form reply or retry is sent.
- Every observation window is GET-only and must count zero mutations. Ten checks are computed from real observations (child running, waiting and idle; the leaf provider refusing the grown target; the anchor refused as foreign; an injected owner and a changed agent policy refused; an expired five-second proof authorizing nothing; two identical settled proofs). Anything not observed fails the run.
- As above, the worker runs as the Bridge service user, never opens the OpenCode database and never restarts OpenCode. The target keeps its subagents and the planned file; if it is bound in Zulip, the leaf provider refuses it from then on.
- `stage` writes `adoption-policy.json`, `lineage.json`, a `runtime.json` with one `adoption_projects` entry added, a `config.toml` with only `enrollment_file` changed and an observer file with only `runtime_enrollment_sha256` repinned. A Root with agent switching enabled is refused. Re-pinning another observation, or an OpenCode upgrade that needs one, invalidates the history of a Root that has since grown children.

## Evaluate an OpenCode upgrade

Do not upgrade OpenCode in place. Bridge pins the exact version and refuses anything else. Run `check_native_upgrade.py` first and follow [Upgrade](UPGRADE.md). A clean result only tells you what to requalify.

## Upgrade Zulip

Bridge accepts the Zulip release it was qualified on and later maintenance releases of the same series (for example 11.1 qualified, 11.3 running). A new major release (13.0) or a development build stops it until it is qualified. Older Bridge releases required the exact Zulip release, so even a maintenance upgrade stopped them.

1. Before upgrading, run `check_zulip_upgrade.py --sources zulip-server-<version>.tar.gz` with the deployed release's Python on the bridge host (`--version V --feature-level L` works from the release notes). Exit 0 means Bridge keeps running; 1 means it keeps running but Zulip's upload code changed, so review file transfer (upload association) first; 2 means Bridge would stop, so do not upgrade yet; 3 means it could not tell.
2. Back up Zulip first (`/etc/zulip` and `manage.py backup`), check the tarball against the published `SHA256SUMS`, and keep clear of a Bridge cutover.
3. After upgrading, run the check again without arguments (it asks the live server), then confirm `readyz` and that a message still gets a reply.

`jt-oz-release-watch.timer` looks once a day (09:30) for newer Zulip and OpenCode releases and posts each one once into `Bridge 狀態`, saying whether this Bridge accepts it. It uses GET only and installs nothing.

## Restart and recovery

| Situation | Do |
|---|---|
| Restart Bridge | `systemctl restart jt-oz-bridge jt-oz-observer`. OpenCode work is not touched. Messages from the last 10 minutes go out by themselves; topics with older waiting messages get one reply asking for `!go` / `!no`. Final output should catch up, but this is not yet verified in every case, so check |
| Bridge will not start | `systemctl status jt-oz-bridge`, `journalctl -u jt-oz-bridge -n 50`. Check that `promotion-active` is absent. Run `validate` as the service user |
| After a reboot | Both units are enabled. Check `/readyz`, then `jt-oz-bridge doctor` |
| OpenCode was restarted | Bridge reconnects each topic by itself when it can prove the same session, directory, contract, semantics and installed evidence, and posts one line. Where it could not, the topic says so and one `!ok` there reconnects (`!reconnect` first shows the details); do not fake it from the server |
| Topic shows paused | Tell the person. They review with `!status` and choose `!go` |
| Data loss | Use the held restore into a new directory. It starts with all features off and needs review |

## When replies stop

Check in this order. All of it is read-only.

```sh
systemctl is-active jt-oz-bridge jt-oz-observer opencode
curl -s http://127.0.0.1:8765/readyz          # default bind; expect ready true
jt-oz-bridge doctor
jt-oz-bridge sessions                         # state and "paused" for each conversation
journalctl -u jt-oz-bridge --since -1h -p warning --no-pager
journalctl -u jt-oz-bridge --since -1h --no-pager | grep -E 'work_deferred|root_watch|creation_held|creation_restore|public_feed'
```

| You see | Meaning | Do |
|---|---|---|
| `paused=True` for that topic | The queue is held, usually after a stop, a move or a recovery | The person reviews `!status` and resumes with `!go` |
| `work_deferred category=... count=... reason=...` | Bridge keeps refusing some work and retrying. Logged at most every 5 minutes per category. `category` says what | A few that stop are normal. If it continues, read the category. `native_state_not_current` means Bridge cannot prove the conversation's state |
| `root_watch_lost session=...` | Bridge lost its watch on that conversation. Work there is refused until it returns. It retries by itself | Wait for the next line |
| `root_watch_restored session=...` | The watch came back with the same OpenCode | None. Check that replies resumed |
| `root_watch_restore_deferred session=... error_type=...` | The retry failed and stays closed | If it repeats, check OpenCode and the owner helper |
| `root_watch_revoked cause=... session=...` | The watch was dropped: `generation` means enrollment changed, `watch_failed` means setting it up failed. Newer than some releases, so absence means little | Look for `root_watch_lost` next |
| `public_feed_event_discarded reason=oversized session=...` | One OpenCode event was too large to read (over 1 MiB), for example a tool reading a big file. Bridge dropped it without storing it and keeps running. That conversation's next step is checked again from OpenCode; `unattributed` means every conversation is | None if replies continue. If it repeats for one conversation, keep the logs and report the time |
| `creation_held action=... kind=... code=...` | A new conversation from chat stopped before it was connected. The topic stays "creating". `code` says which check failed | The person types anything in that topic to see the status, then `!go`. If the same code returns, keep the logs and report it |
| `creation_restore_deferred action=... session=... kind=... code=...` | At startup one conversation opened from chat could not be connected again (in any project, for example after an OpenCode plugin or policy change). Bridge starts anyway; only that conversation refuses work and is read again (GET only) every 30 seconds. A message sent there meanwhile waits up to 5 minutes; if the conversation is still not back, the person is told once that it was not sent | Wait for `creation_restore_recovered`. If the same code repeats, keep the logs and report it; `created_root_current_policy_changed` or `creation_policy_source_drifted_from_operator_approval` means OpenCode's policy changed and needs an operator review |
| `creation_restore_recovered action=...` | That conversation was connected again | None. Check that replies resumed |
| `runtime_component_failed stage=worker component=... error_type=... code=...` | One background worker stopped, so Bridge exited and systemd starts it again. `code` is the fixed reason, or `-`. A failed OpenCode read in `native-session-graphs`, or a session that changed while it was read, is retried instead and shows as `work_deferred category=original_graph_native_unavailable` or `original_graph_changed_while_reading` | If the same component and code repeat, keep the logs and report them |
| `work_deferred category=original_graph_native_unavailable ... reason=upstream_rejected_request` about once an hour | OpenCode unloads an idle project after about an hour. Its first read after reloading (`/api/agent/build`) is refused once, and Bridge reads again a few seconds later | None. Report it only if the count rises every minute |
| `dispatch_outcome_uncertain operation=... steer=... kind=... code=...` | Bridge could not tell whether OpenCode received a message (for example the connection broke while sending). `kind` and `code` say how; no text is logged. The message is never sent again by itself | Wait for the `uncertain_prompt_*` line that settles it. Keep the line if it repeats |
| `dispatch_steered` / `dispatch_steer_deferred code=...` | A message sent while OpenCode worked joined the running reply (`steered`), or could not join and waits to start its own reply after it (`deferred`; `code` says why, for example `v2_native_steer_session_not_running` when the turn had just ended or `v2_native_steer_transport_did_not_send` when the send guard refused it before any byte of the message left). No text is logged | None. If every message is `deferred` with the same code, keep the lines and report them |
| `uncertain_prompt_read_back_admitted` / `uncertain_prompt_never_arrived` | Bridge read OpenCode's conversation back (GET only): the message is there and its reply is followed as usual, or it never arrived and the topic is told once to send it again | None. `never_arrived`: the person resends |
| `uncertain_prompt_readback_unavailable` / `uncertain_prompt_left_for_review check=...` | This Bridge cannot read messages back, or this message cannot be checked that way (`check` says why: files, text, operation or another root). It stays uncertain and Bridge never resends it | Keep the logs and report them; the person checks the topic and resends if the reply never comes |
| `zulip_change_paused reason=... scope=... bindings=N` | A Zulip change paused topics: `queue_registered` (startup), `queue_expired`, a message move/delete, or a channel, member, person or organization change (`scope=all` pauses every topic). The next plain message in a paused topic resumes it when nothing else waits; otherwise reply `!go` | None, unless it repeats without a change you know of |
| `zulip_release_not_qualified version=... feature_level=... qualified=V/L` | The Zulip server runs a release the bridge was not qualified for, so the bridge refuses Zulip work and restarts until it matches. A later maintenance release of the qualified series (for example 11.1 qualified, 11.3 running) is accepted on its own: Zulip keeps the API within a series and ships security fixes that way. A new major release (13.0) or a development build is not | Upgrade Zulip within its series freely (run `check_zulip_upgrade.py` first). Before a major upgrade, have the bridge qualified for it first, or roll Zulip back |
| A ⏳ "The AI is still working (N min so far)" line in a topic | That topic's turn still runs and nothing new had appeared there for 2 minutes (typing alone is easy to miss). At most one per turn, sent like any other post; none while a permission request or choice buttons wait on the person. A Bridge restart in the middle of the turn does not repeat it while it is still the newest post. A line not yet sent when the reply or the turn's end comes first is cancelled unsent (audit event `still_working_notice_retired`). The line may say `waiting for the tool X to finish` (the tool is the slow part: OpenCode or the MCP server behind it) or `the model is thinking or writing` (the model is the slow part: try a new conversation or a lower `!model` variant), or that the model service failed for now and OpenCode is retrying (the reason, such as too many requests, comes from the model service), or that OpenCode is compacting the conversation. The journal logs `still_working_notice_queued binding=... minutes=N waits_on=tool|retry|compaction|model|unknown` | None. If the reply never comes, check as above |
| A ⚠️ "The AI seems to be repeating the same step (N times)" line in a topic | The model said the same words and called the same tool 5 times in a row in one turn (the step's message counts them, e.g. `🔧 search ×5`). At most one per turn; queued with the step's plan, so a Bridge restart does not repeat it (audit event `transcript_repeat_hint_queued`). One not yet sent when the turn's reply, outcome or next input comes is cancelled unsent (status `repeat_hint_superseded`, audit event `transcript_repeat_hint_retired`). Bridge never stops the turn itself | Up to the person: `!stop` (or its button) stops the turn; otherwise it keeps running. A model that loops often may be too weak for the task |
| A 💡 "This conversation is long (about N tokens)" line in a topic | A reply's step read 60,000 tokens of context or more, so every step re-reads that much and gets slow (minutes instead of seconds). Sent once per connected topic, after the reply (audit event `transcript_long_context_hint_queued`); a restart does not repeat it. It names `!new` in a new topic only when the binding's project is enrolled for creation | Up to the person: a new conversation is faster. If they want it in a project that cannot create from chat, enroll that project for creation (`ops/server/certify_creation.py`) |
| `restart_pause_released` / `restart_pause_kept_old binding=... after=unclear_work` | After a restart a topic waited for an unclear message to settle (checked every 30 seconds). `released` sent the held messages; `kept_old` told the topic once to use `!go` | None |
| A ⚠️ message in the topic `Bridge 狀態` | Bridge failed and did not come back by itself within four minutes (one notice per outage; a failure that systemd's next try fixes, as at boot, is not announced). "OpenCode changed" means a pinned file no longer matches; "a plugin was just updated" means an approved observer plugin's file no longer has its approved sha256; "settings or a plugin changed" means a startup check refused, with its reason code; "Zulip now runs a release this Bridge has not been qualified on" names both releases | Stopped: read the journal. Changed: run `check_native_upgrade.py` and do not restart OpenCode to clear it. Settings or plugin: review the change (for an approved observer plugin, read it in full and update its sha256 in the config). Zulip: see [Upgrade Zulip](#upgrade-zulip); qualify Bridge or roll Zulip back |
| A 🔔 message in the topic `Bridge 狀態` | The daily release watch found a newer Zulip or OpenCode release, named once per release, with whether this Bridge accepts it | A Zulip maintenance release: plan the upgrade ([Upgrade Zulip](#upgrade-zulip)). A Zulip major release or any OpenCode release: qualify first; do not upgrade in place |
| A ⚠️ "Bridge is stopped, so this message did not reach OpenCode" reply in an ordinary topic | `jt-oz-bridge-standby.service` (started with the stop notice) answers each topic once while Bridge is down, in the configured private channels only, with that fixed sentence. It reads no content, sends nothing to OpenCode and exits within about a minute once Bridge is ready | Fix the stop as above. Bridge's restart catch-up handles the messages themselves |
| A ✅ message in the topic `Bridge 狀態` | `jt-oz-bridge-recovered.timer` (every 2 minutes) saw Bridge ready again after a stop notice | None. People see it was a pause, not a loss |
| `bridge_retry start after=...s unit=...` in `journalctl -u jt-oz-bridge-retry` | systemd had given up on Bridge (or on the observer) five or more minutes earlier; `jt-oz-bridge-retry.timer` (every 5 minutes) started it again. Bridge repeats every startup check, so a cause that is still there (for example an unapproved plugin) fails again and is retried later | Fix the cause as for the ⚠️ message; Bridge then comes back by itself |
| Someone writes in the topic `Bridge 狀態` while Bridge runs | Bridge answers once that the topic only carries status notices and that Bridge is running; it never offers a conversation menu there, so the topic is never connected to an AI conversation | None. Talk to the AI in another topic |
| Service down, nothing in that topic | The notice failed to post (Zulip down, or the units are not installed) | Treat as stopped; check `journalctl -u jt-oz-bridge-notice` |

**After a reboot of the server:** `jt-oz-bridge.service` starts after `opencode.service` and waits up to two minutes for OpenCode to listen before it starts (it never starts a stopped OpenCode). If it still fails three times, the retry timer starts it again every five minutes. The observer waits up to three minutes for Bridge to be ready and is retried the same way. The first start may come before OpenCode is fully ready; the automatic retry handles it, and a failure on that first try posts no ⚠️ notice. Topics then continue as after any Bridge restart: messages sent at most ten minutes before Bridge came back go out by themselves, older ones wait for `!go`, and the next plain message in a topic that only the restart paused resumes it.

If Bridge keeps refusing after OpenCode finished, keep the logs and restart Bridge only. Report the time and topic. A work item stuck between sent and finished is never resent automatically, because resending could run it twice.

**Install:** copy `ops/server/bridge_notice.py` to `/opt/jt-oz-bridge/bridge-notice.py`, install `jt-oz-bridge-notice.service`, `jt-oz-bridge-recovered.service` / `.timer` and `jt-oz-bridge-retry.service` / `.timer` (enable both timers; the retry needs `ops/server/bridge_retry.sh` as `/opt/jt-oz-bridge/bridge-retry.sh`), and give `jt-oz-bridge.service` `OnFailure=jt-oz-bridge-notice.service jt-oz-bridge-standby.service` (drop-in or unit); the standby needs `ops/server/bridge_standby.py` as `/opt/jt-oz-bridge/bridge-standby.py` and `jt-oz-bridge-standby.service`. Before enabling the timer, delete a long-stale `/var/lib/jt-oz-bridge-notice/last`, or it sends one needless "back" notice. Older releases did not clear that file after a stop, so every stop after the first one went unannounced.

## Backups

- Take full snapshots with `jt-oz-bridge backup`. Stop Bridge first; an active service is refused.
- Back up the master key separately. A snapshot without it cannot be read, and the two should not be stored together.
- Keep each deploy's control directory until the next release has been accepted. Its database copy is a rollback aid, not a backup, because it has no artifacts or config.
- Snapshots do not include root-managed enrollment files, secret files or OpenCode's data. Back those up separately and requalify after restoring a host.
- Test a restore into a new directory. Never overwrite the live database.
