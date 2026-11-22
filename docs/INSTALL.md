# Install jt-oz-bridge

English · [繁體中文](INSTALL_zh-tw.md) · [日本語](INSTALL_ja.md) · [Upgrade](UPGRADE.md) · [Uninstall](UNINSTALL.md) · [Overview](../README.md)

This guide installs the bridge as a systemd service on a Linux host that already runs OpenCode, from the internet or from an offline (air-gapped) bundle. jt-oz-bridge `0.1.1` is a **development preview**: complete real-human and mobile acceptance are not finished. Start with a disposable OpenCode project.

The bridge never installs, starts, restarts or upgrades OpenCode, never reads OpenCode's database and never creates or copies a session to get past a problem. Keep it that way while you install.

## 1. Requirements

| Item | Requirement |
|---|---|
| Host | Linux with systemd, x86_64. Developed on Ubuntu 24.04. Other architectures are not certified yet. |
| Python | CPython 3.13, readable by the service user and **not** under `/root` or `/home` (the unit sets `ProtectHome=true`). A distribution package or a uv-managed Python in a shared directory both work; see step 4. |
| Tools | `uv` (recommended) or `pip`, `sha256sum`, `curl`, root access for installation. |
| OpenCode | An OpenCode server (V2 API; developed against 2.0.32, see [compatibility](COMPATIBILITY.md)) already running under its own OS account and listening on loopback. The bridge pins the exact version it was qualified with. |
| Zulip | A self-hosted Zulip server (developed against 12.3) where you can create a bot and a private channel. |
| Resources | The bridge unit is limited to 1 GiB of memory. Plan disk for the database, encrypted artifacts and backups (the default artifact quota is 2 GiB). |

## 2. Default layout

| Path | Contents | Owner and mode |
|---|---|---|
| `/opt/jt-oz-bridge/releases/<wheel-sha256>/` | One directory per release: wheel, `requirements.txt`, SBOM, checksums and `venv/` | `root:jtoz`, directories 755, files 644 |
| `/opt/jt-oz-bridge/` | Helper scripts (`owner-probe.py`, `directory-probe.py`, `bridge-notice.py`, `bridge-standby.py`) and an optional shared Python | `root`, 755 / 644 |
| `/etc/jt-oz-bridge/config.toml` | Configuration | `root:jtoz`, 640 |
| `/etc/jt-oz-bridge/secrets/` | Encryption key, Zulip bot API key, OpenCode credential | `jtoz:jtoz`, directory 700, files 600 |
| `/var/lib/jt-oz-bridge/` | State: `bridge.db` and `artifacts/` | `jtoz:jtoz`, 700 |
| `/etc/systemd/system/` | Units and drop-ins from `ops/server/` | `root`, 644 |
| `/usr/local/bin/jt-oz-bridge` | Symlink to the active release's CLI | `root` |

`jtoz` is the service user the shipped units use. Paths are defaults; if you change them, change the units and the configuration together. Keep the state directory and secrets off synchronized or network file systems (Nextcloud, NFS, SMB).

Run every command in this guide in a root shell (`sudo -i`) with a normal umask, unless it says otherwise:

```sh
umask 022
export UV_LINK_MODE=copy   # venv files are copies, not hard links into root's uv cache
```

## 3. Service user and directories

```sh
useradd --system --user-group --home-dir /var/lib/jt-oz-bridge --no-create-home \
  --shell /usr/sbin/nologin jtoz
install -d -o root -g root -m 755 /opt/jt-oz-bridge /opt/jt-oz-bridge/releases
install -d -o root -g jtoz -m 750 /etc/jt-oz-bridge
install -d -o jtoz -g jtoz -m 700 /etc/jt-oz-bridge/secrets /var/lib/jt-oz-bridge
```

## 4. Python 3.13

Use a distribution Python if it is 3.13:

```sh
PY=/usr/bin/python3.13
"$PY" --version
```

Otherwise install a uv-managed Python into a shared directory (online), or unpack the one from the offline bundle (section 5.2):

```sh
uv python install 3.13 --install-dir /opt/jt-oz-bridge/python
chmod -R go+rX /opt/jt-oz-bridge/python
PY=$(echo /opt/jt-oz-bridge/python/cpython-3.13.*/bin/python3.13)
"$PY" --version
```

## 5. Get the release files

A release is the wheel, its hash-locked `requirements.txt`, its SBOM `jt-oz-bridge-<version>.sbom.cdx.json` (CycloneDX 1.5) and a source archive for the configuration example and the systemd units. Build them on any machine with network access, `git` and `uv`:

```sh
git clone https://github.com/jasoncheng7115/jt-oz-bridge.git
cd jt-oz-bridge
git checkout <release tag or commit>
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml)
OUT=../jt-oz-bridge-$VERSION
mkdir "$OUT"
uv build --wheel --out-dir "$OUT"
uv export --frozen --no-dev --no-emit-project --no-header --format requirements-txt \
  -o "$OUT/requirements.txt"
git archive --format=tar.gz --prefix=jt-oz-bridge-src/ -o "$OUT/jt-oz-bridge-src.tar.gz" HEAD
```

Each GitHub release carries the wheel with its `jt-oz-bridge-<version>.sbom.cdx.json` and `SHA256SUMS`; install that wheel and that SBOM together. For a wheel you built yourself, run the test suite on the same checkout first (as a non-root user) and generate the SBOM from it:

```sh
uv sync --locked --python 3.13
uv run --no-sync python -m scripts.make_sbom --uv uv \
  --wheel "$OUT/jt_oz_bridge-$VERSION-py3-none-any.whl" \
  --output "$OUT/jt-oz-bridge-$VERSION.sbom.cdx.json"
```

`make_sbom` fails if a locked runtime dependency is not installed at exactly that version in the environment it runs in.

### 5.1 Online target

Write checksums and copy the directory to the target:

```sh
(cd "$OUT" && sha256sum *.whl requirements.txt *.sbom.cdx.json *.tar.gz > SHA256SUMS)
```

### 5.2 Offline (air-gapped) bundle

On the connected machine, also download every dependency wheel for the **target** platform and Python. The hashes in `requirements.txt` are enforced while downloading:

```sh
uv venv --seed --python 3.13 ../dl-tools        # a throwaway venv that has pip
mkdir "$OUT/wheels"
../dl-tools/bin/python -m pip download --require-hashes --only-binary=:all: \
  --implementation cp --python-version 3.13 --abi cp313 --abi abi3 --abi none \
  --platform manylinux_2_28_x86_64 --platform manylinux_2_17_x86_64 \
  --platform manylinux2014_x86_64 --platform any \
  -r "$OUT/requirements.txt" -d "$OUT/wheels"
```

The `manylinux_2_28` wheels need glibc 2.28 or newer on the target. For another architecture, replace `x86_64` in the platform tags (not certified).

If the target has no Python 3.13 or no `uv`, carry them too. These commands take the connected machine's own, so run them on a machine of the target's architecture:

```sh
uv python install 3.13 --install-dir ../py313
tar -C ../py313 -czf "$OUT/cpython-3.13-linux-x86_64.tar.gz" .
cp "$(command -v uv)" "$OUT/uv"
```

Then write the checksums over everything and move the directory to the target on your approved media:

```sh
(cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
```

The bundle then contains:

```text
jt-oz-bridge-<version>/
├── jt_oz_bridge-<version>-py3-none-any.whl
├── requirements.txt                    # hash-locked runtime dependencies
├── jt-oz-bridge-<version>.sbom.cdx.json
├── jt-oz-bridge-src.tar.gz             # config.example.toml, ops/server/ units and helpers
├── wheels/                             # dependency wheels for the target
├── cpython-3.13-linux-x86_64.tar.gz    # optional
├── uv                                  # optional
└── SHA256SUMS
```

On an offline target without Python 3.13, unpack the carried Python into the shared directory instead of the online command in step 4:

```sh
install -d -m 755 /opt/jt-oz-bridge/python
tar -xzf cpython-3.13-linux-x86_64.tar.gz -C /opt/jt-oz-bridge/python
chmod -R go+rX /opt/jt-oz-bridge/python
PY=$(echo /opt/jt-oz-bridge/python/cpython-3.13.*/bin/python3.13)
```

## 6. Install the release

On the target, in the copied release directory:

```sh
cd /path/to/jt-oz-bridge-<version>
sha256sum -c SHA256SUMS
VERSION=0.1.1
WHEEL=jt_oz_bridge-$VERSION-py3-none-any.whl
SHA=$(sha256sum "$WHEEL" | cut -d' ' -f1)
R=/opt/jt-oz-bridge/releases/$SHA
test ! -e "$R"            # a release directory is never reused
install -d -m 755 "$R"
cp "$WHEEL" requirements.txt "jt-oz-bridge-$VERSION.sbom.cdx.json" SHA256SUMS "$R/"
```

**Online**, install the locked dependencies, then the wheel without dependencies:

```sh
uv venv --python "$PY" "$R/venv"
uv pip install --python "$R/venv/bin/python" --require-hashes -r "$R/requirements.txt"
uv pip install --python "$R/venv/bin/python" --no-deps "$R/$WHEEL"
```

**Offline**, install from the bundle only (use `./uv` if you carried it):

```sh
uv venv --offline --python "$PY" "$R/venv"
uv pip install --offline --no-index --find-links ./wheels \
  --python "$R/venv/bin/python" --require-hashes -r "$R/requirements.txt"
uv pip install --offline --no-index --python "$R/venv/bin/python" --no-deps "$R/$WHEEL"
```

With plain `pip` instead of `uv`, the same offline install, including the venv, is:

```sh
"$PY" -m venv "$R/venv"
"$R/venv/bin/pip" install --no-index --find-links ./wheels --require-hashes -r "$R/requirements.txt"
"$R/venv/bin/pip" install --no-index --no-deps "$R/$WHEEL"
```

Then hand the release to the service group and make the CLI available on the host:

```sh
chown -R root:jtoz "$R"
chmod -R go+rX "$R"
ln -sfn "$R/venv/bin/jt-oz-bridge" /usr/local/bin/jt-oz-bridge
```

## 7. Verify the SBOM

The SBOM must name this exact wheel and exactly the third-party packages installed in the release venv:

```sh
F=$(mktemp)
uv pip freeze --python "$R/venv/bin/python" | grep -v '^jt-oz-bridge' > "$F"
"$R/venv/bin/python" -I - "$R/jt-oz-bridge-$VERSION.sbom.cdx.json" "$SHA" "$F" <<'PY'
import json, re, sys
bom = json.load(open(sys.argv[1]))
assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
assert bom["metadata"]["component"]["hashes"] == [{"alg": "SHA-256", "content": sys.argv[2]}], "wheel hash"
norm = lambda name: re.sub(r"[-_.]+", "-", name).lower()
listed = {(norm(c["name"]), c["version"]) for c in bom["components"]}
frozen = {(norm(a), b) for a, b in (l.strip().split("==") for l in open(sys.argv[3]) if l.strip())}
assert listed == frozen, (sorted(listed - frozen), sorted(frozen - listed))
print("SBOM matches:", len(listed), "components and the wheel hash")
PY
rm -f "$F"
```

With a pip-created venv, use `"$R/venv/bin/pip" freeze` in the `uv pip freeze` line.

## 8. Configure

Unpack the source archive somewhere temporary and start from the example configuration:

```sh
tar -xzf jt-oz-bridge-src.tar.gz            # creates ./jt-oz-bridge-src/
install -o root -g jtoz -m 640 jt-oz-bridge-src/config.example.toml /etc/jt-oz-bridge/config.toml
```

For the first start, change only the key reference and keep every integration disabled:

```toml
[app]
state_dir = "/var/lib/jt-oz-bridge"
bind_host = "127.0.0.1"
bind_port = 8765

[database]
url = "sqlite+aiosqlite:////var/lib/jt-oz-bridge/bridge.db"

[security]
secret_key_ref = "file:/etc/jt-oz-bridge/secrets/master.key"
```

Secret references are `env:NAME` or `file:/absolute/path`. A secret file must be a regular file (not a symlink), owned by the service user, readable only by its owner (mode 600) and at most 64 KiB. Unknown configuration keys are rejected. `JTOZ__SECTION__FIELD` environment variables override single settings.

Validate the file as the service user (this opens no connection and resolves no credential), create the encryption key once, and create the database:

```sh
B="runuser -u jtoz -- $R/venv/bin/jt-oz-bridge --config /etc/jt-oz-bridge/config.toml"
$B validate
$B generate-key --secret-output /etc/jt-oz-bridge/secrets/master.key
$B migrate
```

`generate-key` refuses to overwrite an existing file and never prints the key. **Back the key up separately now** (for example to offline media): a database or backup cannot be read without it, and the key must not be stored with the backups. `migrate` is explicit and can be repeated; `serve` refuses an unmigrated database and refuses to run as root.

## 9. Install and start the service

Install the main unit and point it at the release with a drop-in, so later upgrades only change the drop-in:

```sh
SRC=jt-oz-bridge-src/ops/server
install -m 644 "$SRC/jt-oz-bridge.service" /etc/systemd/system/
install -d -m 755 /etc/systemd/system/jt-oz-bridge.service.d
cat > /etc/systemd/system/jt-oz-bridge.service.d/50-release.conf <<EOF
[Service]
ExecStart=
ExecStart=$R/venv/bin/jt-oz-bridge --config /etc/jt-oz-bridge/config.toml serve
EOF
systemctl daemon-reload
systemctl enable --now jt-oz-bridge
```

The unit runs as `jtoz` with no capabilities, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=true`, write access only to `/var/lib/jt-oz-bridge` and a 1 GiB memory limit. It names `jt-opencode-owner.service` and the stop-notice units (section 12); systemd only logs a note while those are not installed.

## 10. Smoke checks

```sh
systemctl is-active jt-oz-bridge
systemctl show jt-oz-bridge -p NRestarts -p ExecStart
curl -s http://127.0.0.1:8765/healthz     # {"status":"alive"}
curl -s http://127.0.0.1:8765/readyz      # {"ready":true,"mode":"foundation","agent_consumers":false}
journalctl -u jt-oz-bridge --since -5min -p warning --no-pager
```

`foundation` means the service, configuration, key and database work, with no integration running yet. `/readyz` answers 503 with `"ready":false` while the database or the runtime is not ready. A second copy of the service is refused while the first holds its lease.

## 11. Connect Zulip and OpenCode

Do this one project at a time, starting with a disposable one. The detailed procedures are in [Operations](OPERATIONS_SOP.md).

### Zulip

1. In Zulip, create a **generic bot** (Personal settings → Bots → Add a new bot). Do not give it administrator rights.
2. Store its API key without putting it on the command line:

   ```sh
   runuser -u jtoz -- sh -c 'umask 077; cat > /etc/jt-oz-bridge/secrets/zulip-api-key'
   # paste the key, press Enter, then Ctrl-D
   ```

3. Create a **private** channel with protected history. Add the bot and only the people who may use the projects it serves; everyone in a channel can read its topics.
4. Note the numeric user IDs of those people and the channel ID (shown in each profile and in the channel settings).
5. In `[[zulip_realms]]`, set `enabled = true`, `url`, `bot_email`, `api_key_ref = "file:/etc/jt-oz-bridge/secrets/zulip-api-key"`, `allowed_user_ids` and `allowed_channel_ids`. Keep `request_budget` below the rate limit your Zulip server applies to the bot.

### OpenCode

1. OpenCode must already run under its own account, listening on loopback (for example `opencode serve --hostname 127.0.0.1 --port 4096`; `ops/server/opencode.service` is an example unit). Do not let anything restart it as part of the bridge setup.
2. In `[[opencode_backends]]`, set `enabled = true`, `base_url` and, if your server requires one, `credential_ref` as a `file:` reference. In `[[projects]]`, describe the project and its workspace directory.
3. Install the read-only helpers that prove which OpenCode process, dataset and directory are the real ones. Copy `ops/server/owner-probe.py` and `directory-probe.py` to `/opt/jt-oz-bridge/`, install `jt-opencode-owner.socket` / `.service` and `jt-opencode-directory.socket` / `.service`, and set `User=` / `Group=` in both services to the account that runs OpenCode. Enable the sockets once their JSON configuration exists (the onboarding step writes it).
4. Onboard the project with `ops/server/onboard_root.py` (`prepare`, `directory`, `probe`, `cleanup`, `seal`), as described in [Operations: onboard a project](OPERATIONS_SOP.md#onboard-a-project). It proves one existing session with read-only requests and controlled test files, and writes a sealed configuration, the runtime enrollment and the local observer policy. It never opens OpenCode's database and never restarts OpenCode.
5. With the bridge stopped, run `enroll-runtime` as the service user with the sealed configuration, install the sealed files, and start again:

   ```sh
   systemctl stop jt-oz-bridge
   runuser -u jtoz -- "$R/venv/bin/jt-oz-bridge" --config <sealed config> enroll-runtime
   # install the sealed config.toml and local-observer.json into /etc/jt-oz-bridge/
   systemctl start jt-oz-bridge
   curl -s http://127.0.0.1:8765/readyz      # expect "mode":"managed","agent_consumers":true
   ```

6. Install the local observer for `jt-oz-bridge sessions` and `doctor`: `jt-oz-observer.service` with a drop-in `/etc/systemd/system/jt-oz-observer.service.d/50-release.conf` like the one in section 9 (`ExecStart=` empty, then `ExecStart=$R/venv/bin/jt-oz-bridge --config /etc/jt-oz-bridge/config.toml observe-serve --policy /etc/jt-oz-bridge/local-observer.json`). Enable it, and start it only after `/readyz` reports ready.
7. In Zulip, open a new topic in the channel and type anything. Pick the conversation; then type a task.

## 12. Optional units

**Stop and recovery notices.** Copy `ops/server/bridge_notice.py` to `/opt/jt-oz-bridge/bridge-notice.py` and `bridge_standby.py` to `/opt/jt-oz-bridge/bridge-standby.py`, install `jt-oz-bridge-notice.service`, `jt-oz-bridge-standby.service`, `jt-oz-bridge-recovered.service` and `jt-oz-bridge-recovered.timer`, then:

```sh
/usr/bin/python3 -I /opt/jt-oz-bridge/bridge-notice.py --dry-run   # prints, sends nothing
systemctl daemon-reload
systemctl enable --now jt-oz-bridge-recovered.timer
```

When the bridge fails and does not come back by itself within four minutes, one notice is posted to the first allowed channel (topic `Bridge 狀態`), the standby answers each topic once, and the timer posts one "back" notice when `/readyz` is ready again. These scripts use only the Python standard library and read the bridge configuration and secrets as root.

**Release watch (optional).** Copy `ops/server/release_watch.py` to `/opt/jt-oz-bridge/release-watch.py`, install `jt-oz-release-watch.service` and `jt-oz-release-watch.timer`, then:

```sh
/usr/bin/python3 -I /opt/jt-oz-bridge/release-watch.py --dry-run   # prints, sends nothing
systemctl daemon-reload
systemctl enable --now jt-oz-release-watch.timer
```

Once a day it asks, with GET only, for the live Zulip release, GitHub's public list of Zulip releases and OpenCode's update metadata, and posts each newer release once into `Bridge 狀態`, saying whether this bridge accepts it. It installs nothing. Before upgrading Zulip, run `ops/server/check_zulip_upgrade.py` (see the operations SOP).

**Admin console.** `runuser -u jtoz -- "$R/venv/bin/jt-oz-bridge" --config /etc/jt-oz-bridge/config.toml bootstrap-admin --username admin` prints a one-time password that must be changed at first login. The console uses Secure cookies, so it needs an HTTPS reverse proxy and `admin.public_url`; keep the bridge itself on loopback.

## 13. Troubleshooting

| Symptom | Check |
|---|---|
| `Configuration/operation rejected` | Run `validate` as `jtoz`. Check paths, owners and modes in section 2; secret files must be mode 600 and owned by `jtoz`. The message deliberately omits the submitted values. |
| Service exits immediately | `journalctl -u jt-oz-bridge -n 50`. Was `migrate` run with this release? Is the interpreter outside `/root` and `/home`? |
| `/readyz` is 503 | The database, lease or runtime is not ready yet; read the journal. After onboarding, `jt-oz-bridge doctor` explains which part is missing. |
| `pip download` cannot find a wheel | The dependency has no wheel for that platform tag; add the right `--platform` tag or build the wheel on a machine of the target platform. |
| `--require-hashes` fails | The file does not match the lock. Do not remove the flag; fetch the file again from the official index. |

Next: [Upgrade](UPGRADE.md) · [Uninstall](UNINSTALL.md) · [Operations](OPERATIONS_SOP.md)
