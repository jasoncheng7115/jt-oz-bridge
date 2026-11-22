# Upgrade jt-oz-bridge

English · [繁體中文](UPGRADE_zh-tw.md) · [日本語](UPGRADE_ja.md) · [Install](INSTALL.md) · [Uninstall](UNINSTALL.md) · [Overview](../README.md)

An upgrade installs the new release **beside** the running one, backs up the bridge's own database, migrates it, switches the service with a systemd drop-in, checks readiness and keeps the previous release for rollback. The same steps work online and offline; only the way the release files arrive differs.

OpenCode is never part of a bridge upgrade: do not stop, restart or upgrade it here. Work running in OpenCode continues while the bridge is stopped, and the bridge catches up afterwards (messages from the last 10 minutes are sent by themselves; older ones wait for the person to answer `!go` or `!no`).

The layout and conventions are those of [Install](INSTALL.md): a root shell with `umask 022` and `UV_LINK_MODE=copy`, service user `jtoz`, releases under `/opt/jt-oz-bridge/releases/<wheel-sha256>/`, and a drop-in `50-release.conf` that selects the release.

## Before you start

- Read the release notes or the commits since your release. Does it change the database schema? Does it need configuration changes, new units or new helper scripts? Does it say that rollback below it is not possible?
- Use a wheel that passed the full test gate, with its SBOM.
- Choose a quiet moment. `jt-oz-bridge sessions --active` shows work in progress. The bridge is down for about a minute.
- Make sure there is disk space for a full backup.
- Note the current release and OpenCode's process identity:

```sh
OLD=$(systemctl show jt-oz-bridge -p ExecStart --value | grep -o '/opt/jt-oz-bridge/releases/[0-9a-f]\{64\}' | head -1)
echo "$OLD"
systemctl show opencode -p MainPID -p NRestarts -p InvocationID   # use your OpenCode unit name
```

## 1. Install the new release side by side

Follow [Install](INSTALL.md) sections 5 to 7 with the new release files: build or fetch them online, or carry an offline bundle (section 5.2) and install with `--offline --no-index --find-links ./wheels`. Verify `SHA256SUMS` and the SBOM as described there. **Skip the `ln -sfn` line for now**; the CLI symlink is switched in step 4.

```sh
NEW=/opt/jt-oz-bridge/releases/<new wheel sha256>
runuser -u jtoz -- "$NEW/venv/bin/jt-oz-bridge" --config /etc/jt-oz-bridge/config.toml validate
```

The running service is not touched by any of this. If the new release needs configuration changes, write them to a copy (`/etc/jt-oz-bridge/config.toml.new`, `root:jtoz` 640), validate the copy with the new release, and keep the current file for rollback. If the release ships changed helper scripts or units (compare with `cmp` against what is installed), prepare them too.

## 2. Stop the bridge and back up

```sh
STAMP=$(date +%Y%m%d-%H%M%S)
C=/var/backups/jt-oz-bridge-upgrade/$STAMP
install -d -m 700 /var/backups/jt-oz-bridge-upgrade "$C"
install -d -o jtoz -g jtoz -m 700 /var/backups/jt-oz-bridge
cp -a /etc/jt-oz-bridge/config.toml /etc/systemd/system/jt-oz-bridge.service.d "$C/"
cp -a /etc/systemd/system/jt-oz-observer.service.d "$C/" 2>/dev/null || true
readlink /usr/local/bin/jt-oz-bridge > "$C/cli.before"

systemctl stop jt-oz-observer jt-oz-bridge
runuser -u jtoz -- "$OLD/venv/bin/jt-oz-bridge" --config /etc/jt-oz-bridge/config.toml \
  backup --output "/var/backups/jt-oz-bridge/pre-upgrade-$STAMP" | tee "$C/backup.json"
```

The backup is an authenticated snapshot of the database, the encrypted artifacts and the effective configuration. It refuses to run while the bridge is active. It does **not** contain the encryption key, secret files or enrollment files, so keep those backed up separately. Its output names the current schema as `schema_revision`.

## 3. Migrate with the new release

```sh
runuser -u jtoz -- "$NEW/venv/bin/jt-oz-bridge" --config /etc/jt-oz-bridge/config.toml migrate
"$NEW/venv/bin/python" -I -c 'import sqlite3; db = sqlite3.connect("file:/var/lib/jt-oz-bridge/bridge.db?mode=ro", uri=True); print(db.execute("select version_num from alembic_version").fetchone()[0])'
```

Compare the printed revision with `schema_revision` in `$C/backup.json`. **If it changed, the previous release can no longer run on this database**: from here, rollback means restoring the backup (step 6, case B), not just switching code. `migrate` is a no-op when the schema is already current. If you use PostgreSQL, query the same `alembic_version` table with your database tools.

## 4. Switch

```sh
sed -i "s#$OLD#$NEW#g" /etc/systemd/system/jt-oz-bridge.service.d/50-release.conf
sed -i "s#$OLD#$NEW#g" /etc/systemd/system/jt-oz-observer.service.d/50-release.conf 2>/dev/null || true
# only if prepared in step 1:
#   install -o root -g jtoz -m 640 /etc/jt-oz-bridge/config.toml.new /etc/jt-oz-bridge/config.toml
ln -sfn "$NEW/venv/bin/jt-oz-bridge" /usr/local/bin/jt-oz-bridge
systemctl daemon-reload
systemctl start jt-oz-bridge
for i in $(seq 1 45); do curl -sf http://127.0.0.1:8765/readyz && break; sleep 2; done
systemctl start jt-oz-observer    # only after /readyz is ready; skip if not installed
```

Start the observer only after the bridge reports ready: it needs the migrated schema, and starting both at once can make it fail once.

## 5. Smoke checks

Wait about 30 seconds, then:

```sh
systemctl is-active jt-oz-bridge jt-oz-observer
systemctl show jt-oz-bridge -p NRestarts -p ExecStart      # NRestarts=0, ExecStart names $NEW
curl -s http://127.0.0.1:8765/readyz                        # "ready":true
journalctl -u jt-oz-bridge --since -2min -p warning --no-pager
systemctl show opencode -p MainPID -p NRestarts -p InvocationID   # identical to before
jt-oz-bridge doctor
```

Any failure here is a reason to roll back. A passing smoke check only proves the service started; send a short message in a disposable topic to check the chat path.

## 6. Roll back

**Case A: the schema did not change.** Point the service back at the previous release:

```sh
systemctl stop jt-oz-observer jt-oz-bridge
cp -a "$C/jt-oz-bridge.service.d/." /etc/systemd/system/jt-oz-bridge.service.d/
test -d "$C/jt-oz-observer.service.d" && cp -a "$C/jt-oz-observer.service.d/." /etc/systemd/system/jt-oz-observer.service.d/
cp -a "$C/config.toml" /etc/jt-oz-bridge/config.toml
ln -sfn "$(cat "$C/cli.before")" /usr/local/bin/jt-oz-bridge
systemctl daemon-reload
systemctl start jt-oz-bridge
for i in $(seq 1 45); do curl -sf http://127.0.0.1:8765/readyz && break; sleep 2; done
systemctl start jt-oz-observer
```

Then repeat the smoke checks.

**Case B: the schema changed.** The previous release cannot read the migrated database, and an older database file must never be copied over newer data. You have two choices:

1. **Fix forward (recommended).** Keep the new schema and deploy a corrected newer release with these same steps.
2. **Restore the pre-upgrade backup.** With the previous release, restore the snapshot into a **new** directory and review the held recovery: the restored copy starts with every feature off and every topic paused until reviewed, then `complete-restore` finishes it. Everything the bridge recorded after the upgrade is lost from its own records (what happened in OpenCode stays in OpenCode), so people may need to check their topics.

```sh
systemctl stop jt-oz-observer jt-oz-bridge
cp -a "$C/config.toml" /etc/jt-oz-bridge/config.toml
install -d -o jtoz -g jtoz -m 700 /var/lib/jt-oz-bridge-recovery
runuser -u jtoz -- "$OLD/venv/bin/jt-oz-bridge" --config /etc/jt-oz-bridge/config.toml \
  restore --backup "/var/backups/jt-oz-bridge/pre-upgrade-$STAMP" \
  --destination "/var/lib/jt-oz-bridge-recovery/restore-$STAMP"
```

When the review is complete, switch the drop-ins and the CLI symlink back to the previous release as in case A.

Some releases record data that older releases cannot replay even without a schema change (for example conversations created from chat); their release notes say so, and the answer is also to fix forward.

## 7. Clean up

Keep the previous release, the backup and `$C` until the new release has been accepted. Then remove release directories that nothing references any more:

```sh
grep -h ExecStart= /etc/systemd/system/jt-oz-*.service.d/*.conf
readlink /usr/local/bin/jt-oz-bridge
rm -rf /opt/jt-oz-bridge/releases/<old wheel sha256>     # never the active or the previous one
```

A venv keeps a link to the Python it was created with. If you installed a newer Python 3.13 under `/opt/jt-oz-bridge/python`, keep the old one until no remaining release uses it (`readlink -f <release>/venv/bin/python`).

## Offline upgrade

Build the new bundle on a connected machine exactly as in [Install, section 5.2](INSTALL.md#52-offline-air-gapped-bundle): wheel, `requirements.txt`, SBOM, source archive, `wheels/` for the target platform, optionally Python and `uv`, and `SHA256SUMS`. On the target, verify `sha256sum -c SHA256SUMS`, install into the new release directory with `--offline --no-index --find-links ./wheels --require-hashes`, verify the SBOM, then continue with steps 2 to 7 above. Nothing in steps 2 to 7 needs network access except your chat check.

## OpenCode upgrades are separate

Never upgrade OpenCode in the same window. The bridge pins the exact OpenCode version and policy it was qualified with and refuses to start against anything else until it is requalified. Evaluate an OpenCode upgrade with `ops/server/check_native_upgrade.py` first.
