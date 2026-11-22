# Uninstall jt-oz-bridge

English · [繁體中文](UNINSTALL_zh-tw.md) · [日本語](UNINSTALL_ja.md) · [Install](INSTALL.md) · [Upgrade](UPGRADE.md) · [Overview](../README.md)

This removes the bridge, its units, releases, state, configuration and service user from a host installed as in [Install](INSTALL.md). It does not touch OpenCode, and it deletes nothing in Zulip. Run the commands in a root shell. Steps 1 and 5 are optional, but deleting state and keys cannot be undone.

## 1. Keep what you may need (optional)

With the bridge stopped, take a final snapshot, and keep the encryption key **separately** from it. Without the key the snapshot cannot be read.

```sh
systemctl stop jt-oz-observer jt-oz-bridge
install -d -o jtoz -g jtoz -m 700 /var/backups/jt-oz-bridge
runuser -u jtoz -- /usr/local/bin/jt-oz-bridge --config /etc/jt-oz-bridge/config.toml \
  backup --output "/var/backups/jt-oz-bridge/final-$(date +%Y%m%d-%H%M%S)"
```

Also copy anything you want to keep from `/etc/jt-oz-bridge/` (configuration, runtime enrollment, observer policy) and `/etc/jt-oz-bridge/secrets/master.key` to protected storage, not next to the snapshot.

## 2. Stop and disable every unit

```sh
systemctl disable --now jt-oz-observer.service jt-oz-bridge.service
systemctl disable --now jt-oz-bridge-recovered.timer 2>/dev/null || true
systemctl disable --now jt-oz-release-watch.timer 2>/dev/null || true
systemctl disable --now jt-opencode-owner.socket jt-opencode-directory.socket 2>/dev/null || true
systemctl stop jt-oz-bridge-standby.service jt-oz-bridge-notice.service jt-oz-bridge-recovered.service \
  jt-opencode-owner.service jt-opencode-directory.service 2>/dev/null || true
systemctl list-units --all 'jt-oz-*' 'jt-opencode-*'      # nothing should be active
```

Stopping the owner, directory and proxy helpers does not affect OpenCode itself. Disable the stop-notice timer before the bridge goes away, or it keeps checking for a service that no longer exists.

## 3. Remove units and drop-ins

```sh
cd /etc/systemd/system
rm -f jt-oz-bridge.service jt-oz-observer.service \
  jt-oz-bridge-notice.service jt-oz-bridge-standby.service \
  jt-oz-bridge-recovered.service jt-oz-bridge-recovered.timer \
  jt-oz-release-watch.service jt-oz-release-watch.timer \
  jt-opencode-owner.service jt-opencode-owner.socket \
  jt-opencode-directory.service jt-opencode-directory.socket
rm -rf jt-oz-bridge.service.d jt-oz-observer.service.d
systemctl daemon-reload
systemctl reset-failed
```

Only remove the `jt-opencode-*` helpers if this host has no other bridge installation that uses them. Leave `opencode.service` and its drop-ins alone: they belong to OpenCode.

## 4. Remove the program

```sh
rm -f /usr/local/bin/jt-oz-bridge
rm -rf /opt/jt-oz-bridge          # releases, venvs, helper scripts and the shared Python, if installed there
```

Each release directory is self-contained (its wheel, venv and SBOM), so nothing else on the host was installed by `pip` or `uv` system-wide. If you installed `uv` only for the bridge, remove it the way you installed it.

## 5. Remove state, configuration and secrets

Only after step 1, if you want to keep anything:

```sh
rm -rf /var/lib/jt-oz-bridge                  # bridge.db, WAL files, encrypted artifacts
rm -rf /var/lib/jt-oz-bridge-notice           # stop-notice state, if installed
rm -rf /var/lib/jt-oz-release-watch           # release-watch state, if installed
rm -rf /var/lib/jt-oz-bridge-recovery         # held restores, if any
rm -rf /etc/jt-oz-bridge                      # config.toml, enrollment, observer policy, secrets/
rm -f /etc/opencode-owner-probe.json /etc/opencode-directory-probe.json
```

Whether deleted files can be recovered from the disk depends on your storage (SSDs, snapshots, copy-on-write file systems). If that matters, rotate the credentials in step 7 instead of relying on deletion. Remove backups in `/var/backups/jt-oz-bridge*` according to your retention policy.

## 6. Remove the service user

```sh
userdel jtoz
getent group jtoz && groupdel jtoz
find / -xdev \( -user jtoz -o -group jtoz \) -print 2>/dev/null | head
```

The last command should print nothing. Check any POSIX ACL you added for the observer socket or project directories during onboarding, and remove it.

## 7. Zulip and OpenCode

Nothing is deleted there automatically.

| Where | What stays | What you may want to do |
|---|---|---|
| Zulip | The bot account and its API key, the private channels, every topic and message, uploaded files and the bridge's notices | Deactivate the bot (Personal settings → Bots) so its API key stops working; archive or delete channels and topics according to your retention policy |
| OpenCode | All sessions, including conversations created or forked from chat (they are permanent OpenCode sessions), their history, files the agent created in project directories, and OpenCode's configuration | Nothing is required. Review sessions created from chat and delete them in OpenCode if you no longer need them |
| OpenCode credential | The password or token the bridge used for the OpenCode API | Rotate it if the bridge had its own credential |
| Network | Reverse-proxy or firewall rules you added for the admin console or the OpenCode relay | Remove them |

## 8. Check

```sh
systemctl list-unit-files 'jt-oz-*' 'jt-opencode-*'   # no units
ss -ltnp | grep -w 8765                               # no listener
systemctl is-active opencode                          # OpenCode still running, untouched
```
