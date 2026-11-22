#!/bin/bash
# Run by jt-oz-bridge-retry.timer. systemd gives up on Bridge after three quick
# failures, for example while OpenCode is still loading after a reboot or until a
# changed plugin is approved. Once Bridge has been failed for five minutes, start it
# again, so it comes back by itself when the cause is gone. Bridge repeats every
# startup check, so a refusal (such as plugin drift) simply fails again. A stop by
# hand or by a cutover leaves the unit inactive, not failed, and is left alone.
# The observer reads Bridge's state and gives up the same way, so it gets the same.
set -u
AFTER=${JT_OZ_RETRY_AFTER:-300}
retry() {
    local unit=$1 since failed_at down
    systemctl is-failed -q "$unit" || return 0
    # Unix time: a zone name such as CST is ambiguous to date(1).
    since=$(systemctl show --timestamp=unix -P InactiveEnterTimestamp "$unit")
    [ -n "$since" ] || return 0
    failed_at=$(date -d "$since" +%s) || return 0
    down=$(( $(date +%s) - failed_at ))
    [ "$down" -ge "$AFTER" ] || return 0
    echo "bridge_retry start after=${down}s unit=${unit}"
    systemctl reset-failed "$unit"
    systemctl start --no-block "$unit"
}
retry jt-oz-bridge.service
retry jt-oz-observer.service
