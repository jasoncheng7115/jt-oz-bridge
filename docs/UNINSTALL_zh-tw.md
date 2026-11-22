# 移除 jt-oz-bridge

[English](UNINSTALL.md) · 繁體中文 · [日本語](UNINSTALL_ja.md) · [安裝](INSTALL_zh-tw.md) · [升級](UPGRADE_zh-tw.md) · [總覽](../README_zh-tw.md)

本文件說明如何從依[安裝](INSTALL_zh-tw.md)部署的主機上，移除橋接及其單元、版本、狀態、設定與服務帳號。它不會動到 OpenCode，也不會刪除 Zulip 中的任何東西。請在 root shell 中執行指令。第 1 與第 5 步可選，但刪除狀態與金鑰後無法復原。

## 1. 保留可能需要的資料（選用）

在橋接停止時做最後一次快照，並把加密金鑰與快照**分開**保存；沒有金鑰就讀不了快照。

```sh
systemctl stop jt-oz-observer jt-oz-bridge
install -d -o jtoz -g jtoz -m 700 /var/backups/jt-oz-bridge
runuser -u jtoz -- /usr/local/bin/jt-oz-bridge --config /etc/jt-oz-bridge/config.toml \
  backup --output "/var/backups/jt-oz-bridge/final-$(date +%Y%m%d-%H%M%S)"
```

也請把 `/etc/jt-oz-bridge/` 中想保留的檔案（設定、runtime enrollment、observer 政策）與 `/etc/jt-oz-bridge/secrets/master.key` 複製到受保護的位置，不要和快照放在一起。

## 2. 停止並停用所有單元

```sh
systemctl disable --now jt-oz-observer.service jt-oz-bridge.service
systemctl disable --now jt-oz-bridge-recovered.timer 2>/dev/null || true
systemctl disable --now jt-oz-release-watch.timer 2>/dev/null || true
systemctl disable --now jt-opencode-owner.socket jt-opencode-directory.socket 2>/dev/null || true
systemctl stop jt-oz-bridge-standby.service jt-oz-bridge-notice.service jt-oz-bridge-recovered.service \
  jt-opencode-owner.service jt-opencode-directory.service 2>/dev/null || true
systemctl list-units --all 'jt-oz-*' 'jt-opencode-*'      # nothing should be active
```

停止 owner、目錄與 proxy 輔助服務不會影響 OpenCode 本身。請在橋接移除前先停用停止通知的 timer，否則它會一直檢查已不存在的服務。

## 3. 移除單元與 drop-in

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

只有在這台主機沒有其他橋接安裝使用 `jt-opencode-*` 輔助服務時，才移除它們。`opencode.service` 及其 drop-in 屬於 OpenCode，請不要動。

## 4. 移除程式

```sh
rm -f /usr/local/bin/jt-oz-bridge
rm -rf /opt/jt-oz-bridge          # releases, venvs, helper scripts and the shared Python, if installed there
```

每個版本目錄都是自給自足的（自己的 wheel、venv 與 SBOM），因此主機上沒有任何東西是用 `pip` 或 `uv` 全系統安裝的。若 `uv` 只是為了橋接而安裝，請依當初的安裝方式移除。

## 5. 移除狀態、設定與密鑰

只在完成第 1 步（若要保留資料）之後執行：

```sh
rm -rf /var/lib/jt-oz-bridge                  # bridge.db, WAL files, encrypted artifacts
rm -rf /var/lib/jt-oz-bridge-notice           # stop-notice state, if installed
rm -rf /var/lib/jt-oz-release-watch           # release-watch state, if installed
rm -rf /var/lib/jt-oz-bridge-recovery         # held restores, if any
rm -rf /etc/jt-oz-bridge                      # config.toml, enrollment, observer policy, secrets/
rm -f /etc/opencode-owner-probe.json /etc/opencode-directory-probe.json
```

刪除的檔案能否從磁碟救回，取決於儲存設備（SSD、快照、copy-on-write 檔案系統）。若這點很重要，請依第 7 步輪替憑證，而不要只依賴刪除。`/var/backups/jt-oz-bridge*` 中的備份請依保存政策處理。

## 6. 移除服務帳號

```sh
userdel jtoz
getent group jtoz && groupdel jtoz
find / -xdev \( -user jtoz -o -group jtoz \) -print 2>/dev/null | head
```

最後一個指令應該沒有任何輸出。若納管時曾為 observer socket 或專案目錄加過 POSIX ACL，請檢查並移除。

## 7. Zulip 與 OpenCode

這兩邊都不會自動刪除任何東西。

| 位置 | 保留的內容 | 你可能想做的事 |
|---|---|---|
| Zulip | bot 帳號及其 API 金鑰、私人頻道、所有話題與訊息、上傳的檔案，以及橋接發出的通知 | 停用 bot（個人設定 → Bots），讓它的 API 金鑰失效；依保存政策封存或刪除頻道與話題 |
| OpenCode | 所有 session，包括從聊天建立或 fork 的對話（它們是永久的 OpenCode session）、其歷史、Agent 在專案目錄中建立的檔案，以及 OpenCode 的設定 | 不需要做任何事。檢查從聊天建立的 session，不再需要的話在 OpenCode 中刪除 |
| OpenCode 憑證 | 橋接用來存取 OpenCode API 的密碼或 token | 若橋接有自己的憑證，請輪替 |
| 網路 | 為管理主控台或 OpenCode 轉送新增的反向代理或防火牆規則 | 移除 |

## 8. 確認

```sh
systemctl list-unit-files 'jt-oz-*' 'jt-opencode-*'   # no units
ss -ltnp | grep -w 8765                               # no listener
systemctl is-active opencode                          # OpenCode still running, untouched
```
