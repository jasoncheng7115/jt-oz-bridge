# 升級 jt-oz-bridge

[English](UPGRADE.md) · 繁體中文 · [日本語](UPGRADE_ja.md) · [安裝](INSTALL_zh-tw.md) · [移除](UNINSTALL_zh-tw.md) · [總覽](../README_zh-tw.md)

升級時，新版本會安裝在執行中版本的**旁邊**；接著備份橋接自己的資料庫、執行遷移、用 systemd drop-in 切換服務、檢查就緒狀態，並保留前一版以便回滾。線上與離線的步驟相同，差別只在版本檔案如何送到主機。

OpenCode 永遠不屬於橋接升級的一部分：在這裡不要停止、重啟或升級它。橋接停止期間，OpenCode 中的工作會繼續執行，橋接恢復後會補上（最近 10 分鐘內的訊息會自動送出；更早的訊息等使用者回覆 `!go` 或 `!no`）。

目錄配置與慣例同[安裝](INSTALL_zh-tw.md)：root shell 使用 `umask 022` 與 `UV_LINK_MODE=copy`、服務帳號 `jtoz`、版本放在 `/opt/jt-oz-bridge/releases/<wheel-sha256>/`，並以 drop-in `50-release.conf` 選擇版本。

## 開始之前

- 閱讀版本說明或自你目前版本以來的 commit：是否變更資料庫 schema？是否需要修改設定、新增單元或輔助腳本？是否說明無法回滾到它之前的版本？
- 使用通過完整測試閘門的 wheel 及其 SBOM。
- 選一個空檔進行。`jt-oz-bridge sessions --active` 會列出進行中的工作。橋接大約會停止一分鐘。
- 確認磁碟空間足夠做一次完整備份。
- 記下目前版本與 OpenCode 的行程識別：

```sh
OLD=$(systemctl show jt-oz-bridge -p ExecStart --value | grep -o '/opt/jt-oz-bridge/releases/[0-9a-f]\{64\}' | head -1)
echo "$OLD"
systemctl show opencode -p MainPID -p NRestarts -p InvocationID   # use your OpenCode unit name
```

## 1. 並列安裝新版本

依[安裝](INSTALL_zh-tw.md)第 5 至 7 節，用新版本的檔案操作：線上建置或取得，或帶著離線套件包（第 5.2 節）並以 `--offline --no-index --find-links ./wheels` 安裝。依該文件驗證 `SHA256SUMS` 與 SBOM。**先略過 `ln -sfn` 那一行**；CLI 符號連結在第 4 步才切換。

```sh
NEW=/opt/jt-oz-bridge/releases/<new wheel sha256>
runuser -u jtoz -- "$NEW/venv/bin/jt-oz-bridge" --config /etc/jt-oz-bridge/config.toml validate
```

以上步驟都不會動到執行中的服務。若新版本需要修改設定，請寫到副本（`/etc/jt-oz-bridge/config.toml.new`，`root:jtoz` 640），用新版本驗證副本，並保留目前的檔案以便回滾。若版本附帶有變更的輔助腳本或單元（用 `cmp` 與已安裝的比對），也一併準備好。

## 2. 停止橋接並備份

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

備份是經過驗證的快照，包含資料庫、加密附件與實際生效的設定。橋接執行中時會拒絕備份。它**不**包含加密金鑰、密鑰檔或 enrollment 檔，這些請另外備份。輸出中的 `schema_revision` 是目前的 schema。

## 3. 以新版本執行遷移

```sh
runuser -u jtoz -- "$NEW/venv/bin/jt-oz-bridge" --config /etc/jt-oz-bridge/config.toml migrate
"$NEW/venv/bin/python" -I -c 'import sqlite3; db = sqlite3.connect("file:/var/lib/jt-oz-bridge/bridge.db?mode=ro", uri=True); print(db.execute("select version_num from alembic_version").fetchone()[0])'
```

把印出的 revision 與 `$C/backup.json` 中的 `schema_revision` 比對。**若有改變，前一版就無法再使用這個資料庫**：從這裡開始，回滾代表要還原備份（第 6 步情況 B），而不只是切換程式。schema 已是最新時，`migrate` 不做任何事。若使用 PostgreSQL，請用資料庫工具查詢同一個 `alembic_version` 資料表。

## 4. 切換

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

等橋接回報就緒後才啟動 observer：它需要遷移後的 schema，兩者同時啟動可能讓它失敗一次。

## 5. 冒煙檢查

約 30 秒後執行：

```sh
systemctl is-active jt-oz-bridge jt-oz-observer
systemctl show jt-oz-bridge -p NRestarts -p ExecStart      # NRestarts=0, ExecStart names $NEW
curl -s http://127.0.0.1:8765/readyz                        # "ready":true
journalctl -u jt-oz-bridge --since -2min -p warning --no-pager
systemctl show opencode -p MainPID -p NRestarts -p InvocationID   # identical to before
jt-oz-bridge doctor
```

這裡任何一項失敗，都應回滾。冒煙檢查通過只證明服務已啟動；請在拋棄式話題送一則短訊息，確認聊天路徑。

## 6. 回滾

**情況 A：schema 沒有改變。** 把服務指回前一版：

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

然後重做冒煙檢查。

**情況 B：schema 已改變。** 前一版無法讀取遷移後的資料庫，而且絕不可把較舊的資料庫檔案覆蓋到較新的資料上。你有兩個選擇：

1. **往前修正（建議）。** 保留新 schema，用相同步驟部署修正後的更新版本。
2. **還原升級前的備份。** 用前一版把快照還原到**新的**目錄，並審查暫停式恢復：還原的副本啟動時所有功能都關閉、每個話題都暫停，直到審查完成，再用 `complete-restore` 收尾。橋接在升級後記錄的一切都會從它自己的紀錄中消失（OpenCode 中發生的事仍留在 OpenCode），因此使用者可能需要檢查自己的話題。

```sh
systemctl stop jt-oz-observer jt-oz-bridge
cp -a "$C/config.toml" /etc/jt-oz-bridge/config.toml
install -d -o jtoz -g jtoz -m 700 /var/lib/jt-oz-bridge-recovery
runuser -u jtoz -- "$OLD/venv/bin/jt-oz-bridge" --config /etc/jt-oz-bridge/config.toml \
  restore --backup "/var/backups/jt-oz-bridge/pre-upgrade-$STAMP" \
  --destination "/var/lib/jt-oz-bridge-recovery/restore-$STAMP"
```

審查完成後，依情況 A 把 drop-in 與 CLI 符號連結切回前一版。

有些版本即使沒有改變 schema，也會記錄舊版本無法重播的資料（例如從聊天建立的對話）；版本說明會註明，處理方式同樣是往前修正。

## 7. 清理

在新版本通過驗收之前，保留前一版、備份與 `$C`。之後再移除已不被任何東西參照的版本目錄：

```sh
grep -h ExecStart= /etc/systemd/system/jt-oz-*.service.d/*.conf
readlink /usr/local/bin/jt-oz-bridge
rm -rf /opt/jt-oz-bridge/releases/<old wheel sha256>     # never the active or the previous one
```

venv 會連結到建立它時使用的 Python。若你在 `/opt/jt-oz-bridge/python` 安裝了較新的 Python 3.13，請保留舊的，直到沒有任何剩下的版本使用它（`readlink -f <release>/venv/bin/python`）。

## 離線升級

在可連網的機器上，完全依照[安裝第 5.2 節](INSTALL_zh-tw.md)建立新版本的套件包：wheel、`requirements.txt`、SBOM、原始碼封存檔、目標平台的 `wheels/`、選用的 Python 與 `uv`，以及 `SHA256SUMS`。在目標主機上先執行 `sha256sum -c SHA256SUMS`，以 `--offline --no-index --find-links ./wheels --require-hashes` 安裝到新的版本目錄，驗證 SBOM，再繼續上面的第 2 至 7 步。第 2 至 7 步除了聊天確認之外，都不需要網路。

## OpenCode 升級是另一件事

不要在同一個維護時段升級 OpenCode。橋接會鎖定驗證時的 OpenCode 確切版本與政策，遇到其他版本會拒絕啟動，直到重新驗證為止。升級 OpenCode 前請先用 `ops/server/check_native_upgrade.py` 評估。
