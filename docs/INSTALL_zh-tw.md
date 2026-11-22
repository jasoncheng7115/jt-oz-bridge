# 安裝 jt-oz-bridge

[English](INSTALL.md) · 繁體中文 · [日本語](INSTALL_ja.md) · [升級](UPGRADE_zh-tw.md) · [移除](UNINSTALL_zh-tw.md) · [總覽](../README_zh-tw.md)

本指南說明如何在已執行 OpenCode 的 Linux 主機上，把橋接安裝成 systemd 服務；可從網路安裝，也可用離線（隔離網路）套件包安裝。jt-oz-bridge `0.1.1` 是**開發預覽版**：完整的真人與手機驗收尚未完成，請先用拋棄式的 OpenCode 專案開始。

橋接永遠不會安裝、啟動、重啟或升級 OpenCode，永遠不讀 OpenCode 的資料庫，也不會為了繞過問題而建立或複製 session。安裝過程中也請維持這些原則。

## 1. 需求

| 項目 | 需求 |
|---|---|
| 主機 | 使用 systemd 的 Linux，x86_64。開發環境為 Ubuntu 24.04；其他架構尚未驗證。 |
| Python | CPython 3.13，服務帳號必須能讀取，且**不可**放在 `/root` 或 `/home` 之下（單元設定了 `ProtectHome=true`）。發行版套件或放在共用目錄的 uv 管理 Python 皆可，見第 4 節。 |
| 工具 | `uv`（建議）或 `pip`、`sha256sum`、`curl`，安裝時需要 root 權限。 |
| OpenCode | 已用自己的作業系統帳號執行、只在 loopback 監聽的 OpenCode 伺服器（V2 API；開發時使用 2.0.32，見[相容性](COMPATIBILITY_zh-tw.md)）。橋接會鎖定驗證時的確切版本。 |
| Zulip | 可建立 bot 與私人頻道的自架 Zulip 伺服器（開發時使用 12.3）。 |
| 資源 | 橋接單元的記憶體上限為 1 GiB。請為資料庫、加密附件與備份預留磁碟空間（附件預設配額 2 GiB）。 |

## 2. 預設目錄配置

| 路徑 | 內容 | 擁有者與權限 |
|---|---|---|
| `/opt/jt-oz-bridge/releases/<wheel-sha256>/` | 每個版本一個目錄：wheel、`requirements.txt`、SBOM、checksum 與 `venv/` | `root:jtoz`，目錄 755、檔案 644 |
| `/opt/jt-oz-bridge/` | 輔助腳本（`owner-probe.py`、`directory-probe.py`、`bridge-notice.py`、`bridge-standby.py`）與選用的共用 Python | `root`，755／644 |
| `/etc/jt-oz-bridge/config.toml` | 設定檔 | `root:jtoz`，640 |
| `/etc/jt-oz-bridge/secrets/` | 加密金鑰、Zulip bot API 金鑰、OpenCode 憑證 | `jtoz:jtoz`，目錄 700、檔案 600 |
| `/var/lib/jt-oz-bridge/` | 狀態：`bridge.db` 與 `artifacts/` | `jtoz:jtoz`，700 |
| `/etc/systemd/system/` | 來自 `ops/server/` 的單元與 drop-in | `root`，644 |
| `/usr/local/bin/jt-oz-bridge` | 指向使用中版本 CLI 的符號連結 | `root` |

`jtoz` 是隨附單元使用的服務帳號。以上為預設路徑；若要更改，單元與設定檔必須一起修改。狀態目錄與密鑰不可放在同步或網路檔案系統（Nextcloud、NFS、SMB）上。

除非另有說明，本指南的指令都在 root shell（`sudo -i`）中、以一般 umask 執行：

```sh
umask 022
export UV_LINK_MODE=copy   # venv files are copies, not hard links into root's uv cache
```

## 3. 服務帳號與目錄

```sh
useradd --system --user-group --home-dir /var/lib/jt-oz-bridge --no-create-home \
  --shell /usr/sbin/nologin jtoz
install -d -o root -g root -m 755 /opt/jt-oz-bridge /opt/jt-oz-bridge/releases
install -d -o root -g jtoz -m 750 /etc/jt-oz-bridge
install -d -o jtoz -g jtoz -m 700 /etc/jt-oz-bridge/secrets /var/lib/jt-oz-bridge
```

## 4. Python 3.13

若發行版的 Python 是 3.13，直接使用：

```sh
PY=/usr/bin/python3.13
"$PY" --version
```

否則把 uv 管理的 Python 安裝到共用目錄（線上），或解開離線套件包中的 Python（第 5.2 節）：

```sh
uv python install 3.13 --install-dir /opt/jt-oz-bridge/python
chmod -R go+rX /opt/jt-oz-bridge/python
PY=$(echo /opt/jt-oz-bridge/python/cpython-3.13.*/bin/python3.13)
"$PY" --version
```

## 5. 取得版本檔案

一個版本包含 wheel、以雜湊鎖定的 `requirements.txt`、SBOM `jt-oz-bridge-<version>.sbom.cdx.json`（CycloneDX 1.5），以及提供設定範例與 systemd 單元的原始碼封存檔。請在任何有網路、`git` 與 `uv` 的機器上產生：

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

每個 GitHub release 都附有 wheel、它的 `jt-oz-bridge-<version>.sbom.cdx.json` 與 `SHA256SUMS`；請把那個 wheel 與那份 SBOM 一起安裝。若是自己建的 wheel，先在同一份 checkout 上跑完整測試（以非 root 帳號），再從它產生 SBOM：

```sh
uv sync --locked --python 3.13
uv run --no-sync python -m scripts.make_sbom --uv uv \
  --wheel "$OUT/jt_oz_bridge-$VERSION-py3-none-any.whl" \
  --output "$OUT/jt-oz-bridge-$VERSION.sbom.cdx.json"
```

若執行環境中有任何鎖定的執行期相依套件版本不符，`make_sbom` 會失敗。

### 5.1 線上目標主機

寫入 checksum，再把整個目錄複製到目標主機：

```sh
(cd "$OUT" && sha256sum *.whl requirements.txt *.sbom.cdx.json *.tar.gz > SHA256SUMS)
```

### 5.2 離線（隔離網路）套件包

在可連網的機器上，再為**目標主機**的平台與 Python 下載所有相依套件的 wheel。下載時會強制比對 `requirements.txt` 中的雜湊：

```sh
uv venv --seed --python 3.13 ../dl-tools        # a throwaway venv that has pip
mkdir "$OUT/wheels"
../dl-tools/bin/python -m pip download --require-hashes --only-binary=:all: \
  --implementation cp --python-version 3.13 --abi cp313 --abi abi3 --abi none \
  --platform manylinux_2_28_x86_64 --platform manylinux_2_17_x86_64 \
  --platform manylinux2014_x86_64 --platform any \
  -r "$OUT/requirements.txt" -d "$OUT/wheels"
```

`manylinux_2_28` 的 wheel 需要目標主機的 glibc 為 2.28 以上。其他架構請替換平台標籤中的 `x86_64`（尚未驗證）。

若目標主機沒有 Python 3.13 或 `uv`，也一起帶過去。以下指令取得的是執行機器本身的版本，請在與目標主機相同架構的機器上執行：

```sh
uv python install 3.13 --install-dir ../py313
tar -C ../py313 -czf "$OUT/cpython-3.13-linux-x86_64.tar.gz" .
cp "$(command -v uv)" "$OUT/uv"
```

接著為所有檔案寫入 checksum，再用核准的媒體把目錄搬到目標主機：

```sh
(cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
```

套件包內容如下：

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

在沒有 Python 3.13 的離線目標主機上，用以下指令把帶來的 Python 解到共用目錄，取代第 4 節的線上指令：

```sh
install -d -m 755 /opt/jt-oz-bridge/python
tar -xzf cpython-3.13-linux-x86_64.tar.gz -C /opt/jt-oz-bridge/python
chmod -R go+rX /opt/jt-oz-bridge/python
PY=$(echo /opt/jt-oz-bridge/python/cpython-3.13.*/bin/python3.13)
```

## 6. 安裝版本

在目標主機上，進入複製過來的版本目錄：

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

**線上**：先安裝鎖定的相依套件，再以不含相依套件的方式安裝 wheel：

```sh
uv venv --python "$PY" "$R/venv"
uv pip install --python "$R/venv/bin/python" --require-hashes -r "$R/requirements.txt"
uv pip install --python "$R/venv/bin/python" --no-deps "$R/$WHEEL"
```

**離線**：只從套件包安裝（若有帶 `uv`，請用 `./uv`）：

```sh
uv venv --offline --python "$PY" "$R/venv"
uv pip install --offline --no-index --find-links ./wheels \
  --python "$R/venv/bin/python" --require-hashes -r "$R/requirements.txt"
uv pip install --offline --no-index --python "$R/venv/bin/python" --no-deps "$R/$WHEEL"
```

若使用 `pip` 而非 `uv`，同樣的離線安裝（含建立 venv）如下：

```sh
"$PY" -m venv "$R/venv"
"$R/venv/bin/pip" install --no-index --find-links ./wheels --require-hashes -r "$R/requirements.txt"
"$R/venv/bin/pip" install --no-index --no-deps "$R/$WHEEL"
```

接著把版本交給服務群組，並讓主機上可以使用 CLI：

```sh
chown -R root:jtoz "$R"
chmod -R go+rX "$R"
ln -sfn "$R/venv/bin/jt-oz-bridge" /usr/local/bin/jt-oz-bridge
```

## 7. 驗證 SBOM

SBOM 必須指名這個確切的 wheel，且列出的第三方套件必須與版本 venv 中實際安裝的完全相同：

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

若 venv 是用 pip 建立的，`uv pip freeze` 那一行請改用 `"$R/venv/bin/pip" freeze`。

## 8. 設定

把原始碼封存檔解到暫存位置，從範例設定開始：

```sh
tar -xzf jt-oz-bridge-src.tar.gz            # creates ./jt-oz-bridge-src/
install -o root -g jtoz -m 640 jt-oz-bridge-src/config.example.toml /etc/jt-oz-bridge/config.toml
```

第一次啟動時，只修改金鑰參照，所有整合都保持停用：

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

密鑰參照的格式為 `env:NAME` 或 `file:/absolute/path`。密鑰檔必須是一般檔案（不可是符號連結）、擁有者為服務帳號、只有擁有者可讀（權限 600），且不超過 64 KiB。未知的設定鍵會被拒絕。可用 `JTOZ__SECTION__FIELD` 環境變數覆寫單一設定。

以服務帳號驗證設定檔（不建立連線、不解析憑證），建立一次加密金鑰，再建立資料庫：

```sh
B="runuser -u jtoz -- $R/venv/bin/jt-oz-bridge --config /etc/jt-oz-bridge/config.toml"
$B validate
$B generate-key --secret-output /etc/jt-oz-bridge/secrets/master.key
$B migrate
```

`generate-key` 不會覆寫既有檔案，也不會印出金鑰。**請現在就另外備份金鑰**（例如存到離線媒體）：沒有它就無法讀取資料庫或備份，而且金鑰不可與備份放在一起。`migrate` 需明確執行，可重複執行；`serve` 會拒絕尚未遷移的資料庫，也拒絕以 root 執行。

## 9. 安裝並啟動服務

安裝主單元，並用 drop-in 指向版本目錄；之後升級只需修改 drop-in：

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

此單元以 `jtoz` 執行，沒有任何 capability，啟用 `NoNewPrivileges`、`ProtectSystem=strict`、`ProtectHome=true`，只能寫入 `/var/lib/jt-oz-bridge`，記憶體上限 1 GiB。單元中提到 `jt-opencode-owner.service` 與停止通知單元（第 12 節）；這些尚未安裝時，systemd 只會記錄一則提示。

## 10. 冒煙檢查

```sh
systemctl is-active jt-oz-bridge
systemctl show jt-oz-bridge -p NRestarts -p ExecStart
curl -s http://127.0.0.1:8765/healthz     # {"status":"alive"}
curl -s http://127.0.0.1:8765/readyz      # {"ready":true,"mode":"foundation","agent_consumers":false}
journalctl -u jt-oz-bridge --since -5min -p warning --no-pager
```

`foundation` 表示服務、設定、金鑰與資料庫都正常，但還沒有任何整合在執行。資料庫或 runtime 尚未就緒時，`/readyz` 會回 503 與 `"ready":false`。第一個服務持有租約期間，第二個服務實例會被拒絕。

## 11. 連接 Zulip 與 OpenCode

一次處理一個專案，先從拋棄式專案開始。詳細程序見[維運](OPERATIONS_SOP_zh-tw.md)。

### Zulip

1. 在 Zulip 建立 **generic bot**（個人設定 → Bots → 新增 bot），不要給它管理員權限。
2. 儲存它的 API 金鑰，不要讓金鑰出現在指令列上：

   ```sh
   runuser -u jtoz -- sh -c 'umask 077; cat > /etc/jt-oz-bridge/secrets/zulip-api-key'
   # paste the key, press Enter, then Ctrl-D
   ```

3. 建立保護歷史記錄的**私人**頻道。只加入 bot 和可以使用該頻道所屬專案的人；頻道成員都能讀到其中所有話題。
4. 記下這些人的數字使用者 ID 與頻道 ID（可在個人資料與頻道設定中看到）。
5. 在 `[[zulip_realms]]` 設定 `enabled = true`、`url`、`bot_email`、`api_key_ref = "file:/etc/jt-oz-bridge/secrets/zulip-api-key"`、`allowed_user_ids` 與 `allowed_channel_ids`。`request_budget` 要低於 Zulip 伺服器對該 bot 的速率限制。

### OpenCode

1. OpenCode 必須已用自己的帳號執行，並只在 loopback 監聽（例如 `opencode serve --hostname 127.0.0.1 --port 4096`；`ops/server/opencode.service` 是範例單元）。設定橋接的過程中，不要讓任何東西重啟它。
2. 在 `[[opencode_backends]]` 設定 `enabled = true`、`base_url`；若伺服器需要憑證，以 `file:` 參照設定 `credential_ref`。在 `[[projects]]` 描述專案與其工作目錄。
3. 安裝唯讀輔助服務，用來證明哪個 OpenCode 行程、資料集與目錄才是真的。把 `ops/server/owner-probe.py` 與 `directory-probe.py` 複製到 `/opt/jt-oz-bridge/`，安裝 `jt-opencode-owner.socket`／`.service` 與 `jt-opencode-directory.socket`／`.service`，並把兩個服務的 `User=`／`Group=` 改成執行 OpenCode 的帳號。等它們的 JSON 設定存在後（由納管步驟產生）再啟用 socket。
4. 用 `ops/server/onboard_root.py`（`prepare`、`directory`、`probe`、`cleanup`、`seal`）納管專案，作法見[維運：納管專案](OPERATIONS_SOP_zh-tw.md)。它以唯讀請求與受控測試檔證明一個既有 session，並寫出封存的設定、runtime enrollment 與本機 observer 政策；過程中不會開啟 OpenCode 的資料庫，也不會重啟 OpenCode。
5. 在橋接停止時，以服務帳號用封存的設定執行 `enroll-runtime`，安裝封存的檔案，再重新啟動：

   ```sh
   systemctl stop jt-oz-bridge
   runuser -u jtoz -- "$R/venv/bin/jt-oz-bridge" --config <sealed config> enroll-runtime
   # install the sealed config.toml and local-observer.json into /etc/jt-oz-bridge/
   systemctl start jt-oz-bridge
   curl -s http://127.0.0.1:8765/readyz      # expect "mode":"managed","agent_consumers":true
   ```

6. 為 `jt-oz-bridge sessions` 與 `doctor` 安裝本機 observer：`jt-oz-observer.service` 加上與第 9 節相同形式的 drop-in `/etc/systemd/system/jt-oz-observer.service.d/50-release.conf`（先寫空的 `ExecStart=`，再寫 `ExecStart=$R/venv/bin/jt-oz-bridge --config /etc/jt-oz-bridge/config.toml observe-serve --policy /etc/jt-oz-bridge/local-observer.json`）。啟用它，並在 `/readyz` 回報就緒之後才啟動。
7. 在 Zulip 的頻道中開新話題，隨便輸入一句話，選擇對話，然後輸入任務。

## 12. 選用單元

**停止與恢復通知。** 把 `ops/server/bridge_notice.py` 複製為 `/opt/jt-oz-bridge/bridge-notice.py`、`bridge_standby.py` 複製為 `/opt/jt-oz-bridge/bridge-standby.py`，安裝 `jt-oz-bridge-notice.service`、`jt-oz-bridge-standby.service`、`jt-oz-bridge-recovered.service` 與 `jt-oz-bridge-recovered.timer`，然後：

```sh
/usr/bin/python3 -I /opt/jt-oz-bridge/bridge-notice.py --dry-run   # prints, sends nothing
systemctl daemon-reload
systemctl enable --now jt-oz-bridge-recovered.timer
```

當橋接失敗且四分鐘內沒有自己恢復時，會在第一個允許的頻道（話題 `Bridge 狀態`）發一則通知，standby 會在每個話題回覆一次；`/readyz` 恢復就緒後，timer 會再發一則「已恢復」通知。這些腳本只用 Python 標準函式庫，並以 root 讀取橋接設定與密鑰。

**版本監看（選用）。** 把 `ops/server/release_watch.py` 複製為 `/opt/jt-oz-bridge/release-watch.py`，安裝 `jt-oz-release-watch.service` 與 `jt-oz-release-watch.timer`，然後：

```sh
/usr/bin/python3 -I /opt/jt-oz-bridge/release-watch.py --dry-run   # prints, sends nothing
systemctl daemon-reload
systemctl enable --now jt-oz-release-watch.timer
```

它每天只用 GET 查一次實際 Zulip 版本、GitHub 上公開的 Zulip 版本清單與 OpenCode 的更新資訊，每個新版本只在 `Bridge 狀態` 發一次，並寫明這一版橋接接不接受。它不安裝任何東西。升級 Zulip 前請執行 `ops/server/check_zulip_upgrade.py`（見維運 SOP）。

**管理主控台。** `runuser -u jtoz -- "$R/venv/bin/jt-oz-bridge" --config /etc/jt-oz-bridge/config.toml bootstrap-admin --username admin` 會印出一次性密碼，第一次登入時必須更改。主控台使用 Secure cookie，因此需要 HTTPS 反向代理與 `admin.public_url`；橋接本身請維持在 loopback。

## 13. 疑難排解

| 症狀 | 檢查 |
|---|---|
| `Configuration/operation rejected` | 以 `jtoz` 執行 `validate`。檢查第 2 節的路徑、擁有者與權限；密鑰檔必須是 600 且擁有者為 `jtoz`。此訊息刻意不顯示輸入值。 |
| 服務立刻結束 | `journalctl -u jt-oz-bridge -n 50`。是否已用這個版本執行 `migrate`？Python 直譯器是否在 `/root` 與 `/home` 之外？ |
| `/readyz` 回 503 | 資料庫、租約或 runtime 尚未就緒，請看 journal。納管後可用 `jt-oz-bridge doctor` 找出缺少的部分。 |
| `pip download` 找不到 wheel | 該相依套件沒有該平台標籤的 wheel；加上正確的 `--platform` 標籤，或在目標平台的機器上建置 wheel。 |
| `--require-hashes` 失敗 | 檔案與鎖定檔不符。不要拿掉這個選項，請從官方套件索引重新取得檔案。 |

下一步：[升級](UPGRADE_zh-tw.md) · [移除](UNINSTALL_zh-tw.md) · [維運](OPERATIONS_SOP_zh-tw.md)
