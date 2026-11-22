# 維運手冊

[English](OPERATIONS_SOP.md) · [安裝](INSTALL_zh-tw.md) · [升級](UPGRADE_zh-tw.md) · [測試](TESTING_zh-tw.md)

說明如何在已有 OpenCode 的 Linux 主機上執行 jt-oz-bridge。路徑都是預設值：設定在 `/etc/jt-oz-bridge`，狀態在 `/var/lib/jt-oz-bridge/service`，版本在 `/opt/jt-oz-bridge/releases/<wheel-sha256>`。這是開發版（0.1.1），尚無正式發行；照這些步驟做，本身並不代表部署已可正式上線。

## 永遠適用的規則

- **Bridge 的任何操作都不重啟 OpenCode。** Bridge 有自己的生命週期。重啟會中斷進行中對話的即時串流，必須經 OpenCode 管理者同意。
- **不讀也不複製 OpenCode 資料庫。** Bridge 只用它的 API。用 `stat` 看檔案屬性可以。
- 不為了過關而建立、fork 或複製對話。
- 不用舊的 Bridge 資料庫蓋掉新資料，也不降版越過已遷移的 schema。往前修。
- 不替別人恢復被保留的工作。要不要恢復（`!go`）由該話題的人決定。Bridge 重新啟動後，最近 10 分鐘內的訊息（包括離線期間傳的）會自動送出，有更早的訊息在等的話題會收到一次回覆。重啟或斷線造成的暫停，該話題的人送出新訊息時也會自動繼續，除非有執行中、狀態不明或因其他原因保留的工作。有人自己選的暫停不會被自動解除。
- 機密放在僅擁有者可讀的檔案。下面的指令只用引用，不放值。
- Bridge 的規則關不住有特權的 OpenCode。OpenCode 有 sudo 時，Bridge 的核准不是沙箱。

## 安裝

設定、機密檔、金鑰與首次遷移請照[安裝](INSTALL_zh-tw.md)。簡單說：

1. 建立服務帳號和僅擁有者可讀的狀態目錄。
2. 建立版本目錄（見下一節步驟 2）。
3. 由 `config.example.toml` 寫出 `/etc/jt-oz-bridge/config.toml`，再執行 `jt-oz-bridge --config <設定檔> validate`，它不會開任何連線。
4. 用服務帳號執行一次 `generate-key`，金鑰另外備份。然後執行 `migrate`。
5. 從 `ops/server/` 安裝 unit：`jt-oz-bridge.service`、`jt-oz-observer.service` 和輔助 socket。加上 drop-in 把 `ExecStart` 指向該版本。
6. 至少納管一個專案（見下），再啟動服務。

## 部署新版本

功能整批上線：完整測試、不啟用安裝，再做一次短切換並自動回滾。

### 1. 跑完整測試

從 GitHub release 取得 wheel 與 SBOM（`jt-oz-bridge-<版本>.sbom.cdx.json`），或從同一份 checkout 自行建置兩者。先在那份 checkout 上跑完整測試，以非 root 帳號、在有真實 CPU 的主機上執行：用 root 執行會讓檔案權限測試失敗，慢的虛擬 CPU 會趕不上時間限制。

```sh
uv sync --locked
uv run ruff check src tests scripts && uv run mypy src
uv run pytest -q -p no:cacheprovider tests
uv build --wheel --out-dir dist
uv run python -m scripts.make_sbom --uv uv --wheel dist/<wheel> --output dist/jt-oz-bridge-<版本>.sbom.cdx.json
```

每個測試都要通過且零 skip。測試通過只代表從那份 checkout 建出的 wheel，所以要把那個 wheel 和那份 SBOM 一起安裝。測試執行期間不要改動 checkout。大量測試前先查磁碟：至少 12 GiB，且預估會超過 80% 就先停。

### 2. 安裝但不啟用

```sh
R=/opt/jt-oz-bridge/releases/<wheel-sha256>
install -d -o root -g <服務群組> -m 755 "$R"
cp <wheel> uv.lock pyproject.toml "$R/"
uv export --frozen --no-dev --no-emit-project --format requirements-txt -o "$R/requirements.txt"
uv venv --python <python3.13> "$R/venv"
uv pip install --python "$R/venv/bin/python" --require-hashes -r "$R/requirements.txt"
uv pip install --python "$R/venv/bin/python" --no-deps "$R/<wheel>"
runuser -u <服務帳號> -- "$R/venv/bin/jt-oz-bridge" --config /etc/jt-oz-bridge/config.toml validate
```

這不會動到執行中的服務。檔案必須讓服務群組讀得到。

### 3. 切換並自動回滾

把這些步驟寫成腳本，第 4 步之後、資料庫遷移（第 7 步）之前，任何失敗都執行回滾。所有東西存到一個新的、僅 root 可讀的控制目錄。

1. 確認目前 drop-in 指向舊版、wheel hash 相符，且 `/etc/jt-oz-bridge/promotion-active` 不存在。那個檔案會擋住服務啟動。
2. 記錄 OpenCode 身分：`systemctl show opencode -p MainPID -p ExecMainStartTimestampMonotonic -p NRestarts -p InvocationID`。
3. 保存兩個 drop-in 和 CLI symlink 的目標。
4. `systemctl stop jt-oz-bridge jt-oz-observer`
5. 用 SQLite backup API 把 Bridge 資料庫備份到控制目錄，權限 600。這份只用於退回。真正的備份請做完整快照。
6. 記下未完成的傳送和未結束的動作。未完成的輸出若依賴這版改掉的東西，就在這裡停止。
7. schema 有變時，用服務帳號執行 `migrate`。**從這裡開始不能靠換回程式回滾**，因為舊版讀不了新資料庫。只能往前修。
8. 把兩個 drop-in 和 CLI symlink 指向新版，然後 `systemctl daemon-reload` 並啟動兩個服務。
9. 30 秒後做冒煙測試。兩個 unit 都 active 且 `NRestarts=0`，`ExecStart` 是新版，OpenCode 身分沒變，schema 符合預期，`/readyz` 回報 ready，`journalctl -p warning` 沒有新內容。
10. 任何失敗都回滾（第 7 步已遷移資料庫時除外，那時改為往前修正）：還原 drop-in 和 CLI symlink，`daemon-reload`，重啟兩個服務，再檢查一次。

冒煙測試只證明服務有起來。聊天、按鈕、檔案和手機還要由真人在官方電腦版與手機 App 實際試過。

回滾到不支援附按鈕佇列回覆的舊版時，有些收據舊程式無法重播：附按鈕存下的 closed 佇列回覆多了 `widget` 欄位，Bridge 問過的單獨「ok」有 `bare-answer` 收據。只影響這類訊息的重送事件，會改成擱置，不會重播。

## 納管專案

用選定版本的 Python 以 root 執行 `ops/server/onboard_root.py`。它用唯讀請求和受控測試檔，在這台主機上證明一個既有對話。它不開 OpenCode 資料庫，也不重啟 OpenCode。

spec 檔要寫 `tag`、`release`、`project_id`、`directory`、`session_id`、`native_project_id` 和 `probe_socket`。

```sh
PY="<版本>/venv/bin/python -I -B"
$PY onboard_root.py prepare   --spec spec.json
$PY onboard_root.py directory --spec spec.json
# 用產生的 helper 設定，在 probe_socket 上跑一個私有目錄 helper
$PY onboard_root.py probe     --spec spec.json
$PY onboard_root.py cleanup   --spec spec.json
$PY onboard_root.py seal      --spec spec.json
runuser -u <服務帳號> -- <版本>/venv/bin/jt-oz-bridge --config <封存的設定檔> validate
```

`probe` 失敗也要跑 `cleanup`。這些步驟在執行中的服務旁進行。接著在一個短時段內啟用，並先留存 helper 設定、主設定和 observer 檔的複本以便回滾：

1. 停 observer 和 Bridge。照上面方式備份 Bridge 資料庫。
2. 安裝新的 helper 設定，只重啟目錄 helper。
3. 用服務帳號以封存的設定檔執行 `enroll-runtime`。
4. 安裝封存的設定和 observer 檔，再啟動 Bridge 和 observer。
5. 確認 OpenCode 身分沒變。任何失敗就還原複本並重啟。

只授權該專案該用的人。授權前先看該對話的 agent 能做什麼。工具範圍很廣的對話，會把那些能力交給所有被授權的人。

## 開放專案「開新對話」

以 root 用現役 release 的 Python 執行 `ops/server/certify_creation.py`。`plan` 只送 GET，列出會送出的請求與政策範本 checksum。`certify` 只送一次 `session.create`，且必須帶 `--template-sha256 <plan 的 checksum> --i-understand-this-creates-a-permanent-native-session`。這會在 OpenCode 永久留下一個對話，聊天無法刪除。新對話的權限規則請用該 agent 自己的規則，新對話的實際權限才會和既有對話完全相同。工具會寫出證據與一筆 `creation_projects`。接著：

1. 把那筆加進新的 runtime manifest，並在同一 backend 每個 Root 的 `verified_operations` 加上 `session.create` 與 `session.get`。
2. 複製 config 指向它，設 `session_creation_enabled = true`；複製 observer 檔並更新 `runtime_enrollment_sha256`。
3. 以服務帳號驗證副本，再像切換版本一樣在短時間內切換；保留舊 config 與 observer 檔，回滾時一併還原。

新對話的規則與來源對話相同、且專案沒有已儲存的永久允許時，可以用 `!files` 與 `!file`。照上面做法照抄 agent 自己的規則就符合。

一旦透過聊天建立過對話，就不要回滾到不支援建立的版本：它啟動時還原會拒絕較新的建立紀錄，Bridge 會停住。請改為往前修。

## 一個專案一個私人頻道

`[[zulip_realms.channel_projects]]` 指定某個頻道服務哪些專案。在有列出的頻道開新話題，只會出現那些專案的對話與 **開新對話**；沒列出的頻道照舊列出全部專案。列出的頻道必須已在 `allowed_channel_ids` 內。從有列出的頻道建立的連線，無論經由任何選單或代碼，都連不到其他專案。

1. 在 Zulip 建立私人頻道並開啟受保護歷史，只加入 Bot 與有該專案授權的人。
2. 把頻道 ID 加進 `allowed_channel_ids`，並新增 `channel_projects`，填 `channel_id` 與 `projects`。
3. 停止 Bridge 後，以服務帳號用新 config 執行 `enroll-runtime`，它會檢查頻道為私人且每位成員都已核准。
4. 照上面方式切換，保留舊 config 以便回滾。

## 開啟檔案傳輸

納管後 `!file` 下載就可用。上傳要執行 `ops/server/enable_file_transfer.py` 才開啟，一次一個對話。AI 產出檔自動回傳是另一件事（見[下方](#開放-ai-產出檔自動回傳)）。

```sh
PY="<版本>/venv/bin/python -I -B"
$PY enable_file_transfer.py preflight --spec spec.json     # 不寫任何東西
$PY enable_file_transfer.py prepare   --spec spec.json     # exit 3 表示等待真人上傳
# 由真人在該對話的話題上傳一個真實檔案，然後：
$PY enable_file_transfer.py scan-source --spec spec.json
$PY enable_file_transfer.py prepare   --spec spec.json --message-id <id>
$PY enable_file_transfer.py activate  --spec spec.json     # 短暫停機，冒煙失敗會回滾
$PY enable_file_transfer.py status    --spec spec.json
```

選用的版本必須支援逐對話的檔案範圍，否則工具會回報 `release_lacks_workspace_roots_scope`，要先部署較新的版本。工具需要一次真人上傳。它不會發訊息到 Zulip，也不會假造。其他對話的項目維持不變。專案在 `/home` 底下會被拒絕，因為服務看不到那個路徑。退回用 `rollback` 和 `namespace-remove`。完成後請真人在該話題於電腦版與手機各試一次上傳與 `!file` 下載。

## 開放 AI 產出檔自動回傳

AI 產出檔自動回傳預設關閉，一次只對一個已納管的 Root 開啟。[`certify_generated.py`](../ops/server/certify_generated.py) 替該 Root 產生限定範圍的 `qualified-generated-outputs-v2` 證據，並備妥切換用檔案。證據只涵蓋實際案例讀到的產出來源與最大檔案大小；其他產出一律計為不支援（見限定範圍資格）。以 root 用所選版本的 Python 逐步執行：

```sh
$PY certify_generated.py plan    --spec spec.json   # 只有 GET，不寫任何檔
$PY certify_generated.py certify --spec spec.json --plan-sha256 <plan 輸出值> \
    --i-understand-this-sends-operator-prompts-to-the-original-root
$PY certify_generated.py stage   --spec spec.json   # 不送任何 OpenCode 請求
```

`spec.json` 需有 `tag`，以及 `project_id` 或 `session_id` 其中之一；`config`、`observer`、`output`、`stage` 為選填絕對路徑，兩個輸出目錄都不得已存在。

- `certify` 對該 Root 最多送 2 則 operator 提示及最多 12 個權限回覆。只有 `<資料夾>/jt-oz-generated-<tag>` 內預定的檔案與那一條預定指令回 `once`，其餘一律 `reject`，從不回 `always`。其他任何 mutation，以及超過 8000 次 GET 或 2 GiB 回應都會拒絕。不送 interrupt、表單回覆，也不重試。
- Worker 在 transient unit 內以 Bridge 服務帳號執行；不開 OpenCode 資料庫、不重啟 OpenCode，前後的 OpenCode PID、重啟次數與 binary SHA-256 必須完全相同。
- 六項負向檢查都用真正的 reader 對實際擷取的產出執行。只有每個欄位都來自實際觀察且 runtime 驗證器接受時才寫出證據；否則 `FAILED.json` 與被拒的證據留在輸出目錄。
- 預定檔案會留在 Root 的 workspace，operator 的對話會成為它歷史的一部分（可能被鏡像到已綁定的話題）。這些 operator 提示不能取代真人在聊天與手機上實際試用。
- `stage` 寫出新的 `runtime.json`、只改 `enrollment_file` 與 `generated_returns_enabled = true` 的 `config.toml`，以及只重釘 `runtime_enrollment_sha256` 的 observer 檔，寫出前先經 runtime 自己的載入器驗證。照上面方式切換到這些檔案之前都不會生效。

## 開放子代理（樹狀 lineage）

只有 leaf 資格的 Root，一旦它的 agent 啟動子代理，就拒絕所有工作（`leaf_descendants_require_qualification`）。[`certify_lineage.py`](../ops/server/certify_lineage.py) 產生經 operator 審閱的 `installed-original-lineage-resource-observation-v1` 文件（`qualification_scope: "tree"`），並備妥把一個已納管 Root 切到樹狀 provider 的 `adoption_projects` 項目（見明確 runtime pin）。以 root 用所選版本的 Python 逐步執行：

```sh
$PY certify_lineage.py plan    --spec spec.json   # 只有 GET，不寫任何檔
$PY certify_lineage.py certify --spec spec.json --plan-sha256 <plan 輸出值> \
    --i-understand-this-sends-operator-prompts-to-the-target-session
$PY certify_lineage.py stage   --spec spec.json   # 只有 GET，之後寫出 stage
```

`spec.json` 需有 `tag`、以 `project_id` 或 `session_id` 其中之一指定 anchor Root，以及 `target_session_id`：同一專案與資料夾下、Bridge 不認得（未納管、不是聊天開的或分支出來的）、沒有子會話、可拋棄的頂層 session，例如為此在 TUI 開的一個。`config`、`observer`、`output`、`stage` 為選填絕對路徑，兩個輸出目錄都不得已存在。

- 觀察在 target 上取得，絕不在 anchor 上，因為子代理一旦產生就無法從 session 移除。Runtime 只在 anchor 及其專案內每個聊天開的 Root 還沒有子會話時記錄第一個樹狀基準。`plan` 把已有子會話的 Root 列為 `activation_blockers`，只要還有任何一項，`stage` 就拒絕。
- `certify` 對 target 最多送 2 則 operator 提示（一則啟動會寫出 `<資料夾>/jt-oz-lineage-<tag>/child.txt` 的 `general` 子代理，另一則啟動一個會再啟動子代理的子代理），並對 target 與已驗證的子孫最多回 6 個權限要求：只有預定的 `task` 啟動與那一個檔案回 `once`，其餘一律 `reject`，從不回 `always`。超過 12000 次 GET 會拒絕；不送 interrupt、表單回覆，也不重試。
- 每個觀察窗都只送 GET，mutation 計數必須為零。十項檢查都由實際觀察計算（子會話執行中、等待與閒置；leaf provider 拒絕已長出子會話的 target；anchor 被當成外部 session 拒絕；注入的 owner 與改過的 agent policy 被拒；過期的五秒 proof 不再授權任何事；兩個相同的已穩定 proof）。任何沒觀察到的項目都使整次失敗。
- 同上，worker 以 Bridge 服務帳號執行，不開 OpenCode 資料庫、不重啟 OpenCode。Target 會保留子代理與預定檔案；若它已綁 Zulip 話題，leaf provider 從此會拒絕它。
- `stage` 寫出 `adoption-policy.json`、`lineage.json`、只加入一個 `adoption_projects` 項目的 `runtime.json`、只改 `enrollment_file` 的 `config.toml`，以及只重釘 `runtime_enrollment_sha256` 的 observer 檔。啟用 agent 切換的 Root 會被拒絕。改釘另一份觀察，或 OpenCode 升級後需要新觀察，都會使之後長出子會話的 Root 歷史失效。

## 評估 OpenCode 升級

不要就地升級 OpenCode。Bridge 綁定確切版本，其他一律拒絕。先執行 `check_native_upgrade.py`，再照[升級](UPGRADE_zh-tw.md)。結果乾淨也只代表知道要重新驗證什麼。

## 升級 Zulip

Bridge 接受驗證過的 Zulip 版本，以及同一大版之後的維護版（例如驗證 11.1、實際 11.3）。新的大版（13.0）或開發版會讓 Bridge 停下，直到完成驗證。較舊的 Bridge 版本要求 Zulip 版本完全相同，所以連維護版升級都會讓它停下。

1. 升級前，在 Bridge 主機上用已部署版本的 Python 執行 `check_zulip_upgrade.py --sources zulip-server-<版本>.tar.gz`（也可依發布說明用 `--version V --feature-level L`）。結束碼 0 表示 Bridge 會繼續運作；1 表示會繼續運作，但 Zulip 的上傳程式變了，先審閱檔案傳送（上傳關聯）；2 表示 Bridge 會停下，先不要升級；3 表示無法判斷。
2. 先備份 Zulip（`/etc/zulip` 與 `manage.py backup`），用官方 `SHA256SUMS` 核對 tarball，並避開 Bridge 切換。
3. 升級後不帶參數再跑一次（會詢問實際伺服器），然後確認 `readyz`，並確認訊息仍有回覆。

`jt-oz-release-watch.timer` 每天（09:30）查一次 Zulip 與 OpenCode 有沒有新版本，每個新版本只在 `Bridge 狀態` 發一次，並寫明這一版 Bridge 接不接受。只用 GET，不安裝任何東西。

## 重啟與復原

| 情況 | 做法 |
|---|---|
| 重啟 Bridge | `systemctl restart jt-oz-bridge jt-oz-observer`。不會動到 OpenCode 的工作。最近 10 分鐘內的訊息會自動送出；有更早訊息在等的話題會收到一次回覆，請對方選 `!go`／`!no`。最終輸出應會補上，但尚未在所有情況驗證過，請確認 |
| Bridge 起不來 | `systemctl status jt-oz-bridge`、`journalctl -u jt-oz-bridge -n 50`。確認沒有 `promotion-active`。用服務帳號執行 `validate` |
| 重開機之後 | 兩個 unit 都已 enable。先看 `/readyz`，再 `jt-oz-bridge doctor` |
| OpenCode 被重啟過 | 能證明是同一 session、資料夾、contract、semantics 與安裝證據時，Bridge 會自己接回每個話題並貼一行告知。沒能接回的話題會告知，在那裡回一次 `!ok` 就會接上（`!reconnect` 可先看細節），不要從伺服器端假造 |
| 話題顯示暫停 | 告訴該話題的人。由他用 `!status` 檢視，再決定要不要 `!go` |
| 資料遺失 | 用保留式還原還原到新目錄。它一開始所有功能都關閉，需要審核 |

## 回覆停止時

照順序檢查，全部唯讀。

```sh
systemctl is-active jt-oz-bridge jt-oz-observer opencode
curl -s http://127.0.0.1:8765/readyz          # 預設綁定；應為 ready true
jt-oz-bridge doctor
jt-oz-bridge sessions                         # 每個對話的狀態與是否 paused
journalctl -u jt-oz-bridge --since -1h -p warning --no-pager
journalctl -u jt-oz-bridge --since -1h --no-pager | grep -E 'work_deferred|root_watch|creation_held|creation_restore|public_feed'
```

| 看到 | 意思 | 做法 |
|---|---|---|
| 該話題 `paused=True` | 佇列被保留，通常在停止、移動或復原之後 | 由該話題的人用 `!status` 檢視後，以 `!go` 恢復 |
| `work_deferred category=... count=... reason=...` | Bridge 一直拒絕某些工作並重試，每類最多 5 分鐘記一次。`category` 指出是什麼 | 少數幾筆後停止是正常的。持續就看 category。`native_state_not_current` 表示 Bridge 無法證明該對話的狀態 |
| `root_watch_lost session=...` | Bridge 失去對該對話的監看，恢復前會拒絕那裡的工作。它會自己重試 | 等下一行 |
| `root_watch_restored session=...` | 監看恢復，OpenCode 還是同一個 | 不用動。確認回覆有恢復 |
| `root_watch_restore_deferred session=... error_type=...` | 重試失敗，維持關閉 | 重複出現就檢查 OpenCode 和 owner helper |
| `root_watch_revoked cause=... session=...` | 監看被撤掉：`generation` 表示納管內容變了，`watch_failed` 表示建立失敗。部分舊版沒有這行，沒看到不代表什麼 | 接著找 `root_watch_lost` |
| `public_feed_event_discarded reason=oversized session=...` | 有一個 OpenCode 事件太大無法讀取（超過 1 MiB），例如工具讀了大檔案。Bridge 丟棄它、不存放，並繼續運作。該對話的下一步會重新向 OpenCode 確認；`unattributed` 表示所有對話都重新確認 | 回覆有繼續就不用動。同一對話重複出現就保留 log 並回報時間 |
| `creation_held action=... kind=... code=...` | 從聊天開的新對話在連上前停下，話題維持「建立中」。`code` 指出哪個檢查沒過 | 本人在那個話題隨便打一句看狀態，再打 `!go`。同一個 code 再出現就保留 log 回報 |
| `creation_restore_deferred action=... session=... kind=... code=...` | 啟動時，有一個從聊天開的對話無法重新連上（任何專案都適用，例如 OpenCode 外掛或權限設定改變後）。Bridge 仍會啟動，只有那個對話拒絕工作，並每 30 秒重新讀取（只用 GET）。這段時間在那裡送的訊息最多等 5 分鐘；還接不回就告知對方一次「沒有送出」 | 等 `creation_restore_recovered`。同一個 code 重複出現就保留 log 回報；`created_root_current_policy_changed` 或 `creation_policy_source_drifted_from_operator_approval` 表示 OpenCode 權限設定變了，需要操作者審查 |
| `creation_restore_recovered action=...` | 那個對話已重新連上 | 不用動。確認回覆有恢復 |
| `runtime_component_failed stage=worker component=... error_type=... code=...` | 有一個背景工作停了，所以 Bridge 結束，再由 systemd 重新啟動。`code` 是固定的原因代碼，沒有就是 `-`。`native-session-graphs` 讀 OpenCode 失敗，或讀到一半對話剛好有變動時，改為稍後重試，會記成 `work_deferred category=original_graph_native_unavailable` 或 `original_graph_changed_while_reading` | 同一個 component 和 code 重複出現，就保留 log 回報 |
| 大約每小時一次 `work_deferred category=original_graph_native_unavailable ... reason=upstream_rejected_request` | OpenCode 會在專案閒置約一小時後卸載它，重新載入後的第一次讀取（`/api/agent/build`）會被拒絕一次，Bridge 幾秒後再讀 | 不用動。只有在每分鐘都增加時才回報 |
| `dispatch_outcome_uncertain operation=... steer=... kind=... code=...` | Bridge 無法確定 OpenCode 有沒有收到一則訊息（例如送到一半連線斷了）。`kind` 和 `code` 說明情況，不記錄內文。這則訊息不會自動重送 | 等後面確認結果的 `uncertain_prompt_*` 那行。重複出現就保留這行 |
| `dispatch_steered`／`dispatch_steer_deferred code=...` | OpenCode 工作中送的訊息送進了進行中的回覆（`steered`），或插不進去、改等這一輪結束後自己開一個回覆（`deferred`；`code` 說明原因，例如這一輪剛結束是 `v2_native_steer_session_not_running`，送出防護在訊息任何 byte 送出前拒絕是 `v2_native_steer_transport_did_not_send`）。不記錄內文 | 不用動。若每則都是同一個 code 的 `deferred`，保留這些行回報 |
| `uncertain_prompt_read_back_admitted`／`uncertain_prompt_never_arrived` | Bridge 回讀 OpenCode 的對話（只用 GET）：訊息在裡面就照常追回覆；從沒送到就在話題通知一次，請本人再送一次 | 不用動。`never_arrived` 時由本人重送 |
| `uncertain_prompt_readback_unavailable`／`uncertain_prompt_left_for_review check=...` | 這個 Bridge 無法回讀，或這則訊息不能用回讀確認（`check` 說明原因：檔案、文字、操作種類或其他 Root）。它維持結果不明，Bridge 不會重送 | 保留 log 回報；本人看話題，一直沒回覆就重送 |
| `zulip_change_paused reason=... scope=... bindings=N` | Zulip 的變動暫停了話題：`queue_registered`（啟動）、`queue_expired`、訊息被移動／刪除，或頻道、成員、人員、組織變更（`scope=all` 會暫停所有話題）。沒有其他待處理的工作時，被暫停話題的下一則一般訊息就會恢復；否則回 `!go` | 不用動；若一直出現又沒有已知的變更再查 |
| `zulip_release_not_qualified version=... feature_level=... qualified=V/L` | Zulip 伺服器跑的版本不是 Bridge 驗證過的，Bridge 拒絕處理 Zulip 工作並重啟，直到版本相符。驗證過的版本之後同一大版的維護版（例如驗證 11.1、實際 11.3）會自動接受：Zulip 在同一大版內維持 API，安全修正也這樣發布。新的大版（13.0）或開發版不會自動接受 | 同一大版內的 Zulip 更新可直接升級（先跑 `check_zulip_upgrade.py`）。跨大版升級前，先讓 Bridge 完成該版的驗證，否則把 Zulip 退回 |
| 話題出現 ⏳「AI 還在處理中（已 N 分鐘）」 | 該話題的這一輪還在執行，且話題已 2 分鐘沒有新內容（只有「輸入中」很容易漏看）。每一輪最多一則，和其他訊息一樣送出；權限要求或選項按鈕等本人回覆時不發。這一輪中途 Bridge 重啟，只要那則仍是最新一則就不會再發。回覆或這一輪結束比它先到時，尚未送出的那則會取消不送（稽核事件 `still_working_notice_retired`）。這一行可能寫「正在等工具 X 跑完」（慢在工具，也就是 OpenCode 或它背後的 MCP 伺服器）或「模型正在思考或撰寫回覆」（慢在模型，可開新對話或用 `!model` 選較低的 variant）。journal 記 `still_working_notice_queued binding=... minutes=N waits_on=tool|model|unknown` | 不用動。一直沒有回覆再照上面檢查 |
| 話題出現 ⚠️「AI 好像在重複同一步（已 N 次）」 | 同一輪中模型連續 5 次說同樣的話、呼叫同樣的工具（該步驟的訊息會計數，例如 `🔧 search ×5`）。每一輪最多一則；與該步驟的計畫一起排入，Bridge 重啟不會再發（稽核事件 `transcript_repeat_hint_queued`）。這一輪的回覆、結果或下一則輸入先到時，尚未送出的那則會取消不送（狀態 `repeat_hint_superseded`，稽核事件 `transcript_repeat_hint_retired`）。Bridge 不會自己停止這一輪 | 由本人決定：`!stop`（或按鈕）停止這一輪，否則繼續執行。常常重複的模型可能不適合這個工作 |
| 話題出現 💡「這個對話已經很長（約 N tokens）」 | 某則回覆所屬步驟讀入的內容達 60,000 tokens 以上，之後每一步都要重讀這麼多而變慢（從幾秒變成幾分鐘）。每個已連線話題只發一則，排在回覆之後（稽核事件 `transcript_long_context_hint_queued`），重啟不會再發。只有該 binding 的專案已開放開新對話時，才會提到在新話題送 `!new` | 由本人決定：開新對話會比較快。若要在還不能從聊天開新對話的專案使用，替該專案開放開新對話（`ops/server/certify_creation.py`） |
| `restart_pause_released`／`restart_pause_kept_old binding=... after=unclear_work` | 重啟後，話題等一則不明訊息結清（每 30 秒檢查）。`released` 已送出保留的訊息；`kept_old` 已在話題提醒一次用 `!go` | 不用動 |
| 話題 `Bridge 狀態` 有 ⚠️ 訊息 | Bridge 失敗且四分鐘內沒有自己恢復（每次停止只通知一次；像開機時那樣 systemd 下一次重試就好的失敗不通知）。「OpenCode 版本已變更」表示綁定的檔案不符；「外掛剛更新」表示核准過的觀察外掛檔案和核准的 sha256 不符；「設定或外掛變了」表示啟動檢查拒絕，訊息附原因代碼；「Zulip 已升級成這一版 Bridge 還沒確認過的版本」會寫出兩邊的版本 | 停止：看 journal。變更：執行 `check_native_upgrade.py`，不要靠重啟 OpenCode 來消除。設定或外掛：審閱變更（核准過的觀察外掛要全文重讀後再改 config 的 sha256）。Zulip：見[升級 Zulip](#升級-zulip)；完成 Bridge 驗證或把 Zulip 退回 |
| 話題 `Bridge 狀態` 有 🔔 訊息 | 每日版本監看發現 Zulip 或 OpenCode 有新版本，每個版本只發一次，並寫明這一版 Bridge 接不接受 | Zulip 維護版：安排升級（[升級 Zulip](#升級-zulip)）。Zulip 大版或任何 OpenCode 新版：先驗證，不要就地升級 |
| 一般話題出現 ⚠️「Bridge 目前停止，這則訊息沒有送到 OpenCode」 | `jt-oz-bridge-standby.service`（和停止通知一起啟動）在 Bridge 停止期間，對每個話題回這句固定的話一次，只在設定的私人頻道。它不讀內容、不送任何東西給 OpenCode，Bridge 就緒後約一分鐘內自己結束 | 照上面處理停止。訊息本身由 Bridge 重啟後的補收處理 |
| 話題 `Bridge 狀態` 有 ✅ 訊息 | 停止通知之後，`jt-oz-bridge-recovered.timer`（每 2 分鐘）看到 Bridge 已就緒 | 不用處理。大家能看出只是暫停，沒有遺失 |
| `journalctl -u jt-oz-bridge-retry` 有 `bridge_retry start after=...s unit=...` | systemd 放棄 Bridge（或觀察服務）已滿 5 分鐘，`jt-oz-bridge-retry.timer`（每 5 分鐘）再啟動一次。Bridge 每次啟動都重做所有檢查，原因還在（例如外掛未核准）就會再失敗，之後再試 | 照 ⚠️ 訊息那列處理原因；處理好後 Bridge 會自己回來 |
| Bridge 運作時有人在話題 `Bridge 狀態` 打字 | Bridge 回一句：這個話題只放狀態通知、Bridge 有在運作；不會在這裡跳出選對話的選單，所以這個話題不會被連到 AI 對話 | 不用處理。和 AI 說話請到其他話題 |
| 服務停了，但該話題沒有訊息 | 通知沒送出去（Zulip 停了，或 unit 沒安裝） | 當作已停止處理；看 `journalctl -u jt-oz-bridge-notice` |

**伺服器重開機後：** `jt-oz-bridge.service` 排在 `opencode.service` 之後啟動，並先等 OpenCode 開始接受連線（最多兩分鐘）；它不會去啟動被停掉的 OpenCode。若仍連續失敗三次，retry timer 每 5 分鐘再啟動一次。觀察服務會先等 Bridge 就緒（最多三分鐘），也由 retry timer 照樣重試。第一次啟動可能早於 OpenCode 準備完成；自動重試會處理，第一次嘗試的失敗不會發 ⚠️ 通知。之後話題和一般 Bridge 重啟一樣：Bridge 回來前 10 分鐘內送出的訊息會自己送出，更早的等 `!go`；只因重啟而暫停的話題，下一則一般訊息就會恢復。

OpenCode 已結束但 Bridge 仍持續拒絕時，保留 log，只重啟 Bridge，並回報時間和話題。卡在「已送出、未完成」的工作不會自動重送，因為重送可能跑兩次。

**安裝：** 把 `ops/server/bridge_notice.py` 複製到 `/opt/jt-oz-bridge/bridge-notice.py`，安裝 `jt-oz-bridge-notice.service`、`jt-oz-bridge-recovered.service`／`.timer` 和 `jt-oz-bridge-retry.service`／`.timer`（兩個 timer 都要啟用；retry 需要把 `ops/server/bridge_retry.sh` 放成 `/opt/jt-oz-bridge/bridge-retry.sh`），並讓 `jt-oz-bridge.service` 帶 `OnFailure=jt-oz-bridge-notice.service jt-oz-bridge-standby.service`（drop-in 或 unit）；standby 要把 `ops/server/bridge_standby.py` 放成 `/opt/jt-oz-bridge/bridge-standby.py`，並安裝 `jt-oz-bridge-standby.service`。啟用 timer 前若 `/var/lib/jt-oz-bridge-notice/last` 是很久以前留下的，先刪掉，不然會多送一則「已恢復」。較舊的版本每次停止後都沒有清這個檔，所以第一次之後的停止都不會再通知。

## 備份

- 完整快照用 `jt-oz-bridge backup`。先停 Bridge，服務運作中會被拒絕。
- 主金鑰另外備份。沒有它快照無法讀取，兩者不要存在一起。
- 每次部署的控制目錄留到下一版被接受為止。裡面的資料庫複本是回滾輔助，不是備份，因為沒有附件和設定。
- 快照不含 root 管理的納管檔、機密檔和 OpenCode 的資料。這些另外備份，還原主機後要重新驗證。
- 還原測試一律到新目錄，絕不覆蓋現役資料庫。
