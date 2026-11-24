# 公開發布守門

[English](PUBLIC_RELEASE.md) · 繁體中文

公開的 GitHub repository 絕不是把這個開發 repository 直接推上去。它由 [`scripts/public_export.py`](../scripts/public_export.py) 從單一 commit 全新產生：只複製 `publish/allowlist.txt` 列出的檔案；`publish/overlay/` 補上只有公開版才有的東西（CI、Pages workflow、`.gitignore`）；結果建立一個新的 commit，不帶任何舊歷史。[`scripts/public_gate.py`](../scripts/public_gate.py) 必須在 commit 前檢查整個檔案樹、commit 後再檢查整個 repository，兩次都通過；只要有一筆命中，匯出結果就會被刪除。

## 絕不公開

| 類別 | 例子 | 由誰擋下 |
| --- | --- | --- |
| 機密 | 密碼、API key、Bot key、token、私鑰、cookie、`/etc/jt-oz-bridge/secrets` | 金鑰／token 規則、禁止的檔案類型（`.pem`、`.key`、`.env`…） |
| 帳號與個資 | 使用者名稱、email、聊天使用者 ID、真實姓名 | email 規則、擁有者私有字詞清單 |
| 主機與網路 | 主機名稱、內部網域、內網 IP、實際站台的連接埠、防火牆與反向代理設定 | IP 規則（只允許 RFC 5737 範例、loopback 與測試用來編造私有位址的 `10.0.0.0/24`）、私有字詞清單、白名單 |
| 客戶與專案 | 客戶名稱、專案名稱與路徑、OpenCode 專案目錄 | 私有字詞清單 |
| 實機證據 | 測試報告、實際安裝的驗證 JSON、資料庫檔、log、備份 | 白名單（從不列入）、禁止的檔案類型 |
| Session 痕跡 | OpenCode session ID、AI 助理的 session 連結或筆記 | session ID 規則、助理痕跡規則 |
| Git 歷史 | 舊 commit、commit 訊息與作者 | 全新的單一 commit repository；歷史也會掃描 |

## 擁有者私有字詞清單

只對某個站台算私有的字詞（主機名稱、帳號、客戶、專案、真實 session ID）不能寫進這個 repository，因為規則本身會被公開。擁有者把它們放在 repository 外的檔案（權限 600），用 `--private-terms` 傳入。一行一個字詞，不分大小寫、以完整字詞比對；`re:` 開頭的行是正規表示式。這份清單的命中永遠不能以審核放行。只要出現新的主機、帳號、客戶或專案，就要加進清單。

## 已審核的行

有些測試會故意放假的金鑰或帳密，例如證明遮罩功能會移除它們。這種行可以列在 `publish/reviewed-findings.txt`，格式是 `路徑<TAB>規則<TAB>行摘要<TAB>原因`；守門檢查會在每筆命中旁印出行摘要。那一行只要有任何改動，摘要就會改變，審核即失效。只能審核虛構的值，絕不能審核真實的值。

## 檢查清單

1. 先在私有 repository commit 這次的改動；匯出讀的是那個 commit，不是工作目錄。
2. 新的公開檔案已列入 `publish/allowlist.txt`；清單裡不能有任何私有名稱（清單本身也會公開）。
3. 有新的主機、帳號、客戶或專案時，更新擁有者私有字詞清單。
4. 產生：`python -m scripts.public_export --out <新目錄> --private-terms <檔案> --author "Name <e-mail>"`，最後必須是 `PASS`。作者與提交者照所給的內容公開，是守門檢查唯一不檢查的文字。
5. 把匯出的檔案清單讀過一遍（`git -C <目錄> ls-files`），新檔案用眼睛抽查；規則只能抓格式，抓不到意思。
6. 在匯出目錄跑公開 CI 的步驟：`uv sync --locked`、`ruff check`、`ruff format --check`、`mypy src`、`pytest -q tests`。
7. 第 4～6 步都通過後才推到 GitHub。推上去就立刻公開，就算之後刪掉也可能已被複製；萬一推出任何私有內容，先輪替該機密，再重寫公開 repository。
8. 發布檔（wheel、CycloneDX SBOM、checksum）來自同一個 commit 的完整測試。
9. 每個公開 repository 只需做一次，在它的 GitHub 設定裡：Pages 的來源設成 GitHub Actions；Secrets and variables → Actions 新增變數 `JTOZ_PUBLIC_IDENTITY`，內容和第 4 步的 `Name <e-mail>` 相同。CI 會把它交給守門檢查，沒有設定時，commit 作者的 email 會被擋下。
10. 兩次發布之間只能更新網站、`docs/` 與最上層的 Markdown 檔，方式是在 `main` 上加一個不打標籤的 commit，由 Pages 發布。程式碼、測試與打包的變更只能隨新版本發布。
