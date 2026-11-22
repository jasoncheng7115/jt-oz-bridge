# 相容性狀態

[English](COMPATIBILITY.md)

**尚未認證任何 OpenCode／Zulip／手機版本組合**；應用程式版本不等於相容認證。下表列出程式的目標版本，以及各元件現有的證據種類。

| 元件 | 證據 | 狀態 |
|---|---|---|
| Python 3.13／macOS arm64 | native 依賴安裝、本機測試與型別檢查 | 本機開發基準，尚非 Linux runtime 認證。 |
| Python 3.13／Linux amd64 | 在開發主機上的打包 import、依賴檢查、Zulip gateway／source／audience 與 native read RPC 檢查 | 有限定範圍 runtime 證據；完整 Linux 資料庫／後端／手機認證仍待完成。 |
| SQLite WAL | 真正本機 migration、交易、復原與並行測試 | 基礎儲存已測，還原／保留認證待完成。 |
| PostgreSQL | 已有依賴與 dialect 程式 | 尚未做執行測試。 |
| OpenCode V1 | 已讀官方 server 文件，選取 health fixture 與 mock 通訊測試 | 已實作唯讀探索；尚無已安裝 V1 後端取得資格。 |
| OpenCode V2（以 2.0.32 開發） | 公開／source-tag fixture，加上已驗證身分的安裝版 2.0.32 OpenAPI 與真正 read RPC | 2.0.32 的安裝 schema／auth 已知；預設 CLI 不回放 durable events，live feed 有事件。原 owner、完整 mutation／recovery 與手機仍待 qualification。 |
| Zulip 12.3（feature level 500） | 私人頻道中的專用一般 Bot；Linux 打包 post／read／find／edit 與 scope／source 檢查 | 此限定 API 檢查通過；完整 consumer 與手機整合待完成。 |
| 官方 iOS／Android | 沒有真正手機橋接證據 | 尚未驗證。 |

401／403 後不自動改匿名重試；URL／路徑／session 標題一致不能證明執行身分。唯讀 probe 成功也不啟用寫入。變更啟用前，保存安裝契約 hash、驗證行為、後端身分／執行者、專案範圍與必要權限／表單／事件行為，並記錄測試日期、OS、版本、案例 ID 與去機密證據。

本基礎階段查閱的官方參考：[OpenCode server](https://opencode.ai/docs/server/)、[Zulip 佇列](https://zulip.com/api/register-queue)、[Zulip 事件](https://zulip.com/api/get-events)、[FastAPI lifespan](https://fastapi.tiangolo.com/advanced/events/)、[SQLAlchemy asyncio](https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html)。文件衍生 fixture 與真正安裝後端擷取仍分開。

公開 V2 OpenAPI 與官方 v2.0.30 原始碼標籤 snapshot 的 hash 已保存在 `tests/fixtures/contracts/manifest.json`。原始碼標籤相符不能認證安裝中的後端。

安裝擷取使用獨立的 provenance manifest，不與文件衍生 fixture 混合。每個安裝後端都要以自己擷取的契約取得資格，其他安裝的擷取不能沿用。
