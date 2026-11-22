# 測試與證據邊界

[English](TESTING.md)

使用搭配 [uv](https://docs.astral.sh/uv/) 的 Python 3.13 環境：

```sh
uv sync --locked
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts
uv run mypy src
uv run pytest -q
uv run python -m scripts.public_gate .
uv build
uv run pip-audit --local --skip-editable
```

單元測試涵蓋嚴格範例設定、危險覆寫、secret 檔案權限、參數詞庫與字面命令邊界。整合測試使用真正的暫存 SQLite WAL 資料庫與 Alembic migration，檢查原子收件／checkpoint、並行去重、commit 失敗注入、CAS 派送競態、held／ambiguous 復原、outbox 目標 revision、consumer lease、輸入／輸出授權範圍、語言保存與管理員登入／CSRF／節流／body 限制。

通訊測試採 HTTPX MockTransport 及具有來源／hash 的文件衍生 fixture，只證明隔離環境的請求／錯誤處理，不證明真正 OpenCode 相容。V1／Zulip fixture 是選取範例；V2 fixture 是具有 hash 紀錄的完整官方公開／原始碼標籤 OpenAPI snapshot。API UI 測試使用 ASGI 用戶端；真正瀏覽器／Playwright 呈現及手機開發流程尚未執行。

自動測試通過不等於它涵蓋的功能已經驗收。哪些經過真人、實際伺服器與手機確認，寫在各份說明與[相容性矩陣](COMPATIBILITY_zh-tw.md)；其他一律視為尚未驗證。

正式版本仍需安裝後端契約、真正原 session 執行者、真正權限／表單互動、可丟棄 Git 發布測試、上游收件前後故障、TLS 錯誤、保留／配額、SQLite 還原、PostgreSQL 執行／遷移、Linux 架構、效能情境與官方 iOS／Android 實機證據；本機通過數不能代替。

依安裝鎖定依賴執行稽核；公告服務無法連線屬於未能驗證，不是無漏洞結果。

每次新增、異動功能或推進版本號，都要跑上面完整的測試，不能只跑改動附近的測試；先前 commit 的結果不能算在之後的 commit 上。持續整合在每次推送都跑同樣的 lint、型別、測試與內容閘門；推送版本 tag 時還會建置 wheel 和 SBOM。

維護者手上的版本有些測試會讀取實際 OpenCode 與 Zulip 伺服器的錄製資料。這些資料含有真實訊息與識別碼，所以它們和讀取它們的測試不公開。
