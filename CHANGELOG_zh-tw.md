# 變更紀錄

[English](CHANGELOG.md) · 繁體中文 · [日本語](CHANGELOG_ja.md)

版本號遵循 [語意化版本](https://semver.org/lang/zh-TW/)。1.0.0 之前，次版本可能變更設定或行為；說明會寫出如何升級。

## 0.1.1

- 公開 CI 的守門檢查改從 repository 變數 `JTOZ_PUBLIC_IDENTITY`（或 `--identity`）讀取唯一公開的 commit 作者。少了它，守門檢查會擋下該作者的 email，所以 0.1.0 只打了標籤、沒有發布。

## 0.1.0

第一個公開預覽版。這不是完成的正式版本，請看 [README](README_zh-tw.md) 的狀態說明。

- 在 Zulip 話題裡和既有的 OpenCode 對話溝通：就是你在電腦前用的同一個對話，不複製也不分岔。
- AI 執行時原地更新進度，並說明回覆是在等工具還是在等模型。
- AI 忙碌時送的訊息會加入進行中的回合；無法加入時就排到下一輪。
- 權限請求和提問可以在手機上用短指令回答，電腦版也有按鈕。
- 從聊天開新對話、從 OpenCode 自己的清單選模型，以及排程送出。
- 啟用的專案可雙向傳檔；HTML 只提供原檔下載。
- Bridge、OpenCode 或主機重啟後自動恢復；需要管理員處理時，在狀態話題通知一次。
- 升級 OpenCode 或 Zulip 前的相容性檢查，以及每日新版本通知。
- Python 3.13，預設 SQLite，每版附 CycloneDX SBOM，授權 GPL-3.0-only。
