# 範例:shop-api

一個假想的 Node 專案跑完整個流程後留下的檔案,用來看報表長什麼樣子。

**這是測試資料,不是真實專案的掃描結果。**

- 專案是 `tests/fixtures/projects/shop-api`,只有幾個套件。
- lodash、lodash-es、qs 的公告是真實的 GitHub 公告。
- `cvescan-fixture-evil` 與 `MAL-2026-900001` 是虛構的,用來示範惡意套件的處理方式。
- KEV(已知遭利用)、EPSS、Node 的停止支援日期是**虛構的測試資料**,不代表真實世界。
- 以開發模式(`CVESCAN_ENGINE=native`)產生,日期是模擬的,所以環境那一行寫的是 native 而不是 docker。

## 發生了什麼

| 日期 | 事件 | 結果 |
|---|---|---|
| 11-01 | 第一次掃描 | 未解決 5:1 個惡意套件、lodash 2 項、lodash-es 2 項 |
| 11-01 | Agent 分析,`verify` 通過 | lodash 兩項由排程調高到本週 |
| 11-04 | 升級 lodash、移除惡意套件後重掃 | 未解決 2,「你修掉 3」 |
| 11-06 | qs 的公告發布後重掃 | 未解決 3,「新公告 1」,只有這一項需要分析 |
| 11-06 | Agent 分析新增的那一項,`verify` 通過 | qs 列為立即 |

完整的終端機輸出在 [terminal.txt](terminal.txt),包含最後的 `cvescan status`。

## 檔案

```
latest/                          11-06 的狀態
├── report.md                    給人看的報表,純規則產生
├── report.json                  同樣的內容,給 AI 與其他工具
├── sbom.cdx.json                全部套件與相依樹
├── analysis.json                agent 寫的結論(這次只有 qs 一項)
└── analysis.md                  verify 通過後由工具產生,含先前沿用的結論
runs/20261101T013000Z-5962d5/    11-01 第一次掃描,同樣五個檔案
```

真正的報表資料夾裡還有 `ANALYZE.md` 與 `analysis.schema.json`(給 agent 的指示與輸出格式),
內容與 `core/cvescan_core/data/` 相同,這裡不重複放。11-04 那次的資料夾也省略了。

建議的閱讀順序:`runs/…/report.md` → `runs/…/analysis.md` → `latest/report.md` → `latest/analysis.md`。

## 關於這裡的 AI 分析

兩份 `analysis.json` 是 Claude 只讀 `report.json`、依照 `ANALYZE.md` 寫的,兩次都是第一次送出就通過
`cvescan verify`。它們示範的是格式與流程,不是對真實專案的安全建議。

幾個可以對照規則看的地方:

- lodash 兩項被調高優先序,理由是修補版落在宣告的版本範圍內、一次升級解決兩項。調高不需要額外依據。
- 沒有任何一項被調降:這個專案沒有 `.cvescan.toml`,agent 沒有可以引用的背景。
- 惡意套件的處置是移除,不是升級。
- qs 列在已知遭利用清單,規則基準就是立即,agent 不能調降。
- `analysis.md` 裡的版本、路徑與指令都來自掃描結果。例如 agent 對 lodash 的兩項分別填了各自的修補版,
  文件顯示的是工具合併後、能同時解決兩項的那個版本。
