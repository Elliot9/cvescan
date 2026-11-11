# cvescan 分析:shop-api

- 依據報表:2026-11-01 01:30(UTC+00:00)(`20261101T013000Z-5962d5`),專案版本 deps-5962d5d
- 驗證:通過(2026-11-01 01:40(UTC+00:00))|模型自述:Claude
- 範圍:已分析 5 / 未解決 5

> 這份文件由 cvescan 依照通過驗證的 analysis.json 產生。判定與理由來自 AI;版本、路徑與指令來自掃描結果。
> AI 看不到程式碼,無法確認有漏洞的程式是否真的被呼叫。

## 摘要

最優先的是 cvescan-fixture-evil:它被通報為惡意套件,這是事故,不是版本問題。先移除,並把安裝過它的開發機與 CI 視為已暴露。其次是 lodash:它是正式環境的直接相依,一次升級就能解決兩項,而且修補版落在目前宣告的版本範圍內,成本很低,所以我把兩項從排程調高到本週。lodash-es 只經由開發工具帶入,更新 lockfile 即可,維持觀察。報表沒有提供這個服務是否對外、是否處理不受信任輸入的背景,所以沒有任何一項被調降。另外請留意:專案宣告的 Node 18 已停止支援,Dockerfile 的基底映像不在這次掃描範圍內。

## 立即(1)

### cvescan-fixture-evil 1.0.3 · MAL-2026-900001

- 判定:受影響|惡意套件
- 理由(AI):這個套件被通報為惡意套件,公告描述它會在安裝時讀取環境變數並送往遠端主機。它是專案直接宣告的正式環境相依,只要執行過安裝,安裝當下的環境變數就可能已經外洩。處置是移除並做事故處理:安裝過它的開發機與 CI 都應視為已暴露,輪替它們用過的憑證。升級版本不能解決這個問題。
- 處置:移除 cvescan-fixture-evil。當作已經中招處理:輪替這台機器與 CI 用過的憑證,檢查安裝時間前後的異常活動
- 路徑:shop-api > cvescan-fixture-evil@1.0.3
- 編號:`F-8085ab2cd5`

## 本週(2)

### lodash 4.17.15 · GHSA-p6mc-m468-83gw / CVE-2020-8203

- 判定:受影響|高(CVSS 7.4)|EPSS 2.3%
- 優先序:本週(規則基準是排程,AI 調高)
- 理由(AI):lodash 是正式環境的直接相依,安裝的版本在受影響範圍內。公告指出,當屬性名稱來自使用者輸入時,pick、set、update 等函式可被用來污染 Object 的 prototype。報表無法判斷程式是否這樣使用,但修補版落在專案宣告的版本範圍內,升級成本低,而且同一次升級也解決另一項 lodash 的漏洞,所以從排程調高到本週,不必先花時間確認用法。
- 處置:npm install lodash@4.17.21|`package-lock.json`
- 路徑:shop-api > lodash@4.17.15
- 編號:`F-9376dd2c7a`

### lodash 4.17.15 · GHSA-35jh-r3h4-6jhm / CVE-2021-23337

- 判定:受影響|高(CVSS 7.2)|EPSS 0.8%
- 優先序:本週(規則基準是排程,AI 調高)
- 理由(AI):同一個 lodash,公告指出 template 函式可被用來做命令注入。是否真的受影響取決於程式有沒有把不受信任的內容交給 template,這一點報表看不出來。因為修補版在宣告的版本範圍內、與上一項是同一個升級動作,直接升級比先調查更省事,所以同樣調高到本週。
- 處置:npm install lodash@4.17.21|`package-lock.json`
- 路徑:shop-api > lodash@4.17.15
- 編號:`F-235dcdf6b9`

## 觀察(2)

### lodash-es 4.17.15 · GHSA-p6mc-m468-83gw / CVE-2020-8203

- 判定:受影響|高(CVSS 7.4)|EPSS 2.3%
- 理由(AI):lodash-es 不是專案直接宣告的,而是由開發用的 cvescan-fixture-devtool 帶入,只出現在開發環境。上層要求的版本範圍已經涵蓋修補版,所以更新 lockfile 就能解決,不需要改任何宣告。影響面限於開發與建置流程,維持觀察;建議在處理 lodash 時順手更新。
- 處置:npm update lodash-es(上層允許 4.17.21,更新 lockfile 即可)|`package-lock.json`
- 路徑:shop-api > cvescan-fixture-devtool@2.0.0 > lodash-es@4.17.15
- 編號:`F-27998651e6`

### lodash-es 4.17.15 · GHSA-35jh-r3h4-6jhm / CVE-2021-23337

- 判定:受影響|高(CVSS 7.2)|EPSS 0.8%
- 理由(AI):與上一項是同一個套件、同一條相依路徑,只在開發環境。template 的命令注入需要有不受信任的內容進到建置工具才會成立。修補版在上層允許的範圍內,更新 lockfile 即可,維持觀察。
- 處置:npm update lodash-es(上層允許 4.17.21,更新 lockfile 即可)|`package-lock.json`
- 路徑:shop-api > cvescan-fixture-devtool@2.0.0 > lodash-es@4.17.15
- 編號:`F-33535ff7bc`

## Runtime

- node 18.20.4(`.nvmrc`):已停止支援(2025-04-30)
- node 22.11.0(`Dockerfile`):落後最新修補版 22.21.0
