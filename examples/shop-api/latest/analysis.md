# cvescan 分析:shop-api

- 依據報表:2026-11-06 01:05(UTC+00:00)(`20261106T010500Z-57a0c8`),專案版本 deps-57a0c8c
- 驗證:通過(2026-11-06 01:20(UTC+00:00))|模型自述:Claude
- 範圍:已分析 3 / 未解決 3

> 這份文件由 cvescan 依照通過驗證的 analysis.json 產生。判定與理由來自 AI;版本、路徑與指令來自掃描結果。
> AI 看不到程式碼,無法確認有漏洞的程式是否真的被呼叫。

## 摘要

這次只有一項新的待分析項目,而且是最急的:qs 被新公告點名,並且已列入已知遭利用清單。qs 不是專案直接宣告的,而是 express 帶進來的,express 與 body-parser 都把它鎖在受影響的版本,所以單純更新 lockfile 無效,要升級 express 或用 overrides 指定修補版。先前已分析的兩項 lodash-es 沒有變化,維持觀察。

## 立即(1)

### qs 6.7.0 · GHSA-hrpp-h998-j3pp / CVE-2022-24999

- 判定:受影響|高(CVSS 7.5)|已知遭利用(KEV)|EPSS 31.2%
- 理由(AI):qs 在正式環境,經由 express 與 body-parser 兩條路徑帶入。公告指出,未經驗證的遠端攻擊者只要在網址的查詢字串放入特製內容,就能讓 Node 行程卡住,而這正是 express 解析查詢字串的典型用法。它已列入已知遭利用清單,規則基準就是立即,不能調降。兩個上層都要求固定的受影響版本,修補版不在它們允許的範圍內,所以必須升級 express,或在 package.json 用 overrides 指定修補版。
- 處置:上層鎖住了舊版:升級 express 到會帶入 qs 6.7.3 以上的版本,或在 package.json 的 overrides 指定 qs@6.7.3|`package-lock.json`
- 路徑:shop-api > express@4.17.1 > qs@6.7.0
- 路徑:shop-api > express@4.17.1 > body-parser@1.19.0 > qs@6.7.0
- 編號:`F-e9c770be69`

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
