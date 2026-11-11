# cvescan 報表:shop-api

- 掃描時間:2026-11-01 01:30(UTC+00:00)|專案版本:deps-5962d5d
- 漏洞資料庫:2026-11-01 01:30(UTC+00:00) 同步
- 工具:cvescan 0.1.0|osv-scanner 2.7.1
- 掃描品質:**完整**
- 掃描範圍:1 個 lockfile、8 個套件(完整清單見 `sbom.cdx.json`)

## 結論

未解決 5(立即 1|本週 0|排程 2|觀察 2)
首次掃描,之後的報表會列出與上次的差異
其中:惡意套件 1

## 升級動作

以「要動哪個套件」為單位,一個動作可能同時解決多個漏洞。

| # | 套件 | 目前 | 目標 | 解決 | 位置 | 做法 |
|---|---|---|---|---|---|---|
| A-1 | cvescan-fixture-evil | 1.0.3 | 移除 | 1 項(立即) | `package-lock.json` | 移除 cvescan-fixture-evil。當作已經中招處理:輪替這台機器與 CI 用過的憑證,檢查安裝時間前後的異常活動 |
| A-2 | lodash | 4.17.15 | 4.17.21 | 2 項(排程) | `package-lock.json` | npm install lodash@4.17.21 |
| A-3 | lodash-es | 4.17.15 | 4.17.21 | 2 項(觀察) | `package-lock.json` | npm update lodash-es(上層允許 4.17.21,更新 lockfile 即可) |

## 未解決項目

### 立即(1)

- **cvescan-fixture-evil 1.0.3** · MAL-2026-900001 · 惡意套件
  - 編號:`F-8085ab2cd5`|已存在 0 天
  - 摘要:Malicious code in cvescan-fixture-evil (npm)
  - 位置:`package-lock.json`,版本 1.0.3(正式環境,直接相依)
  - 排序依據:已通報為惡意套件

### 排程(2)

- **lodash 4.17.15** · GHSA-p6mc-m468-83gw / CVE-2020-8203 · 高(CVSS 7.4) · EPSS 2.3%
  - 編號:`F-9376dd2c7a`|已存在 0 天
  - 摘要:Prototype Pollution in lodash
  - 位置:`package-lock.json`,版本 4.17.15(正式環境,直接相依)
  - 修補版:4.17.19
  - 排序依據:CVSS 7.4;EPSS 2.3%
- **lodash 4.17.15** · GHSA-35jh-r3h4-6jhm / CVE-2021-23337 · 高(CVSS 7.2) · EPSS 0.8%
  - 編號:`F-235dcdf6b9`|已存在 0 天
  - 摘要:Command Injection in lodash
  - 位置:`package-lock.json`,版本 4.17.15(正式環境,直接相依)
  - 修補版:4.17.21
  - 排序依據:CVSS 7.2;EPSS 0.8%

### 觀察(2)

- **lodash-es 4.17.15** · GHSA-p6mc-m468-83gw / CVE-2020-8203 · 高(CVSS 7.4) · EPSS 2.3%
  - 編號:`F-27998651e6`|已存在 0 天
  - 摘要:Prototype Pollution in lodash
  - 位置:`package-lock.json`,版本 4.17.15(開發用,間接相依)
  - 修補版:4.17.20
  - 路徑:shop-api > cvescan-fixture-devtool@2.0.0 > lodash-es@4.17.15(上層要求 `^4.17.15`:修補版在範圍內)
  - 排序依據:CVSS 7.4;EPSS 2.3%;只出現在開發用相依套件,降一級
- **lodash-es 4.17.15** · GHSA-35jh-r3h4-6jhm / CVE-2021-23337 · 高(CVSS 7.2) · EPSS 0.8%
  - 編號:`F-33535ff7bc`|已存在 0 天
  - 摘要:Command Injection in lodash
  - 位置:`package-lock.json`,版本 4.17.15(開發用,間接相依)
  - 修補版:4.17.21
  - 路徑:shop-api > cvescan-fixture-devtool@2.0.0 > lodash-es@4.17.15(上層要求 `^4.17.15`:修補版在範圍內)
  - 排序依據:CVSS 7.2;EPSS 0.8%;只出現在開發用相依套件,降一級

## Runtime

Lockfile 掃描不包含直譯器本身。下表是專案檔案裡宣告的版本,實際部署的版本可能不同。

| Runtime | 宣告版本 | 來源 | 狀態 | 該版本線最新 | 停止支援日 |
|---|---|---|---|---|---|
| node | 18.20.4 | `.nvmrc` | 已停止支援(EOL) | 18.20.8 | 2025-04-30 |
| node | >=18 | `package.json` | 只宣告範圍,未鎖定版本 | – | – |
| node | 22.11.0 | `Dockerfile` | 落後最新修補版 | 22.21.0 | 2027-04-30 |

## 盲區

沒有發現未掃描的相依套件來源。

## 其他限制

- 偵測到 Dockerfile:基底映像與 OS 套件不在掃描範圍
- 未做可達性分析:報表無法判斷有漏洞的程式碼是否真的被呼叫
- 樣本檢查(確認 scanner 與資料庫真的有在運作):npm 通過

---

這份報表完全由規則產生,沒有 AI 參與。AI 的分析在 `analysis.md`,通過 `cvescan verify` 之後才會產生。
