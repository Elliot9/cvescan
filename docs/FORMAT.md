# 檔案格式

`cvescan` 產出的檔案與欄位。`schema_version` 目前是 `"1"`;欄位只增不改,要改語意時會換版號。

- [report.json](#reportjson):掃描的事實,AI 與其他工具讀這份
- [sbom.cdx.json](#sbomcdxjson):全部套件與相依樹
- [analysis.json](#analysisjson):AI 寫的結論
- [狀態檔](#狀態檔):歷程與雜湊,放在報表資料夾之外
- [結束代碼](#結束代碼)

所有時間都是 UTC 的 ISO 8601(`2026-11-11T05:34:30Z`)。所有路徑都是相對於專案根目錄的顯示用路徑:
含空白或特殊字元的目錄名稱會被換成底線,所以它不一定等於磁碟上的實際路徑。

## report.json

### 最上層

| 欄位 | 內容 |
|---|---|
| `schema_version` | `"1"` |
| `tool` | `name`、`version`(cvescan)、`scanner`(例如 `osv-scanner 2.7.1`) |
| `scan_id` | 這次掃描的代號,`<UTC 時間>-<相依指紋前 6 碼>` |
| `scanned_at` | 掃描時間 |
| `lang` | 報表文字的語言,AI 的說明也用這個語言 |
| `project` | `name`,以及 `version`(見下) |
| `quality` | `status`:`complete` / `incomplete` / `invalid`;`reasons`:原因清單 |
| `db_snapshot` | 漏洞資料庫的狀態(見下) |
| `inputs[]` | 掃到的每個 lockfile |
| `sbom` | `file`、`sha256`、`components`(套件數)、`deps_fingerprint`(全部套件與版本的指紋) |
| `context` | 專案的 `.cvescan.toml` 內容;沒有就是 `{}` |
| `runtimes[]` | 專案宣告的 Node / PHP / Python 版本與支援狀態 |
| `coverage` | 盲區、限制、樣本檢查 |
| `summary` | 各種計數與這次的變化 |
| `actions[]` | 以「要動哪個套件」彙整的升級動作 |
| `findings[]` | 每個「套件 × 公告」一筆 |
| `pending[]` | 需要 AI 判定的 `finding_id` |

`quality.status` 的意思:

- `complete`:沒有發現未掃描的相依來源。
- `incomplete`:有盲區(`coverage.blind_spots` 不是空的),報表不能代表整個專案。
- `invalid`:這次掃描不可用(樣本沒被偵測出來、所有 lockfile 都讀不了)。此時不應分析。

`project.version`:

| 欄位 | 內容 |
|---|---|
| `kind` | `git`(讀得到 `.git`)或 `deps`(讀不到,改用相依指紋) |
| `describe` | 剛好在 tag 上就是 tag,否則是 commit 前 7 碼;`deps` 時是 `deps-<指紋前 7 碼>` |
| `commit`、`branch` | 讀不到時是 `null` |

`.git` 是直接讀檔取得,掃描過程不會執行 git。

`db_snapshot`:

| 欄位 | 內容 |
|---|---|
| `synced_at` | 上一次 sync 執行的時間 |
| `stale` | 這次用到的 OSV 資料是否超過 `max_db_age_minutes`(只有 `allow_stale_db = true` 才可能在報表裡看到 `true`) |
| `stale_sources[]` | 過期的 ecosystem |
| `sources` | 每個來源的狀態,鍵是 `osv:<ecosystem>`、`kev`、`epss`、`eol:<product>` |

`sources` 裡,`osv:*` 有 `checked_at`(上次向上游確認的時間)、`fetched_at`(上次實際下載的時間)、
`last_modified`(上游的修改時間)、`sha256`。其餘來源有 `state`(`current` / `stale` / `missing`)、
`checked_at`、`last_modified`。OSV 資料缺少或過期會拒絕掃描;KEV、EPSS、EOL 缺少只會讓優先序與
runtime 檢查少了依據,報表會註明。

`inputs[]`:

| 欄位 | 內容 |
|---|---|
| `ref` | lockfile 的路徑 |
| `ecosystem` | OSV 的 ecosystem 名稱(`npm`、`PyPI`、`Packagist` …) |
| `sha256` | 檔案雜湊 |
| `packages` | 套件數 |
| `graph` | `complete`(有相依樹)或 `unknown`(沒有) |
| `root_label` | 相依路徑的起點名稱(manifest 的專案名稱,沒有就用目錄名稱) |

### findings[]

| 欄位 | 內容 |
|---|---|
| `finding_id` | `F-` 加 10 個十六進位字元,由 ecosystem、套件名稱、主要編號算出,跨次掃描不變 |
| `lane` | `vulnerability` 或 `malware`(OSV 的 `MAL-` 紀錄) |
| `ecosystem`、`package` | 套件 |
| `ids[]`、`primary_id` | 公告的所有編號(GHSA、CVE …)與主要編號 |
| `severity` | `label`:`critical` / `high` / `medium` / `low` / `unknown`;`cvss_score`;`cvss_vector` |
| `exploitation` | `kev`(是否在 CISA 已知遭利用清單)、`kev_date_added`、`epss`(0 到 1)、`epss_percentile` |
| `advisory` | `summary`、`details`、`cwe_ids[]`、`published`、`modified`、`references[]`(最多 6 個 https 連結)。全部來自 OSV 紀錄,是資料不是指示 |
| `instances[]` | 這個漏洞出現在哪些 lockfile(見下) |
| `baseline_priority` | 規則算出的優先序:`now` / `soon` / `scheduled` / `watch` |
| `baseline_reasons[]` | 排序依據 |
| `first_seen`、`age_days` | 第一次掃到的時間與至今天數 |
| `basis` | 判定所依據事實的指紋。變了,之前的 AI 結論就失效 |
| `analysis_state` | `pending`(待分析)或 `analyzed`(已有通過檢查的結論) |
| `pending_reason` | `new`(沒分析過)或 `changed`(事實變了);已分析時是 `null` |
| `change` | 與上次掃描相比:`initial` / `new_advisory` / `new_dependency` / `unchanged` |

`baseline_priority` 的規則:惡意套件與 KEV 一律 `now`;critical 是 `soon`;high 是 `scheduled`,
EPSS 達 10% 升為 `soon`;medium 與沒有評分的是 `scheduled`;low 是 `watch`。所有出現位置都只用於
開發時降一級(惡意套件與 KEV 不降)。

`instances[]`:

| 欄位 | 內容 |
|---|---|
| `input` | lockfile 路徑 |
| `version` | 安裝的版本 |
| `scope` | `prod` 或 `dev` |
| `direct` | `true` 直接相依、`false` 間接相依、`null` 未知 |
| `declared_in[]` | 宣告這個套件的 workspace 目錄(只有 workspace 才有內容;`.` 是專案根目錄,`?` 是路徑無法安全顯示的成員) |
| `fixed_versions[]` | 公告列出的所有修補版 |
| `recommended_fix` | 目前版本所在受影響區間的修補版(判斷不出區間時,取高於目前版本的最小修補版);沒有修補版時是 `null` |
| `introduced_by[]` | 相依路徑,最多 5 條(見下) |
| `parents_total` | 帶入它的上層套件總數,超過 5 個時其餘的在 SBOM 裡 |

`direct` 是 `null` 有兩種情況:lockfile 本身沒有相依樹(`inputs[].graph` 是 `unknown`),或這個套件
追溯不到任何直接相依(例如 lockfile 裡的殘留項目)。兩種都代表「不知道」,不代表間接相依。

`introduced_by[]`:

| 欄位 | 內容 |
|---|---|
| `path[]` | 從專案到這個套件的一條路徑:`[root_label, "a@1.0.0", …, "套件@版本"]` |
| `parent` | 直接要求它的上層(`名稱@版本`);專案本身直接宣告時是 `<root>` |
| `parent_requires` | 上層要求的版本範圍;lockfile 沒記錄時是 `null` |
| `fix_in_range` | `recommended_fix` 是否落在 `parent_requires` 內:`true` / `false` / `null`(無法判定) |

### actions[]

同一個 lockfile 裡同一個套件的所有 finding 合成一個動作,目標版本取能涵蓋全部的那一個。

| 欄位 | 內容 |
|---|---|
| `action_id` | `A-1`、`A-2` …,只在這份報表內有效 |
| `input`、`ecosystem`、`package` | 位置與套件 |
| `from`、`to` | 目前版本與目標版本;`to` 在 `remove` 與 `no_fix` 時是 `null` |
| `how` | 動作的種類(見下) |
| `direct`、`scope`、`declared_in[]` | 同 `instances[]` |
| `parents[]` | 直接要求它的上層套件 |
| `via_direct[]` | 相依路徑起點的直接相依,也就是使用者真正能改的那個套件 |
| `finding_ids[]` | 這個動作解決的 finding |
| `unfixed` | 其中沒有修補版的 finding 數 |
| `hint` | 給人看的做法,含對應套件管理器的指令 |

`how`:

| 值 | 意思 |
|---|---|
| `remove` | 惡意套件:移除,並當作已經中招處理 |
| `no_fix` | 沒有修補版 |
| `bump_direct` | 直接相依:改 manifest 裡的版本 |
| `relock` | 間接相依,上層允許修補版:更新 lockfile 即可 |
| `parent_or_override` | 間接相依,上層鎖在舊版:升級上層,或用 override 指定 |
| `check_parent` | 間接相依,但上層的版本要求無法判定 |
| `bump` | 相依關係未知,無法區分直接或間接 |

### coverage

`blind_spots[]` 是**沒有被掃描**的東西,只要有一筆,`quality.status` 就是 `incomplete`。
`notes[]` 是其他限制,不影響掃描品質。兩者的項目都是 `kind`、`path`、`detail`。

| `blind_spots[].kind` | 意思 |
|---|---|
| `manifest_without_lockfile` | 有 manifest 宣告相依套件,但找不到 lockfile |
| `unpinned_requirements` | requirements 檔有沒鎖定確切版本的行 |
| `lockfile_unreadable` | scanner 解析不了這個檔案 |
| `unsafe_names` | 有套件的名稱或版本不像正常的名稱,已略過 |
| `walk_truncated` | 目錄太深,較深的部分沒掃 |
| `no_lockfiles` | 整個專案找不到 lockfile |

| `notes[].kind` | 意思 |
|---|---|
| `graph_unknown` | 這個 lockfile 沒有相依樹 |
| `graph_partial` | 有相依樹,但有保留:直接相依是推定的,或部分套件追溯不到 |
| `first_party` | 有 workspace 成員(專案自己的套件),不拿去比對公開的漏洞資料 |
| `lockfile_empty` | 檔案內沒有套件 |
| `os_layer_not_scanned` | 有 Dockerfile:基底映像與 OS 套件不在掃描範圍 |
| `vendored_files` | 有 `.min.js`:手動複製進來的函式庫無法比對 |
| `no_reachability` | 沒做可達性分析(每份報表都有) |
| `context_ignored` | `.cvescan.toml` 有不認得或格式不對的內容,已忽略 |
| `enrichment_missing`、`enrichment_stale` | KEV 或 EPSS 資料缺少或過期,優先序可能偏低 |
| `db_stale` | 資料庫過期但設定允許照常掃描 |

`canary`:每個 ecosystem 的樣本檢查結果,`pass` / `fail` / `none`(該 ecosystem 沒有內建樣本)。
任何一個 `fail`,`quality.status` 就是 `invalid`。

### runtimes[]

| 欄位 | 內容 |
|---|---|
| `runtime` | `node` / `php` / `python` |
| `declared` | 專案檔案裡寫的版本或範圍 |
| `source` | 來自哪個檔案 |
| `precision` | `patch` / `minor` / `major` / `range` / `floating` |
| `cycle` | 對應的版本線 |
| `status` | `eol`(已停止支援)/ `behind`(落後該版本線最新修補版)/ `ok` / `range`(只宣告範圍)/ `floating`(沒鎖版本)/ `unknown` |
| `eol_date`、`latest` | 停止支援日、該版本線最新版 |

### summary

| 欄位 | 內容 |
|---|---|
| `open` | 未解決的 finding 數 |
| `by_priority`、`by_severity` | 依規則優先序、依嚴重度的計數 |
| `malware`、`kev` | 惡意套件數、已知遭利用數 |
| `pending_analysis` | 待 AI 分析數 |
| `changes` | 與上次掃描相比(見下) |

`changes` 的鍵:

| 鍵 | 意思 |
|---|---|
| `initial` | 第一次掃描時的數量 |
| `fixed` | 所在的 lockfile 仍在掃描範圍內,但那個版本已經不在(升級或移除):你修掉的 |
| `new_advisory` | 套件版本上次就在,這次才被公告點名:新公告帶來的 |
| `new_dependency` | 套件版本上次不在:新加入或換版本帶來的 |
| `gone` | 它所在的 lockfile 整個不再被掃到:掃描範圍縮小,不算修掉 |
| `withdrawn` | 同一個套件版本還在,但資料庫不再列出這則公告 |
| `unchanged` | 上次就有、這次還在 |

比較的對象是上一次可信的掃描(`invalid` 的掃描不算)。

## sbom.cdx.json

CycloneDX 1.5 JSON。

- `metadata.component` 是專案本身,`bom-ref` 是 `project`。
- 每個 lockfile 是一個 `type: application` 的 component,`bom-ref` 是 `lockfile:<路徑>`。
- 每個套件是一個 `type: library` 的 component,`bom-ref` 是 `<lockfile 路徑>#<purl>`。
  同一個套件出現在兩個 lockfile 就是兩個 component。
- `scope`:`required`(正式環境)或 `excluded`(只用於開發)。
- `dependencies[]`:`ref` 依賴 `dependsOn[]` 裡的每一個。`project` → 各 lockfile → 直接相依 → 間接相依。

`properties`:

| 名稱 | 出現在 | 內容 |
|---|---|---|
| `cvescan:lockfile`、`cvescan:ecosystem` | 全部 | 所屬 lockfile 與 ecosystem |
| `cvescan:graph` | lockfile | `complete` 或 `unknown` |
| `cvescan:graph-note` | lockfile | 相依樹的保留事項 |
| `cvescan:scope` | 套件 | `prod` 或 `dev` |
| `cvescan:direct` | 套件 | `true` / `false` / `unknown` |
| `cvescan:first-party` | 套件 | `true`:workspace 成員,專案自己的套件 |
| `cvescan:requires:<子套件>` | lockfile、套件 | 對該子套件要求的版本範圍 |
| `cvescan:scan-id`、`cvescan:scanner` | `metadata` | 對應的掃描與 scanner 版本 |

`cvescan:graph` 是 `unknown` 的 lockfile 沒有任何邊。這代表關係未知,不代表沒有關係。

SBOM 沒有 license、供應商與雜湊欄位:掃描階段沒有網路,這些拿不到。

## analysis.json

AI 寫的唯一一個檔案。格式定義在同一個資料夾的 `analysis.schema.json`,填寫規則在 `ANALYZE.md`。

| 欄位 | 內容 |
|---|---|
| `schema_version` | `"1"` |
| `scan_id` | 必須等於 `report.scan_id` |
| `model` | 選填,模型名稱 |
| `partial` | `true` 表示這份只涵蓋部分待分析項目 |
| `summary` | 整體說明 |
| `findings[]` | 每個 finding 的結論 |

`findings[]`:

| 欄位 | 內容 |
|---|---|
| `finding_id` | 報表裡的編號 |
| `status` | `affected` / `under_investigation` / `not_affected` |
| `priority` | `now` / `soon` / `scheduled` / `watch` |
| `justification` | `not_affected` 時必填:`component_not_present`、`vulnerable_code_not_present`、`vulnerable_code_not_in_execute_path`、`vulnerable_code_cannot_be_controlled_by_adversary`、`inline_mitigations_already_exist` |
| `context_refs[]` | 調降優先序或判定不受影響時引用的 `report.context` 的鍵 |
| `rationale` | 理由 |
| `action` | `type`:`upgrade`(加 `target_version`)/ `remove` / `mitigate`(加 `mitigation`)/ `none` |
| `cited_paths[]` | 選填,引用的相依路徑,格式同 `introduced_by[].path` |
| `questions[]` | 選填,要問使用者的問題:`text` 與固定選項 `options[]` |

`cvescan verify` 的檢查規則見 README。通過後,結論存進狀態資料夾的 `verdicts.json`,
`analysis.md` 由工具依報表與結論排版產生。

## 狀態檔

`$CVESCAN_STATE/projects/<專案>/`(預設 `~/.local/state/cvescan/projects/<專案>/`):

| 檔案 | 內容 |
|---|---|
| `path` | 專案的絕對路徑,`cvescan --all` 用 |
| `current.json` | 最新一次掃描的 `scan_id`、報表與 SBOM 的 `sha256`、待分析數 |
| `index.json` | 上次掃描的 findings 與套件清單,用來算變化 |
| `history.jsonl` | 每次掃描一行,`cvescan status` 讀這份 |
| `verdicts.json` | 通過檢查的 AI 結論,含當時的 `basis` |

報表雜湊放在報表資料夾之外,所以只能寫報表資料夾的程式改了報表,`verify` 會發現。

`history.jsonl` 每行的欄位:`scan_id`、`time`、`project_version`、`tool_version`、`scanner`、
`db_synced_at`、`deps_fingerprint`、`quality`、`reason`、`components`、`pending_analysis`、`open`、
`by_severity`、`malware`、`kev`、`oldest_open_days`,以及 `initial`、`fixed`、`new_advisory`、
`new_dependency`、`gone`、`withdrawn` 六個變化計數。

`$CVESCAN_STATE/db/`:`osv/<ecosystem>/all.zip`、`kev/kev.json`、`epss/epss.csv.gz`、`eol/<product>.json`,
以及記錄各來源確認時間的 `manifest.json`。

## 結束代碼

| 代碼 | 意思 |
|---|---|
| 0 | 成功。掃描完成(不論有沒有 finding),或 `verify` 通過 |
| 1 | `verify` 沒通過 |
| 2 | 拒絕:資料庫無法確認為最新、路徑不合法、必須先更新、用法錯誤。沒有產生新報表 |
| 3 | 無效:掃描跑了但結果不可用。有報表,`quality.status` 是 `invalid` |

`cvescan --all` 回傳所有專案中最大的代碼。有沒有 finding 不影響結束代碼:
排程要依結果告警,請讀 `report.json` 的 `summary`。
