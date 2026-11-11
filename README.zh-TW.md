# cvescan

**相依套件漏洞掃描,加上看不到程式碼的 AI 分析。**

[English](README.md) · [繁體中文](README.zh-TW.md)

![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)
![Status: proof of concept](https://img.shields.io/badge/status-proof%20of%20concept-orange)

cvescan 在鎖死的 container 裡掃描專案的相依套件,產出一份固定格式的漏洞報表與 SBOM。
掃描過程沒有 AI。之後由你自己的 AI agent(任何 model)只讀報表資料夾做分析,分析結果要
通過規則檢查才算數。你的程式碼從頭到尾不會進到 model。

狀態:v0.1.0,概念驗證。哪些測過、哪些還沒,見[專案現況](#專案現況)。

## 為什麼做這個

- **要的是判斷,不是清單。** Scanner 會列出幾百筆漏洞。哪些重要、先修哪個、要改什麼,
  才是真正花時間的地方,而這正是語言模型擅長的事。
- **程式碼不離開你的機器。** 很多情況下不能把私有專案交給 model。這裡 model 拿到的是
  一份關於相依套件的報表,不是程式碼。
- **結果可以查核。** 掃描是純規則的,而且會說清楚哪些東西沒掃到。AI 只能填一張表,
  由規則檢查決定收不收:它不能建議升級到掃描沒列出的版本,不能引用不存在的 CVE 編號
  或相依路徑,也不能偷偷把問題降級。

## 運作方式

```
cvescan <專案路徑>
  [1/3] detect   程式碼唯讀、無網路   找出專案用到哪些 ecosystem
  [2/3] sync     無程式碼、有網路     更新 OSV、CISA KEV、EPSS、EOL 資料
  [3/3] scan     程式碼唯讀、無網路   osv-scanner 離線比對 → 報表、SBOM、歷程
                          │
                          ▼
        ~/cvescan/<專案>/latest/        AI 唯一會讀的東西
                          │
  你的 agent              讀 ANALYZE.md,寫 analysis.json
  cvescan verify <專案>   規則檢查,通過才產生 analysis.md
```

前三步是純規則程式,不呼叫任何 model,不需要 API key。

| 步驟 | 你的程式碼 | 網路 | AI |
|---|---|---|---|
| detect | 唯讀掛載 | 沒有 | 沒有 |
| sync | 沒有掛載 | 有,用來下載資料庫 | 沒有 |
| scan | 唯讀掛載 | 沒有 | 沒有 |
| 你的 agent | 不需要,它只讀報表資料夾 | 看你的 agent | 有 |
| verify、status | 沒有掛載 | 沒有 | 沒有 |

每個步驟都是獨立的 container:根檔案系統唯讀、沒有任何 capability、以你的使用者身分執行。
`tests/docker_e2e.sh` 會從 container 裡面確認這些性質。

## 實際跑起來的樣子

下面是 repo 內附的小型測試專案的輸出。裡面的惡意套件與停止支援日期是測試資料。

```console
$ cvescan ~/work/shop-api
環境   docker ✓|磁碟 29 GB ✓|cvescan 0.1.0
[1/3] detect  找到 npm(1 個 lockfile)
[2/3] sync
       已更新 npm、KEV、EPSS、EOL nodejs、EOL php、EOL python
[3/3] scan    1 個 lockfile、8 個套件
結果   完整
       未解決 5(立即 1|本週 0|排程 2|觀察 2)
       首次掃描,之後的報表會列出與上次的差異
       其中 1 個惡意套件
       runtime:node 18.20.4 已停止支援
       runtime:node 22.11.0 落後最新修補版 22.21.0
報表   ~/cvescan/shop-api/latest/
下一步 請你的 agent「分析 shop-api 的 CVE 報表」(待分析 5 項)
```

報表會把漏洞彙整成「要動哪個套件」:

| # | 套件 | 目前 | 目標 | 解決 | 做法 |
|---|---|---|---|---|---|
| A-1 | cvescan-fixture-evil | 1.0.3 | 移除 | 1 項(立即) | 移除,並當作已經中招處理 |
| A-2 | lodash | 4.17.15 | 4.17.21 | 2 項(排程) | `npm install lodash@4.17.21` |
| A-3 | lodash-es | 4.17.15 | 4.17.21 | 2 項(觀察) | `npm update lodash-es`,上層已經允許修補版 |

掃過幾次之後,`cvescan status` 會告訴你有沒有變好,以及數字為什麼變:

```console
$ cvescan status shop-api
shop-api|首次掃描 2026-11-01|共 3 次|AI 分析:已完成
未解決數趨勢  █▄▅  5 → 3

時間         專案版本      未解決  你修掉  新公告  相依變動  不再掃到  掃描
11-06 01:05  deps-57a0c8c       3       0       1         0         0  完整
11-04 02:10  deps-57a0c8c       2       3       0         0         0  完整
11-01 01:30  deps-5962d5d       5       –       –         –         –  完整(首次)
```

這個範例的完整檔案(包含 AI 的分析)在 [examples/shop-api](examples/shop-api/README.md)。

## 快速開始

### 需求

- Docker,而且正在執行。Linux 與 macOS 實際用過,其他平台見[專案現況](#專案現況)。
- bash 與 git。
- 至少 2 GB 的可用磁碟空間,放漏洞資料庫。
- 安裝時、以及每次掃描的 sync 步驟需要連到:Docker Hub、GitHub releases、
  `osv-vulnerabilities.storage.googleapis.com`、`www.cisa.gov`、
  `epss.empiricalsecurity.com`、`endoflife.date`。公司網路見[在公司 proxy 後面](#在公司-proxy-後面)。

### 1. 安裝

```bash
git clone https://github.com/Elliot9/cvescan.git cvescan-src
cd cvescan-src
./install.sh
```

刻意 clone 到 `cvescan-src`:`~/cvescan` 是預設放報表的資料夾,原始碼放在那裡的話 `install.sh` 會停下來。

`install.sh` 會建置映像、把 `cvescan` 指令放到 `~/.local/bin`、建立
`~/.config/cvescan/config.toml`,並先下載 npm、PyPI、Packagist 的資料庫,讓第一次掃描不用等。
如果 `~/.local/bin` 不在 `PATH` 裡,加進去:

```bash
export PATH="$HOME/.local/bin:$PATH"    # 寫進 ~/.zshrc 或 ~/.bashrc
cvescan --version
```

映像裡只有 Python 標準函式庫,加上一個以 SHA-256 核對過的 osv-scanner 2.7.1。沒有其他東西。

| `install.sh` 的環境變數 | 作用 |
|---|---|
| `CVESCAN_PREWARM="npm,Go"` | 現在要下載哪些資料庫;設成空字串就不下載 |
| `CVESCAN_PYTHON_IMAGE=<映像>` | 改用其他 registry 的 Python 映像(3.11 以上)當基底 |
| `CVESCAN_BIN_DIR=<目錄>` | `cvescan` 指令要放的位置 |

### 2. 掃描專案

```bash
cvescan ~/work/my-project
```

報表在 `~/cvescan/my-project/latest/`,想自己看就打開 `report.md`。安裝時沒下載的 ecosystem,
會在第一次用到時下載。

### 3. 讓你的 agent 分析報表

把 `skills/` 裡的兩個 skill 交給你的 agent。放哪裡依 agent 而定,Claude Code 是 `~/.claude/skills/`:

```bash
mkdir -p ~/.claude/skills
cp -R skills/cve-analyze skills/cve-audit ~/.claude/skills/
```

在報表資料夾(不是你的專案)裡啟動 agent,然後說:

```
cd ~/cvescan
<啟動你的 agent>
> 分析 my-project 的 CVE 報表
```

Agent 會讀 `latest/ANALYZE.md`、寫出 `analysis.json`,再執行 `cvescan verify my-project`。
檢查通過後,cvescan 產生 `latest/analysis.md`:先做什麼、為什麼、確切的指令。

沒有 skill 機制的 agent 也可以用:直接請它讀 `~/cvescan/my-project/latest/ANALYZE.md` 並照做。
規則、步驟與輸出格式都寫在那個檔案裡,skill 只負責把 agent 帶到那裡。

### 4. 修正、重掃、看趨勢

```bash
cvescan ~/work/my-project      # 升級之後
cvescan status my-project
```

重掃之後,AI 只需要處理新出現、或事實有變的項目。之前給過的結論會沿用。

## 搭配 AI agent

### 兩種用法

**你掃描,agent 只分析。** 就是上面的快速開始。Agent 不執行掃描,也不需要碰專案。

**Agent 從頭做到尾。** 用 `cve-audit` skill,你可以說「掃描並分析 ~/work/my-project」。
Agent 執行 `cvescan <路徑>`,再接著做分析。掃描仍然在 cvescan 的 container 裡進行,
agent 拿到的是報表,不是程式碼。

### 讓 agent 真的看不到程式碼

掃描階段的隔離由 cvescan 保證。Agent 碰得到什麼,取決於你怎麼啟動它:

- 在報表根目錄(`~/cvescan`)啟動,把它的檔案存取限制在這個資料夾。
- 指令只放行 `cvescan`。

掃描的關卡(資料庫多久算過期等)只能寫在 `config.toml`,所以只被允許執行 `cvescan` 的 agent 沒辦法放寬。它做得到的兩件事事後都看得出來:`--exclude` 會縮小掃描範圍,受影響的每份報表都有 `excluded_paths` 註記;`remove --yes` 會刪掉一個專案的報表與歷程,該專案會從 `cvescan status` 消失。
如果在專案目錄裡啟動 agent,skill 只能要求它不要讀程式碼,擋不住。

### `verify` 檢查什麼

AI 只寫一個檔案:`analysis.json`。給人看的 `analysis.md` 由 cvescan 排版,
版本、路徑與指令都取自掃描結果。

- 分析對應的是目前這份報表,而且報表在掃描後沒被改過(雜湊存在報表資料夾之外)。
- 每個待分析的項目都有結論。項目很多時可以分批做。
- 文字裡不能出現報表以外的 CVE / GHSA / MAL 編號或連結。
- AI 可以調高優先序。要調降或判定「不受影響」,必須引用你提供的背景。
- 惡意套件與已知遭利用的項目不能調降。惡意套件的處置只能是移除。
- 升級目標必須是報表列出的修補版。
- AI 引用的每一條相依路徑都必須真的存在於 SBOM。

結論不會回流到掃描:被判定不受影響的項目,下次掃描照樣列在報表裡,只是不再回到待分析清單。

### 給 AI 背景資訊

專案根目錄可以放一個選填的 `.cvescan.toml`。只收固定欄位,不收自由文字:

```toml
[context]
internet_facing = true            # true / false
handles_untrusted_input = true    # true / false
environment = "production"        # production / internal / development
```

AI 要調降優先序只能靠這裡的內容,而且每次都必須指出它依據的是哪個欄位。

## 指令

| 指令 | 作用 |
|---|---|
| `cvescan <專案路徑>` | detect、sync、scan;寫出 `~/cvescan/<專案>/latest/` |
| `cvescan <專案路徑> --exclude <樣式>` | 同上,但不掃指定的目錄或檔案,說明見下方 |
| `cvescan --all` | 重掃所有掃過的專案,給排程用 |
| `cvescan verify [專案]` | 檢查 AI 的 `analysis.json`,通過後產生 `analysis.md` |
| `cvescan status [專案]` | 所有專案的總覽,或單一專案的歷程 |
| `cvescan remove <專案> [--yes]` | 刪除一個專案的報表與歷程,例如掃錯資料夾的時候;不會動到你的程式碼 |
| `cvescan --version`、`cvescan --help` | 版本與用法 |

`--exclude` 可以重複。不含 `/` 的樣式比對任何一層的目錄或檔案名稱(`--exclude .worktrees`),含 `/` 的從專案根目錄比對(`--exclude apps/legacy`),可用萬用字元 `*` 和 `?`。樣式會記在這個專案上,之後的掃描和 `cvescan --all` 都會沿用;再下一次 `--exclude` 會取代原本的,`--no-exclude` 會清掉。用了排除的報表會有 `excluded_paths` 註記。

`remove` 收的是 `cvescan status` 顯示的專案名稱。刪除前會詢問;`--yes` 不詢問,沒有人在終端機前時必須加。

| 結束代碼 | 意思 |
|---|---|
| 0 | 成功:掃描完成(不論有沒有漏洞),或 `verify` 通過 |
| 1 | `verify` 沒通過 |
| 2 | 拒絕:資料庫無法確認為最新、路徑不合法、必須先更新、用法錯誤。沒有產生新報表 |
| 3 | 無效:掃描跑了但結果不可信。有報表,裡面會寫原因 |

有沒有漏洞不影響結束代碼。排程要依結果告警,請讀 `report.json` 的 `summary`。

## 報表裡有什麼

```
~/cvescan/<專案>/
├── latest/
│   ├── report.json            給機器和 AI 的事實
│   ├── report.md              同樣的內容給人看,純規則產生
│   ├── sbom.cdx.json          CycloneDX 1.5:全部套件加相依樹
│   ├── ANALYZE.md             給 AI 的指示
│   ├── analysis.schema.json   AI 輸出的格式
│   ├── analysis.json          AI 寫的
│   └── analysis.md            verify 通過後由 cvescan 產生
└── runs/<scan id>/            之前的報表
```

- **Findings**:每個「套件 × 公告」一筆,含公告內容、CVSS、CISA KEV、EPSS、修補版、規則算出的優先序。
- **相依路徑**:誰把它帶進來、上層要求的版本範圍、修補版是否落在範圍內。
- **升級動作**:以「要動哪個套件」彙整,附上對應套件管理器的指令。
- **惡意套件**:OSV 的 `MAL-` 紀錄走獨立路線。處置是移除並做事故處理,不是升級。
- **盲區**:沒有 lockfile 的 manifest、未鎖定版本的 requirements、解析失敗的檔案。
  有盲區時掃描會標成「不完整」,不會讓「0 個漏洞」被誤認成「安全」。
- **樣本檢查**:每次掃描夾帶一個已知有洞的 lockfile。掃不出來,這次掃描就判定「無效」。
- **Runtime**:專案宣告的 Node、PHP、Python 版本是否已停止支援,或落後最新修補版。
- **數字為什麼變**:你修掉的、新公告帶來的、相依變動帶來的、不再掃到的,分開計算。

欄位說明:[docs/FORMAT.md](docs/FORMAT.md)。

### 支援的 lockfile

套件清單來自 osv-scanner,所以它讀得懂的 lockfile 都會掃。相依樹由 cvescan 自己建立,
目前支援這些格式:

| Lockfile | 套件清單 | 相依樹 | 相依樹用真實 lockfile 核對過 |
|---|---|---|---|
| `package-lock.json` v2 / v3、`npm-shrinkwrap.json` | ✓ | ✓ 含 workspaces | ✓ npm 10 |
| `yarn.lock` v1 | ✓ | ✓ 含 workspaces | ✓ yarn 1.22 |
| `poetry.lock` | ✓ | ✓ | ✓ Poetry 2.4 |
| `uv.lock` | ✓ | ✓ | ✓ uv 0.11 |
| `composer.lock` | ✓ | ✓ | ✗ 只用手寫的範例測過 |
| `pnpm-lock.yaml`、yarn berry、`bun.lock` | ✓ | 尚未實作 | – |
| `requirements.txt`、`Pipfile.lock` | ✓ | 檔案本身沒有這項資訊 | – |
| 其他 osv-scanner 支援的格式 | ✓ | 尚未實作 | – |

沒有相依樹、或追溯不到直接相依的套件,關係一律標成「未知」,不會用猜的。

Workspace(monorepo)裡,成員宣告的套件算直接相依,報表會指出是哪個成員目錄宣告的。

## 設定

`~/.config/cvescan/config.toml`。所有項目與預設值在 [config.example.toml](config.example.toml)。
最常用到的:

| 項目 | 預設 | 作用 |
|---|---|---|
| `max_db_age_minutes` | 60 | 資料庫超過這個時間沒確認為最新,就拒絕掃描 |
| `allow_stale_db` | false | 離線時照常掃描,報表標記資料庫過期 |
| `keep_runs` | 10 | 每個專案保留幾次完整報表;歷程摘要永久保留 |
| `update.manifest_url` | 空 | 新版資訊的網址,留空就不檢查 |
| `update.auto_update_unattended` | true | 沒人在場時,直接套用符合條件的更新 |
| `update.cooldown_days` | 3 | 沒人在場時,只套用發布滿這麼多天的版本 |
| `[sources]` | 公開網址 | 有內部鏡像的話改這裡 |

掃描的關卡只存在這個檔案裡,不能從指令列帶;指令列唯一收的掃描選項是 `--exclude`。

資料夾位置用環境變數指定:`CVESCAN_HOME`(報表,預設 `~/cvescan`)、`CVESCAN_STATE`
(資料庫與歷程,預設 `~/.local/state/cvescan`)、`CVESCAN_CONFIG_DIR`。
專案和這些資料夾不能互相包含。

### 在公司 proxy 後面

需要下載的步驟(sync 與新版檢查)會沿用目前 shell 的設定。其他步驟沒有網路,也拿不到這些設定。

- `HTTPS_PROXY`、`HTTP_PROXY`、`NO_PROXY`(大小寫皆可)會傳進 container。
  指向 `localhost` 或 `127.x` 的 proxy 不會傳,因為 container 裡連不到。
- `SSL_CERT_FILE` 指向的 CA 憑證檔會以唯讀掛進 container,給會攔截 TLS 的 proxy 用。

### 排程重掃

`cvescan --all` 會重掃所有掃過的專案。crontab 可以這樣寫;cron 的 `PATH` 很短,
要自己設一個找得到 Docker 的:

```
PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin
17 3 * * *  $HOME/.local/bin/cvescan --all >> $HOME/.local/state/cvescan/cron.log 2>&1
```

目前沒有通知機制。要告警的話,外層腳本能用的是結束代碼與 `report.json`。

## 安全模型

cvescan 強制做到的:

- **掃描沒辦法把程式碼送出去。** 看得到程式碼的步驟,除了 loopback 沒有任何網路介面。
  有網路的步驟,沒有掛載程式碼。
- **掃描沒辦法改你的專案。** 程式碼是唯讀掛載。
- **不執行專案裡的任何東西。** cvescan 只解析 lockfile 與 manifest。
  不跑安裝腳本,也不執行 git,`.git` 是直接讀檔。
- **detect、sync、scan 沒有 AI。**
- **資料庫過期就停下來**,不會產出一份讓人安心的舊報表。
- **專案內容一律當成有敵意。** 套件名稱、版本、路徑在寫進 AI 會讀的檔案之前,
  都要通過很窄的字元檢查,所以 lockfile 沒辦法夾帶指令給 model。
- **AI 改不了事實。** 見[`verify` 檢查什麼](#verify-檢查什麼)。

它不做的:

- 它不替你把 agent 關起來。那取決於你怎麼啟動 agent。
- AI 還是看得到中繼資料:專案名稱、套件名稱(包含私有套件與 workspace 成員)、
  lockfile 路徑、git 分支與 tag 名稱、commit 前 7 碼、宣告的 runtime 版本。
- 基底映像是用 tag 指定,不是 digest。需要的話用 `CVESCAN_PYTHON_IMAGE` 帶 digest。
- 更新機制沒有簽章驗證。沒設 `update.manifest_url` 就不會啟用。
- 它信任 osv-scanner 與上游的資料庫。

如果發現 cvescan 本身的安全問題,請用 repo 的 Security 分頁「Report a vulnerability」回報,
不要開公開的 issue。

## 專案現況

v0.1.0 是概念驗證。目前測過的:

- **66 個單元測試**:版本範圍(npm、Composer、PEP 440)、相依樹、workspace、盲區、
  runtime、變化歸因、惡意輸入、打包。
- **129 項端到端檢查**(`tests/e2e.sh`):真正的 wrapper 加真正的 osv-scanner 2.7.1,
  對本機的假上游,涵蓋掃描、`verify` 的每條規則、修正後重掃、`status`、各道關卡。
- **60 項 wrapper 檢查**(`tests/wrapper_isolation.sh`):用假的 `docker` 記錄 wrapper
  要求的旗標與掛載。
- **59 項真實 container 檢查**(`tests/docker_e2e.sh`),Linux、Docker 29,root 與一般使用者
  各跑一次:`install.sh`,然後在真正的 container 裡掃描、`verify`、`status`,
  再用同一組旗標重新啟動每個步驟的 container,從裡面探測網路、掛載與權限。
- **相依樹與真實 lockfile 核對**:用 npm 10、yarn 1.22、Poetry 2.4、uv 0.11 實際產生 lockfile
  (含 npm 與 yarn 的 workspace),相依樹的套件與 osv-scanner 列出的完全一致,
  而且每個都追溯得到直接相依。
- **在 macOS 上手動跑過一次**(Apple Silicon):安裝、從 OSV、CISA KEV、EPSS、endoflife.date
  下載真實資料、完整掃描一個真實的 monorepo(四個 `yarn.lock`、約 3,400 個套件)。

還沒測過的:

- macOS 上的自動化測試,特別是 macOS 內建的 bash 3.2。Wrapper 刻意只用 bash 3.2 有的語法。
- 用預設的 `python:3.13-slim` 基底跑 `tests/docker_e2e.sh`。目前是透過
  `CVESCAN_PYTHON_IMAGE` 用另一個 Python 3.13 映像跑的。
- Podman(`CVESCAN_ENGINE=podman`)。Rootless 模式下 `--user` 的對應方式不同,很可能要調整。
- SELinux 強制模式的主機。Bind mount 可能被擋;wrapper 不會替你的專案重新標籤。
- Windows。需要在 WSL2 裡執行。
- `composer.lock` 的相依樹與 Composer 實際產生的 lockfile 核對。
- 透過真正的 proxy 下載。設定有傳進 container,但沒有測試實際經 proxy 連線。
- 實際下載更新。判斷邏輯是用假的 `docker` 測的。

`tests/fixtures/advisories/` 裡的測試公告是真實的 GitHub 公告,只有 `MAL-2026-900001` 是虛構的。
測試用的 KEV、EPSS、EOL 資料也是虛構的。

## 已知限制

- 指令輸出與報表目前只有繁體中文。
- 沒有可達性分析:cvescan 無法判斷有漏洞的程式碼是否真的被呼叫。
- 它掃的是 lockfile。基底映像、OS 套件、手動複製進 repo 的程式碼不在範圍內;
  看到 Dockerfile 或 vendored 檔案時,報表會註明。
- pnpm、yarn berry、bun 沒有相依樹。它們的套件照樣會掃。
- Runtime 檢查看的是專案宣告的版本,不是實際部署的版本,也不是逐一比對直譯器的 CVE。
- SBOM 沒有 license 欄位,因為掃描階段沒有網路。
- 排程重掃沒有通知機制。
- 不會自動修正。cvescan 告訴你要改什麼,不會替你改。

## 常見的拒絕與錯誤

| 訊息開頭 | 原因與處理 |
|---|---|
| `環境   找不到 docker` | 沒裝 Docker,或不在 `PATH` 裡 |
| `環境   docker 沒有在執行` | 啟動 Docker |
| `環境   找不到映像 cvescan:0.1.0` | 到原始碼資料夾執行 `./install.sh` |
| `環境   磁碟只剩` | 存放資料庫的位置可用空間不到 2 GB |
| `拒絕   缺少漏洞資料庫` | 下載失敗;確認網路或 proxy 設定後重跑 |
| `拒絕   漏洞資料庫超過 60 分鐘沒有確認為最新` | 連不到上游;修好網路,離線使用則設 `allow_stale_db = true` |
| `拒絕   專案和 cvescan 的資料夾不能互相包含` | 專案放在報表或狀態資料夾裡面,或反過來 |
| `拒絕   … 是 cvescan 的原始碼資料夾` | 報表資料夾是這個 repo 的 clone;把 clone 移走,或設定 `CVESCAN_HOME` |
| `cvescan 不接受選項` | 不認得的選項;除了 `--exclude` 和 `--no-exclude`,設定寫在 `config.toml` |
| `排除   …` | 這次掃描不掃這些樣式(有「沿用」表示是之前記住的設定) |

## 更新與移除

更新:拉新版再安裝一次。

```bash
cd cvescan-src
git pull
./install.sh
```

全部移除:

```bash
rm ~/.local/bin/cvescan
docker image rm cvescan:0.1.0
rm -rf ~/.local/state/cvescan    # 資料庫、歷程、已接受的 AI 結論
rm -rf ~/.config/cvescan         # 設定
rm -rf ~/cvescan                 # 報表
```

## 開發

```bash
python3 -m unittest discover -s tests -p "test_*.py"
CVESCAN_SCANNER=/path/to/osv-scanner tests/e2e.sh            # -v 顯示每個指令的輸出
CVESCAN_SCANNER=/path/to/osv-scanner tests/wrapper_isolation.sh
tests/docker_e2e.sh                                          # 需要 Docker;會建置映像
```

前三個需要 Python 3.11 以上,不需要 Docker。其中兩個 shell 測試另外需要你的平台用的
[osv-scanner 2.7.1](https://github.com/google/osv-scanner/releases/tag/v2.7.1) 執行檔。
在 Docker Desktop 上跑 `docker_e2e.sh` 要加 `CVESCAN_TEST_HOST=host.docker.internal`。

`CVESCAN_ENGINE=native` 會不經 container 直接執行核心。它沒有任何隔離,只供開發與測試。

核心在 `core/cvescan_core/`,只用 Python 標準函式庫:

| 模組 | 職責 |
|---|---|
| `lockfiles.py` | 找 lockfile、建相依樹、檢查名稱與路徑 |
| `sync.py`、`enrich.py` | 下載與讀取 OSV、KEV、EPSS、EOL |
| `scan.py` | 關卡、執行 osv-scanner、組出報表 |
| `findings.py` | Findings、規則優先序、升級動作 |
| `coverage.py`、`runtimes.py` | 盲區、runtime |
| `sbom.py` | CycloneDX 輸出與路徑查核 |
| `verify.py` | 檢查 `analysis.json`、產生 `analysis.md` |
| `history.py` | 歷程、變化歸因、`status` |
| `update.py` | 新版檢查 |

Repo 根目錄的 `cvescan` 檔案是 wrapper:純 bash,每個步驟啟動一個 container。

## 參與貢獻

歡迎開 issue 與 pull request。適合入手的地方:

- 輸出與報表的英文版
- pnpm、yarn berry、bun 的相依樹
- Podman、SELinux、macOS 的測試
- 跑四組測試的 CI

送 pull request 之前請先跑測試,並說明哪幾組你沒辦法跑。

## 資料來源與致謝

cvescan 是包在 [osv-scanner](https://github.com/google/osv-scanner) 外面的一層,使用
[OSV.dev](https://osv.dev/)、
[CISA 已知遭利用漏洞清單](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)、
[EPSS](https://www.first.org/epss/) 與 [endoflife.date](https://endoflife.date/) 的資料。
各自有自己的使用條款。cvescan 與它們沒有隸屬關係,也未經它們背書。

## 授權

[Apache-2.0](LICENSE)。著作權聲明與第三方資料見 [NOTICE](NOTICE)。
