# cvescan

**Dependency CVE scanning with a code-blind AI hand-off.**

[English](README.md) · [繁體中文](README.zh-TW.md)

![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)
![Status: proof of concept](https://img.shields.io/badge/status-proof%20of%20concept-orange)

cvescan scans a project's dependencies for known vulnerabilities inside a
locked-down container and writes a fixed-format report plus an SBOM. No AI
takes part in the scan. Afterwards your own AI agent, on any model, reads only
the report folder and triages the findings, and its conclusions count only
after they pass rule checks. Your source code never reaches the model.

> [!NOTE]
> Command output and reports are currently written in Traditional Chinese
> (zh-TW). JSON keys, the SBOM and the instructions for the AI are in English.
> An English locale does not exist yet. This README translates the output you
> will see, and there is a [glossary](#reading-the-output) at the end.

Status: v0.1.0, a proof of concept. [Project status](#project-status) lists
what has been tested and what has not.

## Why

- **Triage, not a list.** A scanner prints hundreds of findings. Deciding
  which ones matter, in what order, and what to change is the real work, and
  language models are good at it.
- **No code leaves your machine.** Handing a private repository to a model is
  often not allowed. Here the model gets a report about your dependencies and
  never the code.
- **Results you can check.** The scan is deterministic and says what it could
  not see. The AI fills in a form that a rule checker accepts or rejects: it
  cannot propose an upgrade to a version the scan did not list, cite a CVE id
  or a dependency path that is not there, or quietly downgrade a finding.

## How it works

```
cvescan <project path>
  [1/3] detect   code read-only, no network   which ecosystems does the project use
  [2/3] sync     no code, network             refresh OSV, CISA KEV, EPSS, end-of-life data
  [3/3] scan     code read-only, no network   osv-scanner, offline -> report, SBOM, history
                               |
                               v
         ~/cvescan/<project>/latest/           the only thing the AI reads
                               |
  your agent                 reads ANALYZE.md, writes analysis.json
  cvescan verify <project>   rule checks; analysis.md is rendered only if they pass
```

The first three steps are plain rule-based code. They call no model and need
no API key.

| Step | Your code | Network | AI |
|---|---|---|---|
| detect | mounted read-only | none | none |
| sync | not mounted | yes, to download databases | none |
| scan | mounted read-only | none | none |
| your agent | not needed, it reads the report folder | whatever your agent uses | yes |
| verify, status | not mounted | none | none |

Every step is its own container with a read-only root filesystem, no
capabilities, and your user id. `tests/docker_e2e.sh` checks these properties
from inside the containers.

## What a run looks like

This is the output for the small test project that ships with the
repository. The malicious package and the end-of-life dates in it are test
data.

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

In English: Docker is running and the disk has room. One npm lockfile was
found, the databases were refreshed, and 8 packages were scanned. The scan is
complete, with 5 open findings: 1 to handle now, 2 to schedule, 2 to watch.
One of them is a malicious package. The declared Node 18 is past end of
life, and Node 22.11.0 is behind the latest patch release. The report is in
`~/cvescan/shop-api/latest/`, and the next step is to ask your agent to
analyze it.

The report groups findings into the upgrades that resolve them:

| # | Package | Current | Target | Resolves | How |
|---|---|---|---|---|---|
| A-1 | cvescan-fixture-evil | 1.0.3 | remove | 1 (now) | remove it and treat the machine as compromised |
| A-2 | lodash | 4.17.15 | 4.17.21 | 2 (scheduled) | `npm install lodash@4.17.21` |
| A-3 | lodash-es | 4.17.15 | 4.17.21 | 2 (watch) | `npm update lodash-es`, the parent already allows the fixed version |

After a few scans, `cvescan status` shows whether things are getting better
and why the number moved:

```console
$ cvescan status shop-api
shop-api|首次掃描 2026-11-01|共 3 次|AI 分析:已完成
未解決數趨勢  █▄▅  5 → 3

時間         專案版本      未解決  你修掉  新公告  相依變動  不再掃到  掃描
11-06 01:05  deps-57a0c8c       3       0       1         0         0  完整
11-04 02:10  deps-57a0c8c       2       3       0         0         0  完整
11-01 01:30  deps-5962d5d       5       –       –         –         –  完整(首次)
```

The columns are: time, project version, open findings, fixed by you, brought
by new advisories, brought by dependency changes, no longer scanned, and scan
quality.

The complete files from this example, including the AI's analysis, are in
[examples/shop-api](examples/shop-api/README.md).

## Quick start

### Requirements

- Docker, running. Linux and macOS have been used; see
  [Project status](#project-status) for other platforms.
- bash and git.
- At least 2 GB of free disk space for the vulnerability databases.
- Network access during install and during each scan's sync step: Docker Hub,
  GitHub releases, `osv-vulnerabilities.storage.googleapis.com`,
  `www.cisa.gov`, `epss.empiricalsecurity.com` and `endoflife.date`.
  [Behind a proxy](#behind-a-proxy) covers corporate networks.

### 1. Install

```bash
git clone https://github.com/Elliot9/cvescan.git cvescan-src
cd cvescan-src
./install.sh
```

The clone goes into `cvescan-src` on purpose: `~/cvescan` is where reports
are written by default, and `install.sh` stops if the source is in there.

`install.sh` builds the image, copies the `cvescan` command to `~/.local/bin`,
creates `~/.config/cvescan/config.toml`, and downloads the npm, PyPI and
Packagist databases so the first scan is quick. If `~/.local/bin` is not on
your `PATH`, add it:

```bash
export PATH="$HOME/.local/bin:$PATH"    # put this in ~/.zshrc or ~/.bashrc
cvescan --version
```

The image holds the Python standard library and one osv-scanner 2.7.1 binary,
checked against a pinned SHA-256. Nothing else is installed.

| Variable for `install.sh` | Effect |
|---|---|
| `CVESCAN_PREWARM="npm,Go"` | databases to download now; an empty string skips the download |
| `CVESCAN_PYTHON_IMAGE=<image>` | build on a Python image (3.11 or newer) from another registry |
| `CVESCAN_BIN_DIR=<dir>` | where to put the `cvescan` command |

### 2. Scan a project

```bash
cvescan ~/work/my-project
```

The report lands in `~/cvescan/my-project/latest/`. Open `report.md` to read
it yourself. Databases for ecosystems that were not downloaded during install
are fetched on first use.

### 3. Let your agent analyze the report

Give your agent the two skills in `skills/`. Where they go depends on the
agent; for Claude Code it is `~/.claude/skills/`:

```bash
mkdir -p ~/.claude/skills
cp -R skills/cve-analyze skills/cve-audit ~/.claude/skills/
```

Start the agent in the reports folder, not in your project, and ask:

```
cd ~/cvescan
<start your agent>
> Analyze the CVE report for my-project
```

The agent reads `latest/ANALYZE.md`, writes `analysis.json`, and runs
`cvescan verify my-project`. When the checks pass, cvescan renders
`latest/analysis.md`: what to do first, why, and the exact commands.

An agent without a skill mechanism works too. Tell it to read
`~/cvescan/my-project/latest/ANALYZE.md` and follow it. The rules, the steps
and the output format are all in that file; the skill only leads the agent
there.

### 4. Fix, rescan, watch the trend

```bash
cvescan ~/work/my-project      # after upgrading
cvescan status my-project
```

A rescan only asks the AI about findings that are new or whose facts changed.
Verdicts it already gave carry over.

## Working with an AI agent

### Two ways to run it

**You scan, the agent analyzes.** This is the quick start above. The agent
never runs the scan and needs no access to the project.

**The agent does both.** With the `cve-audit` skill you can say "scan and
analyze ~/work/my-project". The agent runs `cvescan <path>` and then continues
as above. The scan still happens inside cvescan's containers, so the agent
receives a report, not code.

### Keeping the agent away from your code

cvescan guarantees the isolation of the scan. What the agent can reach depends
on how you start it:

- Start it in the reports root (`~/cvescan`) and limit its file access to that
  folder.
- Allow it one command: `cvescan`.

The `cvescan` command accepts no options, so an agent that may only run
`cvescan` cannot relax a check. If you start the agent inside your project, a
skill can ask it not to read the code but cannot stop it.

### What `verify` enforces

The AI writes one file, `analysis.json`. The document people read,
`analysis.md`, is rendered by cvescan, and its versions, paths and commands
come from the scan.

- The analysis belongs to the current report, and the report has not been
  edited since the scan (its hash is stored outside the report folder).
- Every pending finding has a verdict. Large reports can be done in batches.
- No CVE, GHSA or MAL id and no link that is absent from the report.
- The AI may raise a priority. Lowering one, or calling a finding "not
  affected", requires citing context that you provided.
- Malware and known-exploited findings cannot be lowered. The only action for
  malware is removal.
- An upgrade target must be one of the fixed versions in the report.
- Every dependency path the AI cites must exist in the SBOM.

Verdicts never flow back into the scan. A finding judged "not affected" is
still listed by the next scan; it just does not return to the pending list.

### Giving the AI context

Put an optional `.cvescan.toml` in the project root. It takes fixed fields
only, no free text:

```toml
[context]
internet_facing = true            # true / false
handles_untrusted_input = true    # true / false
environment = "production"        # production / internal / development
```

This is what lets the AI lower a priority, and each time it does, it has to
name the field it relied on.

## Commands

| Command | What it does |
|---|---|
| `cvescan <project path>` | detect, sync, scan; writes `~/cvescan/<project>/latest/` |
| `cvescan --all` | rescans every project scanned before, for scheduled runs |
| `cvescan verify [project]` | checks the AI's `analysis.json` and renders `analysis.md` |
| `cvescan status [project]` | overview of all projects, or the history of one |
| `cvescan --version`, `cvescan --help` | version and usage |

| Exit code | Meaning |
|---|---|
| 0 | success: the scan finished, with or without findings, or `verify` passed |
| 1 | `verify` rejected the analysis |
| 2 | refused: the database could not be confirmed fresh, a bad path, a required update, wrong usage. No new report |
| 3 | invalid: the scan ran but cannot be trusted. A report exists and says why |

Findings do not change the exit code. To alert from a scheduled run, read
`summary` in `report.json`.

## What is in the report

```
~/cvescan/<project>/
├── latest/
│   ├── report.json            the facts, for machines and for the AI
│   ├── report.md              the same for people, produced by rules only
│   ├── sbom.cdx.json          CycloneDX 1.5: every package and the dependency tree
│   ├── ANALYZE.md             instructions for the AI
│   ├── analysis.schema.json   the format the AI must write
│   ├── analysis.json          written by the AI
│   └── analysis.md            rendered by cvescan after verify passes
└── runs/<scan id>/            earlier reports
```

- **Findings**: one per package and advisory, with the advisory text, CVSS,
  CISA KEV, EPSS, fixed versions and a rule-based priority.
- **Dependency paths**: which package pulls it in, the version range that
  parent demands, and whether the fix fits inside that range.
- **Upgrade actions**: findings grouped by the package you have to touch,
  with the command for the package manager in use.
- **Malicious packages**: OSV `MAL-` records take a separate route. The
  action is removal and incident handling, not an upgrade.
- **Blind spots**: manifests without a lockfile, unpinned requirements, files
  that could not be parsed. With a blind spot the scan is marked incomplete,
  so "0 findings" is never mistaken for "safe".
- **Sample check**: every scan carries a lockfile that is known to be
  vulnerable. If it is not flagged, the scan is declared invalid.
- **Runtimes**: whether the declared Node, PHP or Python version is past end
  of life or behind the latest patch release.
- **Why the number changed**: fixed by you, new advisories, dependency
  changes, and no longer scanned are counted separately.

Field reference: [docs/FORMAT.md](docs/FORMAT.md) (Traditional Chinese for
now).

### Supported lockfiles

The package list comes from osv-scanner, so every lockfile it understands is
scanned. Dependency trees are built by cvescan and exist for these formats:

| Lockfile | Packages | Dependency tree | Tree checked against real lockfiles |
|---|---|---|---|
| `package-lock.json` v2 and v3, `npm-shrinkwrap.json` | ✓ | ✓ with workspaces | ✓ npm 10 |
| `yarn.lock` v1 | ✓ | ✓ with workspaces | ✓ yarn 1.22 |
| `poetry.lock` | ✓ | ✓ | ✓ Poetry 2.4 |
| `uv.lock` | ✓ | ✓ | ✓ uv 0.11 |
| `composer.lock` | ✓ | ✓ | ✗ hand-written sample only |
| `pnpm-lock.yaml`, yarn berry, `bun.lock` | ✓ | not implemented | – |
| `requirements.txt`, `Pipfile.lock` | ✓ | the file does not record it | – |
| other formats osv-scanner reads | ✓ | not implemented | – |

Where there is no tree, or a package cannot be traced to a direct dependency,
the relationship is reported as unknown. It is never guessed.

In a workspace (monorepo), what a member declares counts as a direct
dependency, and the report names the member directory that declares it.

## Configuration

`~/.config/cvescan/config.toml`. Every key and its default is in
[config.example.toml](config.example.toml). The ones that matter most:

| Key | Default | Effect |
|---|---|---|
| `max_db_age_minutes` | 60 | refuse to scan when the database has not been confirmed fresh within this time |
| `allow_stale_db` | false | scan anyway when offline, and mark the report as stale |
| `keep_runs` | 10 | how many full reports to keep per project; the history summary is kept forever |
| `update.manifest_url` | empty | where to look for a new version; empty means no check |
| `update.auto_update_unattended` | true | take an eligible update without asking when nobody is present |
| `update.cooldown_days` | 3 | unattended runs only take versions at least this old |
| `[sources]` | public URLs | point these at an internal mirror if you have one |

Settings that change what a scan reports live only in this file. They cannot
be passed on the command line.

Folders are set with environment variables: `CVESCAN_HOME` (reports, default
`~/cvescan`), `CVESCAN_STATE` (databases and history, default
`~/.local/state/cvescan`) and `CVESCAN_CONFIG_DIR`. The project and these
folders must not contain one another.

### Behind a proxy

The steps that download (sync and the update check) pick up the settings of
your shell. The other steps have no network and do not receive them.

- `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`, in either case, are passed into
  the container. A proxy on `localhost` or `127.x` is not passed, because a
  container cannot reach it.
- The CA bundle that `SSL_CERT_FILE` points to is mounted read-only, for
  proxies that intercept TLS.

### Scheduled rescans

`cvescan --all` rescans every project scanned before. A crontab entry could
look like this; cron has a short `PATH`, so set one that includes Docker:

```
PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin
17 3 * * *  $HOME/.local/bin/cvescan --all >> $HOME/.local/state/cvescan/cron.log 2>&1
```

There is no notification mechanism yet. The exit code and `report.json` are
what a wrapper script has to work with.

## Security model

What cvescan enforces:

- **The scan cannot send your code anywhere.** The steps that see the code
  have no network interface other than loopback. The step with network has no
  code mounted.
- **The scan cannot change your project.** The code is mounted read-only.
- **Nothing from your project is executed.** cvescan parses lockfiles and
  manifests. It runs no install scripts and no git commands; it reads `.git`
  files directly.
- **No AI in detect, sync or scan.**
- **A stale database stops the scan** instead of producing a reassuring
  report.
- **Project content is treated as hostile.** Package names, versions and
  paths go through narrow character checks before they reach a file the AI
  reads, so a lockfile cannot smuggle instructions to the model.
- **The AI cannot rewrite the facts.** See
  [What `verify` enforces](#what-verify-enforces).

What it does not do:

- It does not sandbox your agent. That is up to how you start it.
- The AI still sees metadata: the project name, package names including
  private ones and workspace members, lockfile paths, git branch and tag
  names, the short commit hash, and declared runtime versions.
- The base image is pinned by tag, not by digest. Pass a digest through
  `CVESCAN_PYTHON_IMAGE` if you need that.
- The update mechanism has no signature verification. It is off unless you
  set `update.manifest_url`.
- It trusts osv-scanner and the upstream databases.

To report a security problem in cvescan itself, please use "Report a
vulnerability" on the repository's Security tab instead of a public issue.

## Project status

v0.1.0 is a proof of concept. Tested so far:

- **66 unit tests**: version ranges for npm, Composer and PEP 440, dependency
  trees, workspaces, blind spots, runtimes, change attribution, hostile
  input, packaging.
- **129 end-to-end checks** (`tests/e2e.sh`): the real wrapper and the real
  osv-scanner 2.7.1 against a local fake upstream, covering scans, every
  `verify` rule, rescans after fixes, `status`, and each gate.
- **60 wrapper checks** (`tests/wrapper_isolation.sh`): a fake `docker`
  records the flags and mounts the wrapper asks for.
- **59 real-container checks** (`tests/docker_e2e.sh`), on Linux with Docker
  29, as root and as an unprivileged user: `install.sh`, then a scan,
  `verify` and `status` in real containers, then each step's container is
  started again with the same flags and probed from the inside for network,
  mounts and privileges.
- **Dependency trees against real lockfiles** generated with npm 10, yarn
  1.22, Poetry 2.4 and uv 0.11, including npm and yarn workspaces: the tree
  has exactly the packages osv-scanner lists, and every one traces back to a
  direct dependency.
- **One manual run on macOS** (Apple Silicon): install, live downloads from
  OSV, CISA KEV, EPSS and endoflife.date, and a complete scan of a real
  monorepo with four `yarn.lock` files and about 3,400 packages.

Not tested yet:

- Automated tests on macOS, and macOS's own bash 3.2 in particular. The
  wrapper sticks to bash 3.2 syntax on purpose.
- `tests/docker_e2e.sh` on the default `python:3.13-slim` base. It was run on
  another Python 3.13 image through `CVESCAN_PYTHON_IMAGE`.
- Podman (`CVESCAN_ENGINE=podman`). Rootless mode maps `--user` differently
  and will probably need changes.
- Hosts with SELinux enforcing. Bind mounts may be denied; the wrapper does
  not relabel your project.
- Windows. It would have to run inside WSL2.
- The `composer.lock` dependency tree against a lockfile produced by
  Composer.
- Downloads through a real proxy. The settings are passed into the
  container, but no test connected through one.
- Pulling an update. The decision logic is tested with the fake `docker`.

The test advisories in `tests/fixtures/advisories/` are real GitHub
advisories, except `MAL-2026-900001`, which is made up. The KEV, EPSS and
end-of-life data used by the tests is made up as well.

## Limitations

- Output and reports are in Traditional Chinese only.
- No reachability analysis: cvescan cannot tell whether the vulnerable code
  is ever called.
- It scans lockfiles. Base images, OS packages and code copied into the
  repository by hand are out of scope, and the report says so when it sees a
  Dockerfile or vendored files.
- No dependency tree for pnpm, yarn berry or bun. Their packages are still
  scanned.
- The runtime check looks at the version a project declares, not at what is
  deployed, and it is not a per-CVE check of the interpreter.
- The SBOM has no license field, because the scan has no network.
- No notifications for scheduled runs.
- No automatic fixes. cvescan tells you what to change; it does not change
  it.

## Reading the output

| You see | It means |
|---|---|
| `環境` | environment check: container engine, free disk, version |
| `結果 完整` / `不完整` / `無效` | result: complete / incomplete, something was not scanned / invalid |
| `未解決` | open findings |
| `立即` / `本週` / `排程` / `觀察` | priority: now / this week / scheduled / watch |
| `你修掉` / `新公告` / `相依變動` / `不再掃到` | fixed by you / new advisories / dependency changes / no longer scanned |
| `待分析` | findings waiting for the AI |
| `報表` | where the report is |
| `下一步` | what to do next |
| `✓ 通過` / `✗ 未通過` | `verify` passed / failed |
| `拒絕` | refused, exit code 2 |

Common refusals and errors:

| Message starts with | Cause and fix |
|---|---|
| `環境   找不到 docker` | Docker is not installed or not on `PATH` |
| `環境   docker 沒有在執行` | start Docker |
| `環境   找不到映像 cvescan:0.1.0` | run `./install.sh` from the source folder |
| `環境   磁碟只剩` | less than 2 GB free where the databases are stored |
| `拒絕   缺少漏洞資料庫` | the download failed; check the network or the proxy settings and run it again |
| `拒絕   漏洞資料庫超過 60 分鐘沒有確認為最新` | the upstream could not be reached; fix the network, or set `allow_stale_db = true` for offline use |
| `拒絕   專案和 cvescan 的資料夾不能互相包含` | the project is inside the reports or state folder, or the other way round |
| `拒絕   … 是 cvescan 的原始碼資料夾` | the reports folder is a clone of this repository; move the clone, or set `CVESCAN_HOME` |
| `cvescan 不接受選項` | the command takes no options; settings go in `config.toml` |

## Update and uninstall

To update, pull and install again:

```bash
cd cvescan-src
git pull
./install.sh
```

To remove everything:

```bash
rm ~/.local/bin/cvescan
docker image rm cvescan:0.1.0
rm -rf ~/.local/state/cvescan    # databases, history, accepted AI verdicts
rm -rf ~/.config/cvescan         # configuration
rm -rf ~/cvescan                 # reports
```

## Development

```bash
python3 -m unittest discover -s tests -p "test_*.py"
CVESCAN_SCANNER=/path/to/osv-scanner tests/e2e.sh            # -v prints each command's output
CVESCAN_SCANNER=/path/to/osv-scanner tests/wrapper_isolation.sh
tests/docker_e2e.sh                                          # needs Docker; builds the image
```

The first three need Python 3.11 or newer and no Docker. The two shell
suites among them also need an
[osv-scanner 2.7.1](https://github.com/google/osv-scanner/releases/tag/v2.7.1)
binary for your platform. On Docker Desktop, run `docker_e2e.sh` with
`CVESCAN_TEST_HOST=host.docker.internal`.

`CVESCAN_ENGINE=native` runs the core without containers. It has no isolation
at all and exists for development and tests only.

The core is in `core/cvescan_core/` and uses only the Python standard
library:

| Module | Responsibility |
|---|---|
| `lockfiles.py` | finding lockfiles, dependency trees, name and path checks |
| `sync.py`, `enrich.py` | downloading and reading OSV, KEV, EPSS, end-of-life data |
| `scan.py` | gates, running osv-scanner, assembling the report |
| `findings.py` | findings, rule-based priority, upgrade actions |
| `coverage.py`, `runtimes.py` | blind spots, runtimes |
| `sbom.py` | CycloneDX output and path checks |
| `verify.py` | checking `analysis.json`, rendering `analysis.md` |
| `history.py` | history, change attribution, `status` |
| `update.py` | new-version check |

The `cvescan` file in the repository root is the wrapper: plain bash that
starts one container per step.

## Contributing

Issues and pull requests are welcome. Good places to start:

- an English locale for the output and reports
- dependency trees for pnpm, yarn berry and bun
- Podman, SELinux and macOS coverage
- a CI workflow that runs the four test suites

Please run the test suites before opening a pull request, and say which ones
you could not run.

## Data sources and credits

cvescan is a wrapper around [osv-scanner](https://github.com/google/osv-scanner)
and uses data from [OSV.dev](https://osv.dev/), the
[CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
[EPSS](https://www.first.org/epss/) and
[endoflife.date](https://endoflife.date/). Each has its own terms of use.
cvescan is not affiliated with or endorsed by any of them.

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE) for the copyright notice and
third-party data.
