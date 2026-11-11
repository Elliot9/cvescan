"""The scan step: code mounted read-only, no network, no AI.

Pipeline: gate on DB freshness -> find lockfiles -> run osv-scanner offline
(together with a known-vulnerable sample) -> build dependency graphs and the
SBOM -> findings, rule-based priority and upgrade actions -> blind spots ->
compare with the previous scan -> write report.json, report.md, sbom.cdx.json
and the files the AI needs.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import tomllib
import zlib
from datetime import timedelta

from . import __version__, coverage, enrich, findings as F, history, lockfiles, report as report_md, runtimes, sbom, sync
from . import verify as verify_mod
from .model import (
    ANALYSIS_MD, ANALYSIS_SCHEMA, ANALYZE_MD, CONTEXT_FILE, CONTEXT_KEYS, CURRENT, PRIORITIES, QUALITY_LABEL,
    REPORT_JSON, REPORT_MD, SCHEMA_VERSION, VERDICTS, priority_rank,
)
from .util import (
    Invalid, Refusal, dump_json, iso, now_utc, parse_iso, read_json, sha256_file, sha256_text,
    write_atomic, write_json,
)

SCANNER_TIMEOUT = 900
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
# ecosystem -> (sample lockfile under data/canary, package that must be flagged)
CANARY = {
    "npm": ("npm/package-lock.json", "lodash"),
    "PyPI": ("PyPI/requirements.txt", "requests"),
    "Packagist": ("Packagist/composer.lock", "guzzlehttp/guzzle"),
}
_SHA = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")


# --------------------------------------------------------------------------
# Scanner
# --------------------------------------------------------------------------

def scanner_path() -> str:
    for candidate in (os.environ.get("CVESCAN_SCANNER"), "/usr/local/bin/osv-scanner", shutil.which("osv-scanner")):
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise Invalid("找不到 osv-scanner 執行檔")


def scanner_version(binary: str) -> str:
    try:
        output = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    match = re.search(r"osv-scanner version:\s*(\S+)", output)
    return match.group(1) if match else "unknown"


def run_scanner(binary: str, lockfile_args: list[str], db_dir: str):
    """Run osv-scanner offline. Returns (parsed JSON or None, exit code, stderr)."""
    work = tempfile.mkdtemp(prefix="cvescan-")
    try:
        cache = os.path.join(work, "cache")
        os.makedirs(cache)
        # osv-scanner 2.7 reads <cache>/osv-scalibr/<ECOSYSTEM>/all.zip; older
        # releases read <cache>/osv-scanner/... Both names point at the same store.
        for alias in ("osv-scalibr", "osv-scanner"):
            os.symlink(os.path.join(db_dir, "osv"), os.path.join(cache, alias))
        result_file = os.path.join(work, "result.json")
        command = [
            binary, "scan", "source",
            "--offline",                 # no network for anything
            "--no-call-analysis=all",    # call analysis would build (= run) project code
            "--all-packages",            # full inventory, for the SBOM
            "--format", "json",
            "--verbosity", "error",
            "--output-file", result_file,
        ]
        for arg in lockfile_args:
            command += ["-L", arg]
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": work, "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": cache, "NO_COLOR": "1"}
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=SCANNER_TIMEOUT, env=env, cwd=work)
        except subprocess.TimeoutExpired:
            raise Invalid(f"osv-scanner 執行超過 {SCANNER_TIMEOUT} 秒")
        except OSError as exc:
            raise Invalid(f"osv-scanner 無法執行:{exc}")
        return read_json(result_file, None), proc.returncode, proc.stderr
    finally:
        shutil.rmtree(work, ignore_errors=True)


def scan_resilient(binary: str, args: list[str], db_dir: str):
    """Scan all lockfiles in one run; if the scanner aborts, bisect.

    osv-scanner gives up on the whole run when it cannot parse one lockfile
    it was pointed at. One bad file must not hide the rest of a monorepo, so
    the set is split until the unreadable file(s) are isolated.
    Returns (results, args the scanner cannot read, stderr).
    """
    data, code, stderr = run_scanner(binary, args, db_dir)
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        return data["results"], [], stderr
    if code == 128:  # "no package sources found": these files are simply empty
        return [], [], stderr
    if len(args) == 1:
        return [], list(args), stderr
    middle = len(args) // 2
    left = scan_resilient(binary, args[:middle], db_dir)
    right = scan_resilient(binary, args[middle:], db_dir)
    return left[0] + right[0], left[1] + right[1], left[2] + right[2]


# --------------------------------------------------------------------------
# Gate
# --------------------------------------------------------------------------

def gate(manifest: dict, needed: list[str], db_dir: str, cfg: dict, now) -> dict:
    """Refuse to scan with a missing or stale vulnerability DB."""
    max_age = timedelta(minutes=cfg["max_db_age_minutes"])
    sources = manifest.get("sources") or {}
    snapshot = {}
    missing, stale = [], []
    for ecosystem in needed:
        entry = sources.get(f"osv:{ecosystem}") or {}
        if not entry.get("checked_at") or not os.path.isfile(sync.osv_path(db_dir, ecosystem)):
            missing.append(ecosystem)
            continue
        if now - parse_iso(entry["checked_at"]) > max_age:
            stale.append(ecosystem)
        snapshot[f"osv:{ecosystem}"] = {k: entry.get(k) for k in ("checked_at", "fetched_at", "last_modified", "sha256")}
    if missing:
        raise Refusal(f"缺少漏洞資料庫:{'、'.join(missing)}。請確認網路後重跑。")
    if stale and not cfg["allow_stale_db"]:
        raise Refusal(
            f"漏洞資料庫超過 {cfg['max_db_age_minutes']} 分鐘沒有確認為最新({'、'.join(stale)}),不掃描。\n"
            "       需要離線使用時,請在設定檔設定 allow_stale_db = true。"
        )
    for source_id in ("kev", "epss", *(f"eol:{p}" for p in sync.EOL_PRODUCTS)):
        entry = sources.get(source_id) or {}
        if not entry.get("checked_at"):
            state = "missing"
        elif now - parse_iso(entry["checked_at"]) > max_age:
            state = "stale"
        else:
            state = "current"
        snapshot[source_id] = {"state": state, "checked_at": entry.get("checked_at"), "last_modified": entry.get("last_modified")}
    return {"synced_at": manifest.get("synced_at"), "stale": bool(stale), "stale_sources": stale, "sources": snapshot}


# --------------------------------------------------------------------------
# Project facts read without executing anything from the project
# --------------------------------------------------------------------------

def _read_text(path: str, limit: int = 1 << 20) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def _git_facts(src: str):
    """Read HEAD, branch and an exact tag straight from .git files.

    git itself is never run: a repository's own config can make git execute
    commands, and the project is treated as untrusted input.
    """
    git_dir = os.path.join(src, ".git")
    if os.path.isfile(git_dir):
        pointer = _read_text(git_dir, 4096).strip()
        if not pointer.startswith("gitdir:"):
            return None
        git_dir = os.path.normpath(os.path.join(src, pointer[7:].strip()))
    if not os.path.isdir(git_dir):
        return None
    common = git_dir
    common_file = os.path.join(git_dir, "commondir")
    if os.path.isfile(common_file):
        common = os.path.normpath(os.path.join(git_dir, _read_text(common_file, 4096).strip()))

    packed = {}
    peeled = {}
    last_ref = None
    for line in _read_text(os.path.join(common, "packed-refs")).splitlines():
        if line.startswith("#") or not line.strip():
            continue
        if line.startswith("^") and last_ref:
            peeled[last_ref] = line[1:].strip()
            continue
        sha, _, ref = line.partition(" ")
        if _SHA.match(sha) and ref:
            packed[ref.strip()] = sha
            last_ref = ref.strip()

    def resolve(ref: str):
        for base in (git_dir, common):
            text = _read_text(os.path.join(base, *ref.split("/")), 256).strip()
            if _SHA.match(text):
                return text
        return packed.get(ref)

    head = _read_text(os.path.join(git_dir, "HEAD"), 256).strip()
    branch = None
    if head.startswith("ref:"):
        ref = head[4:].strip()
        branch = ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else ref
        commit = resolve(ref)
    else:
        commit = head if _SHA.match(head) else None
    if not commit:
        return None

    def peel_loose(sha: str):
        path = os.path.join(common, "objects", sha[:2], sha[2:])
        try:
            with open(path, "rb") as fh:
                raw = zlib.decompress(fh.read(1 << 16))
        except (OSError, zlib.error):
            return sha
        if raw.startswith(b"tag "):
            match = re.search(rb"\nobject ([0-9a-f]{40,64})\n", b"\n" + raw.split(b"\x00", 1)[-1])
            if match:
                return match.group(1).decode()
        return sha

    tag = None
    for ref, sha in sorted(packed.items()):
        if ref.startswith("refs/tags/") and commit in (sha, peeled.get(ref)):
            tag = ref[len("refs/tags/"):]
    tags_dir = os.path.join(common, "refs", "tags")
    if tag is None and os.path.isdir(tags_dir):
        for current, _, files in os.walk(tags_dir):
            for name in sorted(files):
                sha = _read_text(os.path.join(current, name), 256).strip()
                if _SHA.match(sha) and commit in (sha, peel_loose(sha)):
                    tag = os.path.relpath(os.path.join(current, name), tags_dir).replace(os.sep, "/")
    safe = re.compile(r"^[\w./+-]{1,80}$")
    tag = tag if tag and safe.match(tag) else None
    branch = branch if branch and safe.match(branch) else None
    return {"kind": "git", "describe": tag or commit[:7], "commit": commit[:7], "branch": branch}


def project_version(src: str, deps_fingerprint: str) -> dict:
    facts = _git_facts(src)
    if facts:
        return facts
    return {"kind": "deps", "describe": "deps-" + deps_fingerprint[:7], "commit": None, "branch": None}


def load_context(src: str) -> tuple[dict, str | None]:
    """Optional, user-written facts about the project. Fixed keys, no free text."""
    path = os.path.join(src, CONTEXT_FILE)
    if not os.path.isfile(path):
        return {}, None
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        return {}, f"{CONTEXT_FILE} 無法解析,已忽略"
    section = data.get("context") if isinstance(data.get("context"), dict) else {}
    context = {}
    for key, kind in CONTEXT_KEYS.items():
        value = section.get(key)
        if kind is bool and isinstance(value, bool):
            context[key] = value
        elif isinstance(kind, tuple) and value in kind:
            context[key] = value
    return context, None


# --------------------------------------------------------------------------
# Output folders
# --------------------------------------------------------------------------

def _publish(out_dir: str, staging: str, keep_runs: int) -> None:
    latest = os.path.join(out_dir, "latest")
    runs = os.path.join(out_dir, "runs")
    if os.path.isdir(latest):
        previous = read_json(os.path.join(latest, REPORT_JSON), {}) or {}
        name = previous.get("scan_id") or "unknown"
        os.makedirs(runs, exist_ok=True)
        destination = os.path.join(runs, name)
        if os.path.exists(destination):
            shutil.rmtree(destination, ignore_errors=True)
        os.replace(latest, destination)
    os.replace(staging, latest)
    if os.path.isdir(runs):
        archived = sorted(os.listdir(runs))
        for old in archived[: max(0, len(archived) - max(0, keep_runs - 1))]:
            shutil.rmtree(os.path.join(runs, old), ignore_errors=True)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def _from_project_root(lock_rel: str, directory: str) -> str:
    """A directory relative to a lockfile, shown relative to the project root."""
    if directory == "?":
        return "?"
    base = lock_rel.rpartition("/")[0]
    if directory == ".":
        return base or "."
    return f"{base}/{directory}" if base else directory


def detect(src: str, exclude=()) -> tuple[list[str], int]:
    tree = lockfiles.discover(src, exclude)
    return sorted({lf.ecosystem for lf in tree.lockfiles}), len(tree.lockfiles)


def run(src: str, db_dir: str, state_dir: str, out_dir: str, cfg: dict, project_name: str, display_out: str | None = None, exclude=()) -> int:
    now = now_utc()
    scanned_at = iso(now)
    tree = lockfiles.discover(src, exclude)
    needed = sorted({lf.ecosystem for lf in tree.lockfiles})
    db_state = gate(sync.load_manifest(db_dir), needed, db_dir, cfg, now)

    binary = scanner_path()
    tool = {"name": "cvescan", "version": __version__, "scanner": f"osv-scanner {scanner_version(binary)}"}

    # ---- run the scanner on the project's lockfiles plus the samples -------
    canary_paths = {}
    for ecosystem in needed:
        if ecosystem in CANARY:
            canary_paths[os.path.join(DATA_DIR, "canary", CANARY[ecosystem][0])] = ecosystem
    invalid_reasons = []
    by_path = {}
    failed_args = set()
    if tree.lockfiles:
        args = [lf.osv_arg for lf in tree.lockfiles] + list(canary_paths)
        results, failed, stderr = scan_resilient(binary, args, db_dir)
        failed_args = set(failed)
        if len(failed_args) == len(args):
            detail = (stderr.strip().splitlines() or ["沒有輸出"])[-1][:200]
            raise Invalid(f"osv-scanner 無法讀取任何一個 lockfile:{detail}")
        if "could not load db" in stderr or "no offline version" in stderr:
            invalid_reasons.append("scanner 讀不到漏洞資料庫")
        for result in results:
            path = (result.get("source") or {}).get("path")
            if path:
                by_path.setdefault(path, []).extend(result.get("packages") or [])

    canary = {}
    for ecosystem in needed:
        canary[ecosystem] = "none"
    for path, ecosystem in canary_paths.items():
        wanted = lockfiles.norm_name(ecosystem, CANARY[ecosystem][1])
        flagged = any(
            lockfiles.norm_name(ecosystem, (p.get("package") or {}).get("name") or "") == wanted and p.get("vulnerabilities")
            for p in by_path.get(path, [])
        )
        canary[ecosystem] = "pass" if flagged else "fail"
        if not flagged:
            invalid_reasons.append(f"{ecosystem} 的樣本沒有被偵測出來:資料庫或 scanner 可能異常")

    # ---- inventory + graphs ------------------------------------------------
    inputs = []
    unreadable, empty, graph_notes, rejected = [], [], [], []
    scanned_pairs = []          # (input item, raw scanner package)
    for lf in tree.lockfiles:
        if lf.osv_arg in failed_args:
            unreadable.append(lf.rel)
            continue
        raw_packages = by_path.get(lf.path, [])   # absent from the results means no packages
        if not raw_packages:
            empty.append(lf.rel)
        graph = lockfiles.build_graph(lf)
        parent_dir = os.path.basename(os.path.dirname(lf.path))
        root_label = graph.root_name or (parent_dir if "/" in lf.rel else project_name)
        item = {"rel": lf.rel, "name": lf.name, "ecosystem": lf.ecosystem, "root_label": root_label, "graph": graph, "packages": [], "sha256": sha256_file(lf.path)}
        seen = set()
        outside = members = 0
        for raw in raw_packages:
            info = raw.get("package") or {}
            if not info.get("name") or not info.get("version"):
                continue
            if not lockfiles.safe_name(info["name"]) or not lockfiles.safe_version(info["version"]):
                rejected.append(lf.rel)
                continue
            ecosystem = info.get("ecosystem") or lf.ecosystem
            key = lockfiles.node_key(ecosystem, info["name"], info["version"])
            if key in seen:
                continue
            seen.add(key)
            dev_group = any(str(g).lower() in ("dev", "development", "test") for g in raw.get("dependency_groups") or [])
            # The scanner marks the project's own packages (workspace members) and does not match them against advisories.
            local = "source=LOCAL" in str(info.get("purl") or "").partition("?")[2].split("&")
            if graph.status == "complete" and graph.reachable(key):
                scope = graph.scope_of(key)
                direct = graph.is_direct(key)
            else:
                # Not in the graph, or not traceable to a direct dependency: say unknown, do not guess.
                scope = "dev" if dev_group else "prod"
                direct = None
                outside += graph.status == "complete"
            package = {
                "key": key, "name": info["name"], "version": str(info["version"]), "ecosystem": ecosystem,
                "purl": sbom.purl_for(ecosystem, info["name"], str(info["version"]), info.get("purl")),
                "scope": scope, "direct": direct,
                "first_party": local or (graph.status == "complete" and key in graph.first_party),
                "declared_in": [_from_project_root(lf.rel, d) for d in graph.declared_dirs(key)] if direct else [],
            }
            members += package["first_party"]
            item["packages"].append(package)
            scanned_pairs.append((item, package, raw))
        if graph.status != "complete":
            graph_notes.append((lf.rel, graph.note or "無法建立相依樹", "graph_unknown"))
        elif graph.note:
            graph_notes.append((lf.rel, graph.note, "graph_partial"))
        if outside:
            graph_notes.append((lf.rel, f"有 {outside} 個套件無法追溯到專案的直接相依,它們的相依關係未知", "graph_partial"))
        if members:
            graph_notes.append((lf.rel, f"有 {members} 個套件是專案自己的 workspace 成員,不會拿去比對公開的漏洞資料", "first_party"))
        inputs.append(item)

    total_packages = sum(len(i["packages"]) for i in inputs)
    if tree.lockfiles and total_packages == 0:
        invalid_reasons.append("有 lockfile 但沒有掃到任何套件")

    deps_fingerprint = sbom.fingerprint(inputs)
    project = {"name": project_name, "version": project_version(src, deps_fingerprint)}
    scan_id = now.strftime("%Y%m%dT%H%M%SZ") + "-" + deps_fingerprint[:6]

    # ---- findings ----------------------------------------------------------
    cves = set()
    for _, _, raw in scanned_pairs:
        for group in raw.get("groups") or []:
            cves.update(i for i in (group.get("ids") or []) + (group.get("aliases") or []) if str(i).startswith("CVE-"))
    kev = enrich.load_kev(db_dir)
    epss = enrich.load_epss(db_dir, cves)

    previous_index = history.load_index(state_dir)
    previous_findings = (previous_index or {}).get("findings") or {}
    found = {}
    for item, package, raw in scanned_pairs:
        records_all = [v for v in raw.get("vulnerabilities") or [] if isinstance(v, dict) and not v.get("withdrawn")]
        for group in raw.get("groups") or []:
            wanted = set(group.get("ids") or [])
            records = [r for r in records_all if r.get("id") in wanted]
            if not records:
                continue
            ids = F.sort_ids(list(wanted) + list(group.get("aliases") or []))
            ecosystem = package["ecosystem"]
            fid = F.finding_id(ecosystem, package["name"], F.primary_id(ids))
            finding = found.get(fid)
            if finding is None:
                cve_ids = [i for i in ids if i.startswith("CVE-")]
                kev_hits = [kev[c] for c in cve_ids if c in kev]
                scores = [epss[c] for c in cve_ids if c in epss]
                best = max(scores, key=lambda s: s["score"]) if scores else None
                finding = found[fid] = {
                    "finding_id": fid,
                    "lane": "malware" if any(i.startswith("MAL-") for i in ids) else "vulnerability",
                    "ecosystem": ecosystem,
                    "package": lockfiles.norm_name(ecosystem, package["name"]),
                    "ids": ids,
                    "primary_id": F.primary_id(ids),
                    "severity": F.severity_of(group, records),
                    "exploitation": {
                        "kev": bool(kev_hits),
                        "kev_date_added": kev_hits[0]["date_added"] if kev_hits else None,
                        "epss": best["score"] if best else None,
                        "epss_percentile": best["percentile"] if best else None,
                    },
                    "advisory": F.advisory_of(records),
                    "instances": [],
                }
            finding["instances"].append(F.build_instance(item, package, records, ecosystem))

    findings = []
    verdicts = (read_json(os.path.join(state_dir, VERDICTS), {}) or {}).get("verdicts") or {}
    for fid, finding in found.items():
        finding["instances"].sort(key=lambda i: (i["input"], i["version"]))
        finding["baseline_priority"], finding["baseline_reasons"] = F.baseline(finding)
        first_seen = (previous_findings.get(fid) or {}).get("first_seen") or scanned_at
        finding["first_seen"] = first_seen
        finding["age_days"] = max(0, (now - parse_iso(first_seen)).days)
        finding["basis"] = F.basis(finding)
        verdict = verdicts.get(fid)
        if verdict is None:
            finding["analysis_state"], finding["pending_reason"] = "pending", "new"
        elif verdict.get("basis") != finding["basis"]:
            finding["analysis_state"], finding["pending_reason"] = "pending", "changed"
        else:
            finding["analysis_state"], finding["pending_reason"] = "analyzed", None
        findings.append(finding)
    findings.sort(key=lambda f: (priority_rank(f["baseline_priority"]), -(f["severity"]["cvss_score"] or 0), f["package"], f["finding_id"]))

    # ---- blind spots, runtimes, quality ------------------------------------
    cover = coverage.analyze(tree, unreadable, empty, graph_notes)
    cover["canary"] = canary
    for rel_path in sorted(set(rejected)):
        cover["blind_spots"].append({
            "kind": "unsafe_names", "path": rel_path,
            "detail": f"有 {rejected.count(rel_path)} 個套件的名稱或版本不像正常的套件識別字,已略過,沒有被掃描",
        })
    if exclude:
        if tree.excluded:
            shown = "、".join(tree.excluded[:5]) + (" 等" if len(tree.excluded) > 5 else "")
            detail = f"使用者以 --exclude 排除了 {shown},這些路徑沒有被掃描"
        else:
            detail = f"使用者指定了 --exclude({'、'.join(exclude)}),但沒有比對到任何路徑"
        cover["notes"].append({"kind": "excluded_paths", "path": tree.excluded[0] if tree.excluded else "", "detail": detail})
    context, context_warning = load_context(src)
    if context_warning:
        cover["notes"].append({"kind": "context_ignored", "path": CONTEXT_FILE, "detail": context_warning})
    for source_id, text in (("kev", "KEV(已知遭利用清單)"), ("epss", "EPSS")):
        state = db_state["sources"][source_id]["state"]
        if state != "current":
            cover["notes"].append({"kind": "enrichment_" + state, "path": "", "detail": f"{text} 資料{'缺少' if state == 'missing' else '過期'},優先序可能偏低"})
    if db_state["stale"]:
        cover["notes"].append({"kind": "db_stale", "path": "", "detail": "漏洞資料庫已過期(設定允許照常掃描),近期公布的漏洞可能沒有比對到"})
    runtime_list = runtimes.evaluate(runtimes.detect(tree), enrich.load_eol(db_dir), scanned_at[:10])

    if invalid_reasons:
        quality = {"status": "invalid", "reasons": invalid_reasons}
    elif cover["blind_spots"]:
        quality = {"status": "incomplete", "reasons": [f"{len(cover['blind_spots'])} 個盲區"]}
    else:
        quality = {"status": "complete", "reasons": []}

    # ---- compare with the previous trustworthy scan ------------------------
    index_findings = {
        f["finding_id"]: {
            "ecosystem": f["ecosystem"], "package": f["package"], "ids": f["ids"],
            "instances": [[i["input"], i["version"]] for i in f["instances"]],
            "first_seen": f["first_seen"], "severity": f["severity"]["label"],
        }
        for f in findings
    }
    components = {
        history.component_id(item["rel"], p["ecosystem"], lockfiles.norm_name(p["ecosystem"], p["name"]), p["version"])
        for item in inputs for p in item["packages"]
    }
    input_set = {item["rel"] for item in inputs}
    compare_view = {fid: {"ecosystem": v["ecosystem"], "package": v["package"], "instances": [tuple(i) for i in v["instances"]]} for fid, v in index_findings.items()}
    changes, change_labels = history.attribute(previous_index, compare_view, components, input_set)
    for finding in findings:
        finding["change"] = change_labels.get(finding["finding_id"], "unchanged")

    actions = F.build_actions(findings, {item["rel"]: item["name"] for item in inputs})
    pending = [f["finding_id"] for f in findings if f["analysis_state"] == "pending"]
    by_priority = {p: sum(1 for f in findings if f["baseline_priority"] == p) for p in PRIORITIES}
    by_severity = {s: 0 for s in ("critical", "high", "medium", "low", "unknown")}
    for finding in findings:
        if finding["lane"] != "malware":
            by_severity[finding["severity"]["label"]] += 1
    summary = {
        "open": len(findings),
        "by_priority": by_priority,
        "by_severity": by_severity,
        "malware": sum(1 for f in findings if f["lane"] == "malware"),
        "kev": sum(1 for f in findings if f["exploitation"]["kev"]),
        "pending_analysis": len(pending),
        "changes": changes,
    }

    # ---- write everything into a staging folder, then publish --------------
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(state_dir, exist_ok=True)
    staging = tempfile.mkdtemp(prefix=".staging-", dir=out_dir)
    try:
        bom = sbom.build(project, scan_id, scanned_at, tool, inputs)
        sbom_path = os.path.join(staging, sbom.SBOM_FILE)
        write_atomic(sbom_path, dump_json(bom))
        report = {
            "schema_version": SCHEMA_VERSION,
            "tool": tool,
            "scan_id": scan_id,
            "scanned_at": scanned_at,
            "lang": cfg["lang"],
            "project": project,
            "quality": quality,
            "db_snapshot": db_state,
            "inputs": [
                {"ref": i["rel"], "ecosystem": i["ecosystem"], "sha256": i["sha256"], "packages": len(i["packages"]), "graph": i["graph"].status, "root_label": i["root_label"]}
                for i in inputs
            ],
            "sbom": {"file": sbom.SBOM_FILE, "sha256": sha256_file(sbom_path), "components": total_packages, "deps_fingerprint": deps_fingerprint},
            "context": context,
            "runtimes": runtime_list,
            "coverage": cover,
            "summary": summary,
            "actions": actions,
            "findings": findings,
            "pending": pending,
        }
        report_text = dump_json(report)
        write_atomic(os.path.join(staging, REPORT_JSON), report_text)
        write_atomic(os.path.join(staging, REPORT_MD), report_md.render(report))
        for name in (ANALYZE_MD, ANALYSIS_SCHEMA):
            shutil.copyfile(os.path.join(DATA_DIR, name), os.path.join(staging, name))
        # Verdicts accepted earlier still apply to findings whose facts did not
        # change, so the new folder gets an up-to-date analysis.md right away.
        carried = [v for fid, v in verdicts.items() if fid in found and v.get("basis") == found[fid]["basis"]]
        if carried and quality["status"] != "invalid":
            info = {"summary": "", "carried": True, "model": "、".join(sorted({v["model"] for v in carried if v.get("model")}))}
            last = max((v.get("accepted_at") or "" for v in carried), default="") or scanned_at
            write_atomic(os.path.join(staging, ANALYSIS_MD), verify_mod.render(report, verdicts, info, last))
        os.chmod(staging, 0o700)  # the report is a map of what is exploitable
        _publish(out_dir, staging, cfg["keep_runs"])
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    # ---- state (outside the report folder) ---------------------------------
    report_sha = sha256_text(report_text)
    write_json(os.path.join(state_dir, CURRENT), {
        "scan_id": scan_id, "scanned_at": scanned_at, "report_sha256": report_sha,
        "sbom_sha256": report["sbom"]["sha256"], "pending_analysis": len(pending),
    })
    oldest = max((f["age_days"] for f in findings), default=None)
    entry = {
        "scan_id": scan_id, "time": scanned_at, "project_version": project["version"],
        "tool_version": __version__, "scanner": tool["scanner"], "db_synced_at": db_state["synced_at"],
        "deps_fingerprint": deps_fingerprint, "quality": quality["status"],
        "reason": ";".join(quality["reasons"]) if quality["status"] == "invalid" else None,
        "components": total_packages, "pending_analysis": len(pending),
    }
    if quality["status"] != "invalid":
        entry.update({
            "open": len(findings), "by_severity": by_severity, "malware": summary["malware"], "kev": summary["kev"],
            "oldest_open_days": oldest, **{k: changes[k] for k in ("initial", "fixed", "new_advisory", "new_dependency", "gone", "withdrawn")},
        })
        history.save_index(state_dir, {"scan_id": scan_id, "time": scanned_at, "findings": index_findings, "components": sorted(components), "inputs": sorted(input_set)})
    history.append_history(state_dir, entry)

    # ---- terminal summary --------------------------------------------------
    print(f"[3/3] scan    {len(inputs)} 個 lockfile、{total_packages} 個套件")
    status_text = QUALITY_LABEL[quality["status"]]
    if quality["status"] == "invalid":
        print(f"結果   {status_text}:{';'.join(quality['reasons'])}")
    else:
        detail = ""
        if quality["status"] == "incomplete":
            detail = ":" + cover["blind_spots"][0]["detail"] if len(cover["blind_spots"]) == 1 else f":{len(cover['blind_spots'])} 個盲區"
        elif not findings:
            detail = ":掃描範圍內沒有已知漏洞"
        print(f"結果   {status_text}{detail}")
        print(f"       {report_md.summary_counts(report)}")
        print(f"       {report_md.changes_text(changes)}")
        extras = []
        if summary["malware"]:
            extras.append(f"{summary['malware']} 個惡意套件")
        if summary["kev"]:
            extras.append(f"{summary['kev']} 個已知遭利用")
        if extras:
            print("       其中 " + "、".join(extras))
        shown_runtimes = []
        for runtime in runtime_list:
            if runtime["status"] not in ("eol", "behind"):
                continue
            text = "已停止支援" if runtime["status"] == "eol" else f"落後最新修補版 {runtime['latest']}"
            line = f"       runtime:{runtime['runtime']} {runtime['declared']} {text}"
            if line not in shown_runtimes:
                shown_runtimes.append(line)
        for line in shown_runtimes[:3]:
            print(line)
    shown = (display_out or out_dir).rstrip("/")
    print(f"報表   {shown}/latest/")
    if quality["status"] != "invalid" and pending:
        print(f"下一步 請你的 agent「分析 {project_name} 的 CVE 報表」(待分析 {len(pending)} 項)")
    return 3 if quality["status"] == "invalid" else 0
