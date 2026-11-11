"""Turn scanner results into findings, a rule-based priority, and upgrade actions.

Everything here is deterministic. The priority computed here is the baseline
the AI starts from; `verify` refuses an analysis that lowers it without
user-supplied context.
"""

from __future__ import annotations

from . import versions
from .lockfiles import ROOT, label, norm_name
from .model import PRIORITIES, priority_rank
from .sbom import path_labels
from .util import canonical_json, sha256_text, truncate

_ID_ORDER = {"MAL-": 0, "GHSA": 1, "CVE-": 2}
_GHSA_SEVERITY = {"LOW": "low", "MODERATE": "medium", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical"}
_REF_ORDER = {"ADVISORY": 0, "FIX": 1, "REPORT": 2, "WEB": 3, "PACKAGE": 4}
_MANAGER = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm", "bun.lock": "bun", "composer.lock": "composer",
    "poetry.lock": "poetry", "uv.lock": "uv", "Pipfile.lock": "pipenv",
}


def _id_key(identifier: str):
    return (_ID_ORDER.get(identifier[:4], 3), identifier)


def sort_ids(ids) -> list[str]:
    return sorted(set(ids), key=_id_key)


def primary_id(ids) -> str:
    """Stable identity: GHSA ids are assigned first and never change."""
    ordered = sort_ids(ids)
    for prefix in ("GHSA-", "CVE-"):
        for identifier in ordered:
            if identifier.startswith(prefix):
                return identifier
    return ordered[0]


def finding_id(ecosystem: str, package: str, primary: str) -> str:
    return "F-" + sha256_text(f"{ecosystem}|{norm_name(ecosystem, package)}|{primary}")[:10]


def same_ecosystem(a: str, b: str) -> bool:
    return (a or "").split(":", 1)[0].lower() == (b or "").split(":", 1)[0].lower()


def severity_of(group: dict, records: list[dict]) -> dict:
    score = None
    try:
        score = float(group.get("max_severity") or "")
    except (TypeError, ValueError):
        score = None
    vector = None
    for record in records:
        for item in record.get("severity") or []:
            if isinstance(item, dict) and item.get("score") and vector is None:
                vector = item["score"]
    label_ = None
    if score:
        label_ = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    else:
        for record in records:
            raw = str((record.get("database_specific") or {}).get("severity") or "").upper()
            if raw in _GHSA_SEVERITY:
                label_ = _GHSA_SEVERITY[raw]
                break
    return {"label": label_ or "unknown", "cvss_score": score or None, "cvss_vector": vector}


def _clean(text) -> str:
    return "".join(ch for ch in str(text or "") if ch == "\n" or ch >= " ").strip()


def advisory_of(records: list[dict]) -> dict:
    """The advisory text travels with the report so the AI does not have to
    recall (or invent) what a recent CVE is about. It is data, not instructions."""
    best = next((r for r in records if str(r.get("id", "")).startswith("GHSA-")), records[0])
    details = _clean(best.get("details"))
    summary = _clean(best.get("summary")) or details.split("\n", 1)[0]
    references = []
    for record in records:
        for ref in record.get("references") or []:
            if isinstance(ref, dict) and str(ref.get("url", "")).startswith("https://"):
                references.append((_REF_ORDER.get(ref.get("type"), 5), ref["url"]))
    urls = list(dict.fromkeys(url for _, url in sorted(references)))[:6]
    cwes = sorted({c for r in records for c in ((r.get("database_specific") or {}).get("cwe_ids") or []) if isinstance(c, str)})
    published = sorted(r["published"] for r in records if r.get("published"))
    modified = sorted(r["modified"] for r in records if r.get("modified"))
    return {
        "summary": truncate(summary, 300),
        "details": truncate(details, 1500),
        "cwe_ids": cwes,
        "published": published[0] if published else None,
        "modified": modified[-1] if modified else None,
        "references": urls,
    }


def ranges_for(records: list[dict], ecosystem: str, package: str) -> list[list[dict]]:
    wanted = norm_name(ecosystem, package)
    ranges = []
    for record in records:
        for affected in record.get("affected") or []:
            info = affected.get("package") or {}
            if not same_ecosystem(info.get("ecosystem"), ecosystem):
                continue
            if norm_name(ecosystem, info.get("name") or "") != wanted:
                continue
            for item in affected.get("ranges") or []:
                if item.get("type") != "GIT" and isinstance(item.get("events"), list):
                    ranges.append(item["events"])
    return ranges


def build_instance(input_item: dict, package: dict, records: list[dict], ecosystem: str) -> dict:
    graph = input_item["graph"]
    key = package["key"]
    recommended, fixed = versions.select_fix(package["version"], ranges_for(records, ecosystem, package["name"]))
    introduced, total = [], 0
    if graph.status == "complete" and graph.has(key):
        entries, total = graph.introduced_by(key)
        listed = {p["key"] for p in input_item["packages"]}
        for entry in entries:
            if any(node not in listed for node in entry["chain"]):
                continue  # goes through a package the scanner did not list
            requires = entry["requires"]
            in_range = versions.satisfies(ecosystem, recommended, requires) if recommended and requires else None
            introduced.append({
                "path": path_labels(input_item["root_label"], entry["chain"]),
                "parent": "<root>" if entry["parent"] == ROOT else label(entry["parent"]),
                "parent_requires": requires,
                "fix_in_range": in_range,
            })
    return {
        "input": input_item["rel"],
        "version": package["version"],
        "scope": package["scope"],
        "direct": package["direct"],
        "declared_in": list(package.get("declared_in") or []),
        "fixed_versions": fixed,
        "recommended_fix": recommended,
        "introduced_by": introduced,
        "parents_total": total,
    }


def baseline(finding: dict) -> tuple[str, list[str]]:
    """Rule-based priority. Malware and known-exploited always mean 'now'."""
    if finding["lane"] == "malware":
        return "now", ["已通報為惡意套件"]
    exploitation = finding["exploitation"]
    if exploitation["kev"]:
        return "now", ["列入 CISA 已知遭利用清單(KEV)"]
    severity = finding["severity"]
    score, epss = severity["cvss_score"], exploitation["epss"]
    reasons = []
    if severity["label"] == "unknown":
        priority = "scheduled"
        reasons.append("沒有嚴重度評分,保守排入排程")
    else:
        priority = {"critical": "soon", "high": "scheduled", "medium": "scheduled", "low": "watch"}[severity["label"]]
        reasons.append(f"CVSS {score}" if score else f"嚴重度 {severity['label']}")
        if severity["label"] == "high" and epss is not None and epss >= 0.1:
            priority = "soon"
    if epss is not None:
        reasons.append(f"EPSS {epss * 100:.1f}%")
    if finding["instances"] and all(i["scope"] == "dev" for i in finding["instances"]):
        priority = PRIORITIES[min(len(PRIORITIES) - 1, priority_rank(priority) + 1)]
        reasons.append("只出現在開發用相依套件,降一級")
    if any(not i["recommended_fix"] for i in finding["instances"]):
        reasons.append("目前沒有修補版")
    return priority, reasons


def basis(finding: dict) -> str:
    """Fingerprint of the facts a verdict was based on. When it changes, the
    finding goes back to the pending list."""
    facts = {
        "ids": finding["ids"],
        "lane": finding["lane"],
        "severity": finding["severity"]["label"],
        "kev": finding["exploitation"]["kev"],
        "instances": sorted([i["input"], i["version"], i["recommended_fix"], i["direct"]] for i in finding["instances"]),
    }
    return sha256_text(canonical_json(facts))[:16]


def _hint(lockfile_name: str, how: str, package: str, target, parents: list[str], declared_in=()) -> str:
    manager = _MANAGER.get(lockfile_name) or ("pip" if lockfile_name.endswith(".txt") else None)
    if how == "remove":
        return f"移除 {package}。當作已經中招處理:輪替這台機器與 CI 用過的憑證,檢查安裝時間前後的異常活動"
    if how == "no_fix":
        return "目前沒有修補版:評估緩解措施,或改用替代套件"
    above = "、".join(parents) if parents else "上層套件"
    direct = {
        "npm": f"npm install {package}@{target}",
        "yarn": f"yarn add {package}@{target}",
        "pnpm": f"pnpm add {package}@{target}",
        "bun": f"bun add {package}@{target}",
        "composer": f"composer require {package}:^{target}",
        "poetry": f"poetry add {package}@^{target}",
        "uv": f"uv add '{package}>={target}'",
        "pipenv": f"pipenv install '{package}>={target}'",
        "pip": f"把 {package} 的版本改成 {target}",
    }
    relock = {
        "npm": f"npm update {package}",
        "yarn": f"yarn upgrade {package}",
        "pnpm": f"pnpm update {package}",
        "bun": f"bun update {package}",
        "composer": f"composer update {package} --with-dependencies",
        "poetry": f"poetry update {package}",
        "uv": f"uv lock --upgrade-package {package}",
        "pipenv": f"pipenv update {package}",
        "pip": f"把 {package} 的版本改成 {target}",
    }
    override = {
        "npm": f"在 package.json 的 overrides 指定 {package}@{target}",
        "yarn": f"在 package.json 的 resolutions 指定 {package}@{target}",
        "pnpm": f"在 package.json 的 pnpm.overrides 指定 {package}@{target}",
        "composer": f"在 composer.json 直接 require {package}:^{target}",
        "poetry": f"在 pyproject.toml 直接加上 {package}>={target}",
        "uv": f"在 pyproject.toml 用 constraint-dependencies 指定 {package}>={target}",
    }
    fallback = f"把 {package} 升級到 {target}"
    if how == "bump_direct":
        command = direct.get(manager, fallback)
        if declared_in:
            # Declared by a workspace member: the command has to run where that manifest is.
            places = ["專案根目錄" if place == "." else f"`{place}`" for place in declared_in if place != "?"]
            if "?" in declared_in:
                places.append("一個路徑無法顯示的 workspace 成員")
            return f"{command}(宣告在 {'、'.join(places)}:在該目錄下執行)"
        return command
    if how == "bump":
        # Relationship unknown (no tree, or not traceable): a direct dependency cannot be told from a transitive one.
        first, second = direct.get(manager), relock.get(manager)
        if not first or first == second:
            return first or fallback
        return f"相依關係未知,無法判斷是直接還是間接相依。直接相依:{first};間接相依:{second}"
    if how == "relock":
        return relock.get(manager, fallback) + f"(上層允許 {target},更新 lockfile 即可)"
    if how == "parent_or_override":
        tail = override.get(manager)
        return f"上層鎖住了舊版:升級 {above} 到會帶入 {package} {target} 以上的版本" + (f",或{tail}" if tail else "")
    return f"相依路徑的版本要求無法判定:先試 {relock.get(manager, fallback)},不行再升級 {above}"


def build_actions(findings: list[dict], lockfile_names: dict) -> list[dict]:
    """Group findings into upgrade actions: the unit a person actually works in."""
    buckets = {}
    for finding in findings:
        for instance in finding["instances"]:
            key = (instance["input"], finding["ecosystem"], finding["package"], instance["version"])
            bucket = buckets.setdefault(key, {"ids": [], "targets": [], "unfixed": 0, "instance": instance, "malware": False, "rank": 99})
            bucket["ids"].append(finding["finding_id"])
            bucket["rank"] = min(bucket["rank"], priority_rank(finding["baseline_priority"]))
            if finding["lane"] == "malware":
                bucket["malware"] = True
            elif instance["recommended_fix"]:
                bucket["targets"].append(instance["recommended_fix"])
            else:
                bucket["unfixed"] += 1

    actions = []
    ordered = sorted(buckets.items(), key=lambda kv: (kv[1]["rank"], -len(kv[1]["ids"]), kv[0]))
    for number, (key, bucket) in enumerate(ordered, 1):
        input_rel, ecosystem, package, version = key
        instance = bucket["instance"]
        target = versions.max_version(bucket["targets"])
        parents = sorted({p["parent"] for p in instance["introduced_by"] if p["parent"] != "<root>"})
        # The direct dependency at the head of each path is what the user can actually change.
        via = sorted({p["path"][1].rsplit("@", 1)[0] for p in instance["introduced_by"] if len(p["path"]) > 2})
        if bucket["malware"]:
            how = "remove"
        elif not target:
            how = "no_fix"
        elif instance["direct"] is True:
            how = "bump_direct"
        elif instance["direct"] is False:
            checks = [versions.satisfies(ecosystem, target, p["parent_requires"]) if p["parent_requires"] else None for p in instance["introduced_by"]]
            if checks and all(c is True for c in checks):
                how = "relock"
            elif any(c is False for c in checks):
                how = "parent_or_override"
            else:
                how = "check_parent"
        else:
            how = "bump"
        actions.append({
            "action_id": f"A-{number}",
            "input": input_rel,
            "ecosystem": ecosystem,
            "package": package,
            "from": version,
            "to": None if how in ("remove", "no_fix") else target,
            "how": how,
            "direct": instance["direct"],
            "scope": instance["scope"],
            "parents": parents,
            "via_direct": via,
            "finding_ids": sorted(set(bucket["ids"])),
            "unfixed": bucket["unfixed"],
            "declared_in": list(instance.get("declared_in") or []),
            "hint": _hint(lockfile_names.get(input_rel, ""), how, package, target, via, instance.get("declared_in") or ()),
        })
    return actions
