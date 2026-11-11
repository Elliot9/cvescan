"""report.md: a rule-based, human-readable summary of report.json. No AI."""

from __future__ import annotations

from .model import PRIORITIES, PRIORITY_LABEL, QUALITY_LABEL, SEVERITY_LABEL
from .util import md_inline, parse_iso, to_local

RUNTIME_STATUS = {
    "eol": "已停止支援(EOL)",
    "behind": "落後最新修補版",
    "ok": "正常",
    "unknown": "無法判定",
    "range": "只宣告範圍,未鎖定版本",
    "floating": "未固定版本",
}
CHANGE_LABEL = {
    "initial": "首次掃描",
    "new_advisory": "新公告",
    "new_dependency": "相依變動",
}


def when(text) -> str:
    if not text:
        return "–"
    local = to_local(parse_iso(text))
    offset = local.strftime("%z")
    return local.strftime("%Y-%m-%d %H:%M") + f"(UTC{offset[:3]}:{offset[3:]})"


def severity_text(finding: dict) -> str:
    if finding["lane"] == "malware":
        return SEVERITY_LABEL["malware"]
    severity = finding["severity"]
    text = SEVERITY_LABEL[severity["label"]]
    if severity["cvss_score"]:
        text += f"(CVSS {severity['cvss_score']})"
    return text


def exploitation_text(finding: dict) -> str:
    exploitation = finding["exploitation"]
    parts = []
    if exploitation["kev"]:
        parts.append("已知遭利用(KEV)")
    if exploitation["epss"] is not None:
        parts.append(f"EPSS {exploitation['epss'] * 100:.1f}%")
    return "|".join(parts)


def instance_lines(finding: dict) -> list[str]:
    lines = []
    for instance in finding["instances"]:
        scope = "正式環境" if instance["scope"] == "prod" else "開發用"
        direct = {True: "直接相依", False: "間接相依", None: "相依關係未知"}[instance["direct"]]
        lines.append(f"  - 位置:`{instance['input']}`,版本 {instance['version']}({scope},{direct})")
        places = ["專案根目錄" if d == "." else f"`{d}/`" for d in instance.get("declared_in") or [] if d != "?"]
        if places:
            lines.append("  - 宣告於:" + "、".join(places) + "(workspace)")
        if finding["lane"] != "malware":
            fix = instance["recommended_fix"]
            lines.append(f"  - 修補版:{fix}" if fix else "  - 修補版:目前沒有")
        for intro in instance["introduced_by"]:
            if intro["parent"] == "<root>":
                continue
            note = ""
            if intro["parent_requires"]:
                verdict = {True: "修補版在範圍內", False: "修補版不在範圍內", None: "無法判定"}[intro["fix_in_range"]]
                note = f"(上層要求 `{intro['parent_requires']}`:{verdict})"
            lines.append(f"  - 路徑:{' > '.join(intro['path'])}{note}")
        extra = instance["parents_total"] - len(instance["introduced_by"])
        if extra > 0:
            lines.append(f"  - 另有 {extra} 個上層套件也帶入它(見 SBOM)")
    return lines


def summary_counts(report: dict) -> str:
    summary = report["summary"]
    by_priority = "|".join(f"{PRIORITY_LABEL[p]} {summary['by_priority'][p]}" for p in PRIORITIES)
    return f"未解決 {summary['open']}({by_priority})"


def changes_text(changes: dict) -> str:
    if changes.get("initial") is not None and not any(changes.get(k) for k in ("fixed", "new_advisory", "new_dependency", "gone", "withdrawn", "unchanged")):
        return "首次掃描,之後的報表會列出與上次的差異"
    parts = [f"你修掉 {changes.get('fixed', 0)}", f"新公告 {changes.get('new_advisory', 0)}", f"相依變動 {changes.get('new_dependency', 0)}"]
    if changes.get("gone"):
        parts.append(f"不再掃到 {changes['gone']}(不算修掉)")
    if changes.get("withdrawn"):
        parts.append(f"公告不再適用 {changes['withdrawn']}")
    return "與上次相比:" + "|".join(parts)


def render(report: dict) -> str:
    project = report["project"]
    quality = report["quality"]
    summary = report["summary"]
    out = [f"# cvescan 報表:{project['name']}", ""]
    out.append(f"- 掃描時間:{when(report['scanned_at'])}|專案版本:{project['version'].get('describe') or '–'}")
    out.append(f"- 漏洞資料庫:{when(report['db_snapshot'].get('synced_at'))} 同步" + (";**資料庫已過期**" if report["db_snapshot"].get("stale") else ""))
    out.append(f"- 工具:cvescan {report['tool']['version']}|{report['tool']['scanner']}")
    out.append(f"- 掃描品質:**{QUALITY_LABEL[quality['status']]}**" + (":" + ";".join(quality["reasons"]) if quality["reasons"] else ""))
    out.append(f"- 掃描範圍:{len(report['inputs'])} 個 lockfile、{report['sbom']['components']} 個套件(完整清單見 `{report['sbom']['file']}`)")
    out.append("")

    out += ["## 結論", ""]
    if quality["status"] == "invalid":
        out.append("**這次掃描無效,下面的數字不可信。** 請先排除上面列的原因再重掃。")
        out.append("")
    out.append(summary_counts(report))
    out.append(changes_text(summary["changes"]))
    extras = []
    if summary["malware"]:
        extras.append(f"惡意套件 {summary['malware']}")
    if summary["kev"]:
        extras.append(f"已知遭利用 {summary['kev']}")
    if extras:
        out.append("其中:" + "|".join(extras))
    if summary["open"] == 0 and quality["status"] == "complete":
        out.append("掃描範圍內沒有已知漏洞。")
    elif summary["open"] == 0:
        out.append("**沒有 finding 不代表安全**:這次掃描不完整,請看下面的「盲區」。")
    out.append("")

    findings = report["findings"]
    by_id = {f["finding_id"]: f for f in findings}

    if report["actions"]:
        out += ["## 升級動作", "", "以「要動哪個套件」為單位,一個動作可能同時解決多個漏洞。", ""]
        out.append("| # | 套件 | 目前 | 目標 | 解決 | 位置 | 做法 |")
        out.append("|---|---|---|---|---|---|---|")
        for action in report["actions"]:
            urgent = min((PRIORITIES.index(by_id[i]["baseline_priority"]) for i in action["finding_ids"] if i in by_id), default=3)
            target = action["to"] or ("移除" if action["how"] == "remove" else "無修補版")
            out.append(
                f"| {action['action_id']} | {action['package']} | {action['from']} | {target} | "
                f"{len(action['finding_ids'])} 項({PRIORITY_LABEL[PRIORITIES[urgent]]}) | `{action['input']}` | {action['hint']} |"
            )
        out.append("")

    if findings:
        out += ["## 未解決項目", ""]
        for priority in PRIORITIES:
            group = [f for f in findings if f["baseline_priority"] == priority]
            if not group:
                continue
            out += [f"### {PRIORITY_LABEL[priority]}({len(group)})", ""]
            for finding in group:
                versions = "、".join(dict.fromkeys(i["version"] for i in finding["instances"]))
                head = f"- **{finding['package']} {versions}** · {' / '.join(finding['ids'][:3])} · {severity_text(finding)}"
                extra = exploitation_text(finding)
                if extra:
                    head += f" · {extra}"
                change = CHANGE_LABEL.get(finding.get("change"))
                if change and change != "首次掃描":
                    head += f" · {change}"
                out.append(head)
                out.append(f"  - 編號:`{finding['finding_id']}`|已存在 {finding['age_days']} 天")
                if finding["advisory"]["summary"]:
                    out.append(f"  - 摘要:{md_inline(finding['advisory']['summary'])}")
                out += instance_lines(finding)
                out.append(f"  - 排序依據:{';'.join(finding['baseline_reasons'])}")
            out.append("")

    if report["runtimes"]:
        out += ["## Runtime", "", "Lockfile 掃描不包含直譯器本身。下表是專案檔案裡宣告的版本,實際部署的版本可能不同。", ""]
        out.append("| Runtime | 宣告版本 | 來源 | 狀態 | 該版本線最新 | 停止支援日 |")
        out.append("|---|---|---|---|---|---|")
        for runtime in report["runtimes"]:
            out.append(
                f"| {runtime['runtime']} | {runtime['declared']} | `{runtime['source']}` | {RUNTIME_STATUS[runtime['status']]} | "
                f"{runtime['latest'] or '–'} | {runtime['eol_date'] or '–'} |"
            )
        out.append("")

    coverage = report["coverage"]
    out += ["## 盲區", ""]
    if coverage["blind_spots"]:
        out.append("下列內容**沒有被掃描**,所以這份報表不能代表整個專案:")
        out.append("")
        for spot in coverage["blind_spots"]:
            out.append(f"- `{spot['path'] or '(專案)'}`:{spot['detail']}")
    else:
        out.append("沒有發現未掃描的相依套件來源。")
    out.append("")
    out += ["## 其他限制", ""]
    for note in coverage["notes"]:
        prefix = f"`{note['path']}`:" if note["path"] and note["kind"] in ("graph_unknown", "graph_partial", "first_party", "lockfile_empty") else ""
        out.append(f"- {prefix}{note['detail']}")
    canary = coverage.get("canary") or {}
    if canary:
        text = "、".join(f"{eco} {'通過' if state == 'pass' else '未通過' if state == 'fail' else '無樣本'}" for eco, state in sorted(canary.items()))
        out.append(f"- 樣本檢查(確認 scanner 與資料庫真的有在運作):{text}")
    out.append("")
    out += ["---", "", "這份報表完全由規則產生,沒有 AI 參與。AI 的分析在 `analysis.md`,通過 `cvescan verify` 之後才會產生。", ""]
    return "\n".join(out)
