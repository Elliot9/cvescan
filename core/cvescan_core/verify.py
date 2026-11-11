"""verify: check the AI's analysis.json with plain rules, then render analysis.md.

The AI only fills in a form. This module decides whether the form is
acceptable, and it, not the AI, writes the document a person reads:
versions, paths and commands come from the scan, never from the AI's prose.

Rules enforced here:
  * the analysis must be about the current, unmodified report
  * every pending finding gets exactly one verdict (unless marked partial)
  * no vulnerability ids or links that are not in the report
  * the AI may raise a priority freely; lowering it, or saying "not affected",
    requires user-supplied context; malware and known-exploited findings can
    never be lowered
  * upgrade targets must be fixed versions listed in the report
  * every dependency path the AI cites must exist in the SBOM
"""

from __future__ import annotations

import json
import os
import re

from . import sbom
from . import versions as version_rules
from .model import (
    ACTION_TYPES, ANALYSIS_JSON, ANALYSIS_MD, CURRENT, JUSTIFICATIONS, PRIORITIES, PRIORITY_LABEL,
    REPORT_JSON, SCHEMA_VERSION, STATUS_LABEL, STATUSES, VERDICTS, priority_rank,
)
from .report import exploitation_text, severity_text, when
from .util import iso, md_inline, now_utc, read_json, sha256_file, write_atomic, write_json

MAX_BYTES = 2 * 1024 * 1024
_ID = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|MAL-\d{4}-\d+)\b", re.I)
_URL = re.compile(r"https?://[^\s)>\]\"'`,,。)]+", re.I)


def _text(value, limit: int, required: bool = False):
    """Return (ok, cleaned text)."""
    if value is None and not required:
        return True, ""
    if not isinstance(value, str):
        return False, ""
    cleaned = md_inline(value)
    if (required and not cleaned) or len(cleaned) > limit:
        return False, cleaned
    return True, cleaned


def validate(report: dict, analysis, graph: sbom.SbomGraph) -> tuple[list[str], dict, dict]:
    """Returns (errors, accepted verdicts by finding id, header info)."""
    errors = []
    accepted = {}
    info = {"summary": "", "model": "", "partial": False}
    if not isinstance(analysis, dict):
        return ["analysis.json 最外層必須是一個物件"], accepted, info
    if str(analysis.get("schema_version")) != SCHEMA_VERSION:
        errors.append(f'schema_version 必須是 "{SCHEMA_VERSION}"')
    if analysis.get("scan_id") != report["scan_id"]:
        errors.append(f'scan_id 不符:這份分析寫的是 {analysis.get("scan_id")!r},目前的報表是 {report["scan_id"]!r}。請重新讀取 report.json')
    info["partial"] = analysis.get("partial") is True

    by_id = {f["finding_id"]: f for f in report["findings"]}
    known_ids = {i.upper() for f in report["findings"] for i in f["ids"]}
    known_urls = {u for f in report["findings"] for u in f["advisory"]["references"]}
    context = report.get("context") or {}

    def check_text(where: str, text: str) -> None:
        for match in _ID.findall(text):
            if match.upper() not in known_ids:
                errors.append(f"{where}:提到報表裡沒有的 {match}")
        for url in _URL.findall(text):
            if url.rstrip(".") not in known_urls:
                errors.append(f"{where}:包含報表裡沒有的連結 {url[:80]}")

    ok, summary = _text(analysis.get("summary"), 1200)
    if not ok:
        errors.append("summary 必須是 1200 字以內的文字")
    else:
        info["summary"] = summary
        check_text("summary", summary)
    ok, model = _text(analysis.get("model"), 100)
    info["model"] = "".join(ch for ch in model if ch.isalnum() or ch in " ._:/()-") if ok else ""

    entries = analysis.get("findings")
    if not isinstance(entries, list):
        return errors + ["findings 必須是陣列"], accepted, info
    if len(entries) > 5000:
        return errors + ["findings 筆數過多"], accepted, info

    for position, entry in enumerate(entries, 1):
        if not isinstance(entry, dict):
            errors.append(f"findings 第 {position} 筆不是物件")
            continue
        fid = entry.get("finding_id")
        where = str(fid) if isinstance(fid, str) else f"findings 第 {position} 筆"
        finding = by_id.get(fid) if isinstance(fid, str) else None
        if finding is None:
            errors.append(f"{where}:報表裡沒有這個 finding_id")
            continue
        if fid in accepted:
            errors.append(f"{fid}:重複出現")
            continue
        before = len(errors)

        status = entry.get("status")
        priority = entry.get("priority")
        if status not in STATUSES:
            errors.append(f"{fid}:status 必須是 {' / '.join(STATUSES)}")
        if priority not in PRIORITIES:
            errors.append(f"{fid}:priority 必須是 {' / '.join(PRIORITIES)}")
        ok, rationale = _text(entry.get("rationale"), 800, required=True)
        if not ok:
            errors.append(f"{fid}:rationale 必填,800 字以內")
        else:
            check_text(f"{fid} rationale", rationale)

        refs = entry.get("context_refs") or []
        if not isinstance(refs, list) or not all(isinstance(r, str) for r in refs):
            errors.append(f"{fid}:context_refs 必須是字串陣列")
            refs = []
        for ref in refs:
            if ref not in context:
                errors.append(f"{fid}:context_refs 引用了報表 context 裡沒有的 {ref!r}")
        has_context = bool(refs) and all(r in context for r in refs)

        baseline = finding["baseline_priority"]
        justification = entry.get("justification")
        if status == "not_affected":
            if justification not in JUSTIFICATIONS:
                errors.append(f"{fid}:判定 not_affected 必須附 justification({' / '.join(JUSTIFICATIONS)})")
            if not has_context:
                errors.append(f"{fid}:判定 not_affected 必須用 context_refs 引用使用者提供的 context;沒有依據時請改用 under_investigation 並提出問題")
            if baseline == "now":
                errors.append(f"{fid}:惡意套件或已知遭利用的項目不能判定為 not_affected")
        elif justification is not None:
            errors.append(f"{fid}:只有 not_affected 才填 justification")
        if priority in PRIORITIES and priority_rank(priority) > priority_rank(baseline):
            if baseline == "now":
                errors.append(f"{fid}:規則基準是「立即」(惡意套件或已知遭利用),不能調降")
            elif not has_context:
                errors.append(f"{fid}:優先序從 {baseline} 調降到 {priority},必須用 context_refs 引用使用者提供的 context")

        fixed = {v for i in finding["instances"] for v in i["fixed_versions"]}
        action = entry.get("action")
        clean_action = {"type": "none"}
        if not isinstance(action, dict) or action.get("type") not in ACTION_TYPES:
            errors.append(f"{fid}:action.type 必須是 {' / '.join(ACTION_TYPES)}")
        else:
            kind = action["type"]
            clean_action = {"type": kind}
            if status == "not_affected" and kind != "none":
                errors.append(f"{fid}:not_affected 的 action.type 必須是 none")
            if status == "affected" and kind == "none":
                errors.append(f"{fid}:判定 affected 就必須有處置(upgrade / remove / mitigate)")
            if finding["lane"] == "malware" and status != "not_affected" and kind != "remove":
                errors.append(f"{fid}:惡意套件的處置只能是 remove,不能用升級解決")
            if kind == "upgrade":
                target = action.get("target_version")
                if not fixed:
                    errors.append(f"{fid}:報表裡這個項目沒有修補版,不能用 upgrade;請改用 mitigate 或 remove")
                elif target not in fixed:
                    errors.append(f"{fid}:target_version {target!r} 不在報表列出的修補版內({'、'.join(sorted(fixed))})")
                else:
                    clean_action["target_version"] = target
            if kind == "mitigate":
                ok, mitigation = _text(action.get("mitigation"), 500, required=True)
                if not ok:
                    errors.append(f"{fid}:action.type 為 mitigate 時必須填 mitigation(500 字以內)")
                else:
                    check_text(f"{fid} mitigation", mitigation)
                    clean_action["mitigation"] = mitigation

        labels = {f"{finding['package']}@{i['version']}" for i in finding["instances"]}
        paths = entry.get("cited_paths") or []
        clean_paths = []
        if not isinstance(paths, list) or len(paths) > 5:
            errors.append(f"{fid}:cited_paths 必須是陣列,最多 5 條")
        else:
            for path in paths:
                if not graph.has_path(path):
                    errors.append(f"{fid}:引用的相依路徑不存在於 SBOM:{' > '.join(map(str, path)) if isinstance(path, list) else path!r}")
                elif path[-1] not in labels:
                    errors.append(f"{fid}:引用的路徑沒有通到這個項目的套件({'、'.join(sorted(labels))})")
                else:
                    clean_paths.append(path)

        questions = entry.get("questions") or []
        clean_questions = []
        if not isinstance(questions, list) or len(questions) > 5:
            errors.append(f"{fid}:questions 必須是陣列,最多 5 題")
        else:
            for question in questions:
                ok_text, text = _text(question.get("text") if isinstance(question, dict) else None, 300, required=True)
                options = question.get("options") if isinstance(question, dict) else None
                good_options = isinstance(options, list) and 2 <= len(options) <= 5 and all(isinstance(o, str) and 0 < len(o.strip()) <= 40 for o in options)
                if not ok_text or not good_options:
                    errors.append(f"{fid}:每個問題需要 text(300 字以內)和 2 到 5 個 options")
                else:
                    check_text(f"{fid} questions", text)
                    clean_questions.append({"text": text, "options": [md_inline(o) for o in options]})

        if len(errors) == before:
            accepted[fid] = {
                "status": status, "priority": priority, "justification": justification,
                "context_refs": refs, "rationale": rationale, "action": clean_action,
                "cited_paths": clean_paths, "questions": clean_questions,
            }

    pending = set(report.get("pending") or [])
    missing = sorted(pending - set(accepted) - {e.get("finding_id") for e in entries if isinstance(e, dict)})
    if not info["partial"] and missing:
        shown = "、".join(missing[:10]) + (f" 等 {len(missing)} 項" if len(missing) > 10 else "")
        errors.append(f'有 {len(missing)} 個待分析的 finding 沒有結論:{shown}(一次做不完可以在最外層加 "partial": true)')
    if info["partial"] and not entries:
        errors.append("partial 分析至少要包含一個 finding")
    return errors, accepted, info


# --------------------------------------------------------------------------
# analysis.md
# --------------------------------------------------------------------------

def render(report: dict, verdicts: dict, info: dict, verified_at: str) -> str:
    findings = report["findings"]
    analyzed = [(f, verdicts[f["finding_id"]]) for f in findings if f["finding_id"] in verdicts and verdicts[f["finding_id"]].get("basis") == f["basis"]]
    waiting = [f for f in findings if not any(f is done for done, _ in analyzed)]
    actions_for = {}
    for action in report["actions"]:
        for fid in action["finding_ids"]:
            actions_for.setdefault(fid, []).append(action)

    out = [f"# cvescan 分析:{report['project']['name']}", ""]
    out.append(f"- 依據報表:{when(report['scanned_at'])}(`{report['scan_id']}`),專案版本 {report['project']['version'].get('describe') or '–'}")
    if info.get("carried"):
        out.append(f"- 驗證:沿用先前通過驗證的結論(最後一次 {when(verified_at)})|模型自述:{info.get('model') or '未提供'}")
    else:
        out.append(f"- 驗證:通過({when(verified_at)})|模型自述:{info.get('model') or '未提供'}")
    out.append(f"- 範圍:已分析 {len(analyzed)} / 未解決 {len(findings)}" + (f";**尚有 {len(waiting)} 項待分析**" if waiting else ""))
    out.append("")
    out.append("> 這份文件由 cvescan 依照通過驗證的 analysis.json 產生。判定與理由來自 AI;版本、路徑與指令來自掃描結果。")
    out.append("> AI 看不到程式碼,無法確認有漏洞的程式是否真的被呼叫。")
    out.append("")
    if report["quality"]["status"] != "complete":
        out.append("**注意:這次掃描不完整,有內容沒有被掃到(見文末「盲區」)。**")
        out.append("")
    if info.get("summary"):
        out += ["## 摘要", "", info["summary"], ""]

    questions = []
    for priority in PRIORITIES:
        group = [(f, v) for f, v in analyzed if v["priority"] == priority and v["status"] != "not_affected"]
        if not group:
            continue
        out += [f"## {PRIORITY_LABEL[priority]}({len(group)})", ""]
        for finding, verdict in group:
            versions = "、".join(dict.fromkeys(i["version"] for i in finding["instances"]))
            out.append(f"### {finding['package']} {versions} · {' / '.join(finding['ids'][:3])}")
            out.append("")
            line = f"- 判定:{STATUS_LABEL[verdict['status']]}|{severity_text(finding)}"
            extra = exploitation_text(finding)
            if extra:
                line += f"|{extra}"
            out.append(line)
            base = finding["baseline_priority"]
            if base != priority:
                direction = "調高" if priority_rank(priority) < priority_rank(base) else "調降"
                refs = f",依據 context:{'、'.join(verdict['context_refs'])}" if verdict["context_refs"] and direction == "調降" else ""
                out.append(f"- 優先序:{PRIORITY_LABEL[priority]}(規則基準是{PRIORITY_LABEL[base]},AI {direction}{refs})")
            out.append(f"- 理由(AI):{verdict['rationale']}")
            action = verdict["action"]
            related = actions_for.get(finding["finding_id"], [])
            if action["type"] == "upgrade":
                for item in related:
                    # The tool's target already covers every finding of this package.
                    # Only mention the AI's pick when it asks for something newer.
                    higher = item["to"] and (version_rules.compare(action.get("target_version"), item["to"]) or 0) > 0
                    note = f"(AI 建議升到 {action['target_version']})" if higher else ""
                    out.append(f"- 處置:{item['hint']}{note}|`{item['input']}`")
                if not related:
                    out.append(f"- 處置:升級到 {action['target_version']}")
            elif action["type"] == "remove":
                hints = [item["hint"] for item in related if item["how"] == "remove"]
                out.append(f"- 處置:{hints[0] if hints else '移除 ' + finding['package']}")
            elif action["type"] == "mitigate":
                out.append(f"- 緩解(AI 建議):{action['mitigation']}")
            else:
                out.append("- 處置:先確認下面的問題,暫不動作")
            paths = verdict["cited_paths"] or [i["path"] for inst in finding["instances"] for i in inst["introduced_by"] if len(i["path"]) > 2][:2]
            for path in paths:
                out.append(f"- 路徑:{' > '.join(path)}")
            for question in verdict["questions"]:
                questions.append((finding, question))
                out.append(f"- 需要你確認:{question['text']}({' / '.join(question['options'])})")
            out.append(f"- 編號:`{finding['finding_id']}`")
            out.append("")

    cleared = [(f, v) for f, v in analyzed if v["status"] == "not_affected"]
    if cleared:
        out += [f"## 判定不受影響({len(cleared)})", ""]
        for finding, verdict in cleared:
            out.append(f"- **{finding['package']}** · {finding['ids'][0]}:{verdict['rationale']}(依據 context:{'、'.join(verdict['context_refs'])};{verdict['justification']})")
        out.append("")

    if questions:
        out += ["## 需要你確認的問題", "", "AI 看不到程式碼,下面這些只有你能回答。答案會影響上面的判定。", ""]
        for number, (finding, question) in enumerate(questions, 1):
            out.append(f"{number}. [{finding['package']}] {question['text']}({' / '.join(question['options'])})")
        out.append("")

    if waiting:
        out += ["## 尚未分析", ""]
        for finding in waiting[:50]:
            out.append(f"- `{finding['finding_id']}` {finding['package']} · {finding['ids'][0]} · 規則基準:{PRIORITY_LABEL[finding['baseline_priority']]}")
        if len(waiting) > 50:
            out.append(f"- …另有 {len(waiting) - 50} 項")
        out.append("")

    spots = report["coverage"]["blind_spots"]
    if spots:
        out += ["## 盲區", "", "下列內容沒有被掃描,這份分析不涵蓋它們:", ""]
        for spot in spots:
            out.append(f"- `{spot['path'] or '(專案)'}`:{spot['detail']}")
        out.append("")
    flagged = [r for r in report["runtimes"] if r["status"] in ("eol", "behind")]
    if flagged:
        out += ["## Runtime", ""]
        for runtime in flagged:
            text = f"已停止支援({runtime['eol_date'] or '日期不明'})" if runtime["status"] == "eol" else f"落後最新修補版 {runtime['latest']}"
            out.append(f"- {runtime['runtime']} {runtime['declared']}(`{runtime['source']}`):{text}")
        out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------------

def run(state_dir: str, out_dir: str, display_out: str | None = None) -> int:
    latest = os.path.join(out_dir, "latest")
    report_path = os.path.join(latest, REPORT_JSON)
    analysis_path = os.path.join(latest, ANALYSIS_JSON)
    shown = (display_out or out_dir).rstrip("/") + "/latest"

    def fail(messages: list[str]) -> int:
        print(f"✗ 未通過({len(messages)} 項)")
        for message in messages:
            print(f"  - {message}")
        return 1

    current = read_json(os.path.join(state_dir, CURRENT), None)
    if not current or not os.path.isfile(report_path):
        return fail(["找不到這個專案的報表,請先執行 cvescan <專案路徑>"])
    if sha256_file(report_path) != current.get("report_sha256"):
        return fail(["report.json 在掃描之後被改動過。請重新掃描,不要修改報表"])
    sbom_path = os.path.join(latest, sbom.SBOM_FILE)
    if not os.path.isfile(sbom_path) or sha256_file(sbom_path) != current.get("sbom_sha256"):
        return fail([f"{sbom.SBOM_FILE} 在掃描之後被改動過或遺失。請重新掃描"])
    report = read_json(report_path)
    if report["quality"]["status"] == "invalid":
        return fail(["這次掃描無效,不接受分析。請先排除掃描的問題再重掃"])
    if not os.path.isfile(analysis_path):
        if not report.get("pending"):
            print("✓ 沒有待分析的項目")
            return 0
        return fail([f"找不到 {ANALYSIS_JSON}。請把分析結果寫到 {shown}/{ANALYSIS_JSON}"])
    if os.path.getsize(analysis_path) > MAX_BYTES:
        return fail([f"{ANALYSIS_JSON} 超過 2 MB"])
    try:
        with open(analysis_path, "r", encoding="utf-8") as fh:
            analysis = json.load(fh)
    except (OSError, ValueError) as exc:
        return fail([f"{ANALYSIS_JSON} 不是合法的 JSON:{exc}"])

    graph = sbom.SbomGraph(read_json(sbom_path))
    errors, accepted, info = validate(report, analysis, graph)
    if errors:
        return fail(errors)

    verified_at = iso(now_utc())
    store_path = os.path.join(state_dir, VERDICTS)
    store = read_json(store_path, {}) or {}
    verdicts = store.get("verdicts") or {}
    by_id = {f["finding_id"]: f for f in report["findings"]}
    for fid, verdict in accepted.items():
        verdicts[fid] = {**verdict, "basis": by_id[fid]["basis"], "scan_id": report["scan_id"], "accepted_at": verified_at, "model": info["model"]}
    write_json(store_path, {"verdicts": verdicts})

    remaining = [f["finding_id"] for f in report["findings"] if verdicts.get(f["finding_id"], {}).get("basis") != f["basis"]]
    write_atomic(os.path.join(latest, ANALYSIS_MD), render(report, verdicts, info, verified_at))
    current["pending_analysis"] = len(remaining)
    current["verified_at"] = verified_at
    write_json(os.path.join(state_dir, CURRENT), current)

    print(f"✓ 通過:這次接受 {len(accepted)} 項" + (f",尚有 {len(remaining)} 項待分析" if remaining else ",全部分析完成"))
    print(f"報告   {shown}/{ANALYSIS_MD}")
    return 0
