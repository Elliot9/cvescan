"""Scan history, change attribution, and the `status` views.

Each scan appends one summary line to history.jsonl (kept forever) and
replaces index.json (the last trustworthy scan, used as the comparison base).

Changes between two scans are split by cause, because a rising count does not
mean the project got worse:
  fixed           the package was upgraded or removed
  new_advisory    the package did not change; a new advisory was published
  new_dependency  the package (or that version of it) was added
  gone            the lockfile is no longer scanned; not counted as fixed
  withdrawn       the package is unchanged but the advisory no longer applies
"""

from __future__ import annotations

import json
import os

from .util import append_line, disp_width, pad, parse_iso, read_json, to_local, write_json

HISTORY = "history.jsonl"
INDEX = "index.json"
SPARK = "▁▂▃▄▅▆▇█"
QUALITY_LABEL = {"complete": "完整", "incomplete": "不完整", "invalid": "無效"}


def component_id(input_rel: str, ecosystem: str, name: str, version: str) -> str:
    return f"{input_rel}|{ecosystem}|{name}|{version}"


def load_index(state_dir: str):
    return read_json(os.path.join(state_dir, INDEX), None)


def save_index(state_dir: str, index: dict) -> None:
    write_json(os.path.join(state_dir, INDEX), index)


def read_history(state_dir: str) -> list[dict]:
    entries = []
    try:
        with open(os.path.join(state_dir, HISTORY), "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except ValueError:
                        continue
    except FileNotFoundError:
        pass
    return entries


def append_history(state_dir: str, entry: dict) -> None:
    append_line(os.path.join(state_dir, HISTORY), json.dumps(entry, ensure_ascii=False))


def attribute(previous: dict | None, findings: dict, components: set, inputs: set) -> tuple[dict, dict]:
    """Compare with the previous trustworthy scan.

    `findings`: finding_id -> {"ecosystem", "package", "instances": [(input, version)]}
    Returns (counts, per-finding change label for findings that are new).
    """
    counts = {"initial": 0, "fixed": 0, "new_advisory": 0, "new_dependency": 0, "gone": 0, "withdrawn": 0, "unchanged": 0}
    labels = {}
    if previous is None:
        counts["initial"] = len(findings)
        for fid in findings:
            labels[fid] = "initial"
        return counts, labels

    before = previous.get("findings") or {}
    before_components = set(previous.get("components") or [])
    for fid, finding in findings.items():
        if fid in before:
            counts["unchanged"] += 1
            continue
        existed = any(
            component_id(rel, finding["ecosystem"], finding["package"], version) in before_components
            for rel, version in finding["instances"]
        )
        labels[fid] = "new_advisory" if existed else "new_dependency"
        counts[labels[fid]] += 1
    for fid, finding in before.items():
        if fid in findings:
            continue
        instances = [tuple(i) for i in finding.get("instances") or []]
        still_installed = any(
            component_id(rel, finding["ecosystem"], finding["package"], version) in components
            for rel, version in instances
        )
        if still_installed:
            counts["withdrawn"] += 1
        elif instances and all(rel not in inputs for rel, _ in instances):
            counts["gone"] += 1
        else:
            counts["fixed"] += 1
    return counts, labels


# --------------------------------------------------------------------------
# status
# --------------------------------------------------------------------------

def _table(rows: list[list[str]], aligns: list[str]) -> list[str]:
    widths = [max(disp_width(row[i]) for row in rows) for i in range(len(rows[0]))]
    return ["  ".join(pad(cell, widths[i], aligns[i]) for i, cell in enumerate(row)).rstrip() for row in rows]


def _sparkline(values: list[int]) -> str:
    if not values:
        return ""
    top = max(values) or 1
    return "".join(SPARK[min(len(SPARK) - 1, round(v * (len(SPARK) - 1) / top))] for v in values)


def _when(text: str, with_year: bool = False) -> str:
    local = to_local(parse_iso(text))
    return local.strftime("%Y-%m-%d %H:%M" if with_year else "%m-%d %H:%M")


def _version_label(entry: dict) -> str:
    version = entry.get("project_version") or {}
    return version.get("describe") or version.get("commit") or "–"


def _valid(entries: list[dict]) -> list[dict]:
    return [e for e in entries if e.get("quality") != "invalid"]


def _pending(state_dir: str, last: dict):
    """`verify` updates current.json after the scan wrote its history line."""
    current = read_json(os.path.join(state_dir, "current.json"), None) or {}
    if current.get("scan_id") == last.get("scan_id") and current.get("pending_analysis") is not None:
        return current["pending_analysis"]
    return last.get("pending_analysis")


def _row_changes(entry: dict) -> tuple:
    return tuple(entry.get(k, 0) for k in ("fixed", "new_advisory", "new_dependency", "gone", "withdrawn"))


def render_project(name: str, state_dir: str, now, cfg: dict) -> str:
    entries = read_history(state_dir)
    if not entries:
        return f"{name}:還沒有掃描紀錄。"
    valid = _valid(entries)
    last = entries[-1]
    pending = _pending(state_dir, last)
    head = f"{name}|首次掃描 {_when(entries[0]['time'], True)[:10]}|共 {len(entries)} 次"
    if pending is not None:
        head += f"|AI 分析:{'待處理 ' + str(pending) if pending else '已完成'}"
    lines = [head]

    if valid:
        series = [e.get("open", 0) for e in valid]
        if len(series) > 24:
            step = len(series) / 24
            series = [series[int(i * step)] for i in range(24)] + [series[-1]]
        lines.append(f"未解決數趨勢  {_sparkline(series)}  {valid[0].get('open', 0)} → {valid[-1].get('open', 0)}")
    lines.append("")

    # Collapse runs of scans in which nothing changed.
    groups = []
    for entry in entries:
        same = (
            groups
            and entry.get("quality") != "invalid"
            and groups[-1]["first"].get("quality") != "invalid"
            and not any(_row_changes(entry))
            and not entry.get("initial")
            and entry.get("open") == groups[-1]["last"].get("open")
            and _version_label(entry) == _version_label(groups[-1]["last"])
            and entry.get("quality") == groups[-1]["last"].get("quality")
        )
        if same:
            groups[-1]["quiet"].append(entry)
            groups[-1]["last"] = entry
        else:
            groups.append({"first": entry, "last": entry, "quiet": []})

    rows = [["時間", "專案版本", "未解決", "你修掉", "新公告", "相依變動", "不再掃到", "掃描"]]
    notes = {}
    for group in reversed(groups[-40:]):
        if group["quiet"]:
            quiet = group["quiet"]
            span = _when(quiet[0]["time"])[:5] + " ~ " + _when(quiet[-1]["time"])[:5] if len(quiet) > 1 else _when(quiet[0]["time"])
            rows.append([span, _version_label(quiet[-1]), str(quiet[-1].get("open", 0)), "", "", "", "", ""])
            notes[len(rows) - 1] = f"({len(quiet)} 次掃描,無變化)"
        entry = group["first"]
        if entry.get("quality") == "invalid":
            rows.append([_when(entry["time"]), _version_label(entry), "–", "", "", "", "", "無效"])
            notes[len(rows) - 1] = entry.get("reason") or ""
            continue
        first_scan = bool(entry.get("initial")) or entry is entries[0]
        rows.append([
            _when(entry["time"]),
            _version_label(entry),
            str(entry.get("open", 0)),
            "–" if first_scan else str(entry.get("fixed", 0)),
            "–" if first_scan else str(entry.get("new_advisory", 0)),
            "–" if first_scan else str(entry.get("new_dependency", 0)),
            "–" if first_scan else str(entry.get("gone", 0)),
            QUALITY_LABEL.get(entry.get("quality"), "?") + ("(首次)" if first_scan else ""),
        ])
    table = _table(rows, ["left", "left", "right", "right", "right", "right", "right", "left"])
    for index, text in notes.items():
        if text:
            table[index] = table[index].rstrip() + "  " + text
    lines.extend(table)
    if len(groups) > 40:
        lines.append("…")
    lines.append("")

    if valid:
        latest = valid[-1]
        severity = latest.get("by_severity") or {}
        parts = []
        if latest.get("malware"):
            parts.append(f"惡意套件 {latest['malware']}")
        for key, text in (("critical", "嚴重"), ("high", "高"), ("medium", "中"), ("low", "低"), ("unknown", "未評分")):
            if severity.get(key):
                suffix = f"(已知遭利用 {latest['kev']})" if key == "critical" and latest.get("kev") else ""
                parts.append(f"{text} {severity[key]}{suffix}")
        kev_note = f"|其中已知遭利用 {latest['kev']}" if latest.get("kev") and not severity.get("critical") else ""
        lines.append(f"目前未解決 {latest.get('open', 0)}" + (":" + "|".join(parts) if parts else "") + kev_note)
        if latest.get("oldest_open_days") is not None and latest.get("open"):
            lines.append(f"最久未修:{latest['oldest_open_days']} 天")
        window = [e for e in valid[1:] if (now - parse_iso(e["time"])).days <= 30]
        if window:
            fixed = sum(e.get("fixed", 0) for e in window)
            advisory = sum(e.get("new_advisory", 0) for e in window)
            dependency = sum(e.get("new_dependency", 0) for e in window)
            gone = sum(e.get("gone", 0) for e in window)
            text = f"近 30 天:你修掉 {fixed},新公告帶來 {advisory},相依變動帶來 {dependency}"
            if gone:
                text += f",不再掃到 {gone}(不算修掉)"
            lines.append(text)
    age_days = (now - parse_iso(last["time"])).days
    if age_days >= cfg["stale_scan_days"]:
        lines.append(f"注意:上次掃描是 {age_days} 天前,這段期間公布的新漏洞還沒有比對。")
    return "\n".join(lines)


def _trend(valid: list[dict], now) -> str:
    if len(valid) < 2:
        return "–"
    base = valid[0]
    for entry in valid:
        if (now - parse_iso(entry["time"])).days <= 30:
            break
        base = entry
    delta = valid[-1].get("open", 0) - base.get("open", 0)
    start = valid.index(base)
    if any(e.get("gone") for e in valid[start + 1:]) and delta < 0:
        # Fewer findings because less was scanned is not an improvement.
        return "? 掃描範圍縮小"
    if delta < 0:
        return f"↓ 改善中({delta})"
    if delta > 0:
        return f"↑ 增加(+{delta})"
    return "→ 持平"


def render_overview(state_root: str, now, cfg: dict) -> str:
    try:
        names = sorted(n for n in os.listdir(state_root) if os.path.isdir(os.path.join(state_root, n)))
    except FileNotFoundError:
        names = []
    rows = [["專案", "上次掃描", "未解決", "近 30 天", "待分析", "掃描"]]
    for name in names:
        entries = read_history(os.path.join(state_root, name))
        if not entries:
            continue
        last = entries[-1]
        valid = _valid(entries)
        age_days = (now - parse_iso(last["time"])).days
        when = _when(last["time"], True) if age_days else "今天 " + _when(last["time"])[6:]
        if age_days == 1:
            when = "昨天 " + _when(last["time"])[6:]
        elif age_days > 1:
            when = f"{age_days} 天前"
        stale = age_days >= cfg["stale_scan_days"]
        current = valid[-1] if valid else {}
        pending = _pending(os.path.join(state_root, name), last)
        rows.append([
            name,
            when,
            str(current.get("open", "–")),
            "? 太久沒掃" if stale else _trend(valid, now),
            "–" if pending is None else str(pending),
            QUALITY_LABEL.get(last.get("quality"), "?"),
        ])
    if len(rows) == 1:
        return "還沒有任何專案的掃描紀錄。先執行:cvescan <專案路徑>"
    return "\n".join(_table(rows, ["left", "left", "right", "left", "right", "left"]))
