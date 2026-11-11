#!/usr/bin/env python3
"""Stand-in for the AI in tests: reads report.json and writes analysis.json.

Usage: fake_ai.py <report folder> good|bad|partial|lower

`good` behaves the way ANALYZE.md asks. `bad` breaks one rule per finding so
the test can check that `cvescan verify` catches each of them.
"""

import json
import os
import sys


def verdict_for(finding: dict) -> dict:
    instance = finding["instances"][0]
    paths = [i["path"] for i in instance["introduced_by"]][:1]
    entry = {
        "finding_id": finding["finding_id"],
        "status": "affected",
        "priority": finding["baseline_priority"],
        "justification": None,
        "context_refs": [],
        "rationale": f"安裝的版本落在 {finding['primary_id']} 的受影響範圍內,沒有可以排除它的依據。",
        "cited_paths": paths,
        "questions": [],
    }
    if finding["lane"] == "malware":
        entry["action"] = {"type": "remove"}
        entry["rationale"] = "已通報為惡意套件,安裝過它的機器與 CI 都應視為已外洩。"
    elif instance["recommended_fix"]:
        entry["action"] = {"type": "upgrade", "target_version": instance["recommended_fix"]}
    else:
        entry["status"] = "under_investigation"
        entry["action"] = {"type": "none"}
        entry["rationale"] = "目前沒有修補版,是否受影響取決於有沒有用到公告描述的功能。"
        entry["questions"] = [{"text": f"專案有直接呼叫 {finding['package']} 嗎?", "options": ["是", "否", "不確定"]}]
    return entry


def main() -> int:
    folder, mode = sys.argv[1], sys.argv[2]
    with open(os.path.join(folder, "report.json"), encoding="utf-8") as fh:
        report = json.load(fh)
    by_id = {f["finding_id"]: f for f in report["findings"]}
    pending = [by_id[i] for i in report["pending"]]
    entries = [verdict_for(f) for f in pending]
    analysis = {
        "schema_version": "1",
        "scan_id": report["scan_id"],
        "model": "fake-ai (test)",
        "summary": "先處理惡意套件與已知遭利用的項目,其餘依優先序排入。",
        "findings": entries,
    }

    if mode == "good":
        # Raise one ordinary finding, the way an AI is allowed to.
        for entry in entries:
            finding = by_id[entry["finding_id"]]
            if finding["lane"] != "malware" and finding["baseline_priority"] == "scheduled":
                entry["priority"] = "soon"
                entry["rationale"] += "正式環境的直接相依,修補成本低,建議提前。"
                break
    elif mode == "partial":
        analysis["partial"] = True
        analysis["findings"] = entries[:1]
    elif mode == "bad":
        vulns = [e for e in entries if by_id[e["finding_id"]]["lane"] != "malware"]
        malware = [e for e in entries if by_id[e["finding_id"]]["lane"] == "malware"]
        # 1. one pending finding is left out
        dropped = vulns.pop()
        entries.remove(dropped)
        # 2. an id that is not in the report
        vulns[0]["rationale"] += "另外也受 CVE-2099-12345 影響。"
        # 3. malware "fixed" by upgrading
        for entry in malware:
            entry["action"] = {"type": "upgrade", "target_version": "9.9.9"}
        # 4. priority lowered with no context
        for entry in vulns:
            if entry["priority"] == "scheduled":
                entry["priority"] = "watch"
                break
        # 5. a target version the report does not list
        vulns[1]["action"] = {"type": "upgrade", "target_version": "99.0.0"}
        # 6. a dependency path that does not exist
        vulns[1]["cited_paths"] = [[report["inputs"][0]["root_label"], "express@4.17.1", "lodash@4.17.15"]]
        # 7. a link that is not in the report
        vulns[2]["rationale"] += "修法見 https://evil.example/fix 。"
        # 8. "not affected" on the AI's own say-so
        vulns[2]["status"] = "not_affected"
        vulns[2]["action"] = {"type": "none"}
    elif mode == "lower":
        # Lowering is allowed only by citing user-supplied context.
        entries[0]["priority"] = "watch"
        entries[0]["context_refs"] = ["internet_facing"]
        entries[0]["rationale"] += "服務不對外,排到觀察。"
        if len(entries) > 1:
            entries[1]["status"] = "not_affected"
            entries[1]["justification"] = "vulnerable_code_cannot_be_controlled_by_adversary"
            entries[1]["context_refs"] = ["internet_facing"]
            entries[1]["action"] = {"type": "none"}
            entries[1]["cited_paths"] = []
    else:
        print(f"unknown mode {mode}")
        return 2

    with open(os.path.join(folder, "analysis.json"), "w", encoding="utf-8") as fh:
        json.dump(analysis, fh, ensure_ascii=False, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
