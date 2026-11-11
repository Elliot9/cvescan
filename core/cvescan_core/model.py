"""Shared vocabulary: priorities, severities, file names."""

from __future__ import annotations

SCHEMA_VERSION = "1"

# Most urgent first. The AI may move a finding left (more urgent) freely;
# moving it right needs user-supplied context and is checked by `verify`.
PRIORITIES = ["now", "soon", "scheduled", "watch"]
PRIORITY_LABEL = {"now": "立即", "soon": "本週", "scheduled": "排程", "watch": "觀察"}
SEVERITY_LABEL = {
    "critical": "嚴重", "high": "高", "medium": "中", "low": "低",
    "unknown": "未評分", "malware": "惡意套件",
}
QUALITY_LABEL = {"complete": "完整", "incomplete": "不完整", "invalid": "無效"}

# VEX vocabulary for the AI's verdict.
STATUSES = ["affected", "under_investigation", "not_affected"]
STATUS_LABEL = {"affected": "受影響", "under_investigation": "待確認", "not_affected": "不受影響"}
JUSTIFICATIONS = [
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
]
ACTION_TYPES = ["upgrade", "remove", "mitigate", "none"]

REPORT_JSON = "report.json"
REPORT_MD = "report.md"
ANALYZE_MD = "ANALYZE.md"
ANALYSIS_JSON = "analysis.json"
ANALYSIS_MD = "analysis.md"
ANALYSIS_SCHEMA = "analysis.schema.json"

# Files in the project's state directory (outside the report folder).
CURRENT = "current.json"
VERDICTS = "verdicts.json"

CONTEXT_FILE = ".cvescan.toml"
CONTEXT_KEYS = {
    "internet_facing": bool,
    "handles_untrusted_input": bool,
    "environment": ("production", "internal", "development"),
}


def priority_rank(priority: str) -> int:
    return PRIORITIES.index(priority)
