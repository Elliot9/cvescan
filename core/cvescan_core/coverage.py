"""Blind spots: what this scan could not see.

"0 findings" only means something when the scan covered everything. Each
blind spot listed here downgrades the scan from "complete" to "incomplete".
Notes are things every reader should know but that do not change the status.
"""

from __future__ import annotations

import json
import os
import re
import tomllib

_NPM_LOCKS = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"}
_PY_LOCKS = {"poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "pylock.toml"}
_REQ = re.compile(r"(?:.*[-_.])?requirements(?:[-_.].*)?\.txt")
_PIN = re.compile(r"(===?[^=]|\s@\s)")


def _ancestors(rel_dir: str):
    current = rel_dir
    while True:
        yield current
        if not current:
            return
        current = current.rsplit("/", 1)[0] if "/" in current else ""


def _has(tree, rel_dir: str, names: set, ancestors: bool = False) -> bool:
    dirs = _ancestors(rel_dir) if ancestors else (rel_dir,)
    return any(tree.files_by_dir.get(d, set()) & names for d in dirs)


def _has_requirements(tree, rel_dir: str) -> bool:
    return any(_REQ.fullmatch(name) for name in tree.files_by_dir.get(rel_dir, set()))


def _load_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _load_toml(path: str) -> dict:
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except (OSError, ValueError):
        return {}


def unpinned_lines(path: str) -> int:
    """Requirement lines without an exact pin; those hide transitive packages."""
    count = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.split(" #", 1)[0].strip()
                if not line or line.startswith(("#", "-")):
                    continue
                if not _PIN.search(line + " "):
                    count += 1
    except OSError:
        return 0
    return count


def analyze(tree, unreadable: list[str], empty: list[str], graph_notes: list[tuple]) -> dict:
    blind = []
    notes = []

    def spot(kind, path, detail):
        blind.append({"kind": kind, "path": path, "detail": detail})

    for rel_dir, names in sorted(tree.files_by_dir.items()):
        base = tree.abs_dirs[rel_dir]

        def rel(name):
            return f"{rel_dir}/{name}" if rel_dir else name

        if "package.json" in names and not _has(tree, rel_dir, _NPM_LOCKS, ancestors=True):
            meta = _load_json(os.path.join(base, "package.json"))
            if any(meta.get(k) for k in ("dependencies", "devDependencies", "optionalDependencies")):
                spot("manifest_without_lockfile", rel("package.json"), "有宣告相依套件但找不到 lockfile,這些套件沒有被掃描")
        if "composer.json" in names and "composer.lock" not in names:
            meta = _load_json(os.path.join(base, "composer.json"))
            requires = {k for section in ("require", "require-dev") for k in (meta.get(section) or {})}
            if any(not (k == "php" or k.startswith(("ext-", "lib-"))) for k in requires):
                spot("manifest_without_lockfile", rel("composer.json"), "有宣告相依套件但找不到 composer.lock,這些套件沒有被掃描")
        if "Pipfile" in names and "Pipfile.lock" not in names:
            spot("manifest_without_lockfile", rel("Pipfile"), "找不到 Pipfile.lock,這些套件沒有被掃描")
        if "pyproject.toml" in names and not _has(tree, rel_dir, _PY_LOCKS, ancestors=True) and not _has_requirements(tree, rel_dir):
            meta = _load_toml(os.path.join(base, "pyproject.toml"))
            project = meta.get("project") or {}
            poetry = ((meta.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
            if project.get("dependencies") or any(k.lower() != "python" for k in poetry):
                spot("manifest_without_lockfile", rel("pyproject.toml"), "有宣告相依套件但找不到 lockfile,這些套件沒有被掃描")
        for name in ("setup.py", "setup.cfg", "requirements.in"):
            if name in names and not _has(tree, rel_dir, _PY_LOCKS) and not _has_requirements(tree, rel_dir) and "pyproject.toml" not in names:
                spot("manifest_without_lockfile", rel(name), "找不到對應的 lockfile 或 requirements.txt,這些套件沒有被掃描")
                break
        if "Gemfile" in names and not (names & {"Gemfile.lock", "gems.locked"}):
            spot("manifest_without_lockfile", rel("Gemfile"), "找不到 Gemfile.lock,這些套件沒有被掃描")
        if "Cargo.toml" in names and not _has(tree, rel_dir, {"Cargo.lock"}, ancestors=True):
            spot("manifest_without_lockfile", rel("Cargo.toml"), "找不到 Cargo.lock,這些套件沒有被掃描")

    for lockfile in tree.lockfiles:
        if lockfile.ecosystem == "PyPI" and lockfile.name.endswith(".txt"):
            loose = unpinned_lines(lockfile.path)
            if loose:
                spot("unpinned_requirements", lockfile.rel, f"有 {loose} 行沒有鎖定確切版本,實際安裝的版本與其間接相依無法判定")
    for rel_path in unreadable:
        spot("lockfile_unreadable", rel_path, "scanner 無法解析這個檔案,內容沒有被掃描")
    if tree.truncated:
        spot("walk_truncated", "", "目錄層數超過上限,較深的目錄沒有被掃描")
    if not tree.lockfiles:
        spot("no_lockfiles", "", "整個專案找不到任何 lockfile")

    for rel_path in empty:
        notes.append({"kind": "lockfile_empty", "path": rel_path, "detail": "檔案內沒有任何套件"})
    for entry in graph_notes:
        kind = entry[2] if len(entry) > 2 else "graph_unknown"
        notes.append({"kind": kind, "path": entry[0], "detail": entry[1]})
    if tree.dockerfiles:
        shown = "、".join(tree.dockerfiles[:3]) + (" 等" if len(tree.dockerfiles) > 3 else "")
        notes.append({"kind": "os_layer_not_scanned", "path": tree.dockerfiles[0], "detail": f"偵測到 {shown}:基底映像與 OS 套件不在掃描範圍"})
    if tree.vendored_js:
        notes.append({"kind": "vendored_files", "path": tree.vendored_js[0], "detail": f"偵測到 {len(tree.vendored_js)} 個 .min.js,手動複製進來的函式庫無法比對"})
    notes.append({"kind": "no_reachability", "path": "", "detail": "未做可達性分析:報表無法判斷有漏洞的程式碼是否真的被呼叫"})
    return {"blind_spots": blind, "notes": notes}
