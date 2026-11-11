"""Declared runtime versions and their end-of-life status.

Lockfile scanning does not cover the interpreter itself, which is exactly
where PHP / Node.js / Python core vulnerabilities live. This module reads the
runtime version a project declares and compares it with end-of-life data.
It only reports what the files say; the deployed version may differ.
"""

from __future__ import annotations

import json
import os
import re
import tomllib

from . import versions

PRODUCT = {"node": "nodejs", "php": "php", "python": "python"}
_EXACT = re.compile(r"^v?(\d+(?:\.\d+){0,2})$")
# Declared ranges and image tags come from project files; keep them to
# characters a version range or a tag can have, so they cannot carry prose.
_RANGE = re.compile(r"^[0-9xXvV.*^~<>=!|, -]{1,60}$")
_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")
_FROM = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)", re.I)
_TOOL_NAMES = {"nodejs": "node", "node": "node", "python": "python", "php": "php"}


def _read(path: str, limit: int = 65536) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def _precision(version: str) -> str:
    return ("major", "minor", "patch")[min(version.count("."), 2)]


def _exact(runtime: str, raw: str, source: str):
    m = _EXACT.match(raw.strip())
    if not m:
        return None
    version = m.group(1)
    return {"runtime": runtime, "declared": version, "source": source, "precision": _precision(version)}


def _range(runtime: str, raw, source: str):
    if not isinstance(raw, str) or not _RANGE.match(raw.strip()):
        return None
    return {"runtime": runtime, "declared": raw.strip(), "source": source, "precision": "range"}


def detect(tree) -> list[dict]:
    found = []

    def add(entry):
        if entry and entry not in found:
            found.append(entry)

    for rel_dir, names in sorted(tree.files_by_dir.items()):
        base = tree.abs_dirs[rel_dir]

        def rel(name):
            return f"{rel_dir}/{name}" if rel_dir else name

        for name in (".nvmrc", ".node-version"):
            if name in names:
                first = (_read(os.path.join(base, name)).strip().splitlines() or [""])[0]
                add(_exact("node", first, rel(name)))
        if ".python-version" in names:
            for line in _read(os.path.join(base, ".python-version")).splitlines():
                entry = _exact("python", line, rel(".python-version"))
                if entry:
                    add(entry)
                    break
        if ".tool-versions" in names:
            for line in _read(os.path.join(base, ".tool-versions")).splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] in _TOOL_NAMES:
                    add(_exact(_TOOL_NAMES[parts[0]], parts[1], rel(".tool-versions")))
        if "runtime.txt" in names:
            text = _read(os.path.join(base, "runtime.txt")).strip()
            if text.lower().startswith("python-"):
                add(_exact("python", text[7:], rel("runtime.txt")))
        if "composer.json" in names:
            try:
                meta = json.loads(_read(os.path.join(base, "composer.json"), 1 << 20))
                platform = ((meta.get("config") or {}).get("platform") or {}).get("php")
                entry = _exact("php", platform, rel("composer.json")) if isinstance(platform, str) else None
                add(entry or _range("php", (meta.get("require") or {}).get("php"), rel("composer.json")))
            except (ValueError, AttributeError):
                pass
        if "package.json" in names:
            try:
                meta = json.loads(_read(os.path.join(base, "package.json"), 1 << 20))
                add(_range("node", (meta.get("engines") or {}).get("node"), rel("package.json")))
            except (ValueError, AttributeError):
                pass
        if "pyproject.toml" in names:
            try:
                with open(os.path.join(base, "pyproject.toml"), "rb") as fh:
                    meta = tomllib.load(fh)
                declared = (meta.get("project") or {}).get("requires-python")
                if not declared:
                    declared = (((meta.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}).get("python")
                add(_range("python", declared, rel("pyproject.toml")))
            except (OSError, ValueError, AttributeError):
                pass

    for rel_path in sorted(tree.dockerfiles):
        for line in _read(tree.dockerfile_abs[rel_path]).splitlines():
            m = _FROM.match(line)
            if not m:
                continue
            image, _, tag = m.group(1).partition(":")
            image = image.split("@", 1)[0]
            name = image.rsplit("/", 1)[-1]
            official = image in (name, f"library/{name}", f"docker.io/library/{name}")
            if name not in ("node", "php", "python") or not official:
                continue
            tag = tag.split("@", 1)[0]
            m_tag = re.match(r"^(\d+(?:\.\d+){0,2})(?:[-_].*)?$", tag)
            if m_tag:
                version = m_tag.group(1)
                add({"runtime": name, "declared": version, "source": rel_path, "precision": _precision(version)})
            elif not tag or _TAG.match(tag):
                add({"runtime": name, "declared": tag or "latest", "source": rel_path, "precision": "floating"})
    return found


def _cycle_key(runtime: str, version: str):
    parts = version.split(".")
    if runtime == "node":
        return parts[0]
    return ".".join(parts[:2]) if len(parts) >= 2 else None


def evaluate(entries: list[dict], eol_data: dict, today: str) -> list[dict]:
    """Add status / eol_date / latest to each detected runtime."""
    result = []
    for entry in entries:
        item = dict(entry)
        item.update({"cycle": None, "status": "unknown", "eol_date": None, "latest": None})
        cycles = eol_data.get(PRODUCT[item["runtime"]])
        if item["precision"] == "range":
            item["status"] = "range"
        elif item["precision"] == "floating":
            item["status"] = "floating"
        elif cycles:
            key = _cycle_key(item["runtime"], item["declared"])
            match = next((c for c in cycles if c["cycle"] == key), None) if key else None
            if match:
                item["cycle"] = key
                item["latest"] = match.get("latest")
                eol = match.get("eol")
                if isinstance(eol, str):
                    item["eol_date"] = eol
                    is_eol = eol[:10] <= today
                else:
                    is_eol = eol is True
                if is_eol:
                    item["status"] = "eol"
                elif item["precision"] == "patch" and item["latest"] and (versions.compare(item["declared"], item["latest"]) or 0) < 0:
                    item["status"] = "behind"
                else:
                    item["status"] = "ok"
        result.append(item)
    return result
