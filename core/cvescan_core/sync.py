"""DB sync: the only step that uses the network, and it never sees code.

Downloads, per ecosystem, the OSV database export, plus the KEV catalog, the
EPSS score file and end-of-life data. Each source is fetched with a
conditional request, written to a temp file, checked, then renamed, so a scan
never reads a half-written file. A manifest records what was fetched and when
each source was last confirmed current; the scan gate reads that manifest.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from . import __version__
from .lockfiles import KNOWN_ECOSYSTEMS
from .util import eprint, iso, is_tty, now_utc, read_json, write_json

MANIFEST = "manifest.json"
EOL_PRODUCTS = ("nodejs", "php", "python")
TIMEOUT = 90


def osv_path(db_dir: str, ecosystem: str) -> str:
    return os.path.join(db_dir, "osv", ecosystem, "all.zip")


def kev_path(db_dir: str) -> str:
    return os.path.join(db_dir, "kev", "kev.json")


def epss_path(db_dir: str) -> str:
    return os.path.join(db_dir, "epss", "epss.csv.gz")


def eol_path(db_dir: str, product: str) -> str:
    return os.path.join(db_dir, "eol", f"{product}.json")


def load_manifest(db_dir: str) -> dict:
    manifest = read_json(os.path.join(db_dir, MANIFEST), None)
    if not isinstance(manifest, dict):
        manifest = {}
    manifest.setdefault("schema", 1)
    manifest.setdefault("sources", {})
    return manifest


def _plan(db_dir: str, ecosystems: list[str], cfg: dict) -> list[dict]:
    sources = cfg["sources"]
    plan = []
    for ecosystem in ecosystems:
        plan.append({
            "id": f"osv:{ecosystem}",
            "label": ecosystem,
            "url": f"{sources['osv_base_url'].rstrip('/')}/{urllib.parse.quote(ecosystem)}/all.zip",
            "dest": osv_path(db_dir, ecosystem),
            "kind": "zip",
            "required": True,
        })
    plan.append({"id": "kev", "label": "KEV", "url": sources["kev_url"], "dest": kev_path(db_dir), "kind": "json", "required": False})
    plan.append({"id": "epss", "label": "EPSS", "url": sources["epss_url"], "dest": epss_path(db_dir), "kind": "gzip", "required": False})
    for product in EOL_PRODUCTS:
        plan.append({
            "id": f"eol:{product}",
            "label": f"EOL {product}",
            "url": sources["eol_url_template"].format(product=product),
            "dest": eol_path(db_dir, product),
            "kind": "json",
            "required": False,
        })
    return plan


def _validate(path: str, kind: str) -> None:
    if os.path.getsize(path) == 0:
        raise ValueError("下載到的檔案是空的")
    if kind == "zip":
        with zipfile.ZipFile(path) as archive:
            if not archive.namelist():
                raise ValueError("zip 內沒有任何檔案")
    elif kind == "json":
        with open(path, "rb") as fh:
            json.load(fh)
    elif kind == "gzip":
        with gzip.open(path, "rb") as fh:
            if not fh.read(64):
                raise ValueError("gzip 內容是空的")


class _Progress:
    def __init__(self):
        self.tty = is_tty()
        self.last = -1

    def downloading(self, label: str, done: int, total: int) -> None:
        if not self.tty or not total:
            return
        percent = min(99, done * 100 // total)
        if percent != self.last:
            self.last = percent
            print(f"\r       {label} 下載中 {percent}%   ", end="", flush=True)

    def line(self, text: str) -> None:
        prefix = "\r" if self.tty and self.last >= 0 else ""
        self.last = -1
        print(f"{prefix}       {text}          " if prefix else f"       {text}", flush=True)


def _fetch(item: dict, previous: dict | None, progress: _Progress) -> dict:
    request = urllib.request.Request(item["url"], headers={"User-Agent": f"cvescan/{__version__}"})
    have_file = os.path.isfile(item["dest"])
    if previous and have_file:
        if previous.get("etag"):
            request.add_header("If-None-Match", previous["etag"])
        if previous.get("last_modified"):
            request.add_header("If-Modified-Since", previous["last_modified"])
    os.makedirs(os.path.dirname(item["dest"]), exist_ok=True)
    tmp = item["dest"] + ".part"
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            total = int(response.headers.get("Content-Length") or 0)
            digest = hashlib.sha256()
            size = 0
            with open(tmp, "wb") as out:
                while True:
                    chunk = response.read(1 << 16)
                    if not chunk:
                        break
                    out.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
                    progress.downloading(item["label"], size, total)
            _validate(tmp, item["kind"])
            os.replace(tmp, item["dest"])
            return {
                "url": item["url"],
                "etag": response.headers.get("ETag"),
                "last_modified": response.headers.get("Last-Modified"),
                "sha256": digest.hexdigest(),
                "size": size,
                "changed": True,
            }
    except urllib.error.HTTPError as exc:
        if exc.code == 304 and previous:
            unchanged = {k: previous.get(k) for k in ("url", "etag", "last_modified", "sha256", "size")}
            unchanged["changed"] = False
            return unchanged
        raise
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def run(db_dir: str, ecosystems: list[str], cfg: dict) -> int:
    """Sync everything. Returns 0 when every required source is current."""
    unknown = [e for e in ecosystems if e not in KNOWN_ECOSYSTEMS]
    if unknown:
        eprint(f"sync 拒絕:不認得的 ecosystem {unknown}")
        return 2
    os.makedirs(db_dir, exist_ok=True)
    manifest = load_manifest(db_dir)
    progress = _Progress()
    now = iso(now_utc())
    failed_required = []
    updated, current, failed_optional = [], [], []

    for item in _plan(db_dir, sorted(set(ecosystems)), cfg):
        previous = manifest["sources"].get(item["id"])
        try:
            result = _fetch(item, previous, progress)
        except (urllib.error.URLError, OSError, ValueError, zipfile.BadZipFile) as exc:
            reason = getattr(exc, "reason", None) or exc
            entry = dict(previous or {"url": item["url"]})
            entry["error"] = f"{type(exc).__name__}: {reason}"
            entry["error_at"] = now
            manifest["sources"][item["id"]] = entry
            (failed_required if item["required"] else failed_optional).append(item["label"])
            progress.line(f"{item['label']} 同步失敗({entry['error']})")
            continue
        changed = result.pop("changed")
        entry = dict(result)
        entry["checked_at"] = now
        entry["fetched_at"] = now if changed else (previous or {}).get("fetched_at", now)
        manifest["sources"][item["id"]] = entry
        (updated if changed else current).append(item["label"])

    manifest["synced_at"] = now
    manifest["ok"] = not failed_required
    write_json(os.path.join(db_dir, MANIFEST), manifest)

    parts = []
    if updated:
        parts.append("已更新 " + "、".join(updated))
    if current:
        parts.append("已是最新 " + "、".join(current))
    if parts:
        progress.line("|".join(parts))
    if failed_optional:
        progress.line("輔助資料未更新:" + "、".join(failed_optional) + "(不影響漏洞比對,但優先序可能偏保守)")
    if failed_required:
        progress.line("漏洞資料庫同步失敗:" + "、".join(failed_required))
        return 1
    return 0
