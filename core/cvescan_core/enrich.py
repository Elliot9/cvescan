"""Offline enrichment data: KEV, EPSS, end-of-life.

All of it is downloaded as whole files during sync and joined locally during
the scan, so no CVE id or package name ever leaves the machine.
"""

from __future__ import annotations

import csv
import gzip
import io
import os

from . import sync
from .util import read_json


def load_kev(db_dir: str) -> dict:
    """CVE id -> KEV entry. Empty when the catalog is missing."""
    data = read_json(sync.kev_path(db_dir), None)
    result = {}
    if isinstance(data, dict):
        for item in data.get("vulnerabilities") or []:
            if isinstance(item, dict) and item.get("cveID"):
                result[item["cveID"].upper()] = {
                    "date_added": item.get("dateAdded"),
                    "due_date": item.get("dueDate"),
                    "ransomware_use": item.get("knownRansomwareCampaignUse"),
                }
    return result


def load_epss(db_dir: str, cves: set[str]) -> dict:
    """CVE id -> {"score", "percentile"} for the requested CVEs only."""
    path = sync.epss_path(db_dir)
    result = {}
    if not cves or not os.path.isfile(path):
        return result
    wanted = {c.upper() for c in cves}
    try:
        with gzip.open(path, "rb") as raw:
            reader = csv.reader(io.TextIOWrapper(raw, encoding="utf-8", errors="replace"))
            for row in reader:
                if len(row) < 3 or row[0].startswith("#") or row[0] == "cve":
                    continue
                cve = row[0].upper()
                if cve in wanted:
                    try:
                        result[cve] = {"score": float(row[1]), "percentile": float(row[2])}
                    except ValueError:
                        continue
                    if len(result) == len(wanted):
                        break
    except (OSError, EOFError):
        return result
    return result


def _normalize_cycles(data) -> list[dict]:
    """Accept both endoflife.date API shapes and return [{cycle, eol, latest}]."""
    cycles = []
    if isinstance(data, dict):
        releases = (data.get("result") or {}).get("releases")
        if isinstance(releases, list):
            for release in releases:
                if not isinstance(release, dict) or release.get("name") is None:
                    continue
                latest = release.get("latest")
                eol = release.get("eolFrom")
                if eol is None and isinstance(release.get("isEol"), bool):
                    eol = release["isEol"]
                cycles.append({
                    "cycle": str(release["name"]),
                    "eol": eol,
                    "latest": latest.get("name") if isinstance(latest, dict) else latest,
                })
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("cycle") is not None:
                cycles.append({"cycle": str(item["cycle"]), "eol": item.get("eol"), "latest": item.get("latest")})
    return cycles


def load_eol(db_dir: str) -> dict:
    """product -> list of cycles. Missing products are simply absent."""
    result = {}
    for product in sync.EOL_PRODUCTS:
        cycles = _normalize_cycles(read_json(sync.eol_path(db_dir, product), None))
        if cycles:
            result[product] = cycles
    return result
