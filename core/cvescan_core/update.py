"""Update check for the tool itself.

The check only decides and reports; the wrapper applies the update. A release
is described by a small JSON manifest at a URL the user configures:

    {"version": "0.2.0", "released_at": "2026-11-20T00:00:00Z",
     "image": "registry.example/cvescan@sha256:<64 hex>",
     "min_supported": "0.1.0", "notes": "..."}

Policy:
  * a person at a terminal is asked
  * unattended runs (agent, cron) take the update without asking, but only
    once the release is older than the cool-down period
  * a version below min_supported refuses to scan until updated

Not implemented in this PoC: signature verification of the manifest and the
image. The image reference must be pinned by digest, which fixes its content
but does not prove who published it.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

from . import __version__, versions
from .util import parse_iso

_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:-]{0,200}@sha256:[0-9a-f]{64}$")


def check(cfg: dict, now) -> dict:
    url = cfg["update"]["manifest_url"]
    if not url:
        return {"status": "unconfigured"}
    try:
        request = urllib.request.Request(url, headers={"User-Agent": f"cvescan/{__version__}"})
        with urllib.request.urlopen(request, timeout=15) as response:
            data = json.loads(response.read(65536))
    except (urllib.error.URLError, OSError, ValueError):
        return {"status": "unreachable"}
    if not isinstance(data, dict):
        return {"status": "unreachable"}
    version = str(data.get("version") or "")
    image = str(data.get("image") or "")
    if not _VERSION.match(version) or not _IMAGE.match(image):
        return {"status": "unreachable"}
    if (versions.compare(version, __version__) or 0) <= 0:
        return {"status": "current"}
    minimum = str(data.get("min_supported") or "")
    required = bool(_VERSION.match(minimum) and (versions.compare(__version__, minimum) or 0) < 0)
    age_days = None
    try:
        age_days = (now - parse_iso(str(data.get("released_at")))).days
    except (ValueError, TypeError):
        pass
    cooled = age_days is not None and age_days >= cfg["update"]["cooldown_days"]
    notes = re.sub(r"[^\w\s.,:;()/+\-一-鿿]", "", str(data.get("notes") or ""))[:120]
    return {
        "status": "available",
        "version": version,
        "image": image,
        "required": required,
        "age_days": age_days,
        "unattended": bool(cfg["update"]["auto_update_unattended"] and cooled),
        "notes": notes.replace("\n", " ").strip(),
    }
