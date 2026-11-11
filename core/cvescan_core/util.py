"""Small shared helpers: time, hashing, JSON, terminal width."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
import unicodedata
from datetime import datetime, timedelta, timezone

ISO_FMT = "%Y-%m-%dT%H:%M:%SZ"


def now_utc() -> datetime:
    """Current time in UTC.

    CVESCAN_NOW is a test hook (ISO timestamp). The Docker wrapper never
    forwards it into the container, so it only works in native dev mode.
    """
    override = os.environ.get("CVESCAN_NOW")
    if override:
        return parse_iso(override)
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(ISO_FMT)


def parse_iso(text: str) -> datetime:
    text = text.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def local_tz() -> timezone:
    """Display timezone, passed by the wrapper as CVESCAN_TZ_OFFSET (+0800)."""
    raw = os.environ.get("CVESCAN_TZ_OFFSET", "")
    m = re.fullmatch(r"([+-])(\d{2})(\d{2})", raw)
    if not m:
        return timezone.utc
    sign = 1 if m.group(1) == "+" else -1
    return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3))))


def to_local(dt: datetime) -> datetime:
    return dt.astimezone(local_tz())


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def dump_json(obj) -> str:
    """Stable, human-diffable JSON (key order is the insertion order)."""
    return json.dumps(obj, ensure_ascii=False, indent=2) + "\n"


def canonical_json(obj) -> str:
    """Canonical form used only for fingerprints."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def read_json(path: str, default=None):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return default


def write_atomic(path: str, data) -> None:
    """Write via a temp file in the same directory, then rename."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    mode = "wb" if isinstance(data, (bytes, bytearray)) else "w"
    kwargs = {} if mode == "wb" else {"encoding": "utf-8"}
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, mode, **kwargs) as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_json(path: str, obj) -> None:
    write_atomic(path, dump_json(obj))


def append_line(path: str, line: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line.rstrip("\n") + "\n")


def disp_width(text: str) -> int:
    """Terminal cell width; CJK wide characters count as two cells."""
    width = 0
    for ch in text:
        if unicodedata.combining(ch):
            continue
        width += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return width


def pad(text: str, width: int, align: str = "left") -> str:
    gap = max(0, width - disp_width(text))
    return (" " * gap + text) if align == "right" else (text + " " * gap)


def truncate(text: str, limit: int) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def md_inline(text) -> str:
    """Make untrusted text safe to drop into one Markdown line: no line
    breaks (so it cannot start a heading or a list) and no raw HTML."""
    return " ".join(str(text or "").split()).replace("<", "&lt;")


def is_tty() -> bool:
    return sys.stdout.isatty() and os.environ.get("CVESCAN_PLAIN") != "1"


def eprint(*args) -> None:
    print(*args, file=sys.stderr, flush=True)


class Refusal(Exception):
    """A gate refused to continue (stale DB, nested paths, ...). Exit code 2."""


class Invalid(Exception):
    """The scan ran but its result cannot be trusted. Exit code 3."""
