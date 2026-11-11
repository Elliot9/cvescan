"""Version parsing, comparison and range checks (npm / Composer / PEP 440).

Every function here returns None when it cannot decide. Callers must treat
None as "unknown", never as True or False: an honest "don't know" is better
than a wrong "the fix is in range".
"""

from __future__ import annotations

import re
from functools import cmp_to_key

_PRE_RANK = {
    "dev": 0,
    "a": 1, "alpha": 1,
    "b": 2, "beta": 2,
    "c": 3, "rc": 3, "pre": 3, "preview": 3,
}
_RELEASE = re.compile(r"^(\d+(?:\.\d+)*)(.*)$")
_POST = re.compile(r"(?:post|rev|r|p|pl|patch)[-_.]?(\d*)")


class Version:
    __slots__ = ("release", "pre", "post", "raw")

    def __init__(self, release, pre=None, post=None, raw=""):
        self.release = tuple(release)
        self.pre = pre
        self.post = post
        self.raw = raw

    def key(self, width: int):
        rel = self.release + (0,) * (width - len(self.release))
        pre_key = (0, self.pre) if self.pre is not None else (1, ())
        post_key = self.post if self.post is not None else -1
        return (rel, pre_key, post_key)

    def padded(self, width: int):
        return self.release + (0,) * max(0, width - len(self.release))

    def __repr__(self):
        return f"Version({self.raw!r})"


def parse(text) -> Version | None:
    if isinstance(text, Version):
        return text
    if text is None:
        return None
    s = str(text).strip()
    if not s:
        return None
    if s[0] in "vV" and len(s) > 1 and s[1].isdigit():
        s = s[1:]
    s = s.split("+", 1)[0]
    if "!" in s:  # PEP 440 epoch; rare enough to ignore the epoch itself
        s = s.split("!", 1)[1]
    m = _RELEASE.match(s)
    if not m:
        return None
    release = tuple(int(p) for p in m.group(1).split("."))
    rest = m.group(2).strip().lower().lstrip("-_.")
    pre = None
    post = None
    if rest:
        mp = _POST.fullmatch(rest)
        if mp:
            post = int(mp.group(1) or 0)
        else:
            tokens = re.findall(r"\d+|[a-z]+", rest)
            if not tokens:
                return None
            pre = tuple(
                (0, int(t), "") if t.isdigit() else (1, _PRE_RANK.get(t, 4), t)
                for t in tokens
            )
    return Version(release, pre, post, str(text))


def _as_version(value) -> Version | None:
    if isinstance(value, Version):
        return value
    if isinstance(value, tuple):
        return Version(value, raw=".".join(str(x) for x in value))
    return parse(value)


def compare(a, b) -> int | None:
    """-1 / 0 / 1, or None when either side cannot be parsed."""
    va, vb = _as_version(a), _as_version(b)
    if va is None or vb is None:
        return None
    width = max(len(va.release), len(vb.release))
    ka, kb = va.key(width), vb.key(width)
    return (ka > kb) - (ka < kb)


def sort_versions(values) -> list[str]:
    """Ascending; unparseable versions keep their order at the end."""
    good = [v for v in values if parse(v) is not None]
    bad = [v for v in values if parse(v) is None]
    good.sort(key=cmp_to_key(lambda x, y: compare(x, y) or 0))
    return good + bad


def max_version(values) -> str | None:
    ordered = sort_versions([v for v in values if v])
    return ordered[-1] if ordered else None


# --------------------------------------------------------------------------
# Range checks
# --------------------------------------------------------------------------

def _ge(v, bound):
    return compare(v, bound) >= 0


def _gt(v, bound):
    return compare(v, bound) > 0


def _lt(v, bound):
    return compare(v, bound) < 0


def _le(v, bound):
    return compare(v, bound) <= 0


_PARTIAL = re.compile(
    r"^[vV]?(\d+|[xX*])"
    r"(?:\.(\d+|[xX*]))?"
    r"(?:\.(\d+|[xX*]))?"
    r"(?:\.(\d+|[xX*]))?"
    r"(?:[-+_.]?([0-9A-Za-z][0-9A-Za-z.+_-]*))?$"
)


def _parse_partial(text: str):
    """'1.2.x' -> ([1, 2, None], None). Returns None when not a version."""
    m = _PARTIAL.match(text.strip())
    if not m:
        return None
    parts = []
    for raw in m.groups()[:4]:
        if raw is None:
            break
        parts.append(None if raw in ("x", "X", "*") else int(raw))
    # a wildcard makes everything after it a wildcard too
    for i, value in enumerate(parts):
        if value is None:
            parts = parts[:i] + [None] * (len(parts) - i)
            break
    return parts, m.group(5)


def _exact(parts, suffix):
    text = ".".join(str(p) for p in parts) + (f"-{suffix}" if suffix else "")
    return parse(text)


def _caret_upper(major, minor, patch):
    if major > 0 or minor is None:
        return (major + 1, 0, 0)
    if minor > 0 or patch is None:
        return (0, minor + 1, 0)
    return (0, 0, patch + 1)


def _npm_comparator(v: Version, token: str):
    m = re.match(r"^(\^|~>?|>=|<=|>|<|=)?\s*(.*)$", token)
    op, body = (m.group(1) or ""), m.group(2).strip()
    if body in ("", "*", "x", "X"):
        return True
    parsed = _parse_partial(body)
    if parsed is None:
        return None
    parts, suffix = parsed
    major = parts[0]
    minor = parts[1] if len(parts) > 1 else None
    patch = parts[2] if len(parts) > 2 else None
    if major is None:
        return True
    low = (major, minor or 0, patch or 0)
    full = minor is not None and patch is not None
    exact = _exact(low, suffix) if full else None
    floor = exact if exact is not None else low

    if op == "^":
        return _ge(v, floor) and _lt(v, _caret_upper(major, minor, patch))
    if op in ("~", "~>"):
        upper = (major + 1, 0, 0) if minor is None else (major, minor + 1, 0)
        return _ge(v, floor) and _lt(v, upper)
    if op in ("", "="):
        if minor is None:
            return _ge(v, (major, 0, 0)) and _lt(v, (major + 1, 0, 0))
        if patch is None:
            return _ge(v, (major, minor, 0)) and _lt(v, (major, minor + 1, 0))
        return compare(v, exact) == 0
    if op == ">=":
        return _ge(v, floor)
    if op == ">":
        if minor is None:
            return _ge(v, (major + 1, 0, 0))
        if patch is None:
            return _ge(v, (major, minor + 1, 0))
        return _gt(v, exact)
    if op == "<":
        return _lt(v, floor)
    if op == "<=":
        if minor is None:
            return _lt(v, (major + 1, 0, 0))
        if patch is None:
            return _lt(v, (major, minor + 1, 0))
        return _le(v, exact)
    return None


_NON_REGISTRY = re.compile(
    r"^(npm:|file:|link:|portal:|patch:|workspace:|git[+:@]|github:|gitlab:|bitbucket:|https?:|[\w.-]+/[\w.-]+(#.*)?$)"
)
_HYPHEN = re.compile(r"^\s*(\S+)\s+-\s+(\S+)\s*$")


def _and_set(v: Version, text: str, comparator):
    text = text.strip()
    if text in ("", "*"):
        return True
    hyphen = _HYPHEN.match(text)
    if hyphen:
        low = comparator(v, ">=" + hyphen.group(1))
        high = comparator(v, "<=" + hyphen.group(2))
        if low is None or high is None:
            return None
        return low and high
    text = re.sub(r"(>=|<=|<>|!=|==|>|<|=|\^|~>?)\s+", r"\1", text)
    for token in re.split(r"[\s,]+", text):
        if not token:
            continue
        result = comparator(v, token)
        if result is None:
            return None
        if not result:
            return False
    return True


def npm_satisfies(version, range_text):
    v = parse(version)
    if v is None or range_text is None:
        return None
    text = str(range_text).strip()
    if text in ("", "*", "x", "X", "latest"):
        return True
    if _NON_REGISTRY.match(text):
        return None
    for alternative in re.split(r"\s*\|\|\s*", text):
        result = _and_set(v, alternative, _npm_comparator)
        if result is None:
            return None
        if result:
            return True
    return False


def _composer_comparator(v: Version, token: str):
    token = re.sub(r"@(dev|alpha|beta|rc|stable)$", "", token.strip(), flags=re.I)
    lowered = token.lower()
    if lowered.startswith("dev-") or lowered.endswith("-dev") or "x-dev" in lowered:
        return None
    m = re.match(r"^(\^|~|>=|<=|<>|!=|==|>|<|=)?\s*(.*)$", token)
    op, body = (m.group(1) or ""), m.group(2).strip()
    if body in ("", "*"):
        return True
    parsed = _parse_partial(body)
    if parsed is None:
        return None
    parts, suffix = parsed
    if parts[0] is None:
        return True
    given = [p for p in parts if p is not None]
    wildcard = len(given) < len(parts)
    low = tuple(given) + (0,) * (3 - len(given)) if len(given) < 3 else tuple(given)
    exact = _exact(low, suffix) if not wildcard else None
    floor = exact if exact is not None else low

    if op == "^":
        major = given[0]
        minor = given[1] if len(given) > 1 else None
        patch = given[2] if len(given) > 2 else None
        return _ge(v, floor) and _lt(v, _caret_upper(major, minor, patch))
    if op == "~":
        if len(given) == 1:
            upper = (given[0] + 1, 0, 0)
        else:
            head = list(given[:-1])
            head[-1] += 1
            upper = tuple(head) + (0,)
        return _ge(v, floor) and _lt(v, upper)
    if wildcard:
        head = list(given)
        head[-1] += 1
        matched = _ge(v, tuple(given)) and _lt(v, tuple(head))
        return (not matched) if op in ("!=", "<>") else matched
    if op in ("", "=", "=="):
        return compare(v, exact) == 0
    if op in ("!=", "<>"):
        return compare(v, exact) != 0
    if op == ">=":
        return _ge(v, floor)
    if op == ">":
        return _gt(v, floor)
    if op == "<":
        return _lt(v, floor)
    if op == "<=":
        return _le(v, floor)
    return None


def composer_satisfies(version, constraint):
    v = parse(version)
    if v is None or constraint is None:
        return None
    text = str(constraint).strip()
    if text in ("", "*"):
        return True
    if " as " in text:
        text = text.split(" as ", 1)[0].strip()
    for alternative in re.split(r"\s*\|\|?\s*", text):
        result = _and_set(v, alternative, _composer_comparator)
        if result is None:
            return None
        if result:
            return True
    return False


def _pep440_clause(v: Version, clause: str):
    m = re.match(r"^(~=|===|==|!=|>=|<=|>|<|\^|~)?\s*(.+)$", clause)
    if not m:
        return None
    op, body = (m.group(1) or "=="), m.group(2).strip()
    if op in ("^", "~"):
        return _npm_comparator(v, op + body)
    if body.endswith(".*"):
        if op not in ("==", "!="):
            return None
        head = body[:-2]
        if not re.fullmatch(r"\d+(\.\d+)*", head):
            return None
        prefix = tuple(int(x) for x in head.split("."))
        matched = v.padded(len(prefix))[: len(prefix)] == prefix
        return matched if op == "==" else not matched
    c = compare(v, body)
    if c is None:
        return None
    if op in ("==", "==="):
        return c == 0
    if op == "!=":
        return c != 0
    if op == ">=":
        return c >= 0
    if op == "<=":
        return c <= 0
    if op == ">":
        return c > 0
    if op == "<":
        return c < 0
    if op == "~=":
        base = parse(body)
        if base is None or len(base.release) < 2:
            return None
        prefix = base.release[:-1]
        return c >= 0 and v.padded(len(prefix))[: len(prefix)] == prefix
    return None


def pep440_satisfies(version, specifier):
    v = parse(version)
    if v is None or specifier is None:
        return None
    text = str(specifier).strip()
    if text in ("", "*"):
        return True
    for alternative in re.split(r"\s*\|\|?\s*", text):
        ok = True
        for clause in (c.strip() for c in alternative.split(",")):
            if not clause:
                continue
            result = _pep440_clause(v, clause)
            if result is None:
                return None
            if not result:
                ok = False
                break
        if ok:
            return True
    return False


def satisfies(ecosystem: str, version, range_text):
    """Does `version` satisfy the parent's requirement? True / False / None."""
    if range_text is None:
        return None
    if ecosystem == "npm":
        return npm_satisfies(version, range_text)
    if ecosystem == "Packagist":
        return composer_satisfies(version, range_text)
    if ecosystem == "PyPI":
        return pep440_satisfies(version, range_text)
    return None


# --------------------------------------------------------------------------
# Picking a fixed version out of OSV "affected" ranges
# --------------------------------------------------------------------------

def select_fix(current: str, ranges: list[list[dict]]):
    """Return (recommended, fixed_versions).

    `ranges` is a list of OSV event lists, e.g.
    [[{"introduced": "0"}, {"fixed": "4.17.21"}], ...].
    The recommended fix is the `fixed` bound of the interval that contains
    `current`; when no interval matches, the smallest fixed version above it.
    """
    in_interval = None
    candidates = []
    for events in ranges:
        introduced = None
        for event in events:
            if "introduced" in event:
                introduced = event["introduced"]
            elif "fixed" in event:
                fixed = event["fixed"]
                above = compare(fixed, current)
                if above is None or above > 0:
                    candidates.append(fixed)
                lower_ok = introduced in (None, "0") or (compare(current, introduced) or 0) >= 0
                if lower_ok and above is not None and above > 0 and in_interval is None:
                    in_interval = fixed
                introduced = None
            elif "last_affected" in event or "limit" in event:
                introduced = None
    fixed_versions = sort_versions(sorted(set(candidates)))
    recommended = in_interval or (fixed_versions[0] if fixed_versions else None)
    return recommended, fixed_versions
