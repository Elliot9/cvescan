"""Lockfile discovery and dependency graphs.

osv-scanner extracts a flat package list from many lockfile formats, but it
does not export who depends on whom. The graphs are built here, and only for
formats that actually record that information. Anything else is reported as
"unknown" and never guessed.
"""

from __future__ import annotations

import fnmatch
import glob
import json
import os
import re
import tomllib
from collections import deque
from dataclasses import dataclass, field

ROOT = ("<root>", "")

# Directories that are never walked: dependency installs, VCS data, build output.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor",
    ".venv", "venv", ".tox", "__pycache__", ".mypy_cache", ".pytest_cache",
    "target", "dist", "build", ".terraform", ".cvescan", ".idea", ".vscode",
}
MAX_DEPTH = 12

# filename -> OSV ecosystem. Only names osv-scanner recognises on its own.
LOCKFILES = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "bun.lock": "npm",
    "composer.lock": "Packagist",
    "poetry.lock": "PyPI",
    "uv.lock": "PyPI",
    "Pipfile.lock": "PyPI",
    "pdm.lock": "PyPI",
    "pylock.toml": "PyPI",
    "requirements.txt": "PyPI",
    "go.mod": "Go",
    "Cargo.lock": "crates.io",
    "Gemfile.lock": "RubyGems",
    "gems.locked": "RubyGems",
    "pom.xml": "Maven",
    "gradle.lockfile": "Maven",
    "buildscript-gradle.lockfile": "Maven",
    "packages.lock.json": "NuGet",
    "mix.lock": "Hex",
    "pubspec.lock": "Pub",
    "conan.lock": "ConanCenter",
    "renv.lock": "CRAN",
}
_REQUIREMENTS = re.compile(r"(?:.*[-_.])?requirements(?:[-_.].*)?\.txt")

# Ecosystems the wrapper is allowed to pass from `detect` to `sync`.
KNOWN_ECOSYSTEMS = sorted(set(LOCKFILES.values()))

# Files that matter for blind-spot and runtime detection.
MANIFESTS = {
    "package.json", "composer.json", "pyproject.toml", "Pipfile", "setup.py",
    "setup.cfg", "requirements.in", "Gemfile", "Cargo.toml", "build.gradle",
    "build.gradle.kts",
}
RUNTIME_FILES = {".nvmrc", ".node-version", ".python-version", ".tool-versions", "runtime.txt"}


# Everything read from a project is untrusted, and names, versions,
# requirement strings and paths all end up in files an AI reads. They are
# checked against narrow character sets so none of them can carry a sentence.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9._~@/:+-]{0,213}$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~:!*-]{0,99}$")
_SAFE_REQ_SPACED = re.compile(r"^[0-9xXvV.*^~<>=!|,@ -]{1,100}$")
_SAFE_REQ_COMPACT = re.compile(r"^[A-Za-z0-9.*^~<>=!|,@:/+_#-]{1,100}$")
_UNSAFE_PATH_CHAR = re.compile(r"[^\w./@+~-]")


def safe_name(name) -> bool:
    return isinstance(name, str) and bool(_SAFE_NAME.match(name))


def safe_version(version) -> bool:
    return isinstance(version, (str, int, float)) and bool(_SAFE_VERSION.match(str(version)))


_SAFE_RELPATH = re.compile(r"^[A-Za-z0-9@._-]+(?:/[A-Za-z0-9@._-]+){0,11}$")


def safe_relpath(text) -> bool:
    """A plain relative directory: no spaces, no '..', nothing that could read as prose."""
    return isinstance(text, str) and len(text) <= 200 and bool(_SAFE_RELPATH.match(text)) and ".." not in text.split("/")


def safe_requirement(requires):
    """A version requirement, or None when it is not plainly one."""
    if not isinstance(requires, str):
        return None
    text = requires.strip()
    if _SAFE_REQ_SPACED.match(text) or (" " not in text and _SAFE_REQ_COMPACT.match(text)):
        return text
    return None


def _shown(text: str, used: set) -> str:
    """Display form of a path: unusual characters become '_', kept unique."""
    base = _UNSAFE_PATH_CHAR.sub("_", text)[:200]
    candidate, n = base, 2
    while candidate in used:
        candidate, n = f"{base}~{n}", n + 1
    used.add(candidate)
    return candidate


@dataclass
class Lockfile:
    path: str        # real absolute path, only ever used to open the file
    rel: str         # display path, safe to put in reports
    name: str
    ecosystem: str

    @property
    def osv_arg(self) -> str:
        """Argument for `osv-scanner -L`; non-standard names need a parser hint."""
        if self.name in LOCKFILES:
            return self.path
        return f"requirements.txt:{self.path}"


@dataclass
class Tree:
    """What the walker saw, for blind-spot and runtime detection."""
    root: str
    lockfiles: list = field(default_factory=list)
    files_by_dir: dict = field(default_factory=dict)   # display dir -> set of file names
    abs_dirs: dict = field(default_factory=dict)       # display dir -> real absolute dir
    dockerfiles: list = field(default_factory=list)    # display paths
    dockerfile_abs: dict = field(default_factory=dict)
    vendored_js: list = field(default_factory=list)
    excluded: list = field(default_factory=list)       # display paths the user's exclude patterns removed
    truncated: bool = False


_EXCLUDE_PATTERN = re.compile(r"[A-Za-z0-9@._*?+-]+(?:/[A-Za-z0-9@._*?+-]+)*/?")
MAX_EXCLUDED_SHOWN = 50


def exclude_pattern(text: str) -> str:
    """A user-supplied exclude pattern, limited to characters safe to print in a report."""
    if not _EXCLUDE_PATTERN.fullmatch(text):
        raise ValueError(f"invalid exclude pattern: {text!r}")
    return text.rstrip("/")


def _excluded(rel: str, patterns) -> bool:
    """A pattern with a slash matches the path from the project root, one without matches a name at any depth."""
    name = rel.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatchcase(rel if "/" in pattern else name, pattern) for pattern in patterns)


def discover(root: str, exclude=()) -> Tree:
    root = os.path.abspath(root)
    tree = Tree(root=root)
    used_dirs, used_files = {""}, set()
    shown_dir = {root: ""}

    def skip(real_rel: str) -> bool:
        if not _excluded(real_rel, exclude):
            return False
        if len(tree.excluded) < MAX_EXCLUDED_SHOWN:
            tree.excluded.append(_UNSAFE_PATH_CHAR.sub("_", real_rel)[:200])
        return True

    for current, dirs, files in os.walk(root, followlinks=False):
        rel_dir = shown_dir[current]
        real_dir = "" if current == root else os.path.relpath(current, root).replace(os.sep, "/")
        depth = 0 if not rel_dir else rel_dir.count("/") + 1
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not os.path.islink(os.path.join(current, d)))
        dirs[:] = [d for d in dirs if not skip(f"{real_dir}/{d}" if real_dir else d)]
        if depth >= MAX_DEPTH:
            dirs[:] = []
            tree.truncated = True
        for child in dirs:
            shown_dir[os.path.join(current, child)] = _shown(f"{rel_dir}/{child}" if rel_dir else child, used_dirs)
        interesting = set()
        for name in sorted(files):
            full = os.path.join(current, name)
            known = name in LOCKFILES or name in MANIFESTS or name in RUNTIME_FILES
            is_requirements = bool(_REQUIREMENTS.fullmatch(name))
            is_dockerfile = name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile")
            if not (known or is_requirements or is_dockerfile or name.endswith(".min.js")):
                continue
            if skip(f"{real_dir}/{name}" if real_dir else name):
                continue
            rel = _shown(f"{rel_dir}/{name}" if rel_dir else name, used_files)
            ecosystem = LOCKFILES.get(name)
            if ecosystem is None and _REQUIREMENTS.fullmatch(name):
                ecosystem = "PyPI"
            if ecosystem and os.path.isfile(full) and not os.path.islink(full):
                tree.lockfiles.append(Lockfile(full, rel, name, ecosystem))
                interesting.add(name)
            elif name in MANIFESTS or name in RUNTIME_FILES:
                interesting.add(name)
            elif is_dockerfile:
                tree.dockerfiles.append(rel)
                tree.dockerfile_abs[rel] = full
            elif name.endswith(".min.js") and len(tree.vendored_js) < 200:
                tree.vendored_js.append(rel)
        if interesting:
            tree.files_by_dir[rel_dir] = interesting
            tree.abs_dirs[rel_dir] = current
    tree.lockfiles.sort(key=lambda lf: lf.rel)
    tree.dockerfiles.sort()
    return tree


# --------------------------------------------------------------------------
# Naming
# --------------------------------------------------------------------------

def norm_name(ecosystem: str, name: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "Packagist":
        return name.lower()
    return name


def norm_version(ecosystem: str, version) -> str:
    text = str(version)
    if ecosystem == "Packagist" and len(text) > 1 and text[0] in "vV" and text[1].isdigit():
        return text[1:]
    return text


def node_key(ecosystem: str, name: str, version) -> tuple:
    return (norm_name(ecosystem, name), norm_version(ecosystem, version))


def label(key: tuple) -> str:
    return f"{key[0]}@{key[1]}" if key != ROOT else "<root>"


# --------------------------------------------------------------------------
# Graph
# --------------------------------------------------------------------------

class Graph:
    """Dependency graph of one lockfile."""

    def __init__(self, ecosystem: str, status: str = "complete", note: str = ""):
        self.ecosystem = ecosystem
        self.status = status          # complete | unknown
        self.note = note
        self.root_name = ""
        self.nodes: dict = {}         # key -> display name
        self.edges: dict = {}         # key -> [(child key, requires)]
        self.roots: list = []         # [(child key, requires, scope)]
        self.first_party: set = set() # keys of workspace members (the project's own packages)
        self.declared_in: dict = {}   # key -> set of workspace member directories that declare it
        self._scope: dict = {}
        self._pred: dict = {}
        self._parents: dict = {}
        self._finished = False

    def add_node(self, name: str, version):
        """Returns the node key, or None for a name or version that is not plainly one."""
        if not safe_name(name) or not safe_version(version):
            return None
        key = node_key(self.ecosystem, name, version)
        self.nodes.setdefault(key, name)
        return key

    def add_edge(self, parent, child, requires) -> None:
        if parent is None or child is None or parent == child:
            return
        bucket = self.edges.setdefault(parent, [])
        if all(existing != child for existing, _ in bucket):
            bucket.append((child, safe_requirement(requires)))

    def add_root(self, child, requires, scope: str) -> None:
        if child is None:
            return
        requires = safe_requirement(requires)
        for i, (existing, _, old_scope) in enumerate(self.roots):
            if existing == child:
                if old_scope == "dev" and scope == "prod":
                    self.roots[i] = (child, requires, "prod")
                return
        self.roots.append((child, requires, scope))

    def declare(self, child, directory: str) -> None:
        """Remember that the manifest in `directory` (relative to the lockfile, "." for
        its own directory) declares `child`. Only matters for workspaces."""
        if child is None:
            return
        directory = directory.strip("/") or "."
        if directory != "." and not safe_relpath(directory):
            directory = "?"           # a member whose path cannot be shown safely
        self.declared_in.setdefault(child, set()).add(directory)

    def declared_dirs(self, key: tuple) -> list:
        """Workspace member directories declaring `key`; empty when only the root does."""
        dirs = self.declared_in.get(key) or set()
        return sorted(dirs) if dirs - {"."} else []

    def finish(self) -> "Graph":
        """Compute scope (prod wins over dev), shortest paths and parents."""
        if self._finished:
            return self
        if not safe_name(self.root_name):
            self.root_name = ""
        for scope in ("prod", "dev"):
            queue = deque()
            for child, _, root_scope in self.roots:
                if root_scope == scope and child not in self._scope:
                    self._scope[child] = scope
                    self._pred[child] = ROOT
                    queue.append(child)
            while queue:
                current = queue.popleft()
                for child, _ in self.edges.get(current, []):
                    if child not in self._scope:
                        self._scope[child] = scope
                        self._pred[child] = current
                        queue.append(child)
        for child, requires, _ in self.roots:
            self._parents.setdefault(child, []).append((ROOT, requires))
        for parent, children in self.edges.items():
            for child, requires in children:
                self._parents.setdefault(child, []).append((parent, requires))
        self._finished = True
        return self

    def has(self, key: tuple) -> bool:
        return key in self.nodes

    def scope_of(self, key: tuple):
        return self._scope.get(key)

    def is_direct(self, key: tuple) -> bool:
        return any(child == key for child, _, _ in self.roots)

    def parents_of(self, key: tuple) -> list:
        return self._parents.get(key, [])

    def path_to(self, key: tuple) -> list:
        """Shortest chain of keys from a direct dependency down to `key`."""
        chain = []
        current = key
        seen = set()
        while current in self._pred and current not in seen:
            seen.add(current)
            chain.append(current)
            current = self._pred[current]
            if current == ROOT:
                break
        chain.reverse()
        return chain

    def has_edge(self, parent: tuple, child: tuple) -> bool:
        if parent == ROOT:
            return self.is_direct(child)
        return any(existing == child for existing, _ in self.edges.get(parent, []))

    def introduced_by(self, key: tuple, limit: int = 5) -> tuple[list, int]:
        """Up to `limit` (path, parent, requires) entries explaining why `key` is installed."""
        parents = self.parents_of(key)
        ordered = sorted(parents, key=lambda item: (item[0] != ROOT, item[0]))
        result = []
        for parent, requires in ordered:
            if len(result) >= limit:
                break
            if parent == ROOT:
                chain = [key]
            else:
                head = self.path_to(parent)
                if not head:
                    continue  # the parent itself cannot be traced to a direct dependency
                chain = head + [key]
            result.append({"chain": chain, "parent": parent, "requires": requires})
        return result, len(parents)

    def reachable(self, key: tuple) -> bool:
        """True when `key` can be traced back to a direct dependency of the project."""
        return key in self._scope


def unknown_graph(ecosystem: str, note: str) -> Graph:
    return Graph(ecosystem, status="unknown", note=note)


# --------------------------------------------------------------------------
# npm (package-lock.json v2 / v3)
# --------------------------------------------------------------------------

def _npm_graph(lf: Lockfile) -> Graph:
    with open(lf.path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    packages = data.get("packages")
    if not isinstance(packages, dict) or "" not in packages:
        return unknown_graph("npm", "舊版 package-lock(lockfileVersion 1),無法建立相依樹")
    graph = Graph("npm")
    graph.root_name = (packages[""] or {}).get("name") or data.get("name") or ""

    key_at = {}
    members = []
    for path, entry in packages.items():
        if not path or not isinstance(entry, dict) or entry.get("link"):
            continue
        version = entry.get("version")
        if "node_modules/" not in path:
            # A workspace member: the project's own code. npm records it like a
            # package and the scanner lists it, so it is a node here too.
            members.append(path)
            name = entry.get("name") or path.rsplit("/", 1)[-1]
            key = graph.add_node(name, version) if version else None
            if key:
                key_at[path] = key
                graph.first_party.add(key)
            continue
        if not version:
            continue
        name = entry.get("name") or path.rsplit("node_modules/", 1)[-1]
        key = graph.add_node(name, version)
        if key:
            key_at[path] = key

    def resolve(base: str, dep: str):
        current = base
        while True:
            candidate = (current + "/" if current else "") + "node_modules/" + dep
            entry = packages.get(candidate)
            if isinstance(entry, dict):
                if entry.get("link"):
                    target = entry.get("resolved")   # a link points at a workspace member
                    return target if isinstance(target, str) and target in key_at else None
                return candidate
            if not current:
                return None
            index = current.rfind("node_modules/")
            current = current[:index].rstrip("/") if index > 0 else ""

    def sections(entry: dict, names: tuple):
        for name in names:
            block = entry.get(name)
            if isinstance(block, dict):
                for dep, requires in block.items():
                    yield name, dep, requires

    for path in members:
        if path in key_at:
            graph.add_root(key_at[path], None, "prod")
    # Whatever the root or a workspace member declares is a direct dependency of the project.
    for base in [""] + members:
        entry = packages.get(base) or {}
        for section, dep, requires in sections(entry, ("dependencies", "optionalDependencies", "devDependencies")):
            target = resolve(base, dep)
            if target in key_at:
                graph.add_root(key_at[target], requires, "dev" if section == "devDependencies" else "prod")
                graph.declare(key_at[target], base)
    for path, key in key_at.items():
        entry = packages[path]
        # A member's devDependencies stay out of the edges: they are roots with
        # scope dev, and an edge from a prod member would turn them into prod.
        wanted = ("dependencies", "optionalDependencies") if key in graph.first_party else ("dependencies", "optionalDependencies", "peerDependencies")
        for _, dep, requires in sections(entry, wanted):
            target = resolve(path, dep)
            if target in key_at:
                graph.add_edge(key, key_at[target], requires)
    return graph


# --------------------------------------------------------------------------
# yarn classic (yarn.lock v1)
# --------------------------------------------------------------------------

def _yarn_graph(lf: Lockfile) -> Graph:
    with open(lf.path, "r", encoding="utf-8") as fh:
        text = fh.read()
    if "__metadata:" in text:
        return unknown_graph("npm", "yarn berry 格式的相依樹尚未支援")
    blocks = []
    current = None
    section = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            specs = [s.strip().strip('"') for s in line.rstrip().rstrip(":").split(",")]
            current = {"specs": specs, "version": None, "deps": {}}
            blocks.append(current)
            section = None
        elif current is None:
            continue
        elif line.startswith("    ") and section in ("dependencies", "optionalDependencies"):
            name, _, requires = line.strip().partition(" ")
            current["deps"][name.strip('"')] = requires.strip().strip('"')
        else:
            stripped = line.strip()
            if stripped.endswith(":"):
                section = stripped[:-1]
            else:
                section = None
                field_name, _, value = stripped.partition(" ")
                if field_name == "version":
                    current["version"] = value.strip().strip('"')
    if not blocks:
        return unknown_graph("npm", "yarn.lock 無法解析")

    graph = Graph("npm")
    by_spec = {}
    key_of = {}
    for index, block in enumerate(blocks):
        if not block["version"] or not block["specs"]:
            continue
        name = block["specs"][0].rsplit("@", 1)[0]
        key = graph.add_node(name, block["version"])
        if key is None:
            continue
        key_of[index] = key
        for spec in block["specs"]:
            by_spec[spec] = index
    for index, block in enumerate(blocks):
        if index not in key_of:
            continue
        for dep, requires in block["deps"].items():
            target = by_spec.get(f"{dep}@{requires}")
            if target in key_of:
                graph.add_edge(key_of[index], key_of[target], requires)

    base = os.path.dirname(lf.path)
    manifest = os.path.join(base, "package.json")
    found = False

    def add_roots(meta: dict, directory: str) -> bool:
        added = False
        for section_name, scope in (("dependencies", "prod"), ("optionalDependencies", "prod"), ("devDependencies", "dev")):
            section_data = meta.get(section_name)
            if not isinstance(section_data, dict):
                continue
            for dep, requires in section_data.items():
                target = by_spec.get(f"{dep}@{requires}")
                if target in key_of:
                    graph.add_root(key_of[target], requires, scope)
                    graph.declare(key_of[target], directory)
                    added = True
        return added

    if os.path.isfile(manifest):
        try:
            with open(manifest, "r", encoding="utf-8") as fh:
                meta = json.load(fh)
            if isinstance(meta, dict):
                graph.root_name = meta.get("name") if isinstance(meta.get("name"), str) else ""
                found = add_roots(meta, ".")
                # Workspace members are first-party code: what they require is a direct dependency too.
                real_base = os.path.realpath(base)
                for member in _workspace_manifests(base, meta):
                    try:
                        with open(member, "r", encoding="utf-8") as fh:
                            member_meta = json.load(fh)
                    except (OSError, ValueError):
                        continue
                    if isinstance(member_meta, dict):
                        directory = os.path.relpath(os.path.dirname(member), real_base).replace(os.sep, "/")
                        found = add_roots(member_meta, directory) or found
        except (OSError, ValueError):
            pass
    if not found:
        _roots_from_orphans(graph, "找不到 package.json,直接相依為推定")
    return graph


_WORKSPACE_PATTERN = re.compile(r"^[A-Za-z0-9@._*-]+(?:/[A-Za-z0-9@._*-]+){0,5}/?$")
MAX_WORKSPACE_MEMBERS = 500


def _workspace_manifests(base: str, meta: dict) -> list[str]:
    """package.json files of the workspace members a root package.json names.

    Only plain `dir/*` style patterns are expanded, only inside the lockfile's
    own directory, and never through a symlink.
    """
    patterns = meta.get("workspaces")
    if isinstance(patterns, dict):
        patterns = patterns.get("packages")
    if not isinstance(patterns, list):
        return []
    real_base = os.path.realpath(base)
    found, seen = [], set()
    for pattern in patterns:
        if not isinstance(pattern, str) or not _WORKSPACE_PATTERN.match(pattern):
            continue
        parts = [part for part in pattern.split("/") if part]
        if any(part in (".", "..") or part in SKIP_DIRS for part in parts):
            continue
        for path in sorted(glob.glob(os.path.join(glob.escape(real_base), *parts, "package.json"))):
            if len(found) >= MAX_WORKSPACE_MEMBERS:
                return found
            directory = os.path.dirname(path)
            inside = os.path.relpath(directory, real_base).split(os.sep)
            if any(part in SKIP_DIRS for part in inside):
                continue
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            if os.path.realpath(directory) != directory or path in seen:
                continue  # reached through a symlink, or listed twice
            seen.add(path)
            found.append(path)
    return found


# --------------------------------------------------------------------------
# Composer
# --------------------------------------------------------------------------

def _composer_graph(lf: Lockfile) -> Graph:
    with open(lf.path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    graph = Graph("Packagist")
    by_name = {}
    entries = []
    dev_keys = set()
    for section in ("packages", "packages-dev"):
        for package in data.get(section) or []:
            name, version = package.get("name"), package.get("version")
            if not name or not version:
                continue
            key = graph.add_node(name, version)
            if key is None:
                continue
            by_name[name.lower()] = key
            entries.append((key, package))
            if section == "packages-dev":
                dev_keys.add(key)
    for key, package in entries:
        for dep, constraint in (package.get("require") or {}).items():
            child = by_name.get(dep.lower())
            if child:
                graph.add_edge(key, child, constraint)

    manifest = os.path.join(os.path.dirname(lf.path), "composer.json")
    found = False
    if os.path.isfile(manifest):
        try:
            with open(manifest, "r", encoding="utf-8") as fh:
                meta = json.load(fh)
            graph.root_name = meta.get("name") or ""
            for section, scope in (("require", "prod"), ("require-dev", "dev")):
                for dep, constraint in (meta.get(section) or {}).items():
                    child = by_name.get(dep.lower())
                    if child:
                        graph.add_root(child, constraint, scope)
                        found = True
        except (OSError, ValueError):
            pass
    if not found:
        _roots_from_orphans(graph, "找不到 composer.json,直接相依為推定", dev_keys)
    return graph


def _roots_from_orphans(graph: Graph, note: str, dev_keys=frozenset()) -> None:
    required = {child for children in graph.edges.values() for child, _ in children}
    for key in graph.nodes:
        if key not in required:
            graph.add_root(key, None, "dev" if key in dev_keys else "prod")
    graph.note = note


# --------------------------------------------------------------------------
# Python: poetry.lock / uv.lock
# --------------------------------------------------------------------------

_PEP508 = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*\(?\s*([^;()]*?)\s*\)?\s*(?:;.*)?$")


def parse_pep508(text: str):
    """'flask[async] (>=2.0) ; python_version > "3.8"' -> ('flask', '>=2.0')."""
    m = _PEP508.match(text or "")
    if not m:
        return None, None
    spec = m.group(2).strip()
    if spec.startswith("@"):
        spec = ""
    return m.group(1), (spec or None)


def _poetry_spec(spec):
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict):
        return spec.get("version")
    if isinstance(spec, list):
        versions = [_poetry_spec(item) for item in spec]
        versions = [v for v in versions if v]
        return " || ".join(dict.fromkeys(versions)) if versions else None
    return None


def _poetry_graph(lf: Lockfile) -> Graph:
    with open(lf.path, "rb") as fh:
        data = tomllib.load(fh)
    graph = Graph("PyPI")
    by_name = {}
    entries = []
    dev_keys = set()
    for package in data.get("package") or []:
        name, version = package.get("name"), package.get("version")
        if not name or not version:
            continue
        key = graph.add_node(name, version)
        if key is None:
            continue
        by_name.setdefault(norm_name("PyPI", name), []).append(key)
        entries.append((key, package))
        groups = package.get("groups")
        if package.get("category") == "dev" or (isinstance(groups, list) and "main" not in groups):
            dev_keys.add(key)
    for key, package in entries:
        for dep, spec in (package.get("dependencies") or {}).items():
            for child in by_name.get(norm_name("PyPI", dep), []):
                graph.add_edge(key, child, _poetry_spec(spec))

    def add_root(dep, spec, scope):
        children = by_name.get(norm_name("PyPI", dep or ""), [])
        for child in children:
            graph.add_root(child, spec, scope)
        return bool(children)

    found = False
    manifest = os.path.join(os.path.dirname(lf.path), "pyproject.toml")
    if os.path.isfile(manifest):
        try:
            with open(manifest, "rb") as fh:
                meta = tomllib.load(fh)
            project = meta.get("project") or {}
            poetry = (meta.get("tool") or {}).get("poetry") or {}
            graph.root_name = project.get("name") or poetry.get("name") or ""
            for requirement in project.get("dependencies") or []:
                found |= add_root(*parse_pep508(requirement), "prod")
            for requirements in (project.get("optional-dependencies") or {}).values():
                for requirement in requirements or []:
                    found |= add_root(*parse_pep508(requirement), "prod")
            for requirements in (meta.get("dependency-groups") or {}).values():
                for requirement in requirements or []:
                    if isinstance(requirement, str):
                        found |= add_root(*parse_pep508(requirement), "dev")
            for dep, spec in (poetry.get("dependencies") or {}).items():
                if dep.lower() != "python":
                    found |= add_root(dep, _poetry_spec(spec), "prod")
            for dep, spec in (poetry.get("dev-dependencies") or {}).items():
                found |= add_root(dep, _poetry_spec(spec), "dev")
            for group_name, group in (poetry.get("group") or {}).items():
                scope = "prod" if group_name == "main" else "dev"
                for dep, spec in ((group or {}).get("dependencies") or {}).items():
                    found |= add_root(dep, _poetry_spec(spec), scope)
        except (OSError, ValueError):
            pass
    if not found:
        _roots_from_orphans(graph, "找不到 pyproject.toml,直接相依為推定", dev_keys)
    return graph


def _uv_graph(lf: Lockfile) -> Graph:
    with open(lf.path, "rb") as fh:
        data = tomllib.load(fh)
    graph = Graph("PyPI")
    by_name = {}
    third_party = []
    first_party = []
    for package in data.get("package") or []:
        name, version = package.get("name"), package.get("version")
        source = package.get("source") or {}
        if not name:
            continue
        if any(kind in source for kind in ("virtual", "editable", "directory")):
            first_party.append(package)
            continue
        if not version:
            continue
        key = graph.add_node(name, version)
        if key is None:
            continue
        by_name.setdefault(norm_name("PyPI", name), []).append((str(version), key))
        third_party.append((key, package))

    def targets(dep):
        if not isinstance(dep, dict) or not dep.get("name"):
            return []
        candidates = by_name.get(norm_name("PyPI", dep["name"]), [])
        wanted = dep.get("version")
        if wanted:
            candidates = [c for c in candidates if c[0] == str(wanted)]
        return [key for _, key in candidates]

    def all_deps(package):
        deps = list(package.get("dependencies") or [])
        for extra in (package.get("optional-dependencies") or {}).values():
            deps.extend(extra or [])
        return deps

    for key, package in third_party:
        for dep in all_deps(package):
            for child in targets(dep):
                graph.add_edge(key, child, None)

    found = False
    for package in first_party:
        graph.root_name = graph.root_name or package.get("name") or ""
        metadata = package.get("metadata") or {}
        spec_of = {
            norm_name("PyPI", item["name"]): item.get("specifier")
            for item in metadata.get("requires-dist") or []
            if isinstance(item, dict) and item.get("name")
        }
        dev_spec_of = {}
        for items in (metadata.get("requires-dev") or {}).values():
            for item in items or []:
                if isinstance(item, dict) and item.get("name"):
                    dev_spec_of[norm_name("PyPI", item["name"])] = item.get("specifier")
        for dep in all_deps(package):
            for child in targets(dep):
                graph.add_root(child, spec_of.get(child[0]), "prod")
                found = True
        for items in (package.get("dev-dependencies") or {}).values():
            for dep in items or []:
                for child in targets(dep):
                    graph.add_root(child, dev_spec_of.get(child[0]), "dev")
                    found = True
    if not found:
        _roots_from_orphans(graph, "uv.lock 內沒有專案本身的紀錄,直接相依為推定")
    return graph


# --------------------------------------------------------------------------

_BUILDERS = {
    "package-lock.json": _npm_graph,
    "npm-shrinkwrap.json": _npm_graph,
    "yarn.lock": _yarn_graph,
    "composer.lock": _composer_graph,
    "poetry.lock": _poetry_graph,
    "uv.lock": _uv_graph,
}
_NO_GRAPH_NOTE = {
    "pnpm-lock.yaml": "pnpm-lock.yaml 的相依樹尚未支援",
    "bun.lock": "bun.lock 的相依樹尚未支援",
    "requirements.txt": "requirements.txt 是平的清單,檔案本身不記錄誰依賴誰",
    "Pipfile.lock": "Pipfile.lock 是平的清單,檔案本身不記錄誰依賴誰",
    "go.mod": "go.mod 只區分直接與間接相依,沒有完整相依樹",
}


def build_graph(lf: Lockfile) -> Graph:
    builder = _BUILDERS.get(lf.name)
    if builder is None:
        name = lf.name if lf.name in _NO_GRAPH_NOTE else ("requirements.txt" if lf.ecosystem == "PyPI" and lf.name.endswith(".txt") else lf.name)
        return unknown_graph(lf.ecosystem, _NO_GRAPH_NOTE.get(name, f"{lf.name} 的相依樹尚未支援")).finish()
    try:
        return builder(lf).finish()
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        return unknown_graph(lf.ecosystem, f"解析 {lf.name} 的相依樹失敗:{type(exc).__name__}").finish()
