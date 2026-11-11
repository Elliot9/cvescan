"""CycloneDX SBOM, including the dependency graph.

One SBOM per scan. Every lockfile becomes an "application" component under
the project; its packages are "library" components. For lockfiles whose graph
could be built, the `dependencies` section records who depends on whom, and
the parent's version requirement is kept as a `cvescan:requires:<child>`
property. For the others the packages are listed without `dependencies`
entries, which in CycloneDX means "unknown", not "none".
"""

from __future__ import annotations

import urllib.parse
import uuid

from .lockfiles import ROOT, label, norm_name, norm_version
from .util import sha256_text

SPEC_VERSION = "1.5"
SBOM_FILE = "sbom.cdx.json"

_PURL_TYPE = {
    "npm": "npm", "PyPI": "pypi", "Packagist": "composer", "Go": "golang",
    "crates.io": "cargo", "RubyGems": "gem", "Maven": "maven", "NuGet": "nuget",
    "Hex": "hex", "Pub": "pub", "ConanCenter": "conan", "CRAN": "cran",
}


def purl_for(ecosystem: str, name: str, version: str, scanner_purl: str | None = None) -> str:
    if scanner_purl:
        return scanner_purl.split("?", 1)[0].split("#", 1)[0]
    kind = _PURL_TYPE.get(ecosystem, "generic")
    if ecosystem == "PyPI":
        name = norm_name("PyPI", name)
    if ecosystem == "Maven" and ":" in name:
        name = name.replace(":", "/", 1)
    quoted = "/".join(urllib.parse.quote(part, safe="") for part in name.split("/"))
    return f"pkg:{kind}/{quoted}@{urllib.parse.quote(str(version), safe='')}"


def lockfile_ref(rel: str) -> str:
    return f"lockfile:{rel}"


def component_ref(rel: str, purl: str) -> str:
    return f"{rel}#{purl}"


def fingerprint(inputs: list[dict]) -> str:
    lines = sorted(
        f"{item['rel']}|{item['ecosystem']}|{package['key'][0]}|{package['key'][1]}"
        for item in inputs for package in item["packages"]
    )
    return sha256_text("\n".join(lines))


def build(project: dict, scan_id: str, scanned_at: str, tool: dict, inputs: list[dict]) -> dict:
    """`inputs`: one dict per lockfile with rel, ecosystem, root_label, graph, packages."""
    components = []
    dependencies = [{"ref": "project", "dependsOn": sorted(lockfile_ref(i["rel"]) for i in inputs)}]

    for item in sorted(inputs, key=lambda i: i["rel"]):
        rel, graph = item["rel"], item["graph"]
        ref_of = {package["key"]: component_ref(rel, package["purl"]) for package in item["packages"]}
        known = graph.status == "complete"

        lock_props = [
            {"name": "cvescan:lockfile", "value": rel},
            {"name": "cvescan:ecosystem", "value": item["ecosystem"]},
            {"name": "cvescan:graph", "value": graph.status},
        ]
        if graph.note:
            lock_props.append({"name": "cvescan:graph-note", "value": graph.note})
        if known:
            direct = []
            for child, requires, _ in graph.roots:
                if child in ref_of:
                    direct.append(ref_of[child])
                    if requires:
                        lock_props.append({"name": f"cvescan:requires:{graph.nodes.get(child, child[0])}", "value": str(requires)})
            dependencies.append({"ref": lockfile_ref(rel), "dependsOn": sorted(set(direct))})
        components.append({
            "type": "application",
            "bom-ref": lockfile_ref(rel),
            "name": item["root_label"],
            "properties": lock_props,
        })

        for package in sorted(item["packages"], key=lambda p: p["key"]):
            key = package["key"]
            props = [
                {"name": "cvescan:lockfile", "value": rel},
                {"name": "cvescan:ecosystem", "value": item["ecosystem"]},
                {"name": "cvescan:scope", "value": package["scope"]},
            ]
            in_graph = known and graph.has(key)
            if package.get("first_party"):
                props.append({"name": "cvescan:first-party", "value": "true"})
            if in_graph:
                direct_text = {True: "true", False: "false"}.get(package["direct"], "unknown")
                props.append({"name": "cvescan:direct", "value": direct_text})
                children = []
                for child, requires in graph.edges.get(key, []):
                    if child in ref_of:
                        children.append(ref_of[child])
                        if requires:
                            props.append({"name": f"cvescan:requires:{graph.nodes.get(child, child[0])}", "value": str(requires)})
                dependencies.append({"ref": ref_of[key], "dependsOn": sorted(set(children))})
            components.append({
                "type": "library",
                "bom-ref": ref_of[key],
                "name": package["name"],
                "version": package["version"],
                "purl": package["purl"],
                "scope": "excluded" if package["scope"] == "dev" else "required",
                "properties": props,
            })

    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"cvescan:{project['name']}:{scan_id}")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": scanned_at,
            "tools": [{"vendor": "cvescan", "name": "cvescan", "version": tool["version"]}],
            "component": {
                "type": "application",
                "bom-ref": "project",
                "name": project["name"],
                "version": (project.get("version") or {}).get("describe") or "unknown",
            },
            "properties": [
                {"name": "cvescan:scan-id", "value": scan_id},
                {"name": "cvescan:scanner", "value": tool["scanner"]},
            ],
        },
        "components": components,
        "dependencies": dependencies,
    }


def path_labels(root_label: str, chain: list[tuple]) -> list[str]:
    return [root_label] + [label(key) for key in chain if key != ROOT]


class SbomGraph:
    """Read-only view of an SBOM, used by `verify` to check paths the AI cites."""

    def __init__(self, bom: dict):
        self.names = set()                 # every package name in the SBOM
        self._edges = set()                # (lockfile rel, parent label, child label)
        self._roots = set()                # (lockfile rel, root label)
        components = {c.get("bom-ref"): c for c in bom.get("components") or [] if isinstance(c, dict)}
        label_of = {}
        lock_of = {}
        for ref, component in components.items():
            props = {p.get("name"): p.get("value") for p in component.get("properties") or [] if isinstance(p, dict)}
            lock_of[ref] = props.get("cvescan:lockfile")
            if component.get("type") == "application":
                label_of[ref] = component.get("name") or ""
                self._roots.add((lock_of[ref], label_of[ref]))
            else:
                ecosystem = props.get("cvescan:ecosystem") or ""
                name = component.get("name") or ""
                label_of[ref] = f"{norm_name(ecosystem, name)}@{norm_version(ecosystem, component.get('version'))}"
                self.names.add(name)
                self.names.add(norm_name(ecosystem, name))
        for entry in bom.get("dependencies") or []:
            parent = entry.get("ref")
            if parent not in components:
                continue
            for child in entry.get("dependsOn") or []:
                if child in components:
                    self._edges.add((lock_of[parent], label_of[parent], label_of[child]))

    def has_path(self, path: list) -> bool:
        """True when `path` is a real chain: root label, then consecutive edges."""
        if not isinstance(path, list) or len(path) < 2 or not all(isinstance(p, str) for p in path):
            return False
        for rel, root in self._roots:
            if root != path[0]:
                continue
            if all((rel, path[i], path[i + 1]) in self._edges for i in range(len(path) - 1)):
                return True
        return False
