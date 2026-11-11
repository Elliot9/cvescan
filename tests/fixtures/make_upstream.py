#!/usr/bin/env python3
"""Build a fake "upstream" for tests: OSV zips, KEV, EPSS and end-of-life data.

Usage: make_upstream.py <output dir> [--drop <advisory id> ...]

The OSV records under advisories/ are real GitHub advisories, except
MAL-2026-900001, which is made up. KEV, EPSS and end-of-life files written
here are SYNTHETIC test data: they do not describe the real world.
"""

import gzip
import json
import os
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 2
    out = os.path.abspath(args[0])
    drop = set()
    if "--drop" in args:
        drop = set(args[args.index("--drop") + 1:])

    source = os.path.join(HERE, "advisories")
    for ecosystem in sorted(os.listdir(source)):
        target = os.path.join(out, "osv", ecosystem)
        os.makedirs(target, exist_ok=True)
        with zipfile.ZipFile(os.path.join(target, "all.zip"), "w", zipfile.ZIP_DEFLATED) as archive:
            for name in sorted(os.listdir(os.path.join(source, ecosystem))):
                if name[:-5] in drop:
                    continue
                archive.write(os.path.join(source, ecosystem, name), name)

    kev = {
        "title": "SYNTHETIC TEST FIXTURE - not the real CISA KEV catalog",
        "catalogVersion": "fixture",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2022-24999",
                "dateAdded": "2026-10-20",
                "dueDate": "2026-11-10",
                "knownRansomwareCampaignUse": "Unknown",
            }
        ],
    }
    with open(os.path.join(out, "kev.json"), "w", encoding="utf-8") as fh:
        json.dump(kev, fh)

    epss_rows = [
        "#model_version:fixture,score_date:2026-11-11T00:00:00+0000",
        "cve,epss,percentile",
        "CVE-2021-23337,0.00842,0.74210",
        "CVE-2020-8203,0.02310,0.89120",
        "CVE-2022-24999,0.31200,0.97010",
        "CVE-2024-22195,0.00110,0.30100",
        "CVE-2018-18074,0.00620,0.69800",
        "CVE-2022-29248,0.15300,0.94500",
        "CVE-2022-24775,0.00190,0.41000",
    ]
    with gzip.open(os.path.join(out, "epss.csv.gz"), "wt", encoding="utf-8") as fh:
        fh.write("\n".join(epss_rows) + "\n")

    os.makedirs(os.path.join(out, "eol"), exist_ok=True)
    # nodejs uses the v1 API shape, php and python the older list shape,
    # so both parsers are exercised.
    nodejs = {
        "schema_version": "1.2.0",
        "result": {
            "name": "nodejs",
            "releases": [
                {"name": "24", "isEol": False, "eolFrom": "2028-04-30", "latest": {"name": "24.11.0"}},
                {"name": "22", "isEol": False, "eolFrom": "2027-04-30", "latest": {"name": "22.21.0"}},
                {"name": "18", "isEol": True, "eolFrom": "2025-04-30", "latest": {"name": "18.20.8"}},
            ],
        },
    }
    php = [
        {"cycle": "8.3", "eol": "2027-12-31", "latest": "8.3.36"},
        {"cycle": "8.1", "eol": "2025-12-31", "latest": "8.1.33"},
    ]
    python = [
        {"cycle": "3.12", "eol": "2028-10-31", "latest": "3.12.12"},
        {"cycle": "3.10", "eol": "2026-10-31", "latest": "3.10.19"},
    ]
    for name, data in (("nodejs", nodejs), ("php", php), ("python", python)):
        with open(os.path.join(out, "eol", f"{name}.json"), "w", encoding="utf-8") as fh:
            json.dump(data, fh)
    return 0


if __name__ == "__main__":
    sys.exit(main())
