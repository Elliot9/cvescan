"""User configuration.

Everything that can change what a scan reports lives here, in a file only the
user edits. Nothing in this file can be set from the command line, so an agent
that is allowed to run `cvescan <path>` cannot relax a gate.
"""

from __future__ import annotations

import copy
import os
import tomllib

from .util import eprint

DEFAULTS = {
    "lang": "zh-TW",
    # A scan refuses to run when the vulnerability DB was last confirmed
    # current longer ago than this.
    "max_db_age_minutes": 60,
    # true: scan anyway with a stale DB and mark the report db_stale.
    "allow_stale_db": False,
    # How many full runs (report + SBOM) to keep per project.
    "keep_runs": 10,
    # `status` flags a project as "not scanned for too long" after this.
    "stale_scan_days": 7,
    "update": {
        # Empty: no update check.
        "manifest_url": "",
        # Unattended runs (agent, cron) take an eligible update without asking.
        "auto_update_unattended": True,
        # Unattended runs only take a release that has been out this long.
        "cooldown_days": 3,
    },
    "sources": {
        "osv_base_url": "https://osv-vulnerabilities.storage.googleapis.com",
        "kev_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "epss_url": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
        "eol_url_template": "https://endoflife.date/api/v1/products/{product}/",
    },
}

CONFIG_FILE = "config.toml"


def _merge(base: dict, extra: dict, path: str = "") -> None:
    for key, value in extra.items():
        where = f"{path}{key}"
        if key not in base:
            eprint(f"設定檔:忽略不認得的項目 {where}")
            continue
        expected = base[key]
        if isinstance(expected, dict):
            if isinstance(value, dict):
                _merge(expected, value, where + ".")
            else:
                eprint(f"設定檔:{where} 應該是一個區塊,已忽略")
        elif isinstance(expected, bool):
            if isinstance(value, bool):
                base[key] = value
            else:
                eprint(f"設定檔:{where} 應該是 true 或 false,已忽略")
        elif isinstance(expected, int):
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                base[key] = value
            else:
                eprint(f"設定檔:{where} 應該是非負整數,已忽略")
        elif isinstance(value, str):
            base[key] = value
        else:
            eprint(f"設定檔:{where} 應該是字串,已忽略")


def load(config_dir: str | None) -> dict:
    config = copy.deepcopy(DEFAULTS)
    if not config_dir:
        return config
    path = os.path.join(config_dir, CONFIG_FILE)
    if not os.path.isfile(path):
        return config
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise SystemExit(f"設定檔 {path} 無法讀取:{exc}")
    _merge(config, data)
    return config
