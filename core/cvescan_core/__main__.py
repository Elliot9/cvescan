"""Command line of the core. The `cvescan` wrapper is the only intended caller.

Exit codes: 0 ok, 1 failed check (verify / sync), 2 refused by a gate,
3 the scan ran but its result is not trustworthy.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__, config as config_mod, history, scan as scan_mod, sync as sync_mod, update as update_mod, verify as verify_mod
from .lockfiles import KNOWN_ECOSYSTEMS, exclude_pattern
from .util import Invalid, Refusal, now_utc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cvescan-core", description="cvescan core (called by the cvescan wrapper)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("detect", help="list the ecosystems a project uses")
    p.add_argument("--src", default="/src")
    p.add_argument("--exclude", action="append", default=[], type=exclude_pattern)

    p = sub.add_parser("sync", help="update vulnerability data (network, no code)")
    p.add_argument("--db", default="/db")
    p.add_argument("--config", default="/config")
    p.add_argument("--ecosystems", default="")

    p = sub.add_parser("scan", help="scan a project offline and write the report")
    p.add_argument("--src", default="/src")
    p.add_argument("--db", default="/db")
    p.add_argument("--state", default="/state")
    p.add_argument("--out", default="/out")
    p.add_argument("--config", default="/config")
    p.add_argument("--project", required=True)
    p.add_argument("--display-out", default=None)
    p.add_argument("--exclude", action="append", default=[], type=exclude_pattern)

    p = sub.add_parser("verify", help="check analysis.json and render analysis.md")
    p.add_argument("--state", default="/state")
    p.add_argument("--out", default="/out")
    p.add_argument("--display-out", default=None)

    p = sub.add_parser("status", help="show scan history")
    p.add_argument("--state-root", default="/state")
    p.add_argument("--project", default=None)
    p.add_argument("--config", default="/config")

    p = sub.add_parser("update-check", help="is a newer release available?")
    p.add_argument("--config", default="/config")

    sub.add_parser("version")
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "version":
            print(__version__)
            return 0
        if args.command == "detect":
            ecosystems, count = scan_mod.detect(args.src, args.exclude)
            print(count)
            for ecosystem in ecosystems:
                print(ecosystem)
            return 0
        if args.command == "sync":
            ecosystems = [e for e in args.ecosystems.split(",") if e]
            return sync_mod.run(args.db, ecosystems, config_mod.load(args.config))
        if args.command == "scan":
            return scan_mod.run(args.src, args.db, args.state, args.out, config_mod.load(args.config), args.project, args.display_out, args.exclude)
        if args.command == "verify":
            return verify_mod.run(args.state, args.out, args.display_out)
        if args.command == "status":
            cfg = config_mod.load(args.config)
            if args.project:
                print(history.render_project(args.project, os.path.join(args.state_root, args.project), now_utc(), cfg))
            else:
                print(history.render_overview(args.state_root, now_utc(), cfg))
            return 0
        if args.command == "update-check":
            result = update_mod.check(config_mod.load(args.config), now_utc())
            for key, value in result.items():
                print(f"{key}={'' if value is None else str(value).lower() if isinstance(value, bool) else value}")
            return 0
    except Refusal as exc:
        print(f"拒絕   {exc}")
        return 2
    except Invalid as exc:
        print(f"無效   {exc}")
        return 3
    return 1


# Re-exported so the wrapper can validate what `detect` printed.
ECOSYSTEMS = KNOWN_ECOSYSTEMS

if __name__ == "__main__":
    sys.exit(main())
