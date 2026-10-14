from __future__ import annotations

import argparse
import logging
import sys

from . import __version__
from .alerts import Dispatcher
from .config import load
from .events import CATALOG
from .watcher import Watcher


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ownerwatch", description="Alert when an EVM contract's admin surface changes.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="poll forever and alert")
    r.add_argument("--config", default="config.yaml")
    r.add_argument("--once", action="store_true", help="scan once and exit (for cron)")
    b = sub.add_parser("backfill", help="scan a historical block range and print alerts")
    b.add_argument("--config", default="config.yaml")
    b.add_argument("--from-block", type=int, required=True)
    b.add_argument("--to-block", type=int, required=True)
    sub.add_parser("events", help="list the events in the catalog")
    a = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)

    if a.cmd == "events":
        for s in CATALOG:
            print(f"{s.severity:8} {s.source:18} {s.signature}")
        return 0

    cfg = load(a.config)
    w = Watcher(cfg, Dispatcher(cfg.alerts))
    if a.cmd == "backfill":
        n = w._scan(a.from_block, a.to_block)
        print(f"{n} alerts in blocks {a.from_block}-{a.to_block}", file=sys.stderr)
        return 0
    if a.once:
        w.poll_once()
        return 0
    w.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
