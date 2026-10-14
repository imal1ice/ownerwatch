from __future__ import annotations

import argparse
import logging
import sys

from . import __version__
from .alerts import Dispatcher
from .config import load_all
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
    b.add_argument("--chain", default=None, help="chain_name to backfill when the config has several chains")
    sub.add_parser("events", help="list the events in the catalog")
    pr = sub.add_parser("probe", help="inspect the admin surface of addresses and suggest a config")
    pr.add_argument("addresses", nargs="+")
    pr.add_argument("--rpc", required=True)
    pr.add_argument("--chain-name", default="ethereum")
    pr.add_argument("--safe-chain", default=None, help="Safe Tx Service key (eth, base, arb1, oeth, ...) to add safes: entries")
    pr.add_argument("--label", default="Protocol")
    pr.add_argument("--yaml", action="store_true", help="print only the suggested config")
    pr.add_argument("--markdown", action="store_true", help="print a short admin-surface report in markdown")
    pr.add_argument("--roles-from-logs", action="store_true",
                    help="replay RoleGranted/RoleRevoked logs to list every current role holder (needs an RPC with log history)")
    pr.add_argument("--from-block", type=int, default=0, help="with --roles-from-logs: contract creation block, to limit the scan")
    a = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)

    if a.cmd == "events":
        for s in CATALOG:
            print(f"{s.severity:8} {s.source:18} {s.signature}")
        return 0

    if a.cmd == "probe":
        from web3 import Web3
        from .probe import Prober, describe, markdown_report, suggest_config
        prober = Prober(Web3(Web3.HTTPProvider(a.rpc, request_kwargs={"timeout": 30})))
        roots = [prober.probe(x) for x in a.addresses]
        prober.check_roles(list(prober.seen.keys()))
        if a.roles_from_logs:
            for x in a.addresses:
                try:
                    prober.role_history(x, a.from_block)
                except Exception as e:  # noqa: BLE001
                    print(f"# role history for {x} failed: {e}", file=sys.stderr)
        if a.markdown:
            print(markdown_report(prober, a.label, a.chain_name, roots))
            return 0
        if not a.yaml:
            for n in prober.seen.values():
                print(describe(n))
            print("\n# suggested config\n")
        print(suggest_config(prober, a.rpc, a.chain_name, a.safe_chain, a.label))
        return 0

    cfgs = load_all(a.config)
    if a.cmd == "backfill":
        if len(cfgs) > 1 and not a.chain:
            p.error("--chain is required for a multi-chain config")
        cfg = next((c for c in cfgs if c.chain_name == a.chain), cfgs[0])
        w = Watcher(cfg, Dispatcher(cfg.alerts))
        n, start = 0, a.from_block
        while start <= a.to_block:
            end = min(start + cfg.max_block_range - 1, a.to_block)
            n += w._scan(start, end)
            start = end + 1
        print(f"{n} alerts in blocks {a.from_block}-{a.to_block}", file=sys.stderr)
        return 0
    watchers = [Watcher(c, Dispatcher(c.alerts)) for c in cfgs]
    if a.once:
        for w in watchers:
            w.poll_once()
        return 0
    if len(watchers) == 1:
        watchers[0].run_forever()
        return 0
    import threading
    threads = [threading.Thread(target=w.run_forever, name=w.cfg.chain_name, daemon=True) for w in watchers]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return 0


if __name__ == "__main__":
    sys.exit(main())
