from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import sys
from pathlib import Path

import requests
from web3 import Web3
from web3.exceptions import Web3Exception

from . import __version__
from .alerts import Dispatcher, redact
from .config import load_all
from .events import CATALOG, NOTE_SPECS, VARIANTS
from .watcher import Watcher, build_watchers


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ownerwatch", description="Alert when an EVM contract's admin surface changes.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="poll forever and alert")
    r.add_argument("--config", default="config.yaml")
    r.add_argument("--once", action="store_true", help="scan once and exit (for cron)")
    b = sub.add_parser("backfill", help="scan a historical block range and print alerts (also to jsonl_path, never to webhooks)")
    b.add_argument("--config", default="config.yaml")
    b.add_argument("--from-block", type=int, required=True)
    b.add_argument("--to-block", type=int, required=True)
    b.add_argument("--chain", default=None, help="chain_name to backfill when the config has several chains")
    sub.add_parser("events", help="list the events in the catalog")
    va = sub.add_parser("validate", help="check a config file and print what it would watch")
    va.add_argument("--config", default="config.yaml")
    ta = sub.add_parser("test-alert", help="send a test alert through every configured sink")
    ta.add_argument("--config", default="config.yaml")
    h = sub.add_parser("hosted", help="run watchers for every address with an active on-chain subscription")
    h.add_argument("--rpc", required=True, help="RPC of the chain the Subscriptions contract lives on")
    h.add_argument("--subscriptions", required=True, help="Subscriptions contract address")
    h.add_argument("--configs", default="configs", help="directory of <customer-address>.yaml files")
    h.add_argument("--check-interval", type=int, default=60)
    h.add_argument("--allow-private-urls", action="store_true", help="let customer configs use private and loopback URLs (local test chains only)")
    pr = sub.add_parser("probe", help="inspect the admin surface of addresses and suggest a config")
    pr.add_argument("addresses", nargs="*")
    pr.add_argument("--rpc", default=None)
    pr.add_argument("--config", default=None, help="probe every contract and Safe listed in this config (per chain)")
    pr.add_argument("--chain-name", default=None, help="name used in reports and configs (default: inferred from the RPC chain id)")
    pr.add_argument("--safe-chain", default=None, help="Safe Tx Service key (eth, base, arb1, oeth, ...) to add safes: entries")
    pr.add_argument("--label", default="Protocol")
    pr.add_argument("--yaml", action="store_true", help="print only the suggested config")
    pr.add_argument("--markdown", action="store_true", help="print a short admin-surface report in markdown")
    pr.add_argument("--json", action="store_true", help="print the probed nodes as JSON")
    pr.add_argument("--roles-from-logs", action="store_true",
                    help="replay RoleGranted/RoleRevoked logs to list every current role holder (needs an RPC with log history)")
    pr.add_argument("--from-block", type=int, default=None,
                    help="with --roles-from-logs: first block to scan (default: creation block from Sourcify or a code search)")
    pr.add_argument("--role-candidates", default="",
                    help="comma-separated addresses to test for AccessControl roles without probing them as targets "
                         "(the protocol's Safes and keys from docs or other chains)")
    pr.add_argument("--logs-rpc", default=None,
                    help="with --roles-from-logs: RPC used only for eth_getLogs, e.g. https://mainnet.gateway.tenderly.co (full history, large blocks per call)")
    ds = sub.add_parser("disclosure", help="ERC-8241 control disclosures: draft one from chain state, or check one against it")
    dsub = ds.add_subparsers(dest="dcmd", required=True)
    dd = dsub.add_parser("draft", help="write a starting ERC-8241 disclosure (JSON) for these addresses")
    dd.add_argument("addresses", nargs="+")
    dd.add_argument("--rpc", required=True)
    dd.add_argument("--name", default="Protocol")
    dd.add_argument("--no-roles-from-logs", dest="roles_from_logs", action="store_false",
                    help="only test common roles on named addresses instead of replaying every role grant")
    dd.add_argument("--logs-rpc", default=None, help="RPC for eth_getLogs (default: a public full-history gateway, else --rpc)")
    dd.add_argument("--from-block", type=int, default=None, help="first block of the role replay (default: creation block)")
    dd.add_argument("--block", type=int, default=None, help="read at this block (default: latest)")
    dc = dsub.add_parser("check", help="check an ERC-8241 disclosure (JSON) against chain state; exit 1 on any mismatch or undisclosed power")
    dc.add_argument("file")
    dc.add_argument("--rpc", required=True)
    dc.add_argument("--no-roles-from-logs", dest="roles_from_logs", action="store_false",
                    help="only test common roles on named addresses instead of replaying every role grant")
    dc.add_argument("--logs-rpc", default=None, help="RPC for eth_getLogs (default: a public full-history gateway, else --rpc)")
    dc.add_argument("--from-block", type=int, default=None, help="first block of the role replay (default: creation block)")
    dc.add_argument("--block", type=int, default=None, help="pin every read to this block (default: latest)")
    dc.add_argument("--json", action="store_true", help="print the full report as JSON")
    a = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)

    if a.cmd == "disclosure":
        from .disclosure import Checker, draft, render
        from .probe import make_w3
        w3 = make_w3(a.rpc)
        logs_w3 = make_w3(a.logs_rpc, 60) if a.logs_rpc else None
        opts = dict(roles_from_logs=a.roles_from_logs, logs_w3=logs_w3, from_block=a.from_block)
        try:
            if a.dcmd == "draft":
                print(json.dumps(draft(w3, a.addresses, a.name, a.block, **opts), indent=2))
                return 0
            report = Checker(w3, a.block, **opts).check(json.loads(Path(a.file).read_text()))
        except (RuntimeError, ValueError, OSError, requests.RequestException, Web3Exception) as e:
            # a failed read proves nothing either way: exit 2 keeps it apart from exit 1, a real mismatch
            print(f"error: could not read chain state: {redact(e)}", file=sys.stderr)
            return 2
        print(json.dumps(report, indent=2) if a.json else render(report))
        return 1 if report["summary"]["mismatch"] or report["summary"]["undisclosed"] else 0

    if a.cmd == "events":
        for s in [*CATALOG, *VARIANTS, *NOTE_SPECS.values()]:
            print(f"{s.severity:8} {s.source:18} {s.signature}")
        return 0

    if a.cmd == "hosted":
        from .hosted import HostedRunner
        HostedRunner(a.rpc, a.subscriptions, a.configs, a.check_interval, a.allow_private_urls).run_forever()
        return 0

    if a.cmd == "probe":
        from .probe import Prober, chain_name_for, describe, make_w3, markdown_report, suggest_config
        rc = 0

        def replay(prober, addresses, logs_w3) -> int:
            """Replay role logs for the targets and every AccessControl contract or AccessManager found above them.
            A failed replay means the holder list is incomplete: said in the report, and a non-zero exit."""
            status, done = 0, set()
            while True:
                todo = [x for x in [*addresses, *prober.seen] if x not in done and prober.seen[x].kind != "eoa"]
                if not todo:
                    return status
                for x in dict.fromkeys(todo):
                    done.add(x)
                    try:
                        if prober.seen[x].kind == "access-manager" or prober._supports_access_control(x):
                            prober.role_history(x, a.from_block, logs_w3, log=lambda m: print(m, file=sys.stderr))
                    except Exception as e:  # noqa: BLE001
                        print(f"# role history for {x} failed: {redact(e)}", file=sys.stderr)
                        prober.incomplete.append(f"role history for {x} could not be read, so its holders may be incomplete")
                        status = 2

        def output(prober, chain_name, roots) -> None:
            if a.markdown:
                print(markdown_report(prober, a.label, chain_name, roots))
            elif a.json:
                print(json.dumps({"chain": chain_name, "nodes": [dataclasses.asdict(n) for n in prober.seen.values()],
                                  "incomplete": prober.incomplete}, indent=2))

        extra = [Web3.to_checksum_address(x) for x in a.role_candidates.replace(" ", ",").split(",") if x]
        try:
            if a.config:
                # one report per chain, addresses taken from the config
                cfgs_ = load_all(a.config)
                for cfg in cfgs_:
                    # --rpc overrides a single-chain config; multi-chain configs use probe_rpc_url per chain
                    rpc = a.rpc if (a.rpc and len(cfgs_) == 1) else (cfg.probe_rpc_url or cfg.rpc_url)
                    prober = Prober(make_w3(rpc))
                    name = cfg.chain_name
                    if a.chain_name and len(cfgs_) == 1:
                        name = a.chain_name
                    elif name == "ethereum" and prober.w3.eth.chain_id != 1:    # chain_name left at its default on another chain
                        name = chain_name_for(prober.w3.eth.chain_id)
                    addrs = [c.address for c in cfg.contracts] + [s_.address for s_ in cfg.safes]
                    roots = [prober.probe(x) for x in dict.fromkeys(addrs)]
                    prober.check_roles(list(dict.fromkeys([*prober.seen.keys(), *extra])))
                    if a.roles_from_logs:
                        logs_w3 = make_w3(a.logs_rpc or cfg.rpc_url, 60)
                        rc = max(rc, replay(prober, list(dict.fromkeys(addrs)), logs_w3))
                    if a.markdown or a.json:
                        output(prober, name, roots)
                    else:
                        print(f"# {name}")
                        for n in prober.seen.values():
                            print(describe(n))
                return rc
            if not a.rpc or not a.addresses:
                p.error("probe needs --rpc and at least one address, or --config")
            prober = Prober(make_w3(a.rpc))
            if a.chain_name is None:
                a.chain_name = chain_name_for(prober.w3.eth.chain_id)
            roots = [prober.probe(x) for x in a.addresses]
            prober.check_roles(list(dict.fromkeys([*prober.seen.keys(), *extra])))
            if a.roles_from_logs:
                logs_w3 = make_w3(a.logs_rpc, 60) if a.logs_rpc else None
                rc = replay(prober, [r.address for r in roots], logs_w3)
        except (RuntimeError, ValueError, OSError, requests.RequestException, Web3Exception) as e:
            print(f"error: {redact(e)}\nhint: set probe_rpc_url in the config or pass --rpc with an RPC that serves eth_call", file=sys.stderr)
            return 2
        if a.markdown or a.json:
            output(prober, a.chain_name, roots)
            return rc
        if not a.yaml:
            for n in prober.seen.values():
                print(describe(n))
            print("\n# suggested config\n")
        print(suggest_config(prober, a.rpc, a.chain_name, a.safe_chain, a.label))
        return rc

    try:
        cfgs = load_all(a.config)
    except Exception as e:  # noqa: BLE001
        print(f"config error: {e}", file=sys.stderr)
        return 2
    if a.cmd == "validate":
        from .safe import SafeQueueWatcher
        rc = 0
        for cfg in cfgs:
            sinks = [k for k in ("discord_webhook", "slack_webhook", "telegram_bot_token", "webhook_url", "jsonl_path") if getattr(cfg.alerts, k)]
            print(f"{cfg.chain_name}: {len(cfg.contracts)} contracts, {len(cfg.treasuries)} treasuries, {len(cfg.safes)} safes, sinks: {', '.join(sinks) or 'stdout only'}")
            if cfg.custom_events:
                print(f"  custom events: {', '.join(e.name for e in cfg.custom_events)}")
            try:
                w3 = Web3(Web3.HTTPProvider(cfg.rpc_url, request_kwargs={"timeout": 15}))
                chain_id = w3.eth.chain_id
                print(f"  rpc ok, chain id {chain_id}, head {w3.eth.block_number}")
                must_have_code = [(c.label, c.address) for c in cfg.contracts]
                must_have_code += [(k.symbol, k.address) for t in cfg.treasuries for k in t.tokens]
                must_have_code += [(n.label, n.address) for t in cfg.treasuries for n in t.nfts]
                # a Safe entry for another chain's service cannot be checked on this RPC
                must_have_code += [(s_.label, s_.address) for s_ in cfg.safes if SafeQueueWatcher.CHAIN_IDS.get(s_.chain) == chain_id]
                for label, address in must_have_code:
                    if len(w3.eth.get_code(address)) == 0:
                        print(f"  ERROR {label} {address} has no code on this chain")
                        rc = 1
            except Exception as e:  # noqa: BLE001
                print(f"  rpc FAILED: {redact(e)}")
                rc = 1
        return rc
    if a.cmd == "test-alert":
        from .alerts import Alert
        rc = 0
        for cfg in cfgs:
            ok = Dispatcher(cfg.alerts).send(Alert("info", cfg.chain_name, "0x" + "00" * 20, "ownerwatch", "TestAlert", "ownerwatch",
                                                   "test alert: your sinks are wired up", 0, "-"), force=True)
            rc = rc or (0 if ok else 1)
        return rc
    if a.cmd == "backfill":
        if len(cfgs) > 1 and not a.chain:
            p.error("--chain is required for a multi-chain config")
        if a.chain:
            matches = [c for c in cfgs if c.chain_name == a.chain]
            if not matches:
                p.error(f"no chain named {a.chain!r} in config (have: {', '.join(c.chain_name for c in cfgs)})")
            cfg = matches[0]
        else:
            cfg = cfgs[0]
        # history must not page anyone: stdout and the jsonl file only, and the cursor stays where it is
        quiet = dataclasses.replace(cfg.alerts, discord_webhook="", slack_webhook="", telegram_bot_token="", telegram_chat_id="",
                                    webhook_url="", heartbeat_url="", daily_digest=False)
        w = Watcher(cfg, Dispatcher(quiet))
        try:
            n = w.scan_range(a.from_block, a.to_block)
        except Exception as e:  # noqa: BLE001
            print(f"error: could not read blocks {a.from_block}-{a.to_block}: {redact(e)}. "
                  "Backfill needs an RPC that serves old logs; a failed read says nothing about what happened.", file=sys.stderr)
            return 2
        print(f"{n} alerts in blocks {a.from_block}-{a.to_block}", file=sys.stderr)
        return 0
    watchers = build_watchers(cfgs)
    if a.once:
        rc = 0
        for w in watchers:
            try:
                w.poll_once()
            except Exception as e:  # noqa: BLE001  (one dead chain must not stop the others)
                print(f"{w.cfg.chain_name}: poll failed: {redact(e)}", file=sys.stderr)
                rc = 1
        return rc
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
