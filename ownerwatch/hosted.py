"""Hosted tier runner.

Customers subscribe on-chain (contracts/src/Subscriptions.sol) and send a
config YAML. The operator drops each YAML into `configs/<customer-address>.yaml`.
This runner checks `isActive(address)` for every file, starts a watcher thread
for each active customer, stops it when the subscription lapses, and reloads a
config when its file changes. Alerts go to the customer's own sinks from their YAML.
"""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

from web3 import Web3

from .alerts import Dispatcher
from .config import load_all
from .watcher import Watcher

log = logging.getLogger("ownerwatch.hosted")

SUBS_ABI = [
    {"type": "function", "name": "isActive", "stateMutability": "view",
     "inputs": [{"name": "account", "type": "address"}], "outputs": [{"name": "", "type": "bool"}]},
    {"type": "function", "name": "expiry", "stateMutability": "view",
     "inputs": [{"name": "", "type": "address"}], "outputs": [{"name": "", "type": "uint256"}]},
    {"type": "function", "name": "chainCount", "stateMutability": "view",
     "inputs": [{"name": "", "type": "address"}], "outputs": [{"name": "", "type": "uint256"}]},
]


class Customer:
    def __init__(self, address: str, path: Path, max_chains: int = 0):
        self.address = address
        self.path = path
        self.max_chains = max_chains
        self.mtime = 0.0
        self.stop = threading.Event()
        self.threads: list[threading.Thread] = []

    def start(self) -> None:
        self.stop.clear()
        self.mtime = self.path.stat().st_mtime
        cfgs = load_all(self.path)
        if self.max_chains and len(cfgs) > self.max_chains:
            log.warning("%s paid for %d chains but config has %d; running the first %d",
                        self.address, self.max_chains, len(cfgs), self.max_chains)
            cfgs = cfgs[: self.max_chains]
        for cfg in cfgs:
            cfg.state_file = str(Path("state") / "hosted" / self.address / f"{cfg.chain_name}.json")
            w = Watcher(cfg, Dispatcher(cfg.alerts))
            t = threading.Thread(target=self._loop, args=(w,), name=f"{self.address[:8]}-{cfg.chain_name}", daemon=True)
            t.start()
            self.threads.append(t)
        log.info("started %s (%d chains)", self.address, len(cfgs))

    def _loop(self, w: Watcher) -> None:
        while not self.stop.is_set():
            try:
                w.poll_once()
            except Exception as e:  # noqa: BLE001
                log.warning("%s poll failed: %s", w.cfg.chain_name, e)
            self.stop.wait(w.cfg.poll_interval_seconds)

    def halt(self) -> None:
        self.stop.set()
        for t in self.threads:
            t.join(timeout=5)
        self.threads = []
        log.info("stopped %s", self.address)

    def changed(self) -> bool:
        return self.path.exists() and self.path.stat().st_mtime != self.mtime


class HostedRunner:
    def __init__(self, rpc_url: str, subscriptions: str, configs_dir: str | Path, check_interval: int = 60):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
        self.subs = self.w3.eth.contract(address=Web3.to_checksum_address(subscriptions), abi=SUBS_ABI)
        self.dir = Path(configs_dir)
        self.interval = check_interval
        self.customers: dict[str, Customer] = {}

    def is_active(self, address: str) -> bool:
        return bool(self.subs.functions.isActive(address).call())

    def paid_chains(self, address: str) -> int:
        try:
            return int(self.subs.functions.chainCount(address).call())
        except Exception:  # noqa: BLE001
            return 0

    def reconcile(self) -> None:
        files = {}
        for p in self.dir.glob("*.yaml"):
            try:
                files[Web3.to_checksum_address(p.stem)] = p
            except ValueError:
                log.warning("ignoring %s: file name is not an address", p.name)
        for addr, path in files.items():
            try:
                active = self.is_active(addr)
            except Exception as e:  # noqa: BLE001
                log.warning("isActive(%s) failed: %s", addr, e)
                continue
            cust = self.customers.get(addr)
            if active and cust is None:
                cust = Customer(addr, path, self.paid_chains(addr))
                try:
                    cust.start()
                    self.customers[addr] = cust
                except Exception as e:  # noqa: BLE001
                    log.error("config for %s is invalid: %s", addr, e)
            elif active and cust is not None and cust.changed():
                cust.halt()
                try:
                    cust.start()
                except Exception as e:  # noqa: BLE001
                    log.error("reloaded config for %s is invalid: %s", addr, e)
                    del self.customers[addr]
            elif not active and cust is not None:
                log.info("subscription for %s lapsed", addr)
                cust.halt()
                del self.customers[addr]
        for addr in list(self.customers):
            if addr not in files:
                self.customers[addr].halt()
                del self.customers[addr]

    def run_forever(self) -> None:
        log.info("hosted runner: %s, configs in %s", self.subs.address, self.dir)
        while True:
            try:
                self.reconcile()
            except Exception as e:  # noqa: BLE001
                log.warning("reconcile failed: %s", e)
            time.sleep(self.interval)
