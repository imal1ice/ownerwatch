from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from web3 import Web3

from .alerts import Alert, Dispatcher
from .config import Config
from .events import ADMIN_TOPICS, BY_TOPIC, TRANSFER_SPEC, TRANSFER_TOPIC

log = logging.getLogger("ownerwatch")


def _hex(v) -> str:
    if isinstance(v, (bytes, bytearray)):
        return "0x" + bytes(v).hex()
    s = str(v)
    return s if s.startswith("0x") else "0x" + s


class Cursor:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.last_block: int | None = None
        if self.path.exists():
            self.last_block = json.loads(self.path.read_text()).get("last_block")

    def save(self, block: int) -> None:
        self.last_block = block
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"last_block": block}))


class Watcher:
    def __init__(self, cfg: Config, dispatcher: Dispatcher, w3: Web3 | None = None):
        self.cfg = cfg
        self.dispatcher = dispatcher
        self.w3 = w3 or Web3(Web3.HTTPProvider(cfg.rpc_url, request_kwargs={"timeout": 30}))
        self.labels = cfg.labels()
        self.admin_addresses = [c.address for c in cfg.contracts]
        self.cursor = Cursor(cfg.state_file)
        # decoder contracts: one per event spec, address-less
        self._decoders = {t: self.w3.eth.contract(abi=[s.abi]).events[s.name]() for t, s in BY_TOPIC.items()}
        self._transfer = self.w3.eth.contract(abi=[TRANSFER_SPEC.abi]).events.Transfer()
        self._tokens = {}
        for t in cfg.treasuries:
            for k in t.tokens:
                self._tokens.setdefault(k.address, {})[t.address] = (t, k)

    # ---- block range management -------------------------------------------------
    def _start(self) -> int:
        if self.cursor.last_block is not None:
            return self.cursor.last_block + 1
        if self.cfg.start_block == "latest":
            return self.w3.eth.block_number - self.cfg.confirmations
        return int(self.cfg.start_block)

    def poll_once(self) -> int:
        """Scan from cursor to (head - confirmations). Returns number of alerts."""
        head = self.w3.eth.block_number - self.cfg.confirmations
        start = self._start()
        if start > head:
            return 0
        n = 0
        while start <= head:
            end = min(start + self.cfg.max_block_range - 1, head)
            n += self._scan(start, end)
            self.cursor.save(end)
            start = end + 1
        return n

    def _scan(self, from_block: int, to_block: int) -> int:
        n = 0
        if self.admin_addresses:
            logs = self.w3.eth.get_logs({
                "fromBlock": from_block, "toBlock": to_block,
                "address": self.admin_addresses, "topics": [ADMIN_TOPICS]})
            for lg in logs:
                alert = self._decode_admin(lg)
                if alert:
                    self.dispatcher.send(alert)
                    n += 1
        if self._tokens:
            treasuries = sorted({a for m in self._tokens.values() for a in m})
            padded = ["0x" + "00" * 12 + a[2:].lower() for a in treasuries]
            logs = self.w3.eth.get_logs({
                "fromBlock": from_block, "toBlock": to_block,
                "address": list(self._tokens.keys()), "topics": [TRANSFER_TOPIC, padded]})
            for lg in logs:
                alert = self._decode_transfer(lg)
                if alert:
                    self.dispatcher.send(alert)
                    n += 1
        return n

    # ---- decoding -----------------------------------------------------------------
    def _decode_admin(self, lg) -> Alert | None:
        t0 = _hex(lg["topics"][0])
        spec = BY_TOPIC.get(t0)
        if not spec:
            return None
        try:
            ev = self._decoders[t0].process_log(lg)
        except Exception as e:  # noqa: BLE001
            log.debug("undecodable log %s: %s", t0, e)
            return None
        args = {k: (_hex(v) if isinstance(v, (bytes, bytearray)) else v) for k, v in dict(ev["args"]).items()}
        addr = Web3.to_checksum_address(lg["address"])
        return Alert(
            severity=spec.severity, chain=self.cfg.chain_name, contract=addr,
            label=self.labels.get(addr, addr), event=spec.name, source=spec.source,
            message=spec.describe.format(**args), block=lg["blockNumber"], tx_hash=_hex(lg["transactionHash"]))

    def _decode_transfer(self, lg) -> Alert | None:
        token_addr = Web3.to_checksum_address(lg["address"])
        try:
            ev = self._transfer.process_log(lg)
        except Exception:  # noqa: BLE001
            return None
        src = Web3.to_checksum_address(ev["args"]["from"])
        entry = self._tokens.get(token_addr, {}).get(src)
        if not entry:
            return None
        treasury, token = entry
        amount = ev["args"]["value"] / (10 ** token.decimals)
        if amount < token.min_amount:
            return None
        msg = TRANSFER_SPEC.describe.format(
            amount=f"{amount:,.2f}", symbol=token.symbol, **{"from": src, "to": ev["args"]["to"]})
        return Alert(
            severity=TRANSFER_SPEC.severity, chain=self.cfg.chain_name, contract=src,
            label=treasury.label, event="Transfer", source="ERC-20", message=msg,
            block=lg["blockNumber"], tx_hash=_hex(lg["transactionHash"]))

    # ---- main loop ----------------------------------------------------------------
    def run_forever(self) -> None:
        log.info("watching %d contracts and %d treasuries on %s", len(self.admin_addresses),
                 len(self.cfg.treasuries), self.cfg.chain_name)
        while True:
            try:
                self.poll_once()
            except Exception as e:  # noqa: BLE001
                log.warning("poll failed: %s", e)
            time.sleep(self.cfg.poll_interval_seconds)
