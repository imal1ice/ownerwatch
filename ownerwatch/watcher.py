from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from web3 import Web3

from .alerts import Alert, Dispatcher
from .config import Config
from .decode import describe_call, describe_signature_call
from .safe import SafeQueueWatcher, SafeTarget
from .events import (ADMIN_TOPICS, BY_TOPIC, ERC721_TRANSFER_SPEC, ERC1155_BATCH_SPEC, ERC1155_SINGLE_SPEC,
                     ERC1155_TOPICS, TRANSFER_SPEC, TRANSFER_TOPIC)

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
        self.balances: dict[str, int] = {}
        self.safes: dict = {}
        if self.path.exists():
            d = json.loads(self.path.read_text())
            self.last_block = d.get("last_block")
            self.balances = {k: int(v) for k, v in d.get("balances", {}).items()}
            self.safes = d.get("safes", {})

    def save(self, block: int | None = None) -> None:
        if block is not None:
            self.last_block = block
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"last_block": self.last_block,
                                         "balances": {k: str(v) for k, v in self.balances.items()},
                                         "safes": self.safes}))


class Watcher:
    def __init__(self, cfg: Config, dispatcher: Dispatcher, w3: Web3 | None = None):
        self.cfg = cfg
        self.dispatcher = dispatcher
        self.w3 = w3 or Web3(Web3.HTTPProvider(cfg.rpc_url, request_kwargs={"timeout": 30}))
        self.labels = cfg.labels()
        try:
            self.chain_id = self.w3.eth.chain_id
        except Exception:  # noqa: BLE001
            self.chain_id = None
        self.admin_addresses = [c.address for c in cfg.contracts]
        self.cursor = Cursor(cfg.state_file)
        # decoder contracts: one per event spec, address-less
        self._decoders = {t: self.w3.eth.contract(abi=[s.abi]).events[s.name]() for t, s in BY_TOPIC.items()}
        self._transfer = self.w3.eth.contract(abi=[TRANSFER_SPEC.abi]).events.Transfer()
        self._erc721 = self.w3.eth.contract(abi=[ERC721_TRANSFER_SPEC.abi]).events.Transfer()
        self._e1155_single = self.w3.eth.contract(abi=[ERC1155_SINGLE_SPEC.abi]).events.TransferSingle()
        self._e1155_batch = self.w3.eth.contract(abi=[ERC1155_BATCH_SPEC.abi]).events.TransferBatch()
        self._tokens = {}
        self._nfts = {}
        for t in cfg.treasuries:
            for k in t.tokens:
                self._tokens.setdefault(k.address, {})[t.address] = (t, k)
            for c in t.nfts:
                self._nfts.setdefault(c.address, {})[t.address] = (t, c)
        self._native = [t for t in cfg.treasuries if t.min_native_drop is not None]
        self.safe_queue = None
        if cfg.safes:
            self.safe_queue = SafeQueueWatcher([SafeTarget(s.address, s.label, s.chain) for s in cfg.safes],
                                               cfg.chain_name, cfg.safe_api_key)
            self.safe_queue.import_state(self.cursor.safes)
            self._safe_first_run = not self.cursor.safes

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
        n = 0
        if not (self.admin_addresses or self._tokens or self._nfts):
            head = start - 1  # nothing to scan on-chain
        while start <= head:
            end = min(start + self.cfg.max_block_range - 1, head)
            n += self._scan(start, end)
            self.cursor.save(end)
            start = end + 1
        n += self._check_native(head)
        n += self._check_safes()
        self.dispatcher.heartbeat()
        if self.dispatcher.maybe_digest(self.cfg.chain_name, head):
            n += 1
        return n

    def _check_safes(self) -> int:
        if not self.safe_queue:
            return 0
        alerts = self.safe_queue.poll(first_run=self._safe_first_run)
        if self.safe_queue.last_poll_ok:
            self._safe_first_run = False
        for a in alerts:
            self.dispatcher.send(a)
        self.cursor.safes = self.safe_queue.export_state()
        self.cursor.save()
        return len(alerts)

    def _check_native(self, block: int) -> int:
        n = 0
        for t in self._native:
            bal = self.w3.eth.get_balance(t.address, block_identifier=block)
            prev = self.cursor.balances.get(t.address)
            if prev is not None and prev - bal >= int(t.min_native_drop * 10**18):
                self.dispatcher.send(Alert(
                    severity="high", chain=self.cfg.chain_name, contract=t.address, label=t.label,
                    event="BalanceDrop", source="native",
                    message=f"native balance fell {(prev - bal) / 10**18:,.4f} ({prev / 10**18:,.4f} -> {bal / 10**18:,.4f})",
                    block=block, tx_hash="-"))
                n += 1
            self.cursor.balances[t.address] = bal
        if self._native:
            self.cursor.save()
        return n

    def _logs(self, params: dict, from_block: int, to_block: int, budget: list[int] | None = None) -> list:
        """eth_getLogs with bisection when the RPC rejects the range. A request
        budget stops a dead RPC from turning one chunk into thousands of calls."""
        budget = budget if budget is not None else [64]
        budget[0] -= 1
        if budget[0] < 0:
            raise RuntimeError(f"eth_getLogs request budget exhausted around blocks {from_block}-{to_block}")
        try:
            return self.w3.eth.get_logs({**params, "fromBlock": from_block, "toBlock": to_block})
        except Exception as e:  # noqa: BLE001
            if from_block == to_block:
                raise
            mid = (from_block + to_block) // 2
            log.info("rpc rejected blocks %d-%d (%s); splitting", from_block, to_block, type(e).__name__)
            return self._logs(params, from_block, mid, budget) + self._logs(params, mid + 1, to_block, budget)

    def _scan(self, from_block: int, to_block: int) -> int:
        """Fetch every log for the range first, then dispatch, so a failure in
        one query can never re-send alerts from another."""
        alerts: list[Alert] = []
        if self.admin_addresses:
            for lg in self._logs({"address": self.admin_addresses, "topics": [ADMIN_TOPICS]}, from_block, to_block):
                a = self._decode_admin(lg)
                if a:
                    alerts.append(a)
        if self._tokens:
            treasuries = sorted({a for m in self._tokens.values() for a in m})
            padded = ["0x" + "00" * 12 + a[2:].lower() for a in treasuries]
            for lg in self._logs({"address": list(self._tokens.keys()), "topics": [TRANSFER_TOPIC, padded]}, from_block, to_block):
                a = self._decode_transfer(lg)
                if a:
                    alerts.append(a)
        if self._nfts:
            treasuries = sorted({a for m in self._nfts.values() for a in m})
            padded = ["0x" + "00" * 12 + a[2:].lower() for a in treasuries]
            nft_addrs = list(self._nfts.keys())
            logs = self._logs({"address": nft_addrs, "topics": [TRANSFER_TOPIC, padded]}, from_block, to_block)
            logs += self._logs({"address": nft_addrs, "topics": [ERC1155_TOPICS, None, padded]}, from_block, to_block)
            for lg in logs:
                a = self._decode_nft(lg)
                if a:
                    alerts.append(a)
        for a in alerts:
            self.dispatcher.send(a)
        return len(alerts)

    # ---- decoding -----------------------------------------------------------------
    def _link(self, tx_hash: str) -> str:
        return f"{self.cfg.explorer_url.rstrip('/')}/tx/{tx_hash}" if self.cfg.explorer_url and tx_hash.startswith("0x") else tx_hash

    def _decode_admin(self, lg) -> Alert | None:
        try:
            return self._decode_admin_inner(lg)
        except Exception as e:  # noqa: BLE001
            log.warning("could not decode log in tx %s: %s", _hex(lg.get("transactionHash", b"")), e)
            return None

    def _decode_admin_inner(self, lg) -> Alert | None:
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
        if spec.name == "ProposalCreated":
            args["ntargets"] = len(args.get("targets") or [])
            lines = [ln.strip() for ln in str(args.get("description") or "").splitlines() if ln.strip()]
            args["title"] = lines[0][:120] if lines else "(no description)"
        msg = spec.describe.format(**args)
        if spec.name == "ProposalCreated":
            # decode each action so the alert says what the proposal does, not just that it exists
            targets, datas = args.get("targets") or [], args.get("calldatas") or []
            sigs = args.get("signatures") or []
            actions = []
            for i, (tgt, data) in enumerate(zip(targets, datas)):
                sig = sigs[i] if i < len(sigs) and sigs[i] else None   # GovernorBravo-style explicit signature
                if sig:
                    actions.append(f"{tgt}: {describe_signature_call(sig, data)}")
                else:
                    actions.append(f"{tgt}: {describe_call(data, self.chain_id, tgt)}")
                if i == 4 and len(targets) > 5:
                    actions.append(f"... {len(targets) - 5} more")
                    break
            if actions:
                msg += " | actions: " + "; ".join(actions)
        if spec.name in ("QueueTransaction", "ExecuteTransaction") and args.get("signature"):
            msg += f" = {describe_signature_call(args['signature'], args.get('data') or b'')}"
        if spec.name in ("CallScheduled", "CallExecuted"):
            msg += f" calling {describe_call(args['data'], self.chain_id, args.get('target'))}"
        return Alert(
            severity=spec.severity, chain=self.cfg.chain_name, contract=addr,
            label=self.labels.get(addr, addr), event=spec.name, source=spec.source,
            message=msg, block=lg["blockNumber"], tx_hash=self._link(_hex(lg["transactionHash"])))

    def _decode_nft(self, lg) -> Alert | None:
        coll_addr = Web3.to_checksum_address(lg["address"])
        t0 = _hex(lg["topics"][0])
        try:
            if t0 == TRANSFER_TOPIC:
                if len(lg["topics"]) != 4:
                    return None  # ERC-20 shaped Transfer on an address configured as NFT
                ev = self._erc721.process_log(lg)
                spec = ERC721_TRANSFER_SPEC
            elif t0 == ERC1155_TOPICS[0]:
                ev = self._e1155_single.process_log(lg)
                spec = ERC1155_SINGLE_SPEC
            else:
                ev = self._e1155_batch.process_log(lg)
                spec = ERC1155_BATCH_SPEC
        except Exception:  # noqa: BLE001
            return None
        src = Web3.to_checksum_address(ev["args"]["from"])
        entry = self._nfts.get(coll_addr, {}).get(src)
        if not entry:
            return None
        treasury, coll = entry
        a = dict(ev["args"])
        a["collection"] = coll.label
        if "ids" in a:
            a["count"] = len(a["ids"])
        msg = spec.describe.format(**a)
        return Alert(
            severity=spec.severity, chain=self.cfg.chain_name, contract=src, label=treasury.label,
            event=spec.name, source=spec.source, message=msg,
            block=lg["blockNumber"], tx_hash=self._link(_hex(lg["transactionHash"])))

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
            block=lg["blockNumber"], tx_hash=self._link(_hex(lg["transactionHash"])))

    # ---- main loop ----------------------------------------------------------------
    def run_forever(self) -> None:
        log.info("watching %d contracts, %d treasuries, %d safes on %s", len(self.admin_addresses),
                 len(self.cfg.treasuries), len(self.cfg.safes), self.cfg.chain_name)
        backoff = 0
        while True:
            try:
                self.poll_once()
                backoff = 0
            except Exception as e:  # noqa: BLE001
                backoff = min(backoff * 2 if backoff else 1, 16)
                log.warning("poll failed: %s (backing off x%d)", e, backoff)
            time.sleep(self.cfg.poll_interval_seconds * (backoff or 1))
