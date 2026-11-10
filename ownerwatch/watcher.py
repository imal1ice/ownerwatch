from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

import requests
from eth_abi import decoding, encoding
from eth_abi.codec import ABICodec
from eth_abi.registry import BaseEquals, registry as _default_registry
from web3 import Web3

from .alerts import Alert, Dispatcher, HeartbeatGate, redact
from .config import Config
from .decode import describe_call, describe_signature_call
from .safe import SafeQueueWatcher, SafeTarget
from .events import (ADMIN_TOPICS, BY_TOPIC, DG_STATES, ERC721_TRANSFER_SPEC, ERC1155_BATCH_SPEC, ERC1155_SINGLE_SPEC,
                     ERC1155_TOPICS, NOTE_SPECS, TRANSFER_SPEC, TRANSFER_TOPIC,
                     VARIANTS_BY_TOPIC)

log = logging.getLogger("ownerwatch")

GROW_AFTER = 20     # successful chunks in a row before trying a wider eth_getLogs range again

# Decoder contracts use this codec: a proposer who puts invalid UTF-8 in a description must not make the log undecodable.
_lenient = _default_registry.copy()
_lenient.unregister("string")
_lenient.register(BaseEquals("string"), encoding.TextStringEncoder, decoding.StringDecoder(handle_string_errors="replace"), label="string")
_DECODE_W3 = Web3()
_DECODE_W3.codec = ABICodec(_lenient)


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
        self.outbox: list[dict] = []
        if self.path.exists():
            d = json.loads(self.path.read_text())
            self.last_block = d.get("last_block")
            self.balances = {k: int(v) for k, v in d.get("balances", {}).items()}
            self.safes = d.get("safes", {})
            self.outbox = d.get("outbox", [])

    def save(self, block: int | None = None) -> None:
        if block is not None:
            self.last_block = block
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # write then rename: a crash mid-write must not leave a truncated cursor behind
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps({"last_block": self.last_block,
                                   "balances": {k: str(v) for k, v in self.balances.items()},
                                   "safes": self.safes, "outbox": self.outbox}))
        os.replace(tmp, self.path)


class Watcher:
    def __init__(self, cfg: Config, dispatcher: Dispatcher, w3: Web3 | None = None):
        self.cfg = cfg
        self.dispatcher = dispatcher
        if w3 is None:
            from .probe import make_w3     # local import: probe imports alerts, as this module does
            w3 = make_w3(cfg.rpc_url)
        self.w3 = w3
        self.labels = cfg.labels()
        try:
            self.chain_id = self.w3.eth.chain_id
        except Exception:  # noqa: BLE001
            self.chain_id = None
        self.admin_addresses = [c.address for c in cfg.contracts]
        self._block_times: dict[int, str] = {}
        self.cursor = Cursor(cfg.state_file)
        self.dispatcher.outbox = list(self.cursor.outbox)
        self.should_stop = lambda: False    # the hosted runner points this at its stop event
        self._chunk = cfg.max_block_range
        self._chunk_ok = 0
        self._decimals: dict[str, int | None] = {}
        # decoder contracts: one per event spec, address-less
        self._decoders = {t: _DECODE_W3.eth.contract(abi=[s.abi]).events[s.name]() for t, s in BY_TOPIC.items()}
        self._variants = {t: [(v, _DECODE_W3.eth.contract(abi=[v.abi]).events[v.name]()) for v in vs]
                          for t, vs in VARIANTS_BY_TOPIC.items()}
        self._custom = {e.topic0: (e, _DECODE_W3.eth.contract(abi=[e.abi]).events[e.name]() if e.abi else None)
                        for e in cfg.custom_events}
        self._admin_topics = [*ADMIN_TOPICS, *self._custom]
        self._transfer = _DECODE_W3.eth.contract(abi=[TRANSFER_SPEC.abi]).events.Transfer()
        self._erc721 = _DECODE_W3.eth.contract(abi=[ERC721_TRANSFER_SPEC.abi]).events.Transfer()
        self._e1155_single = _DECODE_W3.eth.contract(abi=[ERC1155_SINGLE_SPEC.abi]).events.TransferSingle()
        self._e1155_batch = _DECODE_W3.eth.contract(abi=[ERC1155_BATCH_SPEC.abi]).events.TransferBatch()
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
                                               cfg.chain_name, cfg.safe_api_key, w3=self.w3)
            self.safe_queue.import_state(self.cursor.safes)

    # ---- block range management -------------------------------------------------
    def _start(self, head: int) -> int:
        if self.cursor.last_block is not None:
            return self.cursor.last_block + 1
        if self.cfg.start_block == "latest":
            self.cursor.save(head - 1)    # "now" is fixed on the first poll, so an outage right after start loses nothing
            return head
        return int(self.cfg.start_block)

    def _save(self, block: int | None = None) -> None:
        self.cursor.outbox = self.dispatcher.outbox
        self.cursor.save(block)

    def poll_once(self) -> int:
        """Scan from cursor to (head - confirmations), then the native balances and Safe queues. Each step runs
        even when an earlier one failed: a dead RPC must not hide the Safe queue, which has its own service.
        Returns the number of alerts; raises the first failure once every step has had its turn."""
        self.dispatcher.flush()
        n = 0
        failure: Exception | None = None
        head = None
        try:
            head = self.w3.eth.block_number - self.cfg.confirmations
            if self.admin_addresses or self._tokens or self._nfts:
                n += self.scan_range(self._start(head), head, self._save)
        except Exception as e:  # noqa: BLE001
            failure = e
        if head is not None:
            try:
                n += self._check_native(head)
            except Exception as e:  # noqa: BLE001
                failure = failure or e
        n += self._check_safes()
        self.dispatcher.flush()
        self._save()
        healthy = failure is None and not self.dispatcher.outbox and (not self.safe_queue or self.safe_queue.last_poll_ok)
        if healthy:
            self.dispatcher.heartbeat(self.cfg.chain_name)
        if head is not None and self.dispatcher.maybe_digest(self.cfg.chain_name, head):
            n += 1
        if failure:
            raise failure
        return n

    def scan_range(self, start: int, end_block: int, on_progress=None) -> int:
        """Scan start..end_block in chunks. A range the RPC rejects is halved and retried, and the working size is
        remembered, so an RPC that caps eth_getLogs at 10 blocks gets through any backlog; progress is saved after
        every chunk. A failure on a single block means the RPC itself is at fault, and propagates."""
        n = 0
        while start <= end_block and not self.should_stop():
            end = min(start + self._chunk - 1, end_block)
            try:
                n += self._scan(start, end)
            except Exception as e:  # noqa: BLE001
                if end == start or isinstance(e, requests.ConnectionError):
                    self._chunk = self.cfg.max_block_range   # the RPC is down, not picky: the size learned so far means nothing
                    raise
                self._chunk = max((end - start + 1) // 2, 1)
                self._chunk_ok = 0
                log.info("rpc rejected blocks %d-%d (%s); trying %d blocks", start, end, type(e).__name__, self._chunk)
                continue
            if on_progress:
                on_progress(end)
            start = end + 1
            self._chunk_ok += 1
            if self._chunk_ok >= GROW_AFTER and self._chunk < self.cfg.max_block_range:
                self._chunk = min(self._chunk * 2, self.cfg.max_block_range)
                self._chunk_ok = 0
        return n

    def _check_safes(self) -> int:
        if not self.safe_queue:
            return 0
        alerts = self.safe_queue.poll()
        for a in alerts:
            self.dispatcher.send(a)
        self.cursor.safes = self.safe_queue.export_state()
        self._save()
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

    def _logs(self, params: dict, from_block: int, to_block: int) -> list:
        return self.w3.eth.get_logs({**params, "fromBlock": from_block, "toBlock": to_block})

    def _scan(self, from_block: int, to_block: int) -> int:
        """Fetch every log for the range first, then dispatch, so a failure in
        one query can never re-send alerts from another."""
        alerts: list[Alert] = []
        if self.admin_addresses:
            for lg in self._logs({"address": self.admin_addresses, "topics": [self._admin_topics]}, from_block, to_block):
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
            a.block_time = self._block_time(a.block)
            self.dispatcher.send(a)
        return len(alerts)

    def _block_time(self, block: int) -> str:
        """The block's timestamp, so alerts are dated when the event happened, not when a poll noticed it."""
        if block not in self._block_times:
            try:
                ts = self.w3.eth.get_block(block)["timestamp"]
                self._block_times[block] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
            except Exception as e:  # noqa: BLE001
                log.debug("no timestamp for block %s: %s", block, e)
                return ""
        return self._block_times[block]

    # ---- decoding -----------------------------------------------------------------
    def _link(self, tx_hash: str) -> str:
        return f"{self.cfg.explorer_url.rstrip('/')}/tx/{tx_hash}" if self.cfg.explorer_url and tx_hash.startswith("0x") else tx_hash

    def _decode_admin(self, lg) -> Alert | None:
        try:
            return self._decode_admin_inner(lg)
        except Exception as e:  # noqa: BLE001
            log.warning("could not decode log in tx %s: %s", _hex(lg.get("transactionHash", b"")), e)
            return self._undecoded(lg, e)

    def _undecoded(self, lg, e: Exception) -> Alert | None:
        """The topic is in the catalog, so this is an admin event whatever its layout: raise it raw, at its usual
        severity. Dropping it would let a contract, or a proposer's crafted input, hide the event from the watcher."""
        t0 = _hex(lg["topics"][0])
        spec = NOTE_SPECS.get(t0) or BY_TOPIC.get(t0)
        if spec is None:
            return None
        addr = Web3.to_checksum_address(lg["address"])
        topics = ", ".join(_hex(t) for t in lg["topics"][1:]) or "none"
        return Alert(
            severity=spec.severity, chain=self.cfg.chain_name, contract=addr,
            label=self.labels.get(addr, addr), event=spec.name, source=spec.source,
            message=f"{spec.signature} in a layout ownerwatch cannot decode ({type(e).__name__}); "
                    f"indexed: {topics}; data: {_hex(lg['data'])[:400]}",
            block=lg["blockNumber"], tx_hash=self._link(_hex(lg["transactionHash"])))

    def _decode_admin_inner(self, lg) -> Alert | None:
        t0 = _hex(lg["topics"][0])
        if t0 in self._custom:
            return self._decode_custom(lg, *self._custom[t0])
        if t0 in NOTE_SPECS:
            return self._decode_note(lg, NOTE_SPECS[t0])
        if t0 not in BY_TOPIC:
            return None
        # a topic can have layouts that differ only in `indexed`; the first that decodes wins
        for spec, decoder in [(BY_TOPIC[t0], self._decoders[t0]), *self._variants.get(t0, [])]:
            try:
                ev = decoder.process_log(lg)
                break
            except Exception as e:  # noqa: BLE001
                log.debug("log %s does not decode as %s: %s", t0, spec.source, e)
                error = e
        else:
            raise error
        args = {k: (_hex(v) if isinstance(v, (bytes, bytearray)) else v) for k, v in dict(ev["args"]).items()}
        addr = Web3.to_checksum_address(lg["address"])
        if spec.name == "ProposalCreated":
            args["ntargets"] = len(args.get("targets") or [])
            lines = [ln.strip() for ln in str(args.get("description") or "").splitlines() if ln.strip()]
            args["title"] = lines[0][:120] if lines else "(no description)"
        if spec.name == "PayloadCreated":
            args["nactions"] = len(args.get("actions") or [])
        if spec.name == "ProposalSubmitted" and "calls" in args:
            args["ncalls"] = len(args.get("calls") or [])
        if spec.name == "DiamondCut":
            args["nfacets"] = len(args.get("_diamondCut") or [])
        if spec.name == "DualGovernanceStateChanged":
            name = lambda i: DG_STATES[i] if 0 <= i < len(DG_STATES) else str(i)
            args["fromState"], args["toState"] = name(args["from"]), name(args["to"])
        msg = spec.describe.format(**args)
        if spec.name == "PayloadCreated":
            parts = []
            for i, act in enumerate(args.get("actions") or []):
                a = act._asdict() if hasattr(act, "_asdict") else (dict(act) if hasattr(act, "keys") else
                     dict(zip(("target", "withDelegateCall", "accessLevel", "value", "signature", "callData"), act)))
                how = "delegatecall " if a.get("withDelegateCall") else ""
                sig, data = a.get("signature") or "", a.get("callData") or b""
                if isinstance(data, (bytes, bytearray)):
                    data = _hex(data)
                what = describe_signature_call(sig, data) if sig else describe_call(data, self.chain_id, a.get("target"), self.w3)
                parts.append(f"{how}{a.get('target')}: {what}")
                if i == 4 and args["nactions"] > 5:
                    parts.append(f"... {args['nactions'] - 5} more")
                    break
            if parts:
                msg += " | actions: " + "; ".join(parts)
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
                    actions.append(f"{tgt}: {describe_call(data, self.chain_id, tgt, self.w3)}")
                if i == 4 and len(targets) > 5:
                    actions.append(f"... {len(targets) - 5} more")
                    break
            if actions:
                msg += " | actions: " + "; ".join(actions)
        if spec.name in ("QueueTransaction", "ExecuteTransaction"):
            if args.get("signature"):
                msg += f" = {describe_signature_call(args['signature'], args.get('data') or b'')}"
            elif args.get("data"):   # empty signature: data is the whole calldata, selector included
                msg += f" = {describe_call(args['data'], self.chain_id, args.get('target'), self.w3)}"
        if spec.name in ("CallScheduled", "CallExecuted"):
            msg += f" calling {describe_call(args['data'], self.chain_id, args.get('target'), self.w3)}"
        return Alert(
            severity=spec.severity, chain=self.cfg.chain_name, contract=addr,
            label=self.labels.get(addr, addr), event=spec.name, source=spec.source,
            message=msg, block=lg["blockNumber"], tx_hash=self._link(_hex(lg["transactionHash"])))

    def _decode_custom(self, lg, event, decoder) -> Alert:
        """An event the config names. Config text never reaches str.format; the message is only the log's own values."""
        topics = ", ".join(_hex(t) for t in lg["topics"][1:]) or "none"
        msg = f"indexed: {topics}; data: {_hex(lg['data'])[:400]}"
        if decoder:
            try:
                args = dict(decoder.process_log(lg)["args"])
                msg = ", ".join(f"{k}={_hex(v) if isinstance(v, (bytes, bytearray)) else v}" for k, v in args.items()) or event.name
            except Exception as e:  # noqa: BLE001
                log.warning("custom event %s does not match its config signature: %s", event.name, e)
                msg = f"layout differs from the signature in the config ({type(e).__name__}); {msg}"
        addr = Web3.to_checksum_address(lg["address"])
        return Alert(
            severity=event.severity, chain=self.cfg.chain_name, contract=addr,
            label=self.labels.get(addr, addr), event=event.name, source="custom",
            message=msg, block=lg["blockNumber"], tx_hash=self._link(_hex(lg["transactionHash"])))

    def _decode_note(self, lg, spec) -> Alert | None:
        """A DSNote log (Sky's pause): rebuild the call from the calldata the note carries."""
        from eth_abi import decode as abi_decode
        _wad, fax = abi_decode(["uint256", "bytes"], bytes(lg["data"]))
        types = spec.signature[spec.signature.index("(") + 1:-1].split(",")   # no tuples in the note signatures
        values = abi_decode(types, bytes(fax)[4:])
        args = dict(zip(spec.args, values))
        args = {k: (_hex(v) if isinstance(v, (bytes, bytearray)) else v) for k, v in args.items()}
        if "usr" in args:
            args["usr"] = Web3.to_checksum_address(args["usr"])
        if "eta" in args:
            try:
                args["eta_iso"] = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(int(args["eta"])))
            except (OverflowError, OSError, ValueError):
                args["eta_iso"] = f"timestamp {args['eta']}"
        addr = Web3.to_checksum_address(lg["address"])
        return Alert(
            severity=spec.severity, chain=self.cfg.chain_name, contract=addr,
            label=self.labels.get(addr, addr), event=spec.name, source=spec.source,
            message=spec.describe.format(**args), block=lg["blockNumber"], tx_hash=self._link(_hex(lg["transactionHash"])))

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
        decimals = self._token_decimals(token)
        if decimals is None:   # unknown scale: the threshold cannot be judged, so do not stay quiet about it
            shown = f"{ev['args']['value']} base units of"
        else:
            amount = ev["args"]["value"] / (10 ** decimals)
            if amount < token.min_amount:
                return None
            shown = f"{amount:,.2f}"
        msg = TRANSFER_SPEC.describe.format(
            amount=shown, symbol=token.symbol, **{"from": src, "to": ev["args"]["to"]})
        return Alert(
            severity=TRANSFER_SPEC.severity, chain=self.cfg.chain_name, contract=src,
            label=treasury.label, event="Transfer", source="ERC-20", message=msg,
            block=lg["blockNumber"], tx_hash=self._link(_hex(lg["transactionHash"])))

    def _token_decimals(self, token) -> int | None:
        """decimals from the config, else from the token itself. Guessing 18 would hide a 50M USDC transfer."""
        if token.decimals is not None:
            return token.decimals
        if token.address not in self._decimals:
            try:
                raw = self.w3.eth.call({"to": token.address, "data": "0x313ce567"})   # decimals()
                self._decimals[token.address] = int.from_bytes(bytes(raw), "big") if len(raw) == 32 else None
            except Exception as e:  # noqa: BLE001
                log.warning("decimals() failed for %s: %s", token.symbol, redact(e))
                return None
        return self._decimals[token.address]

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
                log.warning("poll failed: %s (backing off x%d)", redact(e), backoff)
            time.sleep(self.cfg.poll_interval_seconds * (backoff or 1))


def build_watchers(cfgs: list[Config]) -> list[Watcher]:
    """One Watcher per chain. Chains that share a heartbeat URL share a gate, so the URL stays healthy only when all of them are."""
    watchers = [Watcher(c, Dispatcher(c.alerts)) for c in cfgs]
    by_url: dict[str, list[Watcher]] = {}
    for w in watchers:
        if w.cfg.alerts.heartbeat_url:
            by_url.setdefault(w.cfg.alerts.heartbeat_url, []).append(w)
    for group in by_url.values():
        if len(group) > 1:
            gate = HeartbeatGate({w.cfg.chain_name for w in group})
            for w in group:
                w.dispatcher.heartbeat_gate = gate
    return watchers
