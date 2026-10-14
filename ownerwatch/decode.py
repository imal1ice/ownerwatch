"""Best-effort decoding of calldata in timelock and Safe alerts.

Order of attempts:
1. Sourcify (verified ABI for the target on this chain): full function + args.
2. openchain.xyz, then 4byte.directory: function signature only.
3. Raw selector.
Every lookup is cached in memory and fully optional; offline you still get
the selector.
"""
from __future__ import annotations

import logging

import requests

log = logging.getLogger("ownerwatch")
_sel_cache: dict[str, str | None] = {}
_abi_cache: dict[tuple[int, str], list | None] = {}


def _raw(data: bytes | str) -> bytes:
    return bytes.fromhex(data[2:]) if isinstance(data, str) else bytes(data)


def selector_name(data: bytes | str) -> str | None:
    raw = _raw(data)
    if len(raw) < 4:
        return None
    sel = "0x" + raw[:4].hex()
    if sel in _sel_cache:
        return _sel_cache[sel]
    name = None
    try:
        r = requests.get("https://api.openchain.xyz/signature-database/v1/lookup",
                         params={"function": sel, "filter": "true"}, timeout=5)
        hits = (r.json().get("result", {}).get("function", {}) or {}).get(sel) or []
        if hits:
            name = hits[0]["name"]
    except Exception as e:  # noqa: BLE001
        log.debug("openchain lookup failed: %s", e)
    if name is None:
        try:
            r = requests.get("https://www.4byte.directory/api/v1/signatures/",
                             params={"hex_signature": sel, "ordering": "created_at"}, timeout=5)
            res = r.json().get("results") or []
            if res:
                name = res[0]["text_signature"]
        except Exception as e:  # noqa: BLE001
            log.debug("4byte lookup failed: %s", e)
    _sel_cache[sel] = name
    return name


def verified_abi(chain_id: int, address: str) -> list | None:
    key = (chain_id, address.lower())
    if key in _abi_cache:
        return _abi_cache[key]
    abi = None
    try:
        r = requests.get(f"https://sourcify.dev/server/v2/contract/{chain_id}/{address}", params={"fields": "abi"}, timeout=8)
        if r.status_code == 200:
            abi = r.json().get("abi") or None
    except Exception as e:  # noqa: BLE001
        log.debug("sourcify lookup failed: %s", e)
    _abi_cache[key] = abi
    return abi


MAX_ARG = 80      # characters per argument before clipping
MAX_LIST = 4      # list items shown before "... n more"


def _fmt(v) -> str:
    if isinstance(v, (bytes, bytearray)):
        return _clip("0x" + bytes(v).hex())
    if isinstance(v, dict):   # decoded struct
        return "{" + ", ".join(f"{k}={_fmt(x)}" for k, x in v.items()) + "}"
    if isinstance(v, (list, tuple)):
        items = [_fmt(x) for x in v[:MAX_LIST]]
        if len(v) > MAX_LIST:
            items.append(f"... {len(v) - MAX_LIST} more")
        return "[" + ", ".join(items) + "]"
    return _clip(str(v))


def _clip(s: str) -> str:
    return s if len(s) <= MAX_ARG else s[:MAX_ARG - 1] + "…"


IMPL_SLOT = int("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16)


def implementation_of(w3, address: str) -> str | None:
    """ERC-1967 implementation, else slot 0 if it holds an address (Safe proxies keep the singleton there)."""
    try:
        for slot in (IMPL_SLOT, 0):
            v = bytes(w3.eth.get_storage_at(address, slot))
            if int.from_bytes(v[:12], "big") == 0 and int.from_bytes(v[12:], "big") != 0:
                from web3 import Web3
                cand = Web3.to_checksum_address("0x" + v[12:].hex())
                if len(w3.eth.get_code(cand)) > 0:
                    return cand
    except Exception as e:  # noqa: BLE001
        log.debug("implementation lookup failed for %s: %s", address, e)
    return None


def _try_abi_decode(abi: list, raw: bytes, sel: str, note: str) -> str | None:
    try:
        from web3 import Web3
        fn, args = Web3().eth.contract(abi=abi).decode_function_input(raw)
        inner = ", ".join(f"{k}={_fmt(v)}" for k, v in args.items())
        return f"{fn.fn_name}({inner}) [{sel}, {note}]"
    except Exception as e:  # noqa: BLE001
        log.debug("abi decode failed: %s", e)
        return None


def describe_call(data: bytes | str, chain_id: int | None = None, target: str | None = None, w3=None) -> str:
    raw = _raw(data)
    if not raw:
        return "empty calldata"
    sel = "0x" + raw[:4].hex()
    if chain_id is not None and target:
        abi = verified_abi(chain_id, target)
        if abi:
            out = _try_abi_decode(abi, raw, sel, "verified")
            if out:
                return out
        if w3 is not None:
            impl = implementation_of(w3, target)
            if impl:
                abi = verified_abi(chain_id, impl)
                if abi:
                    out = _try_abi_decode(abi, raw, sel, "verified via implementation")
                    if out:
                        return out
    name = selector_name(raw)
    return f"{name} [{sel}]" if name else f"selector {sel}"


def describe_signature_call(signature: str, data: bytes | str) -> str:
    """GovernorBravo/legacy Timelock style: explicit 'fn(type,type)' plus args-only calldata."""
    raw = _raw(data)
    try:
        from eth_abi import decode as abi_decode
        types_str = signature[signature.index("(") + 1: signature.rindex(")")]
        types = [t.strip() for t in types_str.split(",") if t.strip()]
        if not types:
            return signature
        try:
            values = abi_decode(types, raw)
        except Exception:  # noqa: BLE001
            if len(raw) % 32 != 4:
                raise
            values = abi_decode(types, raw[4:])   # proposer included the selector as well as the signature
        return f"{signature[:signature.index('(')]}({', '.join(_fmt(v) for v in values)})"
    except Exception as e:  # noqa: BLE001
        log.debug("signature decode failed for %s: %s", signature, e)
        return signature
