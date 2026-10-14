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


def _fmt(v) -> str:
    if isinstance(v, (bytes, bytearray)):
        return "0x" + bytes(v).hex()
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(_fmt(x) for x in v) + "]"
    return str(v)


def describe_call(data: bytes | str, chain_id: int | None = None, target: str | None = None) -> str:
    raw = _raw(data)
    if not raw:
        return "empty calldata"
    sel = "0x" + raw[:4].hex()
    if chain_id is not None and target:
        abi = verified_abi(chain_id, target)
        if abi:
            try:
                from web3 import Web3
                fn, args = Web3().eth.contract(abi=abi).decode_function_input(raw)
                inner = ", ".join(f"{k}={_fmt(v)}" for k, v in args.items())
                return f"{fn.fn_name}({inner}) [{sel}, verified]"
            except Exception as e:  # noqa: BLE001
                log.debug("abi decode failed for %s: %s", target, e)
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
