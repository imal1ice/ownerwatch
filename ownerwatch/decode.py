"""Best-effort decoding of timelock payloads via public selector databases.

Looks up the 4-byte selector on openchain.xyz, falling back to 4byte.directory,
with an in-memory cache. Fully optional: when offline the raw selector is shown.
"""
from __future__ import annotations

import logging

import requests

log = logging.getLogger("ownerwatch")
_cache: dict[str, str | None] = {}


def selector_name(data: bytes | str) -> str | None:
    raw = bytes.fromhex(data[2:]) if isinstance(data, str) else bytes(data)
    if len(raw) < 4:
        return None
    sel = "0x" + raw[:4].hex()
    if sel in _cache:
        return _cache[sel]
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
    _cache[sel] = name
    return name


def describe_call(data: bytes | str) -> str:
    raw = bytes.fromhex(data[2:]) if isinstance(data, str) else bytes(data)
    if not raw:
        return "empty calldata"
    sel = "0x" + raw[:4].hex()
    name = selector_name(raw)
    return f"{name} [{sel}]" if name else f"selector {sel}"
