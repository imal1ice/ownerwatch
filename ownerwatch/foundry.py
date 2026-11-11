"""`probe --foundry`: a Foundry test that pins the admin surface the probe saw. Run on a fork of the live chain,
`forge test` fails and names what changed when an owner, proxy slot, role, Safe or timelock delay drifts.

Every pin is read again here, at the probe's block, with the exact call the test makes, and goes in only when that
read gives what the probe reported. Anything else becomes a `// not pinned: <why>` line: nothing is dropped."""
from __future__ import annotations

import re
import time

from eth_abi import decode as abi_decode
from web3 import Web3

from . import __version__
from .alerts import redact
from .probe import (ADMIN_SLOT, AM_PUBLIC_ROLE, BEACON_SLOT, IMPL_SLOT, LEGACY_ADMIN_SLOT, LEGACY_IMPL_SLOTS, ROLES,
                    SAFE_GUARD_SLOT, ZERO, Node, Prober, _clone_target, _pad, _sel)

RPC_ENV = "OWNERWATCH_RPC_URL"
# (slot, Solidity constant, label); only the ERC-1967 three are pinned when empty, on proxies
ERC1967 = ((IMPL_SLOT, "IMPLEMENTATION_SLOT", "ERC-1967 implementation slot"), (ADMIN_SLOT, "ADMIN_SLOT", "ERC-1967 admin slot"),
           (BEACON_SLOT, "BEACON_SLOT", "ERC-1967 beacon slot"))
LEGACY = ((LEGACY_IMPL_SLOTS[0], "ZOS_IMPLEMENTATION_SLOT", "ZeppelinOS implementation slot"),
          (LEGACY_IMPL_SLOTS[1], "PROXIABLE_SLOT", "PROXIABLE implementation slot"),
          (LEGACY_ADMIN_SLOT, "ZOS_ADMIN_SLOT", "ZeppelinOS admin slot"))
IMPL_SLOTS = (IMPL_SLOT, *LEGACY_IMPL_SLOTS)
ADMIN_SLOTS = (ADMIN_SLOT, LEGACY_ADMIN_SLOT)
SAFE_SENTINEL = "0x" + "00" * 19 + "01"
PENDING_GRANT = re.compile(r"^pending grant: role (\d+) goes to (?:EOA )?(0x[0-9a-fA-F]{40})")
KIND = {"address": "ADDRESS", "uint": "UINT", "bool": "BOOL"}


def _text(s: object) -> str:
    """Text from the chain or a verified ABI, made safe for a Solidity comment or string literal: printable ASCII
    without quotes, backslashes or line breaks, and no RPC key."""
    return re.sub(r"[^A-Za-z0-9 _.,:;()\[\]$#@+=<>/'-]", "?", redact(str(s)))


def _a(addr: str) -> str:
    """An address literal Solidity accepts: checksummed, or address(0)."""
    return "address(0)" if int(addr, 16) == 0 else Web3.to_checksum_address(addr)


def _show(w: int, kind: str) -> str:
    if kind == "address" and w < 2**160:
        return Web3.to_checksum_address(w.to_bytes(20, "big"))
    return {1: "true", 0: "false"}.get(w, str(w)) if kind == "bool" else str(w) if kind == "uint" else hex(w)


def _w(r: bytes | None, i: int = 0) -> int | None:
    return int.from_bytes(r[32 * i:32 * i + 32], "big") if r and len(r) >= 32 * (i + 1) else None


def arg_addr(a: str) -> tuple[bytes, str]:
    return _pad(Web3.to_checksum_address(a)), _a(a)


def arg_uint(v: int, typ: str) -> tuple[bytes, str]:
    return v.to_bytes(32, "big"), f"{typ}({v})"


def arg_b32(h: bytes) -> tuple[bytes, str]:
    return h, f"bytes32(0x{h.hex()})" if any(h) else "bytes32(0)"


def _packed(addrs: list[str], var: str = "l") -> tuple[list[str], str]:
    """abi.encodePacked of an address list: inline when short, else built up in `var` four at a time, because a
    long argument list does not fit on the EVM stack at compile time."""
    chunks = [", ".join(_a(a) for a in addrs[i:i + 4]) for i in range(0, len(addrs), 4)] or [""]
    if len(chunks) == 1:
        return [], f"abi.encodePacked({chunks[0]})"
    return ([f"{var} = abi.encodePacked({chunks[0]});"] + [f"{var} = bytes.concat({var}, abi.encodePacked({c}));" for c in chunks[1:]],
            var)


class _Test:
    """The pins of one probed address: one test function that reports every difference it finds."""

    def __init__(self, n: Node):
        self.n = n
        self.lines: list[str] = []
        self.gaps: list[str] = []
        self.done: set[str] = set()      # Node facts a pin reproduces
        self.why: dict[str, str] = {}    # Node fact -> why no pin reproduces it
        self.pins = 0
        self.uses_list = False

    def ref(self, address: str) -> str:
        return "t" if address == self.n.address else _a(address)


class _Writer:
    def __init__(self, prober: Prober, chain_name: str, block: int, roots: list[Node]):
        self.p, self.w3, self.chain_name, self.block, self.roots = prober, prober.w3, chain_name, block, roots
        self.pinned: set[tuple] = set()            # reads already pinned, e.g. a beacon that several proxies share
        self._names: dict[str, dict[str, str]] = {}
        # the addresses the probe tests for roles: every node it saw (role holders and --role-candidates among them)
        # and address(0); the AccessManager pass also tests Safe signers. A grant to one of these is caught even
        # where a contract cannot list its members.
        order = lambda xs: sorted({Web3.to_checksum_address(a) for a in xs}, key=lambda a: int(a, 16))  # noqa: E731
        self.known = order({ZERO, *self.p.seen, *(h for n in self.p.seen.values() for hs in n.roles.values() for h in hs)})
        self.signers = [a for a in order(a for n in self.p.seen.values() for a in n.safe_owners) if a not in self.known]

    # ---- reads at the pinned block ----
    def call(self, to: str, data: bytes, sender: str | None = None) -> bytes | None:
        return self.p._eth_call({"to": to, "data": data, **({"from": sender} if sender else {})})

    def word(self, to: str, sig: str, args=(), index: int = 0, sender: str | None = None) -> int | None:
        return _w(self.call(to, _sel(sig) + b"".join(a[0] for a in args), sender), index)

    def storage(self, address: str, slot: int) -> int:
        return int.from_bytes(bytes(self.w3.eth.get_storage_at(address, slot)), "big")

    # ---- pins ----
    def pin(self, t: _Test, fact: str | None, target: str, sig: str, kind: str, expect: int | None, args=(), index: int = 0,
            sender: str | None = None, label: str | None = None) -> int | None:
        """Pin word `index` of target.sig(args) when it reads as `expect` (any value when expect is None). Returns the
        word read; records why when the read does not reproduce the probe's value."""
        data = _sel(sig) + b"".join(a[0] for a in args)
        w = _w(self.call(target, data, sender), index)
        label = label or (sig if target == t.n.address else f"{sig} of {target}")
        if w is not None and kind == "address" and w >= 2**160:
            w = None      # not an address: the probe reads none from this word either
        if w is None or (expect is not None and w != expect):
            if fact:
                now = "reverts or returns nothing" if w is None else f"returns {_show(w, kind)}"
                t.why.setdefault(fact, f"{label} {now} at block {self.block}" + (f", not {_show(expect, kind)}" if expect is not None else ""))
            return w
        if fact:
            t.done.add(fact)
        key = (target, data, index, sender)
        if key in self.pinned:
            return w
        self.pinned.add(key)
        sol_data = f'abi.encodeWithSignature("{sig}"' + "".join(f", {a[1]}" for a in args) + ")"
        value = _a(_show(w, "address")) if kind == "address" else ("true" if w else "false") if kind == "bool" else str(w)
        if sender:
            t.lines.append(f'_addrFrom({t.ref(target)}, {sol_data}, {_a(sender)}, {value}, "{_text(label)}");')
        elif index:
            value = f"uint160({value})" if kind == "address" else ("1" if w else "0") if kind == "bool" else value
            t.lines.append(f'_word({t.ref(target)}, {sol_data}, {index}, {value}, {KIND[kind]}, "{_text(label)}");')
        else:
            t.lines.append(f'_{"addr" if kind == "address" else kind}({t.ref(target)}, {sol_data}, {value}, "{_text(label)}");')
        t.pins += 1
        return w

    def pin_slot(self, t: _Test, target: str, slot: int, const: str, label: str) -> int:
        w = self.storage(target, slot)
        key = (target, slot)
        if key not in self.pinned:
            self.pinned.add(key)
            t.lines.append(f'_slot({t.ref(target)}, {const}, {_a(_show(w, "address"))}, "{_text(label)}");')
            t.pins += 1
        return w

    def pin_list(self, t: _Test, fact: str, target: str, sig: str, types: list[str], args=(), expect: list[str] | None = None) -> list[str] | None:
        data = _sel(sig) + b"".join(a[0] for a in args)
        r = self.call(target, data)
        try:
            now = [Web3.to_checksum_address(a) for a in abi_decode(types, r)[0]] if r else None
        except Exception:  # noqa: BLE001
            now = None
        if now is None or (expect is not None and sorted(now) != sorted(expect)):
            t.why.setdefault(fact, f"{sig} {'cannot be read' if now is None else 'returns another list'} at block {self.block}")
            return now
        t.done.add(fact)
        pre, expr = _packed(now)
        t.uses_list |= bool(pre)
        sol_data = f'abi.encodeWithSignature("{sig}"' + "".join(f", {a[1]}" for a in args) + ")"
        t.lines += pre + [f'_list({t.ref(target)}, {sol_data}, {expr}, "{_text(sig)}");']
        t.pins += 1
        return now

    def not_held(self, t: _Test, sig: str, role: tuple[bytes, str], name: str, skip: list[str], among: str = "_known()") -> None:
        pre, expr = _packed(skip)
        t.uses_list |= bool(pre)
        t.lines += pre + [f'_notHeld(t, "{sig}", {role[1]}, "{_text(name)}", {among}, {expr});']
        t.pins += 1

    # ---- one probed address ----
    def node(self, n: Node) -> _Test:
        t = _Test(n)
        if n.kind == "eoa":
            self._eoa(t)
            return t
        self._proxy(t)
        self._getters(t)
        if n.kind == "safe":
            self._safe(t)
        if n.diamond:
            self._diamond(t)
        self._delay(t)
        self._access_control(t)
        if n.kind == "access-manager":
            self._access_manager(t)
        if n.kernel:
            t.gaps.append(f"who may upgrade this Aragon app or change its permissions: that lives in the ACL of kernel {n.kernel}, "
                          "which the probe does not read")
        self._coverage(t)
        return t

    def _eoa(self, t: _Test) -> None:
        n = t.n
        want = (bytes.fromhex("ef0100") + bytes.fromhex(n.delegate[2:])) if n.delegate else b""
        if bytes(self.w3.eth.get_code(n.address)) != want:
            t.gaps.append(f"its code: it no longer reads as at probe time (block {self.block})")
            return
        what = f"code (EIP-7702 delegation to {n.delegate})" if n.delegate else "code (an EOA: none)"
        t.lines.append(f'_code(t, hex"{want.hex()}", "{what}");')
        t.pins += 1

    def _proxy(self, t: _Test) -> None:
        n = t.n
        words = {s: self.storage(n.address, s) for s, _, _ in (*ERC1967, *LEGACY)}
        is_proxy = n.kind == "proxy" or bool(n.implementation or n.beacon or any(words[s] for s, _, _ in ERC1967))
        for slot, const, label in (*ERC1967, *LEGACY):
            w = words[slot]
            # a word with dirty high bytes is not an address, and the probe reads none from it
            if w >= 2**160 or (not w and (slot not in (IMPL_SLOT, ADMIN_SLOT, BEACON_SLOT) or not is_proxy)):
                continue
            self.pin_slot(t, n.address, slot, const, label)
            a = _show(w, "address")
            if a == n.implementation and slot in IMPL_SLOTS:
                t.done.add("implementation")
            if a == n.proxy_admin and slot in ADMIN_SLOTS:
                t.done.add("proxy_admin")
            if a == n.beacon and slot == BEACON_SLOT:
                t.done.add("beacon")
        if n.clone_of:
            code = bytes(self.w3.eth.get_code(n.address))
            if _clone_target(code) == n.clone_of:
                t.lines.append(f'_code(t, hex"{code.hex()}", "code (EIP-1167 clone of {n.clone_of}, fixed)");')
                t.pins += 1
                t.done.add("clone_of")
            if n.beacon and "beacon" not in t.done and self.storage(n.clone_of, BEACON_SLOT) == int(n.beacon, 16):
                self.pin_slot(t, n.clone_of, BEACON_SLOT, "BEACON_SLOT", f"ERC-1967 beacon slot of clone target {n.clone_of}")
                t.done.add("beacon")
        if n.beacon:
            # beacon proxies upgrade when the beacon's implementation changes
            expect = int(n.implementation, 16) if n.implementation and "implementation" not in t.done else None
            self.pin(t, "implementation" if expect else None, n.beacon, "implementation()", "address", expect,
                     label=f"implementation() of beacon {n.beacon}")
            b = self.p.seen.get(n.beacon)
            if b is not None and n.proxy_admin and n.proxy_admin in (b.owner, b.proxy_admin, b.admin):
                t.done.add("proxy_admin")     # pinned in the beacon's own test
        if n.proxy_admin and "proxy_admin" not in t.done:
            want = int(n.proxy_admin, 16)
            if n.admin_factory:
                self.pin(t, "proxy_admin", n.admin_factory, "adminOf(address)", "address", want, [arg_addr(n.address)],
                         label=f"adminOf({n.address}) on factory {n.admin_factory}")
            elif n.implementation and self.word(n.address, "admin()", sender=n.proxy_admin) == want:
                # immutable admin in the bytecode: the proxy names it only when asked by the admin itself
                self.pin(t, "proxy_admin", n.address, "admin()", "address", want, sender=n.proxy_admin,
                         label=f"admin() asked by {n.proxy_admin}")
            elif self.word(n.address, "upgradeAdmin()") == want:
                self.pin(t, "proxy_admin", n.address, "upgradeAdmin()", "address", want)

    def _getters(self, t: _Test) -> None:
        n = t.n
        for fact, sig in (("owner", "owner()"), ("pending_owner", "pendingOwner()")):
            v = getattr(n, fact)
            if v:
                self.pin(t, fact, n.address, sig, "address", int(v, 16))
            elif self.call(n.address, _sel(sig)) == bytes(32):
                self.pin(t, None, n.address, sig, "address", 0)      # unset, or renounced: taking it is a change
        if n.admin and n.admin != n.proxy_admin:
            self.pin(t, "admin", n.address, "admin()", "address", int(n.admin, 16))
        for fact, sig in (("kernel", "kernel()"), ("dao", "dao()"), ("emergency", "emergency()"), ("authority", "authority()")):
            if getattr(n, fact):
                self.pin(t, fact, n.address, sig, "address", int(getattr(n, fact), 16))
        if n.authorizer:
            auth = self.pin(t, None, n.address, "getAuthorizer()", "address", None)
            if auth is not None and _show(auth, "address") == n.authorizer:
                t.done.add("authorizer")
            elif auth is not None:
                self.pin(t, "authorizer", _show(auth, "address"), "getActualAuthorizer()", "address", int(n.authorizer, 16))
        for label, a in n.named.items():
            self.pin(t, f"named {label}", n.address, label.split(" ")[0], "address", int(a, 16))
        for ward in n.wards:
            self.pin(t, f"ward {ward}", n.address, "wards(address)", "uint", 1, [arg_addr(ward)], label=f"wards({ward})")
        if n.paused is not None:
            self.pin(t, "paused", n.address, "paused()", "bool", int(n.paused))
        for note in n.notes:
            m = PENDING_GRANT.match(note)
            if m and n.kind == "access-manager":
                role, who = int(m.group(1)), Web3.to_checksum_address(m.group(2))
                self.pin(t, f"pending {role} {who}", n.address, "getAccess(uint64,address)", "uint", None,
                         [arg_uint(role, "uint64"), arg_addr(who)], label=f"getAccess({role}, {who}) (pending grant: takes effect at)")

    def _diamond(self, t: _Test) -> None:
        """Pin an EIP-2535 Diamond's facet set: facetAddresses() must return the same facets. A diamondCut
        that adds, removes or replaces a facet changes this list, so the drift test fails naming it -- the
        only check that catches a facet-level code upgrade, which no ERC-1967 slot reveals."""
        n = t.n
        self.pin_list(t, "facets", n.address, "facetAddresses()", ["address[]"], expect=n.facets)

    def _safe(self, t: _Test) -> None:
        n = t.n
        self.pin(t, "safe_threshold", n.address, "getThreshold()", "uint", n.safe_threshold)
        self.pin_list(t, "safe_owners", n.address, "getOwners()", ["address[]"], expect=n.safe_owners)
        mods = self.pin_list(t, "safe_modules", n.address, "getModulesPaginated(address,uint256)", ["address[]", "address"],
                             [arg_addr(SAFE_SENTINEL), arg_uint(50, "uint256")], expect=n.safe_modules)
        if mods is not None and len(mods) >= 50:
            t.gaps.append("modules past the first 50: the probe reads one page of 50")
        if n.safe_guard:
            w = self.pin_slot(t, n.address, SAFE_GUARD_SLOT,
                              "0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8",
                              "Safe transaction guard (guard_manager.guard.address slot)")
            if w == int(n.safe_guard, 16):
                t.done.add("safe_guard")

    def _delay(self, t: _Test) -> None:
        n = t.n
        if n.kind in ("timelock", "legacy-timelock"):
            levels = []
            for level in (1, 2):    # Aave PayloadsController: an executor and its delay per access level
                r = self.call(n.address, _sel("getExecutorSettingsByAccessControl(uint8)") + level.to_bytes(32, "big"))
                if r and len(r) >= 64:
                    sig, arg = "getExecutorSettingsByAccessControl(uint8)", [arg_uint(level, "uint8")]
                    ex = self.pin(t, None, n.address, sig, "address", None, arg, label=f"executor of access level {level}")
                    d = self.pin(t, None, n.address, sig, "uint", None, arg, index=1, label=f"delay of access level {level}")
                    if ex and d is not None:
                        levels.append(d)
            if n.delay is not None and levels and min(levels) == n.delay:
                t.done.add("delay")
        if n.delay is not None and "delay" not in t.done:
            # the getter the probe took the delay from: OpenZeppelin, Aave executor, Solady, then Compound / DSPause / custom
            for sig in ("getMinDelay()", "getDelay()", "minDelay()", "delay()"):
                if self.word(n.address, sig) == n.delay:
                    self.pin(t, "delay", n.address, sig, "uint", n.delay)
                    if sig == "minDelay()" and not n.roles:
                        t.gaps.append("its proposer, executor and canceller roles: a minDelay() timelock (Solady) keeps them behind "
                                      "hasRole(address,uint256), which the probe does not read")
                    break
        if n.open_executor is not None:
            self.pin(t, "open_executor", n.address, "hasRole(bytes32,address)", "bool", int(n.open_executor),
                     [arg_b32(ROLES["EXECUTOR_ROLE"]), arg_addr(ZERO)], label="hasRole(EXECUTOR_ROLE, address(0)) (open executor)")

    def _role_ids(self, n: Node, name: str) -> list[bytes]:
        """The role ids a role name in the probe's output can stand for. A getter can return any hash
        (POOL_ADMIN_ROLE() is keccak256("POOL_ADMIN") in Aave), so names come from the contract, never from keccak(name)."""
        if re.fullmatch(r"0x[0-9a-fA-F]{64}", name):
            return [bytes.fromhex(name[2:])]
        ids = [bytes(ROLES[name])] if name in ROLES else []
        if name not in ROLES or n.address in self.p.replayed:
            if n.address not in self._names:
                self._names[n.address] = self.p.role_names(n.address)
            ids += [bytes.fromhex(h[2:]) for h, g in self._names[n.address].items() if g == name]
        return list(dict.fromkeys(ids))

    def _access_control(self, t: _Test) -> None:
        n = t.n
        # exactly one word, as the probe requires: a catch-all fallback answers every call with more
        sup = self.call(n.address, _sel("hasRole(bytes32,address)") + bytes(32) + _pad(ZERO))
        if n.kind in ("eoa", "safe") or sup is None or len(sup) != 32:
            for name, holders in n.roles.items():
                t.why.update({f"role {name} {h}": f"hasRole(bytes32,address) does not answer at block {self.block}" for h in holders})
            return
        roles: dict[bytes, str] = {bytes(v): k for k, v in ROLES.items()}
        held: dict[bytes, list[str]] = {}
        for name, holders in n.roles.items():
            ids = self._role_ids(n, name)
            for h in holders:
                hit = next((i for i in ids if self.word(n.address, "hasRole(bytes32,address)", [arg_b32(i), arg_addr(h)]) == 1), None)
                if hit is None:
                    t.why[f"role {name} {h}"] = (f"hasRole is false at block {self.block} for every role id {name} can stand for" if ids
                                                 else f"the role id behind the name {name} is not known")
                    continue
                # a getter named like a common role can return another id: keep the two apart in messages
                roles.setdefault(hit, name if bytes(ROLES.get(name, hit)) == hit else f"{name} 0x{hit.hex()[:8]}")
                held.setdefault(hit, []).append(h)
                t.done.add(f"role {name} {h}")
        r = self.call(n.address, _sel("getRoleMemberCount(bytes32)") + bytes(32))
        count = _w(r) if r and len(r) == 32 else None
        for rid, name in roles.items():
            role = arg_b32(rid)
            # every address the file knows, read in one batch: holders the probe did not report are pinned too
            calls = [(n.address, _sel("hasRole(bytes32,address)") + rid + _pad(a)) for a in self.known]
            have = [a for a, r in zip(self.known, self.p._batch_calls(calls)) if r and len(r) == 32 and _w(r) == 1]
            explicit = [ZERO] if rid == ROLES["EXECUTOR_ROLE"] and n.open_executor is not None else []
            holders = list(dict.fromkeys(held.get(rid, []) + [a for a in have if a not in explicit]))
            for h in holders:
                self.pin(t, None, n.address, "hasRole(bytes32,address)", "bool", 1, [role, arg_addr(h)], label=f"hasRole({name}, {h})")
            if count is not None:
                c = self.pin(t, None, n.address, "getRoleMemberCount(bytes32)", "uint", None, [role], label=f"getRoleMemberCount({name})")
                if c is not None and c > len(holders):
                    t.gaps.append(f"{c - len(holders)} of the {c} {name} members by address: the probe lists up to 50 and "
                                  "tests the addresses it knows; the member count is pinned")
            else:
                self.not_held(t, "hasRole(bytes32,address)", role, name, holders + explicit)
        if count is None:
            t.gaps.append(f"a role granted to an address this file does not list: the contract does not enumerate members, so "
                          f"the {len(self.known)} addresses in _known() are the ones checked")
        if n.address not in self.p.replayed:
            t.gaps.append(f"role ids other than the {len(roles)} pinned here: the probe tests the {len(ROLES)} common role names; "
                          "--roles-from-logs replays every grant")

    def _access_manager(self, t: _Test) -> None:
        m = t.n
        roles = ({0} | set(m.am_roles) | set(m.am_gates) | set(m.am_role_admin) | set(m.am_role_admin.values())
                 | set(m.am_grant_delay)) - {AM_PUBLIC_ROLE}
        for r in sorted(roles):
            rid = arg_uint(r, "uint64")
            among = self.known + self.signers
            calls = [(m.address, _sel("hasRole(uint64,address)") + r.to_bytes(32, "big") + _pad(a)) for a in among]
            have = {a for a, res in zip(among, self.p._batch_calls(calls)) if _w(res)}
            holders = list(dict.fromkeys([h for h, _ in m.am_roles.get(r, [])] + sorted(have)))
            for h, delay in m.am_roles.get(r, []):
                ok = self.pin(t, None, m.address, "hasRole(uint64,address)", "bool", 1, [rid, arg_addr(h)], label=f"hasRole({r}, {h})")
                d = self.pin(t, None, m.address, "hasRole(uint64,address)", "uint", delay, [rid, arg_addr(h)], index=1,
                             label=f"execution delay of role {r} for {h}")
                if ok == 1 and d == delay:
                    t.done.add(f"am_role {r} {h}")
                else:
                    t.why[f"am_role {r} {h}"] = f"hasRole({r}, {h}) at block {self.block} is not (true, {delay})"
            for h in holders:
                if all(h != x for x, _ in m.am_roles.get(r, [])):
                    self.pin(t, None, m.address, "hasRole(uint64,address)", "bool", 1, [rid, arg_addr(h)], label=f"hasRole({r}, {h})")
            self.not_held(t, "hasRole(uint64,address)", (b"", f"bytes32(uint256({r}))"), str(r), holders,
                          "bytes.concat(_known(), _signers())" if self.signers else "_known()")
            got = self.pin(t, None, m.address, "getRoleAdmin(uint64)", "uint", None, [rid], label=f"getRoleAdmin({r})")
            if r in m.am_role_admin and got == m.am_role_admin[r]:
                t.done.add(f"am_role_admin {r}")
            self.pin(t, None, m.address, "getRoleGuardian(uint64)", "uint", None, [rid], label=f"getRoleGuardian({r})")
            got = self.pin(t, None, m.address, "getRoleGrantDelay(uint64)", "uint", None, [rid], label=f"getRoleGrantDelay({r})")
            if r in m.am_grant_delay and got == m.am_grant_delay[r]:
                t.done.add(f"am_grant_delay {r}")
        gates = {(label, r) for r, labels in m.am_gates.items() for label in labels} | {(label, AM_PUBLIC_ROLE) for label in m.am_open}
        # the targets the probe mapped, and any that only the role replay's TargetFunctionRoleUpdated logs named
        targets = {x.address: x for x in self.p._am_targets(m)}
        targets.update({label.rsplit(" on ", 1)[1]: None for label, _ in gates if label.rsplit(" on ", 1)[1] not in targets})
        for address, target in targets.items():
            a = arg_addr(address)
            closed = self.pin(t, None, m.address, "isTargetClosed(address)", "bool", None, [a], label=f"isTargetClosed({address})")
            if closed and address in m.am_closed:
                t.done.add(f"am_closed {address}")
            got = self.pin(t, None, m.address, "getTargetAdminDelay(address)", "uint", None, [a], label=f"getTargetAdminDelay({address})")
            if address in m.am_target_delay and got == m.am_target_delay[address]:
                t.done.add(f"am_target_delay {address}")
            fns = {_sel(f): f.split("(")[0] for f in (self.p._am_target_fns(target)[0] if target else [])}
            # functions found only in the logs are labelled by selector
            fns.update({bytes.fromhex(label[2:10]): label.split(" ")[0] for label, _ in gates
                        if label.startswith("0x") and label.endswith(address)})
            for sel, fname in fns.items():
                r = self.pin(t, None, m.address, "getTargetFunctionRole(address,bytes4)", "uint", None,
                             [a, (sel + bytes(28), f"bytes4(0x{sel.hex()})")], label=f"role of {fname} on {address}")
                t.done.add(f"am_gate {fname} on {address} {r}")
        for label, r in gates:
            if f"am_gate {label} {r}" not in t.done:
                t.why[f"am_gate {label} {r}"] = f"getTargetFunctionRole does not give role {r} at block {self.block}"
        for target in m.am_unmapped:
            t.gaps.append(f"which roles guard the functions of {target} beyond the common ones checked: it has no verified ABI")
        t.gaps.append(f"a role granted to an address this file does not list: an AccessManager does not enumerate members, so "
                      f"the {len(self.known) + len(self.signers)} addresses in _known(){' and _signers()' if self.signers else ''} are the ones checked"
                      + ("" if m.address in self.p.replayed else "; --roles-from-logs adds every account ever granted a role"))

    def _coverage(self, t: _Test) -> None:
        """Every fact the probe reported for this address is pinned, or said not to be, with the reason."""
        n = t.n
        facts: dict[str, object] = {f: getattr(n, f) for f in ("implementation", "proxy_admin", "beacon", "owner", "pending_owner", "admin",
                                                              "clone_of", "authority", "kernel", "authorizer", "dao", "emergency",
                                                              "safe_threshold", "delay", "paused", "open_executor")}
        facts["safe_owners"] = n.safe_owners or None
        facts["safe_modules"] = n.safe_modules or None
        facts["safe_guard"] = n.safe_guard
        facts["facets"] = n.facets or None
        if n.admin and n.admin == n.proxy_admin:
            facts.pop("admin")    # the same address as the upgrade admin, pinned there
        facts.update({f"named {k}": v for k, v in n.named.items()})
        facts.update({f"ward {w}": w for w in n.wards})
        facts.update({f"role {name} {h}": None for name, hs in n.roles.items() for h in hs if f"role {name} {h}" in t.why})
        facts.update({f"am_role {r} {h}": f"delay {d}" for r, hs in n.am_roles.items() for h, d in hs})
        facts.update({f"am_role_admin {r}": a for r, a in n.am_role_admin.items()})
        facts.update({f"am_grant_delay {r}": d for r, d in n.am_grant_delay.items()})
        facts.update({f"am_target_delay {x}": d for x, d in n.am_target_delay.items()})
        facts.update({f"am_closed {x}": True for x in n.am_closed})
        facts.update({k: None for k in t.why if k.startswith("am_gate ")})
        for fact, value in facts.items():
            if value is None and fact not in t.why or fact in t.done:
                continue
            shown = "" if value is None or value is True else f" = {value}"
            t.gaps.append(f"{fact.replace('_', ' ')}{shown}: {t.why.get(fact, f'no read at block {self.block} reproduces it')}")

    # ---- the file ----
    def render(self) -> str:
        tests, names = [], set()
        for n in self.p.seen.values():
            t = self.node(n)
            base = f"test_{n.kind.replace('-', '_')}_{n.address[2:10].lower()}"
            name, i = base, 2
            while name in names:
                name, i = f"{base}_{i}", i + 1
            names.add(name)
            tests.append((name, t))
        pins = sum(t.pins for _, t in tests)
        gaps = [_text(x) for x in self.p.incomplete] + [g for _, t in tests for g in t.gaps]
        chain_id = self.w3.eth.chain_id
        stamp = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(self.w3.eth.get_block(self.block)["timestamp"]))
        roots = [", ".join(r.address for r in self.roots[i:i + 2]) for i in range(0, len(self.roots), 2)]
        chain = _text(self.chain_name) + ("" if self.chain_name == f"chain {chain_id}" else f" (chain id {chain_id})")
        out = [
            "// SPDX-License-Identifier: MIT",
            f"// AdminSurface.t.sol: generated by ownerwatch {__version__} (`ownerwatch probe --foundry`). Regenerate it; do not edit it.",
            "//",
            "// Pins the admin surface of", *(f"//   {r}" for r in roots),
            f"// on {chain} as the probe read it at block {self.block} ({stamp}).",
            f"// setUp() forks the latest block from the RPC URL in the {RPC_ENV} environment variable (vm.envString, then",
            "// vm.createSelectFork); no RPC URL or key is written here. Run it with:",
            f"//   {RPC_ENV}=<an RPC URL for chain id {chain_id}> forge test --match-contract AdminSurface",
            "// A rate-limited RPC (HTTP 429) shows up as a forge database error, not as a change.",
            "//",
            "// This file records state; it does not judge it. A pass means nothing pinned here changed since block",
            f"// {self.block}, not that the setup is safe. A failure names what changed; if the change was intended, regenerate.",
            "// The probe's findings are judgements and are left out; the state behind them is pinned.",
            f"// {pins} values pinned in {sum(1 for _, t in tests if t.lines)} tests; {len(gaps)} `// not pinned:` lines say what is not, and why.",
        ]
        out += [f"// not pinned: {_text(x)}" for x in self.p.incomplete]
        out += ["", "pragma solidity >=0.8.12 <0.9.0;", "", _VM, "", "contract AdminSurface {", _HEADER.replace("@ENV@", RPC_ENV).replace("@CHAIN@", str(chain_id))]
        for name, t in tests:
            n = t.n
            out.append(f"    // {n.address}: {n.kind}" + (f" {n.safe_threshold}-of-{len(n.safe_owners)}" if n.kind == "safe" else ""))
            out += [f"    // not pinned: {_text(g)}" for g in t.gaps]
            if not t.lines:
                out += ["    // nothing to pin: the probe read no admin state here", ""]
                continue
            out.append(f"    function {name}() public {{")
            out.append(f"        address t = {_a(n.address)};")
            if t.uses_list:
                out.append("        bytes memory l;")
            out += [f"        {x}" for x in t.lines]
            out += [f'        _done(t, "{n.kind}");', "    }", ""]
        for fn, addrs, doc in (("_known", self.known, "Every address the probe saw, and address(0): AccessControl roles are checked against these."),
                               ("_signers", self.signers, "Safe signers not listed above: AccessManager roles are checked against these too.")):
            pre, expr = _packed(addrs, "k")
            out += [f"    /// {doc}", f"    function {fn}() private pure returns (bytes memory k) {{"]
            out += [f"        {x}" for x in pre] + [f"        return {expr};", "    }", ""]
        out += [_HELPERS.lstrip("\n"), "}"]
        return "\n".join(out) + "\n"


def foundry_test(prober: Prober, chain_name: str, block: int, roots: list[Node]) -> str:
    """The AdminSurface.t.sol source for everything the prober saw. Reads at `block`, which must be the block the
    probe read at: pin it with w3.eth.default_block before probing."""
    return _Writer(prober, chain_name, block, roots).render()


_VM = """/// The cheatcodes this file uses, so it needs no forge-std.
interface Vm {
    function envString(string calldata name) external view returns (string memory);
    function createSelectFork(string calldata urlOrAlias) external returns (uint256);
    function load(address target, bytes32 slot) external view returns (bytes32);
    function prank(address msgSender) external;
    function toString(address value) external pure returns (string memory);
    function toString(uint256 value) external pure returns (string memory);
    function toString(bytes32 value) external pure returns (string memory);
    function toString(bytes calldata value) external pure returns (string memory);
}"""

_HEADER = """    // forge-lint: disable-next-line(screaming-snake-case-const)
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 private constant ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    bytes32 private constant BEACON_SLOT = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;
    bytes32 private constant ZOS_IMPLEMENTATION_SLOT = keccak256("org.zeppelinos.proxy.implementation");
    bytes32 private constant PROXIABLE_SLOT = keccak256("PROXIABLE");
    bytes32 private constant ZOS_ADMIN_SLOT = keccak256("org.zeppelinos.proxy.admin");
    uint8 private constant ADDRESS = 0;
    uint8 private constant UINT = 1;
    uint8 private constant BOOL = 2;
    string private drift;   // what the running test found changed, one line each

    function setUp() public {
        vm.createSelectFork(vm.envString("@ENV@"));
        require(block.chainid == @CHAIN@, "@ENV@ serves another chain: this file pins chain id @CHAIN@");
    }
"""

_HELPERS = """
    // ---- helpers: each compares one value with what the probe read and records any difference ----
    function _done(address t, string memory kind) private view {
        if (bytes(drift).length != 0) revert(string.concat(vm.toString(t), " (", kind, ") changed:", drift));
    }

    function _diff(string memory what, string memory detail) private {
        drift = string.concat(drift, "\\n  ", what, ": ", detail);
    }

    function _addr(address t, bytes memory data, address pinned, string memory what) private {
        _word(t, data, 0, uint160(pinned), ADDRESS, what);
    }

    function _uint(address t, bytes memory data, uint256 pinned, string memory what) private {
        _word(t, data, 0, pinned, UINT, what);
    }

    function _bool(address t, bytes memory data, bool pinned, string memory what) private {
        _word(t, data, 0, pinned ? 1 : 0, BOOL, what);
    }

    /// An admin that the contract names only to the admin itself (Aave's immutable-admin proxies).
    function _addrFrom(address t, bytes memory data, address from, address pinned, string memory what) private {
        vm.prank(from);
        _word(t, data, 0, uint160(pinned), ADDRESS, what);
    }

    /// Word `index` of what t returns for data.
    function _word(address t, bytes memory data, uint256 index, uint256 pinned, uint8 kind, string memory what) private {
        (bool ok, bytes memory ret) = t.staticcall(data);
        if (!ok || ret.length < 32 * (index + 1)) {
            _diff(what, string.concat("pinned ", _show(pinned, kind), ", now ", ok ? string("returns nothing") : string("reverts")));
        } else if (_at(ret, index) != pinned) {
            _diff(what, string.concat("pinned ", _show(pinned, kind), ", now ", _show(_at(ret, index), kind)));
        }
    }

    function _slot(address t, bytes32 slot, address pinned, string memory what) private {
        uint256 w = uint256(vm.load(t, slot));
        if (w != uint160(pinned)) _diff(what, string.concat("pinned ", vm.toString(pinned), ", now ", _show(w, ADDRESS)));
    }

    function _code(address t, bytes memory pinned, string memory what) private {
        if (keccak256(t.code) != keccak256(pinned)) {
            _diff(what, string.concat("pinned ", vm.toString(pinned), ", now ", t.code.length > 64 ? string.concat(vm.toString(t.code.length), " bytes") : vm.toString(t.code)));
        }
    }

    /// An address list compared as a set: who was removed and who was added.
    function _list(address t, bytes memory data, bytes memory pinned, string memory what) private {
        (bool ok, bytes memory ret) = t.staticcall(data);
        (bool valid, address[] memory now_) = _addresses(ret);
        if (!ok || !valid) {
            _diff(what, ok ? string("now returns something that is not an address list") : string("now reverts"));
            return;
        }
        string memory change;
        for (uint256 i = 0; i < pinned.length / 20; i++) {
            bool kept;
            for (uint256 j = 0; j < now_.length; j++) kept = kept || now_[j] == _item(pinned, i);
            if (!kept) change = string.concat(change, " removed ", vm.toString(_item(pinned, i)), ";");
        }
        for (uint256 j = 0; j < now_.length; j++) {
            if (!_has(pinned, now_[j])) change = string.concat(change, " added ", vm.toString(now_[j]), ";");
        }
        if (bytes(change).length != 0) _diff(what, change);
    }

    /// No address in `among` other than those in `skip` holds the role.
    function _notHeld(address t, string memory sig, bytes32 role, string memory name, bytes memory among, bytes memory skip) private {
        for (uint256 i = 0; i < among.length / 20; i++) {
            address a = _item(among, i);
            if (_has(skip, a)) continue;
            (bool ok, bytes memory ret) = t.staticcall(abi.encodeWithSignature(sig, role, a));
            if (!ok || ret.length < 32) {
                _diff(string.concat(sig, " for ", name), "now reverts");
                return;
            }
            if (_at(ret, 0) != 0) _diff(string.concat("hasRole(", name, ", ", vm.toString(a), ")"), "pinned false, now true");
        }
    }

    function _show(uint256 w, uint8 kind) private pure returns (string memory) {
        if (kind == BOOL && w <= 1) return w == 1 ? string("true") : string("false");
        // forge-lint: disable-next-line(unsafe-typecast)
        if (kind == ADDRESS && w <= type(uint160).max) return vm.toString(address(uint160(w)));   // checked just before
        return kind == UINT ? vm.toString(w) : vm.toString(bytes32(w));
    }

    function _at(bytes memory b, uint256 i) private pure returns (uint256 w) {
        assembly { w := mload(add(b, add(32, mul(i, 32)))) }
    }

    function _item(bytes memory packed, uint256 i) private pure returns (address a) {
        assembly { a := shr(96, mload(add(add(packed, 32), mul(i, 20)))) }
    }

    function _has(bytes memory packed, address a) private pure returns (bool) {
        for (uint256 i = 0; i < packed.length / 20; i++) if (_item(packed, i) == a) return true;
        return false;
    }

    /// An ABI-encoded address[] at the head of a return value, checked so that junk cannot pass as a list.
    function _addresses(bytes memory ret) private pure returns (bool, address[] memory list) {
        if (ret.length < 64) return (false, list);
        uint256 offset = _at(ret, 0);
        if (offset % 32 != 0 || offset > ret.length - 32) return (false, list);
        uint256 count = _at(ret, offset / 32);
        if (count > (ret.length - offset - 32) / 32) return (false, list);
        list = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 w = _at(ret, offset / 32 + 1 + i);
            if (w > type(uint160).max) return (false, list);
            // forge-lint: disable-next-line(unsafe-typecast)
            list[i] = address(uint160(w));   // checked just before
        }
        return (true, list);
    }"""
