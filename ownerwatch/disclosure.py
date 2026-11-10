"""ERC-8241 (Protocol Control Disclosure) core records, as JSON, checked against chain state.

ERC-8241 standardises what a protocol declares about who controls it, and says plainly that it is
"disclosure, not truth": independent verification is still needed. This module is that verification for the
parts chain state can settle. `check` reads every declared component, node and power at one pinned block and
labels each record ok, mismatch or unverifiable; it then lists the control it observes on the declared
components that no power declares (completeness, scoped to the declared components). `draft` writes a starting
disclosure from chain state. The JSON form of the records is documented in docs/erc-8241.md.
"""
from __future__ import annotations

import json

from web3 import Web3

from .probe import AM_PUBLIC_ROLE, AM_ROLE_PREFIX, ROLES, Prober

NODE_TYPES = {"eoa": "EOA", "safe": "MULTISIG", "timelock": "TIMELOCK", "legacy-timelock": "TIMELOCK",
              "proxy": "CONTRACT", "contract": "CONTRACT", "aragon-app": "CONTRACT", "access-manager": "CONTRACT"}
# PowerKinds chain state can settle. Anything else is reported as unverifiable, never as ok.
VERIFIABLE = {"UPGRADE", "OWNERSHIP", "ROLE"}


def manifest_hash(d: dict) -> str:
    """keccak256 of the canonical JSON (sorted keys, no whitespace) with `protocol.manifestHash` left out."""
    body = json.loads(json.dumps(d))
    body.get("protocol", {}).pop("manifestHash", None)
    return "0x" + Web3.keccak(text=json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)).hex().removeprefix("0x")


def _a(x: str | None) -> str | None:
    return Web3.to_checksum_address(x) if x else None


class Checker:
    def __init__(self, w3: Web3, block: int | None = None, roles_from_logs: bool = False,
                 logs_w3: Web3 | None = None, from_block: int | None = None):
        self.w3 = w3
        self.block = block if block is not None else w3.eth.block_number
        w3.eth.default_block = self.block          # every read below is at this one block
        self.prober = Prober(w3)
        self.results: list[dict] = []
        # replay RoleGranted/RoleRevoked up to the pinned block, so every role holder is found, not only those
        # among addresses someone already named
        self.roles_from_logs, self.logs_w3, self.from_block = roles_from_logs, logs_w3, from_block
        self._names: dict[str, dict[str, str]] = {}

    def _role_names(self, addr: str) -> dict[str, str]:
        """Role name -> hash for one contract: the common roles, plus the contract's own bytes32 getters
        (POOL_ADMIN_ROLE() and the like) from its verified ABI."""
        if addr not in self._names:
            m = {k: "0x" + bytes(v).hex() for k, v in ROLES.items()}
            m.update({getter: h for h, getter in self.prober.role_names(addr).items()})
            self._names[addr] = m
        return self._names[addr]

    def _role_hash(self, addr: str, role: str) -> str:
        if role.startswith("0x") and len(role) == 66:
            return role.lower()
        return self._role_names(addr).get(role) or "0x" + bytes(Web3.keccak(text=role)).hex()

    def _role_label(self, addr: str, h: str) -> str:
        return {v: k for k, v in self._role_names(addr).items()}.get(h, h)

    def _am_of(self, t):
        """The AccessManager a contract answers to: itself, or its authority()."""
        if t.kind == "access-manager":
            return t
        return self._node(t.authority) if t.authority else None

    def observed_am_roles(self, t) -> dict[int, list[str]]:
        """AccessManager role id -> holders that reach this contract: every role on the manager itself; on a managed
        target, ADMIN_ROLE and the roles guarding its functions. An AccessManager cannot enumerate members, so
        only the log replay is complete."""
        m = self._am_of(t)
        if m is None:
            return {}
        if self.roles_from_logs and m.address not in self.prober.replayed:
            self.prober.role_history(m.address, self.from_block, self.logs_w3, to_block=self.block)
        return {r: [h for h, _ in holders] for r, holders in m.am_roles.items()
                if t is m or r == 0 or any(g.endswith(t.address) for g in m.am_gates.get(r, []))}

    @staticmethod
    def _am_role_id(role: str, target_is_manager: bool) -> int | None:
        if role.startswith(AM_ROLE_PREFIX):
            return int(role[len(AM_ROLE_PREFIX):])
        if target_is_manager:
            if role == "ADMIN_ROLE":
                return 0
            if role == "PUBLIC_ROLE":
                return AM_PUBLIC_ROLE
            if role.removeprefix("role ").isdigit():
                return int(role.removeprefix("role "))
        return None

    def observed_roles(self, t) -> dict[str, list[str]]:
        """Role hash -> holders at the pinned block. From the log replay when enabled (each holder confirmed
        with hasRole at the pinned block), else from the hasRole sweep over named addresses."""
        if self.roles_from_logs and self.prober._supports_access_control(t.address):
            out = {}
            for name, holders in self.prober.role_history(t.address, self.from_block, self.logs_w3, to_block=self.block).items():
                h = self._role_hash(t.address, name)
                held = [x for x in holders if self.prober._has_role(t.address, bytes.fromhex(h[2:]), x)]
                if held:
                    out[h] = held
            return out
        return {self._role_hash(t.address, name): hs for name, hs in t.roles.items()}

    def _add(self, record: str, rid: str, status: str, detail: str, declared=None, observed=None) -> None:
        self.results.append({"record": record, "id": rid, "status": status, "detail": detail,
                             "declared": declared, "observed": observed})

    def _node(self, address: str):
        return self.prober.seen.get(address) or self.prober.probe(address)

    def _params(self, power: dict, ctl_addr: str | None, pid: str) -> None:
        """Raw execution parameters declared on a power, checked against its controller node."""
        if not ctl_addr:
            return
        c = self._node(ctl_addr)
        if "threshold" in power or "controllerCount" in power:
            if c.kind != "safe":
                self._add("power", pid, "mismatch", f"declares a threshold, but the controller is {NODE_TYPES.get(c.kind, c.kind)}",
                          power.get("threshold"), None)
            else:
                for key, obs in (("threshold", c.safe_threshold), ("controllerCount", len(c.safe_owners))):
                    if key in power and power[key] != obs:
                        self._add("power", pid, "mismatch", f"{key} declared {power[key]}, on-chain {obs}", power[key], obs)
        if "delay" in power:
            obs = c.delay if c.kind in ("timelock", "legacy-timelock") else 0
            if power["delay"] != obs:
                self._add("power", pid, "mismatch", f"delay declared {power['delay']}s, on-chain {obs}s", power["delay"], obs)

    def check(self, d: dict) -> dict:
        nodes = {n["nodeId"]: n for n in d.get("nodes", [])}
        comps = {c["componentId"]: c for c in d.get("components", [])}
        bound = lambda nid: _a(nodes.get(nid, {}).get("address"))    # noqa: E731
        declared_hash = d.get("protocol", {}).get("manifestHash")
        if declared_hash:
            ok = declared_hash.lower() == manifest_hash(d)
            self._add("protocol", "manifestHash", "ok" if ok else "mismatch",
                      "manifest hash matches this file" if ok else "manifest hash does not match this file", declared_hash, manifest_hash(d))
        chain = d.get("protocol", {}).get("chainId")
        if chain is not None and chain != self.w3.eth.chain_id:
            self._add("protocol", "chainId", "mismatch", f"declared chain {chain}, RPC is chain {self.w3.eth.chain_id}", chain, self.w3.eth.chain_id)

        for nid, n in nodes.items():
            if not n.get("address"):
                self._add("node", nid, "unverifiable", "no address binding")
                continue
            obs = self._node(_a(n["address"]))
            t_obs = NODE_TYPES.get(obs.kind, obs.kind.upper())
            problems = []
            if n.get("type") and n["type"].upper() not in (t_obs, "GOVERNOR" if t_obs == "CONTRACT" else t_obs):
                problems.append(f"declared {n['type']}, on-chain {t_obs}")
            observed = {"threshold": obs.safe_threshold, "controllerCount": len(obs.safe_owners) if obs.kind == "safe" else None,
                        "delay": obs.delay if obs.kind in ("timelock", "legacy-timelock") else None}
            for key, val in observed.items():
                if key in n and n[key] != val:
                    problems.append(f"{key} declared {n[key]}, on-chain {val}")
            self._add("node", nid, "mismatch" if problems else "ok", "; ".join(problems) or f"{t_obs} at {n['address']}",
                      {k: n.get(k) for k in ("type", *observed) if k in n}, {"type": t_obs, **{k: v for k, v in observed.items() if v is not None}})

        for cid, c in comps.items():
            addr = _a(c["address"])
            obs = self._node(addr)
            if obs.kind == "eoa":
                self._add("component", cid, "mismatch", "an EIP-7702 account, not a contract" if obs.delegate else "no code at the address",
                          c["address"], None)
                continue
            upgradeable = bool(obs.implementation or obs.beacon or obs.diamond)
            problems = []
            if "upgradeable" in c and c["upgradeable"] != upgradeable:
                problems.append(f"upgradeable declared {c['upgradeable']}, on-chain {upgradeable}")
            if c.get("implementation") and _a(c["implementation"]) != obs.implementation:
                problems.append(f"implementation declared {c['implementation']}, on-chain {obs.implementation}")
            if c.get("adminNodeId") and upgradeable and obs.proxy_admin and bound(c["adminNodeId"]) != obs.proxy_admin:
                problems.append(f"admin declared {c['adminNodeId']} ({bound(c['adminNodeId'])}), on-chain upgrade admin {obs.proxy_admin}")
            # a UUPS proxy (or a Diamond's diamondCut) keeps its upgrade authority in code, which no slot names
            unnamed = upgradeable and not obs.proxy_admin
            unnamed_msg = ("upgradeable (EIP-2535 Diamond), but its diamondCut gate is not readable from state" if obs.diamond
                           else "upgradeable, but its upgrade authority is not readable from state (UUPS)")
            self._add("component", cid, "mismatch" if problems else ("unverifiable" if unnamed else "ok"),
                      "; ".join(problems) or (unnamed_msg if unnamed else "address, upgradeability and admin match"),
                      {k: c.get(k) for k in ("upgradeable", "implementation", "adminNodeId")},
                      {"upgradeable": upgradeable, "implementation": obs.implementation, "upgradeAdmin": obs.proxy_admin})

        candidates = sorted({a for a in [bound(n) for n in nodes] if a}
                            | {x for c in comps.values() for x in (self._node(_a(c["address"])).owner,
                                                                    self._node(_a(c["address"])).proxy_admin) if x})
        for a in candidates:
            self._node(a)
        self.prober.check_roles(candidates)

        declared_keys = set()
        for p in d.get("powers", []):
            pid, kind = p["powerId"], p.get("kind", "").upper()
            comp = comps.get(p.get("target"))
            ctl = bound(p.get("controllerNodeId"))
            if p.get("enabled") is False:
                self._add("power", pid, "unverifiable", "declared disabled")
                continue
            if kind not in VERIFIABLE or not comp:
                self._add("power", pid, "unverifiable",
                          f"{kind or 'no kind'} is not settled by chain state" if comp else "target is not a declared component")
                continue
            target = self._node(_a(comp["address"]))
            if not ctl:     # nothing to compare: "ok" here would vouch for a controller nobody can identify
                self._add("power", pid, "unverifiable", f"controller {p.get('controllerNodeId')} has no address binding")
                continue
            if kind == "UPGRADE":
                upgradeable = bool(target.implementation or target.beacon or target.diamond)
                if upgradeable and not target.proxy_admin:
                    self._add("power", pid, "unverifiable",
                              "diamondCut gate is in the facet code (EIP-2535 Diamond), which no slot names" if target.diamond
                              else "upgrade authority is in the implementation's code (UUPS), which no slot names")
                    continue
                obs, key = target.proxy_admin, ("UPGRADE", target.address, None)
                ok = ctl == obs if upgradeable else False
            elif kind == "OWNERSHIP":
                obs, key = target.owner, ("OWNERSHIP", target.address, None)
                ok = ctl == obs
            else:
                role = p.get("role") or "DEFAULT_ADMIN_ROLE"
                manager = self._am_of(target)
                rid = self._am_role_id(role, target.kind == "access-manager")
                if manager is not None and rid is not None:
                    res = self.prober._am_has_role(manager.address, [(rid, ctl)])[0]
                    obs, key = bool(res and res[0]), ("ROLE", target.address, f"{AM_ROLE_PREFIX}{rid}")
                elif target.kind == "access-manager":
                    self._add("power", pid, "unverifiable", f"role {role} is not an AccessManager role id")
                    continue
                else:
                    h = p.get("roleHash") or self._role_hash(target.address, role)
                    key = ("ROLE", target.address, h)
                    obs = self.prober._has_role(target.address, bytes.fromhex(h[2:]), ctl)
                    named = p.get("roleHash") or role.startswith("0x") or role in self._role_names(target.address)
                    if obs is not True and not named:
                        # only a guess at the hash from the name, with no ABI to confirm it: a miss proves nothing
                        declared_keys.add(key + (ctl,))
                        self._add("power", pid, "unverifiable", f"role {role} could not be resolved to a hash: add roleHash")
                        continue
                ok = obs is True
            declared_keys.add(key + (ctl,))
            n_before = len(self.results)
            self._params(p, ctl, pid)
            if ok and len(self.results) == n_before:
                self._add("power", pid, "ok", f"{kind} over {p['target']} held by {p.get('controllerNodeId')}", ctl, obs)
            elif not ok:
                self._add("power", pid, "mismatch", f"{kind} over {p['target']}: declared {p.get('controllerNodeId')} ({ctl}), on-chain {obs}", ctl, obs)

        for e in d.get("edges", []):
            eid, kind = e["edgeId"], e.get("kind", "").upper()
            src, dst = bound(e.get("from")), bound(e.get("to"))
            if kind not in ("OWNER_OF", "UPGRADE_ADMIN_OF") or not src or not dst:
                self._add("edge", eid, "unverifiable", f"{kind or 'no kind'} between nodes without address bindings is not settled by chain state"
                          if kind in ("OWNER_OF", "UPGRADE_ADMIN_OF") else f"{kind or 'no kind'} is not settled by chain state")
                continue
            t = self._node(dst)
            obs = t.owner if kind == "OWNER_OF" else t.proxy_admin
            self._add("edge", eid, "ok" if obs == src else "mismatch",
                      f"{e['from']} {kind} {e['to']}" + ("" if obs == src else f": on-chain {obs}"), src, obs)

        undisclosed = []
        for cid, c in comps.items():
            t = self._node(_a(c["address"]))
            seen = []
            if t.implementation or t.beacon or t.diamond:
                seen.append(("UPGRADE", None, t.proxy_admin))
            if t.owner:
                seen.append(("OWNERSHIP", None, t.owner))
            for h, holders in self.observed_roles(t).items():
                seen += [("ROLE", h, x) for x in holders]
            for rid, holders in self.observed_am_roles(t).items():
                seen += [("ROLE", f"{AM_ROLE_PREFIX}{rid}", x) for x in holders]
            for kind, role, holder in seen:
                if holder and (kind, t.address, role, holder) not in declared_keys:
                    undisclosed.append({"component": cid, "kind": kind, "role": self._role_label(t.address, role) if role else None,
                                        "holder": holder, "holderType": NODE_TYPES.get(self._node(holder).kind, "?")})
        block = self.w3.eth.get_block(self.block)
        summary = {s: sum(1 for r in self.results if r["status"] == s) for s in ("ok", "mismatch", "unverifiable")}
        summary["undisclosed"] = len(undisclosed)
        return {"block": self.block, "blockHash": "0x" + bytes(block["hash"]).hex(), "chainId": self.w3.eth.chain_id,
                "nonce": d.get("nonce"), "summary": summary, "results": self.results, "undisclosed": undisclosed,
                "scope": ("completeness is checked over the declared components only, for upgrade admins, owner() and every "
                          "AccessControl role holder replayed from RoleGranted/RoleRevoked logs up to the pinned block"
                          if self.roles_from_logs else
                          "completeness is checked over the declared components only, for upgrade admins, owner() and the "
                          "roles ownerwatch tests (" + ", ".join(ROLES) + ") held by addresses the disclosure or the chain "
                          "names; replay role logs for every holder")}


def draft(w3: Web3, addresses: list[str], name: str, block: int | None = None, roles_from_logs: bool = False,
          logs_w3: Web3 | None = None, from_block: int | None = None) -> dict:
    """A starting disclosure from chain state: one component per address, one node per controller, the powers seen."""
    ck = Checker(w3, block, roles_from_logs, logs_w3, from_block)
    p = ck.prober
    roots = [p.probe(a) for a in addresses]
    p.check_roles(list(p.seen.keys()))
    nodes, comps, powers = {}, [], []

    def nid(addr: str) -> str:
        n = p.seen[addr]
        key = f"{NODE_TYPES.get(n.kind, 'CONTRACT').lower()}-{addr[2:].lower()}"   # whole address: vanity prefixes collide
        if key not in nodes:
            nodes[key] = {"nodeId": key, "type": NODE_TYPES.get(n.kind, "CONTRACT"), "address": addr}
            if n.kind == "safe":
                nodes[key].update(threshold=n.safe_threshold, controllerCount=len(n.safe_owners))
            if n.kind in ("timelock", "legacy-timelock"):
                nodes[key]["delay"] = n.delay
        return key

    for r in roots:
        cid = f"component-{r.address[2:].lower()}"
        up = bool(r.implementation or r.beacon or r.diamond)
        comp = {"componentId": cid, "address": r.address, "nodeId": nid(r.address), "type": "contract", "upgradeable": up}
        if r.implementation:
            comp["implementation"] = r.implementation
        if up and r.proxy_admin:
            comp["adminNodeId"] = nid(r.proxy_admin)
            powers.append({"powerId": f"upgrade-{cid}", "kind": "UPGRADE", "enabled": True, "target": cid,
                           "controllerNodeId": nid(r.proxy_admin)})
        if r.owner:
            powers.append({"powerId": f"ownership-{cid}", "kind": "OWNERSHIP", "enabled": True, "target": cid,
                           "controllerNodeId": nid(r.owner)})
        for rh, holders in ck.observed_roles(r).items():
            role = ck._role_label(r.address, rh)
            for h in holders:
                p.seen.get(h) or p.probe(h)
                # the hash travels with the name, so the check does not depend on a verified ABI being reachable later
                powers.append({"powerId": f"{role.lower()[:24]}-{cid}-{h[2:].lower()}", "kind": "ROLE", "role": role, "roleHash": rh,
                               "enabled": True, "target": cid, "controllerNodeId": nid(h)})
        for rid, holders in ck.observed_am_roles(r).items():
            for h in holders:
                p.seen.get(h) or p.probe(h)
                powers.append({"powerId": f"{AM_ROLE_PREFIX}{rid}-{cid}-{h[2:].lower()}", "kind": "ROLE", "role": f"{AM_ROLE_PREFIX}{rid}",
                               "enabled": True, "target": cid, "controllerNodeId": nid(h)})
        comps.append(comp)
    # the chain above the direct controllers, as edges: who owns or upgrades each controller, up to a few hops
    edges, frontier = [], [n["address"] for n in nodes.values()]
    for _ in range(4):
        nxt = []
        for addr in frontier:
            n = p.seen.get(addr) or p.probe(addr)
            for kind, ctl in (("OWNER_OF", n.owner), ("UPGRADE_ADMIN_OF", n.proxy_admin if (n.implementation or n.beacon or n.diamond) else None)):
                if not ctl or ctl == addr:
                    continue
                p.seen.get(ctl) or p.probe(ctl)
                known = any(v["address"] == ctl for v in nodes.values())
                src, dst = nid(ctl), nid(addr)
                eid = f"{kind.lower()}-{src}-{dst}"
                if not any(e["edgeId"] == eid for e in edges):
                    edges.append({"edgeId": eid, "kind": kind, "from": src, "to": dst, "direct": True})
                if not known:
                    nxt.append(ctl)
        frontier = nxt
        if not frontier:
            break
    for pw in powers:
        n = nodes[pw["controllerNodeId"]]
        for k in ("threshold", "controllerCount", "delay"):
            if k in n:
                pw[k] = n[k]
    d = {"standard": "ERC-8241", "standardVersion": "core-draft",
         "protocol": {"name": name, "chainId": w3.eth.chain_id},
         "nonce": 1, "observedAtBlock": ck.block,
         "scope": {"components": [c["componentId"] for c in comps], "assets": [], "exclusions": [], "assumptions": []},
         "nodes": list(nodes.values()), "components": comps, "powers": powers, "edges": edges}
    d["protocol"]["manifestHash"] = manifest_hash(d)
    return d


def render(report: dict) -> str:
    s = report["summary"]
    out = [f"ERC-8241 check at block {report['block']} ({report['blockHash'][:12]}…), chain {report['chainId']}, nonce {report['nonce']}",
           f"ok {s['ok']} · mismatch {s['mismatch']} · unverifiable {s['unverifiable']} · undisclosed {s['undisclosed']}", ""]
    for r in report["results"]:
        if r["status"] != "ok":
            out.append(f"{r['status'].upper():12} {r['record']} {r['id']}: {r['detail']}")
    for u in report["undisclosed"]:
        role = f" {u['role']}" if u["role"] else ""
        out.append(f"UNDISCLOSED  {u['kind']}{role} over {u['component']} held by {u['holder']} ({u['holderType']})")
    out += ["", report["scope"]]
    return "\n".join(out)

