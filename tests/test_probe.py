import shutil

import pytest

from ownerwatch.probe import Prober, describe, markdown_report, suggest_config
from tests.test_watcher import _deploy, anvil, artifacts  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(shutil.which("anvil") is None, reason="foundry not installed")


def test_probe_classifies_eoa_owner(anvil, artifacts):  # noqa: F811
    w3 = anvil
    admin = _deploy(w3, *artifacts["Admin"])
    p = Prober(w3)
    n = p.probe(admin.address)
    assert n.kind == "contract"
    assert n.owner == w3.eth.accounts[0]
    assert any("is an EOA" in x for x in n.notes)
    assert p.seen[w3.eth.accounts[0]].kind == "eoa"
    out = describe(n)
    assert "owner=" in out and " is an EOA " in out
    cfg = suggest_config(p, "http://x", "anvil", None, "Test")
    assert admin.address in cfg and w3.eth.accounts[0] not in cfg


def test_probe_roles(anvil, artifacts):  # noqa: F811
    w3 = anvil
    box = _deploy(w3, *artifacts["RoleBox"])
    p = Prober(w3)
    p.probe(box.address)
    p.probe(w3.eth.accounts[0])
    p.check_roles(list(p.seen.keys()))
    n = p.seen[box.address]
    assert n.roles == {"DEFAULT_ADMIN_ROLE": [w3.eth.accounts[0]]}
    assert any("DEFAULT_ADMIN_ROLE held by EOA" in x for x in n.notes)
    assert "DEFAULT_ADMIN_ROLE:" in describe(n)


def test_role_history_from_logs(anvil, artifacts):  # noqa: F811
    w3 = anvil
    admin = _deploy(w3, *artifacts["Admin"])
    a, b = w3.eth.accounts[0], w3.eth.accounts[1]
    admin.functions.grantRole(b"\x00" * 32, b).transact({"from": a})
    w3.eth.wait_for_transaction_receipt(admin.functions.grantRole(b"\x11" * 32, a).transact({"from": a}))
    p = Prober(w3)
    p.probe(admin.address)
    out = p.role_history(admin.address)
    assert out["DEFAULT_ADMIN_ROLE"] == [b]
    assert out["0x" + "11" * 32] == [a]
    assert any("DEFAULT_ADMIN_ROLE held by EOA" in x for x in p.seen[admin.address].notes)


def test_markdown_report(anvil, artifacts):  # noqa: F811
    w3 = anvil
    admin = _deploy(w3, *artifacts["Admin"])
    p = Prober(w3)
    root = p.probe(admin.address)
    md = markdown_report(p, "Test", "anvil", [root])
    assert md.startswith("# Test admin surface on anvil")
    assert "| contract |" in md and "is an EOA" in md
    assert "(contract) -> " in md and "(eoa)" in md


def test_probe_from_config(anvil, artifacts, tmp_path, capsys):  # noqa: F811
    from ownerwatch.cli import main
    w3 = anvil
    admin = _deploy(w3, *artifacts["Admin"])
    cfg = tmp_path / "c.yaml"
    cfg.write_text(f"rpc_url: {w3.provider.endpoint_uri}\nchain_name: anvil\ncontracts:\n  - address: '{admin.address}'\n    label: A\n")
    assert main(["probe", "--config", str(cfg), "--markdown", "--label", "Acme"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("# Acme admin surface on anvil") and "is an EOA" in out
    # --rpc overrides a broken rpc_url for a single-chain config; probe_rpc_url does the same
    cfg.write_text(f"rpc_url: http://127.0.0.1:1\nchain_name: anvil\ncontracts:\n  - address: '{admin.address}'\n")
    assert main(["probe", "--config", str(cfg), "--rpc", w3.provider.endpoint_uri, "--markdown"]) == 0
    cfg.write_text(f"rpc_url: http://127.0.0.1:1\nprobe_rpc_url: {w3.provider.endpoint_uri}\nchain_name: anvil\ncontracts:\n  - address: '{admin.address}'\n")
    assert main(["probe", "--config", str(cfg), "--markdown"]) == 0
    cfg.write_text(f"rpc_url: http://127.0.0.1:1\nchain_name: anvil\ncontracts:\n  - address: '{admin.address}'\n")
    assert main(["probe", "--config", str(cfg), "--markdown"]) == 2


def test_probe_json(anvil, artifacts, tmp_path, capsys):  # noqa: F811
    import json
    from ownerwatch.cli import main
    w3 = anvil
    admin = _deploy(w3, *artifacts["Admin"])
    assert main(["probe", "--rpc", w3.provider.endpoint_uri, "--json", admin.address]) == 0
    d = json.loads(capsys.readouterr().out)
    kinds = {n["address"]: n["kind"] for n in d["nodes"]}
    assert kinds[admin.address] == "contract" and kinds[w3.eth.accounts[0]] == "eoa"


def test_implementation_of_reads_erc1967_and_slot0(anvil, artifacts):  # noqa: F811
    from ownerwatch.decode import implementation_of
    w3 = anvil
    admin = _deploy(w3, *artifacts["Admin"])          # slot 0 holds `owner` (an EOA, no code) -> None
    assert implementation_of(w3, admin.address) is None
    token = _deploy(w3, *artifacts["Token"])
    slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
    w3.provider.make_request("anvil_setStorageAt", [token.address, slot, "0x" + "00" * 12 + admin.address[2:]])
    assert implementation_of(w3, token.address) == admin.address


class _FakeEth:
    """eth_getLogs stub: rejects ranges wider than `limit` with a range error,
    optionally fails a whole region with a non-range error; counts calls."""

    def __init__(self, limit, logs_at=(), pruned_below=None):
        self.limit, self.logs_at, self.pruned_below, self.calls = limit, set(logs_at), pruned_below, []

    def get_logs(self, params):
        a, b = params["fromBlock"], params["toBlock"]
        self.calls.append((a, b))
        if self.pruned_below is not None and a < self.pruned_below:
            raise ValueError("pruned history unavailable")
        if b - a + 1 > self.limit:
            raise ValueError("query exceeds max block range")
        return [{"blockNumber": n} for n in sorted(self.logs_at) if a <= n <= b]


class _FakeW3:
    def __init__(self, eth):
        self.eth = eth


def test_get_logs_split_adapts_chunk_and_remembers_ceiling():
    eth = _FakeEth(limit=1000, logs_at=[5, 2500, 9999])
    p = Prober.__new__(Prober)
    out = p._get_logs_split({"address": "0x0"}, 0, 9999, w3=_FakeW3(eth))
    assert [l["blockNumber"] for l in out] == [5, 2500, 9999]
    widths = [b - a + 1 for a, b in eth.calls]
    assert max(w for w in widths if w <= 1000) <= 1000
    # after finding the ceiling no chunk wider than it is tried again
    first_ok = next(i for i, w in enumerate(widths) if w <= 1000)
    assert all(w <= 1000 for w in widths[first_ok:])
    assert len(eth.calls) < 40


def test_get_logs_split_raises_on_non_range_error():
    eth = _FakeEth(limit=10**9, pruned_below=100)
    p = Prober.__new__(Prober)
    with pytest.raises(ValueError, match="pruned"):
        p._get_logs_split({"address": "0x0"}, 0, 10_000, w3=_FakeW3(eth))
    assert len(eth.calls) == 1      # no pointless halving


def test_get_logs_split_budget():
    eth = _FakeEth(limit=64)
    p = Prober.__new__(Prober)
    with pytest.raises(RuntimeError, match="budget"):
        p._get_logs_split({"address": "0x0"}, 0, 10_000, w3=_FakeW3(eth), budget=20)


def test_factory_stored_admin_and_solady_timelock(anvil, artifacts):  # noqa: F811
    """A proxy whose upgrade admin lives in its factory must resolve to that admin, not to owner()."""
    w3 = anvil
    tl = _deploy(w3, *artifacts["SoladyTimelockLike"])
    fac = _deploy(w3, *artifacts["ProxyFactoryLike"])
    impl = _deploy(w3, *artifacts["Admin"])
    w3.eth.wait_for_transaction_receipt(fac.functions.deploy(impl.address, tl.address).transact({"from": w3.eth.accounts[0]}))
    proxy = fac.functions.lastProxy().call()
    p = Prober(w3)
    n = p.probe(proxy)
    assert n.kind == "proxy" and n.implementation == impl.address
    assert n.proxy_admin == tl.address and n.admin_factory == fac.address
    t = p.seen[tl.address]
    assert t.kind == "timelock" and t.delay == 86400
    assert not any("no recognised timelock" in x or "upgrade admin" in x for x in n.notes)
    md = markdown_report(p, "T", "anvil", [n])
    assert f"`{tl.address[:6]}…{tl.address[-4:]}`" in md      # controller column shows the timelock, not owner()


def test_owned_custom_timelock(anvil, artifacts):  # noqa: F811
    w3 = anvil
    tl = _deploy(w3, *artifacts["OwnedTimelockLike"])
    n = Prober(w3).probe(tl.address)
    assert n.kind == "timelock" and n.delay == 172800


def test_aave_immutable_admin_proxy_behind_payloads_controller(anvil, artifacts):  # noqa: F811
    """Aave V3: Pool proxy -> PoolAddressesProvider (immutable admin) -> Executor -> PayloadsController.
    The proxy's admin must be found, and the controller's per-executor delay must count as a timelock all the
    way down, so nothing on the path is reported as having no timelock."""
    w3 = anvil
    acct = w3.eth.accounts[0]
    ctl = _deploy(w3, *artifacts["PayloadsControllerLike"])
    ex = _deploy(w3, *artifacts["ExecutorLike"])
    prov = _deploy(w3, *artifacts["AaveProviderLike"])
    impl = _deploy(w3, *artifacts["Admin"])
    for tx in (ctl.functions.setExecutor(1, ex.address, 86400), ctl.functions.setExecutor(2, ex.address, 604800),
               ex.functions.setOwner(ctl.address), prov.functions.setOwner(ex.address), prov.functions.deploy(impl.address)):
        w3.eth.wait_for_transaction_receipt(tx.transact({"from": acct}))
    proxy = prov.functions.lastProxy().call()
    p = Prober(w3)
    n = p.probe(proxy)
    assert n.kind == "proxy" and n.implementation == impl.address and n.proxy_admin == prov.address
    c = p.seen[ctl.address]
    assert c.kind == "timelock" and c.delay == 86400          # the shortest executor delay
    for node in (n, p.seen[prov.address], p.seen[ex.address]):
        assert not any("no recognised timelock" in x or "with no timelock" in x for x in node.notes), node.notes


def test_governance_patterns_of_large_protocols(anvil, artifacts):  # noqa: F811
    """Lido, Balancer, Euler, Curve and Spark governance shapes, each read without a false "no timelock"."""
    from ownerwatch.probe import SKY_PAUSE_PROXY
    w3 = anvil
    acct = w3.eth.accounts[0]
    send = lambda tx: w3.eth.wait_for_transaction_receipt(tx.transact({"from": acct}))  # noqa: E731
    p = Prober(w3)

    app = _deploy(w3, *artifacts["AragonAppLike"])
    n = p.probe(app.address)
    assert n.kind == "aragon-app" and n.kernel and any("Aragon app" in x for x in n.notes)

    auth = _deploy(w3, *artifacts["EnumerableAuthorizer"])
    vault = _deploy(w3, *artifacts["VaultLike"])
    send(vault.functions.setAuthorizer(auth.address))
    p2 = Prober(w3)
    v = p2.probe(vault.address)
    assert v.authorizer == auth.address
    p2.check_roles([])                                   # no candidates: enumeration alone finds the admin
    assert p2.seen[auth.address].roles == {"DEFAULT_ADMIN_ROLE": [acct]}

    tl = _deploy(w3, *artifacts["OwnedTimelockLike"])
    fac = _deploy(w3, *artifacts["FactoryUpgradeAdminLike"])
    send(fac.functions.setUpgradeAdmin(tl.address))
    f = Prober(w3).probe(fac.address)
    assert f.proxy_admin == tl.address and not any("no recognised timelock" in x for x in f.notes)

    ca = _deploy(w3, *artifacts["CurveAdminLike"])
    send(ca.functions.set(app.address, acct))
    c = Prober(w3).probe(ca.address)
    assert c.dao == app.address and c.emergency == acct
    assert any("emergency() is an EOA" in x for x in c.notes)      # the emergency path really is undelayed

    pause = _deploy(w3, *artifacts["DSPauseLike"])
    proxy_art = artifacts["PauseProxyLike"]
    tmp = _deploy(w3, *proxy_art)
    w3.provider.make_request("anvil_setCode", [SKY_PAUSE_PROXY, w3.eth.get_code(tmp.address).hex()])
    w3.eth.contract(address=SKY_PAUSE_PROXY, abi=proxy_art[0]).functions.setOwner(pause.address).transact({"from": acct})
    wards = _deploy(w3, *artifacts["WardsLike"])
    send(wards.functions.rely(SKY_PAUSE_PROXY))
    owned = _deploy(w3, *artifacts["ExecutorLike"])            # owner() = deployer, then handed to the wards contract
    send(owned.functions.setOwner(wards.address))
    p5 = Prober(w3)
    o = p5.probe(owned.address)
    assert p5.seen[wards.address].wards == [SKY_PAUSE_PROXY]
    assert p5.seen[pause.address].kind == "timelock" and p5.seen[pause.address].delay == 172800
    assert not any("no recognised timelock" in x for x in o.notes), o.notes


def test_multisig_role_admin_outside_the_timelock_is_a_finding(anvil, artifacts):  # noqa: F811
    """A Safe holding DEFAULT_ADMIN_ROLE directly acts with no delay even when upgrades are timelocked: the
    "multisig, but no clock" case. A pause role on the same Safe is not a finding."""
    from web3 import Web3
    w3 = anvil
    acct = w3.eth.accounts[0]
    safe = _deploy(w3, *artifacts["MultisigLike"])
    box = _deploy(w3, *artifacts["RoleLog"])
    for tx in (box.functions.grantRole(b"\x00" * 32, safe.address), box.functions.grantRole(Web3.keccak(text="PAUSER_ROLE"), safe.address)):
        w3.eth.wait_for_transaction_receipt(tx.transact({"from": acct}))
    p = Prober(w3)
    n = p.probe(box.address)
    p.probe(safe.address)
    p.check_roles(list(p.seen.keys()))
    assert p.seen[safe.address].kind == "safe"
    assert any(f"DEFAULT_ADMIN_ROLE held by 2-of-3 Safe {safe.address} with no timelock" in x for x in n.notes), n.notes
    assert not any(x.startswith("PAUSER_ROLE held by") for x in n.notes)
    assert "No single-key or zero-delay" not in markdown_report(p, "T", "anvil", [n])


def test_admin_role_found_by_name_and_eoa_findings_do_not_claim_one_key(anvil, artifacts):  # noqa: F811
    """A plain ADMIN_ROLE is tested by name, so a reads-only probe finds it. The chain shows an address, not how its
    key is held, so an EOA finding says what the chain shows and leaves room for an MPC wallet."""
    from web3 import Web3
    w3 = anvil
    acct, holder = w3.eth.accounts[0], w3.eth.accounts[1]
    box = _deploy(w3, *artifacts["RoleLog"])
    w3.eth.wait_for_transaction_receipt(box.functions.grantRole(Web3.keccak(text="ADMIN_ROLE"), holder).transact({"from": acct}))
    p = Prober(w3)
    n = p.probe(box.address)
    p.check_roles([holder])
    assert n.roles.get("ADMIN_ROLE") == [holder]
    assert any(x.startswith(f"ADMIN_ROLE held by EOA {holder}") for x in n.notes), n.notes
    report = markdown_report(p, "T", "anvil", [n])
    assert "not how its key is held" in report
    assert "one private key" not in report


def test_role_candidates_find_holders_without_becoming_targets(anvil, artifacts, capsys):  # noqa: F811
    """--role-candidates tests extra addresses for roles; a holder found that way is classified (here a Safe) and
    the finding appears, but the candidate is not reported as a probed target unless it holds a role."""
    from ownerwatch.cli import main
    w3 = anvil
    acct = w3.eth.accounts[0]
    safe = _deploy(w3, *artifacts["MultisigLike"])
    unrelated = _deploy(w3, *artifacts["Admin"])
    box = _deploy(w3, *artifacts["RoleLog"])
    w3.eth.wait_for_transaction_receipt(box.functions.grantRole(b"\x00" * 32, safe.address).transact({"from": acct}))
    rpc = w3.provider.endpoint_uri
    assert main(["probe", "--rpc", rpc, "--markdown", box.address]) == 0
    assert "2-of-3 Safe" not in capsys.readouterr().out          # the sweep alone cannot see the Safe
    assert main(["probe", "--rpc", rpc, "--markdown", "--role-candidates", f"{safe.address},{unrelated.address}", box.address]) == 0
    out = capsys.readouterr().out
    assert f"DEFAULT_ADMIN_ROLE held by 2-of-3 Safe {safe.address} with no timelock" in out
    assert unrelated.address[:6] not in out


def _am_setup(w3, artifacts, delay=0):  # noqa: F811
    am = _deploy(w3, *artifacts["AccessManagerLike"])
    impl = _deploy(w3, *artifacts["ManagedLike"])
    maker = _deploy(w3, *artifacts["CloneMaker"])
    a0, key = w3.eth.accounts[0], w3.eth.accounts[1]
    w3.eth.wait_for_transaction_receipt(maker.functions.clone(impl.address).transact({"from": a0}))
    clone = w3.eth.contract(address=maker.functions.last().call(), abi=artifacts["ManagedLike"][0])
    clone.functions.setAuthority(am.address).transact({"from": a0})
    pause = bytes(w3.keccak(text="pause()")[:4])
    am.functions.setFn(clone.address, pause, 200).transact({"from": a0})
    am.functions.setAdmin(200, 100).transact({"from": a0})
    w3.eth.wait_for_transaction_receipt(am.functions.grant(100, key, delay).transact({"from": a0}))
    return am, impl, clone, key


def test_access_manager_role_on_clone(anvil, artifacts):  # noqa: F811
    w3 = anvil
    am, impl, clone, key = _am_setup(w3, artifacts)
    p = Prober(w3)
    n = p.probe(clone.address)
    assert n.clone_of == impl.address and n.authority == am.address
    m = p.seen[am.address]
    assert m.kind == "access-manager"
    p.check_roles([key])
    assert m.am_roles[100] == [(key, 0)] and m.am_role_admin[200] == 100
    assert any("role 100 held by EOA" in x and "roles 200 (calls pause)" in x for x in n.notes)
    md = markdown_report(p, "Test", "anvil", [n])
    assert "EIP-1167 clone of" in md and "role 100:" in md and "-> " in md


def test_access_manager_delay_is_not_a_finding(anvil, artifacts):  # noqa: F811
    w3 = anvil
    am, _, clone, key = _am_setup(w3, artifacts, delay=86400)
    p = Prober(w3)
    p.probe(clone.address)
    p.check_roles([key])
    assert p.seen[am.address].am_roles[100] == [(key, 86400)]
    assert not any("role 100" in x for x in p.seen[am.address].notes)


def test_access_manager_roles_from_logs(anvil, artifacts):  # noqa: F811
    w3 = anvil
    am, _, clone, key = _am_setup(w3, artifacts)
    w3.eth.wait_for_transaction_receipt(am.functions.grant(5, w3.eth.accounts[2], 0).transact({"from": w3.eth.accounts[0]}))
    w3.eth.wait_for_transaction_receipt(am.functions.revoke(5, w3.eth.accounts[2]).transact({"from": w3.eth.accounts[0]}))
    p = Prober(w3)
    p.probe(clone.address)
    out = p.role_history(am.address, from_block=0)
    assert out == {"role 100": [key]}
    assert any("role 100 held by EOA" in x for x in p.seen[clone.address].notes)


def test_named_custody_getters_and_7702_owner(anvil, artifacts):  # noqa: F811
    w3 = anvil
    vault = _deploy(w3, *artifacts["FundsLike"])
    holder, curator = w3.eth.accounts[2], w3.eth.accounts[3]
    w3.eth.wait_for_transaction_receipt(vault.functions.set(holder, curator).transact({"from": w3.eth.accounts[0]}))
    # the deployer (owner) gets an EIP-7702 delegation: still an EOA controlled by one key
    delegate = vault.address
    w3.provider.make_request("anvil_setCode", [w3.eth.accounts[0], "0xef0100" + delegate[2:].lower()])
    p = Prober(w3)
    n = p.probe(vault.address)
    owner = p.seen[w3.eth.accounts[0]]
    assert owner.kind == "eoa" and owner.delegate == delegate
    assert any(x.startswith("owner() is an EOA") and "EIP-7702 delegated" in x for x in n.notes)
    assert n.named["fundsHolder() (receives deposits)"] == holder and n.named["curator()"] == curator
    assert any(x.startswith("fundsHolder() (receives deposits) is an EOA") for x in n.notes)
    assert any(x.startswith("curator() is an EOA") for x in n.notes)
    assert "fundsHolder(): " in markdown_report(p, "T", "anvil", [n])


def test_delay_parameter_is_not_a_timelock(anvil, artifacts):  # noqa: F811
    w3 = anvil
    c = _deploy(w3, *artifacts["DelayParamLike"])
    n = Prober(w3).probe(c.address)
    assert n.kind == "contract" and n.delay is None
