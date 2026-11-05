"""probe --foundry: the generated AdminSurface.t.sol passes on an unchanged fork and, after a change, fails naming it."""
import json
import os
import re
import shutil
import subprocess

import pytest
from web3 import Web3

from ownerwatch.cli import main
from ownerwatch.probe import BEACON_SLOT, IMPL_SLOT, SKY_PAUSE_PROXY, Prober
from tests.test_watcher import FIXTURES, _deploy, anvil, artifacts  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(shutil.which("anvil") is None or shutil.which("forge") is None, reason="foundry not installed")
PAUSER = Web3.keccak(text="PAUSER_ROLE")


def _art(name):
    art = json.loads((FIXTURES / "out" / "Admin.sol" / f"{name}.json").read_text())
    return art["abi"], art["bytecode"]["object"]


def _send(w3, tx, sender=None):
    return w3.eth.wait_for_transaction_receipt(tx.transact({"from": sender or w3.eth.accounts[0]}))


def _set_slot(w3, address, slot, value):
    w3.provider.make_request("anvil_setStorageAt", [address, hex(slot), "0x" + "00" * 12 + value[2:]])
    w3.provider.make_request("evm_mine", [])


def _generate(capsys, tmp_path, argv) -> str:
    """Run probe --foundry and lay the file out as a Foundry project, the way a team would drop it into test/."""
    rc = main(["probe", "--foundry", *argv])
    out = capsys.readouterr()
    src = out.out
    assert rc == 0, out.err[-3000:]
    (tmp_path / "test").mkdir(exist_ok=True)
    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / "foundry.toml").write_text('[profile.default]\nsrc = "src"\ntest = "test"\nlibs = []\n')
    (tmp_path / "test" / "AdminSurface.t.sol").write_text(src)
    return src


def _forge(root, rpc) -> dict[str, tuple[str, str | None]]:
    """forge test on a fork of `rpc`: test name -> (status, reason)."""
    r = subprocess.run(["forge", "test", "--root", str(root), "--json", "--no-storage-caching"], capture_output=True, text=True,
                       timeout=300, env={**os.environ, "OWNERWATCH_RPC_URL": rpc})
    try:
        suites = json.loads(r.stdout[r.stdout.index("{"):])
    except ValueError:
        raise AssertionError(f"forge test did not run: {r.stdout[-2000:]} {r.stderr[-2000:]}") from None
    return {name: (res["status"], res["reason"]) for s in suites.values() for name, res in s["test_results"].items()}


def _test_for(results, address):
    name = next((n for n in results if f"_{address[2:10].lower()}(" in n), None)
    assert name, f"no test for {address} in {sorted(results)}"
    return name


@pytest.fixture(scope="module")
def surface(anvil, artifacts):  # noqa: F811
    """Every shape the probe reads, wired together on anvil: an owned contract, an ERC-1967 proxy behind a ProxyAdmin
    owned by an OpenZeppelin-style timelock whose proposer is a Safe, a beacon proxy, a factory proxy behind a Solady
    timelock, Aave's immutable-admin proxy behind a PayloadsController, a Compound-style timelock, AccessControl with and
    without enumeration, an AccessManager over a clone, an EIP-7702 EOA, Aragon, Curve and Maker wards shapes."""
    w3 = anvil
    a0, a1, a2, a3 = w3.eth.accounts[:4]
    d = lambda name: _deploy(w3, *_art(name))  # noqa: E731
    s = {}
    s["owned"] = d("Admin")
    s["safe"] = d("MultisigLike")
    s["timelock"] = d("ProposerTimelock")
    _send(w3, s["timelock"].functions.give(Web3.keccak(text="PROPOSER_ROLE"), s["safe"].address))
    s["proxy_admin"] = d("SettableOwner")
    _send(w3, s["proxy_admin"].functions.setOwner(s["timelock"].address))
    s["impl"] = d("Admin")
    s["proxy"] = d("Token")
    from ownerwatch.probe import ADMIN_SLOT
    _set_slot(w3, s["proxy"].address, IMPL_SLOT, s["impl"].address)
    _set_slot(w3, s["proxy"].address, ADMIN_SLOT, s["proxy_admin"].address)
    s["beacon"] = d("BeaconLike")
    _send(w3, s["beacon"].functions.upgradeTo(s["impl"].address))
    s["beacon_proxy"] = d("Token")
    _set_slot(w3, s["beacon_proxy"].address, BEACON_SLOT, s["beacon"].address)
    clone_target = d("Token")                                 # a clone runs its target's code, so the target's beacon upgrades it
    _set_slot(w3, clone_target.address, BEACON_SLOT, s["beacon"].address)
    maker0 = d("CloneMaker")
    _send(w3, maker0.functions.clone(clone_target.address))
    s["beacon_clone"], s["clone_target"] = maker0.functions.last().call(), clone_target.address
    s["solady"] = d("SoladyTimelockLike")
    fac = d("ProxyFactoryLike")
    _send(w3, fac.functions.deploy(s["impl"].address, s["solady"].address))
    s["factory_proxy"] = fac.functions.lastProxy().call()
    s["ctl"] = d("PayloadsControllerLike")
    ex, prov = d("ExecutorLike"), d("AaveProviderLike")
    for tx in (s["ctl"].functions.setExecutor(1, ex.address, 86400), s["ctl"].functions.setExecutor(2, ex.address, 604800),
               ex.functions.setOwner(s["ctl"].address), prov.functions.setOwner(ex.address), prov.functions.deploy(s["impl"].address)):
        _send(w3, tx)
    s["aave_proxy"], s["provider"] = prov.functions.lastProxy().call(), prov.address
    s["compound"] = d("CompoundTimelockLike")
    s["roles"] = d("RoleLog")                                # deployer holds DEFAULT_ADMIN_ROLE
    _send(w3, s["roles"].functions.grantRole(PAUSER, a1))
    s["authorizer"] = d("EnumerableAuthorizer")
    s["vault"] = d("VaultLike")
    _send(w3, s["vault"].functions.setAuthorizer(s["authorizer"].address))
    s["am"] = d("AccessManagerLike")
    impl, maker = d("ManagedLike"), d("CloneMaker")
    _send(w3, maker.functions.clone(impl.address))
    s["clone"] = w3.eth.contract(address=maker.functions.last().call(), abi=_art("ManagedLike")[0])
    pause = bytes(Web3.keccak(text="pause()")[:4])
    for tx in (s["clone"].functions.setAuthority(s["am"].address), s["am"].functions.setFn(s["clone"].address, pause, 200),
               s["am"].functions.setAdmin(200, 100), s["am"].functions.grant(100, a2, 0), s["am"].functions.setGrantDelay(200, 3600)):
        _send(w3, tx)
    s["funds"] = d("FundsLike")
    _send(w3, s["funds"].functions.set(a1, a3))
    w3.provider.make_request("anvil_setCode", [a3, "0xef0100" + s["impl"].address[2:].lower()])   # curator is a 7702 EOA
    s["app"] = d("AragonAppLike")
    s["curve"] = d("CurveAdminLike")
    _send(w3, s["curve"].functions.set(s["app"].address, a0))
    s["catch_all"] = d("CatchAll")                           # answers every call: not AccessControl, not a Safe
    s["wards"] = d("WardsLike")
    _send(w3, s["wards"].functions.rely(SKY_PAUSE_PROXY))
    roots = [s[k] if isinstance(s[k], str) else s[k].address for k in
             ("owned", "proxy", "safe", "beacon_proxy", "beacon_clone", "factory_proxy", "aave_proxy", "compound", "roles", "vault", "clone",
              "funds", "app", "curve", "wards", "catch_all")]
    return w3, s, roots


def test_generated_test_pins_the_surface_and_names_each_change(surface, tmp_path, capsys):
    w3, s, roots = surface
    rpc = w3.provider.endpoint_uri
    a0, a1, a2, a3 = w3.eth.accounts[:4]
    # an AccessManager does not list its members: the key holding role 100 is found because it is named
    src = _generate(capsys, tmp_path, ["--rpc", rpc, "--role-candidates", a2, *roots])

    # the header says what was read where, and how to run it; no RPC URL is written
    block = w3.eth.block_number
    assert f"at block {block} (" in src and 'vm.envString("OWNERWATCH_RPC_URL")' in src and "vm.createSelectFork(" in src
    assert "it does not judge it" in src and rpc not in src and "127.0.0.1" not in src
    assert "import" not in src                      # self-contained: no forge-std
    assert src.count("    function test_") >= 15
    # what the probe saw is pinned with the read that reproduces it
    assert f'_slot(t, IMPLEMENTATION_SLOT, {s["impl"].address}, "ERC-1967 implementation slot");' in src
    assert f'_addr(t, abi.encodeWithSignature("owner()"), {s["timelock"].address}, "owner()");' in src     # the ProxyAdmin's owner
    assert f'_uint(t, abi.encodeWithSignature("getMinDelay()"), 172800, "getMinDelay()");' in src            # OpenZeppelin
    assert '_uint(t, abi.encodeWithSignature("minDelay()"), 86400, "minDelay()");' in src                   # Solady
    assert '_uint(t, abi.encodeWithSignature("delay()"), 172800, "delay()");' in src                        # Compound
    assert f'adminOf(address)", {s["factory_proxy"]})' in src
    assert f'_addrFrom(t, abi.encodeWithSignature("admin()"), {s["provider"]}, {s["provider"]},' in src        # Aave immutable admin
    assert '"delay of access level 1"' in src and '"executor of access level 2"' in src
    assert f'implementation() of beacon {s["beacon"].address}' in src
    assert f'_slot({s["clone_target"]}, BEACON_SLOT, {s["beacon"].address}, "ERC-1967 beacon slot of clone target {s["clone_target"]}");' in src
    assert '"getThreshold()"' in src and 'abi.encodeWithSignature("getOwners()"), abi.encodePacked(' in src
    catch_all = src.split(f"// {s['catch_all'].address}: ")[1].split("    // 0x")[0]
    assert "hasRole" not in catch_all and "getOwners" not in catch_all, catch_all
    assert "// not pinned: safe modules: getModulesPaginated(address,uint256) cannot be read" in src     # MultisigLike has none
    assert f'"hasRole(PROPOSER_ROLE, {s["safe"].address})"' in src
    assert '"getRoleMemberCount(DEFAULT_ADMIN_ROLE)"' in src
    assert f'"hasRole(100, {a2})"' in src and f'"execution delay of role 100 for {a2}"' in src and '"getRoleGrantDelay(200)"' in src
    assert f'"code (EIP-7702 delegation to {s["impl"].address})"' in src and "code (EIP-1167 clone of" in src
    assert f'"wards({SKY_PAUSE_PROXY})"' in src
    # and what it cannot express is said, with the reason
    assert "// not pinned: who may upgrade this Aragon app" in src
    assert "// not pinned: a role granted to an address this file does not list" in src
    assert "// not pinned: its proposer, executor and canceller roles: a minDelay() timelock (Solady)" in src

    results = _forge(tmp_path, rpc)
    assert all(st == "Success" for st, _ in results.values()), {k: v for k, v in results.items() if v[0] != "Success"}

    def drifted(change, address, *expect):
        snap = w3.provider.make_request("evm_snapshot", [])["result"]
        try:
            change()
            w3.provider.make_request("evm_mine", [])
            res = _forge(tmp_path, rpc)
        finally:
            w3.provider.make_request("evm_revert", [snap])
        failed = {k: v[1] for k, v in res.items() if v[0] != "Success"}
        name = _test_for(res, address)
        assert list(failed) == [name], failed
        for e in expect:
            assert e in failed[name], failed[name]

    drifted(lambda: _send(w3, s["owned"].functions.transferOwnership(a2)), s["owned"].address,
            f"{s['owned'].address} (contract) changed:", f"owner(): pinned {a0}, now {a2}")
    drifted(lambda: _send(w3, s["proxy_admin"].functions.setOwner(a1)), s["proxy_admin"].address,
            f"owner(): pinned {s['timelock'].address}, now {a1}")
    drifted(lambda: _set_slot(w3, s["proxy"].address, IMPL_SLOT, s["owned"].address), s["proxy"].address,
            f"ERC-1967 implementation slot: pinned {s['impl'].address}, now {s['owned'].address}")
    drifted(lambda: _send(w3, s["beacon"].functions.upgradeTo(s["owned"].address)), s["beacon_proxy"].address,
            f"implementation() of beacon {s['beacon'].address}: pinned {s['impl'].address}, now {s['owned'].address}")
    drifted(lambda: _send(w3, s["roles"].functions.grantRole(PAUSER, s["safe"].address)), s["roles"].address,
            f"hasRole(PAUSER_ROLE, {s['safe'].address}): pinned false, now true")
    drifted(lambda: _send(w3, s["roles"].functions.revokeRole(b"\x00" * 32, a0)), s["roles"].address,
            f"hasRole(DEFAULT_ADMIN_ROLE, {a0}): pinned true, now false")
    drifted(lambda: _set_slot(w3, s["authorizer"].address, 0, "0x" + "00" * 19 + "02"), s["authorizer"].address,
            "getRoleMemberCount(DEFAULT_ADMIN_ROLE): pinned 1, now 2")
    drifted(lambda: _send(w3, s["compound"].functions.setDelay(3600)), s["compound"].address, "delay(): pinned 172800, now 3600")
    drifted(lambda: _send(w3, s["ctl"].functions.setExecutor(1, a1, 86400)), s["ctl"].address,
            f"executor of access level 1: pinned")
    drifted(lambda: _send(w3, s["am"].functions.revoke(100, a2)), s["am"].address, f"hasRole(100, {a2}): pinned true, now false")
    drifted(lambda: _send(w3, s["am"].functions.grant(200, a0, 0)), s["am"].address, f"hasRole(200, {a0}): pinned false, now true")
    drifted(lambda: w3.provider.make_request("anvil_setCode", [s["safe"].address, w3.eth.get_code(_deploy(w3, *_art("SafeWithModule")).address).hex()]),
            s["safe"].address, "getOwners():", "removed 0x0000000000000000000000000000000000001001;",
            f"added {Web3.to_checksum_address(Web3.keccak(text='s0')[-20:])};")
    drifted(lambda: w3.provider.make_request("anvil_setCode", [a3, "0xef0100" + s["owned"].address[2:].lower()]), a3,
            f"code (EIP-7702 delegation to {s['impl'].address}): pinned 0xef0100")


def test_role_ids_come_from_the_contract_not_from_the_name(anvil, artifacts, tmp_path, capsys, monkeypatch):  # noqa: F811
    """A role getter can return any hash: Aave's POOL_ADMIN_ROLE() is keccak256("POOL_ADMIN"). The test must pin the
    id the contract uses; keccak256("POOL_ADMIN_ROLE") would pass vacuously and never fail. A name no read can map is
    reported, not guessed."""
    w3 = anvil
    a0, a1 = w3.eth.accounts[:2]
    box = _deploy(w3, *_art("RoleLog"))
    pool_admin = Web3.keccak(text="POOL_ADMIN")
    _send(w3, box.functions.grantRole(pool_admin, a1))
    _send(w3, box.functions.grantRole(Web3.keccak(text="SOMETHING_ELSE"), a1))
    monkeypatch.setattr(Prober, "role_names", lambda self, addr: {"0x" + bytes(pool_admin).hex(): "POOL_ADMIN_ROLE"})
    src = _generate(capsys, tmp_path, ["--rpc", w3.provider.endpoint_uri, "--roles-from-logs", "--from-block", "0", box.address])
    assert f'bytes32(0x{bytes(pool_admin).hex()}), {a1}), true, "hasRole(POOL_ADMIN_ROLE, {a1})"' in src
    assert bytes(Web3.keccak(text="POOL_ADMIN_ROLE")).hex() not in src
    assert f"hasRole(0x{bytes(Web3.keccak(text='SOMETHING_ELSE')).hex()}, {a1})" in src     # replayed, unnamed: pinned by id
    assert "role ids other than" not in src          # every grant was replayed
    results = _forge(tmp_path, w3.provider.endpoint_uri)
    assert all(st == "Success" for st, _ in results.values()), results
    snap = w3.provider.make_request("evm_snapshot", [])["result"]
    _send(w3, box.functions.revokeRole(pool_admin, a1))
    try:
        failed = [r for st, r in _forge(tmp_path, w3.provider.endpoint_uri).values() if st != "Success"]
    finally:
        w3.provider.make_request("evm_revert", [snap])
    assert len(failed) == 1 and f"hasRole(POOL_ADMIN_ROLE, {a1}): pinned true, now false" in failed[0]


def test_what_cannot_be_reproduced_is_said_not_dropped(anvil, artifacts):  # noqa: F811
    """A fact no read at the pinned block reproduces (here, an owner changed after the probe) becomes a `not pinned`
    line naming it, never a pin that fails at once or a silent omission."""
    from ownerwatch.foundry import foundry_test
    w3 = anvil
    c = _deploy(w3, *_art("SettableOwner"))
    w3.eth.default_block = w3.eth.block_number
    try:
        p = Prober(w3)
        root = p.probe(c.address)
        p.check_roles(list(p.seen))
        root.owner = w3.eth.accounts[5]         # as if the probe had read another owner
        src = foundry_test(p, "anvil", w3.eth.default_block, [root])
    finally:
        w3.eth.default_block = "latest"
    assert f"// not pinned: owner = {w3.eth.accounts[5]}: owner() returns {w3.eth.accounts[0]} at block" in src
    assert f'"owner()");' not in src


def test_untrusted_text_cannot_break_out_of_the_file():
    from ownerwatch.foundry import _text
    assert _text('X"); selfdestruct(payable(0)); //\nfunction \\') == "X?); selfdestruct(payable(0)); //?function ?"
    assert "0123456789abcdef" not in _text("call failed: https://rpc.example/v3/0123456789abcdef0123456789abcdef")


def test_foundry_flag_rules(anvil, artifacts, tmp_path, capsys):  # noqa: F811
    w3 = anvil
    c = _deploy(w3, *_art("SettableOwner"))
    rpc = w3.provider.endpoint_uri
    with pytest.raises(SystemExit):
        main(["probe", "--foundry", "--markdown", "--rpc", rpc, c.address])
    cfg = tmp_path / "multi.yaml"
    cfg.write_text(f"chains:\n  - rpc_url: {rpc}\n    chain_name: a\n    state_file: state/a.json\n    contracts: [{{address: '{c.address}'}}]\n"
                   f"  - rpc_url: {rpc}\n    chain_name: b\n    state_file: state/b.json\n    contracts: [{{address: '{c.address}'}}]\n")
    with pytest.raises(SystemExit):
        main(["probe", "--foundry", "--config", str(cfg)])
    one = tmp_path / "one.yaml"
    one.write_text(f"rpc_url: {rpc}\nchain_name: anvil\ncontracts:\n  - address: '{c.address}'\n")
    capsys.readouterr()
    assert main(["probe", "--foundry", "--config", str(one)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("// SPDX-License-Identifier: MIT") and re.search(r"function test_contract_[0-9a-f]{8}\(\)", out)


@pytest.mark.skipif(not os.environ.get("OWNERWATCH_FORK_RPC"), reason="set OWNERWATCH_FORK_RPC to an Ethereum RPC to run on a mainnet fork")
@pytest.mark.parametrize("targets", [
    ["0x1F98431c8aD98523631AE4a59f267346ea31F984"],     # Uniswap V3 factory: owner -> Compound-style timelock -> GovernorBravo
])
def test_mainnet_fork(targets, tmp_path, capsys):
    rpc = os.environ["OWNERWATCH_FORK_RPC"]
    _generate(capsys, tmp_path, ["--rpc", rpc, *targets])
    results = _forge(tmp_path, rpc)
    assert results and all(st == "Success" for st, _ in results.values()), results
