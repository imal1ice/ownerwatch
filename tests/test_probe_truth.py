"""A clean report must mean the probe looked and found nothing, never that it failed to look."""
import json
import shutil

import pytest
from web3 import Web3

from ownerwatch import __version__
from ownerwatch.cli import main
from ownerwatch.disclosure import Checker, draft, manifest_hash
from ownerwatch.probe import (BEACON_SLOT, IMPL_SLOT, LEGACY_ADMIN_SLOT, LEGACY_IMPL_SLOTS, ProbeRpcError, Prober, _dur, _is_revert,
                              _word_addr, fact_lines, markdown_report)
from tests.test_watcher import _deploy, anvil, artifacts  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(shutil.which("anvil") is None, reason="foundry not installed")
PAUSE = bytes(Web3.keccak(text="pause()")[:4])


@pytest.fixture(autouse=True)
def unpinned(anvil):  # noqa: F811
    """Checker pins the client's default block; the anvil fixture is shared between tests."""
    anvil.eth.default_block = "latest"


def send(w3, tx):
    return w3.eth.wait_for_transaction_receipt(tx.transact({"from": w3.eth.accounts[0]}))


def set_slot(w3, address, slot, value):
    w3.provider.make_request("anvil_setStorageAt", [address, hex(slot), "0x" + "00" * 12 + value[2:]])


# ---- pure helpers -------------------------------------------------------------------------------------------------

def test_word_addr_rejects_what_cannot_be_an_address():
    real = "0x" + "ab" * 20
    assert _word_addr(bytes(12) + bytes.fromhex(real[2:])) == Web3.to_checksum_address(real)
    assert _word_addr((1).to_bytes(32, "big")) is None                # a bool
    assert _word_addr((86400).to_bytes(32, "big")) is None            # a duration
    assert _word_addr((32).to_bytes(32, "big")) is None               # a string offset
    assert _word_addr(b"\xff" * 32) is None                           # a hash
    assert _word_addr(bytes(31)) is None                              # wrong length


def test_durations_read_right():
    assert (_dur(1800), _dur(3600), _dur(172800), _dur(5400), _dur(45)) == ("30m", "1h", "48h", "1h 30m", "45s")


@pytest.mark.parametrize("message", ["execution reverted", "VM execution error.", "invalid opcode: INVALID", "out of gas",
                                     "EVM error InvalidFEOpcode", "Reverted 0x"])
def test_reverts_mean_absent(message):
    assert _is_revert(ValueError(message))


@pytest.mark.parametrize("message", ["block not found", "header not found", "missing trie node", "limit exceeded", "too many requests",
                                     "503 Server Error", "project ID does not have access"])
def test_everything_else_is_a_failed_read(message):
    assert not _is_revert(ValueError(message))


# ---- a failed read is not a clean report --------------------------------------------------------------------------

def test_rpc_failure_raises_instead_of_reading_as_no_owner(anvil, artifacts, monkeypatch):  # noqa: F811
    import ownerwatch.probe as mod
    w3 = anvil
    admin = _deploy(w3, *artifacts["Admin"])
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    p = Prober(w3)
    p._mc = None

    def down(tx):
        raise ValueError({"code": -32005, "message": "limit exceeded"})

    monkeypatch.setattr(w3.eth, "call", down)
    with pytest.raises(ProbeRpcError):
        p.probe(admin.address)


def test_cli_exits_2_on_a_failed_read(anvil, artifacts, monkeypatch, capsys):  # noqa: F811
    import ownerwatch.probe as mod
    w3 = anvil
    admin = _deploy(w3, *artifacts["Admin"])
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    monkeypatch.setattr(mod.Prober, "_call", lambda *a: (_ for _ in ()).throw(ProbeRpcError("RPC failed https://rpc.example/v2/SECRET")))
    assert main(["probe", "--rpc", w3.provider.endpoint_uri, "--markdown", admin.address]) == 2
    out = capsys.readouterr()
    assert "No single-key" not in out.out and "error:" in out.err


def test_failed_role_replay_is_in_the_report_and_the_exit_code(anvil, artifacts, capsys):  # noqa: F811
    w3 = anvil
    box = _deploy(w3, *artifacts["RoleBox"])
    rc = main(["probe", "--rpc", w3.provider.endpoint_uri, "--markdown", "--roles-from-logs", "--logs-rpc", "http://127.0.0.1:1", box.address])
    assert rc == 2
    assert "Not covered: role history" in capsys.readouterr().out


def test_disclosure_check_exits_2_when_the_chain_cannot_be_read(anvil, artifacts, tmp_path, monkeypatch, capsys):  # noqa: F811
    import ownerwatch.probe as mod
    w3 = anvil
    admin = _deploy(w3, *artifacts["Admin"])
    path = tmp_path / "d.json"
    path.write_text(json.dumps(draft(w3, [admin.address], "T")))
    monkeypatch.setattr(mod.Prober, "_has_role", lambda *a: (_ for _ in ()).throw(ProbeRpcError("502")))
    monkeypatch.setattr(mod.Prober, "_batch_calls", lambda *a: (_ for _ in ()).throw(ProbeRpcError("502")))
    assert main(["disclosure", "check", str(path), "--rpc", w3.provider.endpoint_uri, "--no-roles-from-logs"]) == 2


# ---- proxies ------------------------------------------------------------------------------------------------------

def test_beacon_owner_is_the_upgrade_authority(anvil, artifacts):  # noqa: F811
    w3 = anvil
    key = w3.eth.accounts[3]
    beacon = _deploy(w3, *artifacts["SettableOwner"])
    send(w3, beacon.functions.setOwner(key))
    proxy = _deploy(w3, *artifacts["ManagedLike"])
    set_slot(w3, proxy.address, BEACON_SLOT, beacon.address)
    p = Prober(w3)
    n = p.probe(proxy.address)
    assert n.kind == "proxy" and n.beacon == beacon.address and n.proxy_admin == key
    assert any("upgrade admin is an EOA" in x for x in n.notes)
    assert beacon.address in p.seen
    d = draft(w3, [proxy.address], "T")
    assert [x["kind"] for x in d["powers"] if x["controllerNodeId"].endswith(key[2:].lower())] == ["UPGRADE"]
    assert Checker(w3).check(d)["summary"]["mismatch"] == 0


def test_clone_of_a_beacon_proxy_is_upgradeable(anvil, artifacts):  # noqa: F811
    w3 = anvil
    key = w3.eth.accounts[3]
    beacon = _deploy(w3, *artifacts["SettableOwner"])
    send(w3, beacon.functions.setOwner(key))
    target = _deploy(w3, *artifacts["ManagedLike"])
    set_slot(w3, target.address, BEACON_SLOT, beacon.address)
    maker = _deploy(w3, *artifacts["CloneMaker"])
    send(w3, maker.functions.clone(target.address))
    p = Prober(w3)
    n = p.probe(maker.functions.last().call())
    assert n.beacon == beacon.address and n.proxy_admin == key
    assert "upgradeable through its beacon" in markdown_report(p, "T", "x", [n])


def test_zeppelinos_slots_are_read(anvil, artifacts):  # noqa: F811
    """USDC and other early proxies use these slots; they used to read as plain contracts."""
    w3 = anvil
    assert LEGACY_IMPL_SLOTS[0] == 0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3    # as USDC's bytecode has it
    assert LEGACY_ADMIN_SLOT == 0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b
    proxy, impl = _deploy(w3, *artifacts["ManagedLike"]), _deploy(w3, *artifacts["ManagedLike"])
    key = w3.eth.accounts[3]
    set_slot(w3, proxy.address, LEGACY_IMPL_SLOTS[0], impl.address)
    set_slot(w3, proxy.address, LEGACY_ADMIN_SLOT, key)
    n = Prober(w3).probe(proxy.address)
    assert n.kind == "proxy" and n.implementation == impl.address and n.proxy_admin == key
    assert any("upgrade admin is an EOA" in x for x in n.notes)


def test_junk_in_a_proxy_slot_is_not_a_proxy(anvil, artifacts):  # noqa: F811
    w3 = anvil
    c = _deploy(w3, *artifacts["ManagedLike"])
    w3.provider.make_request("anvil_setStorageAt", [c.address, hex(IMPL_SLOT), "0x" + "11" * 32])
    assert Prober(w3).probe(c.address).kind == "contract"


def test_getters_that_do_not_return_addresses_invent_no_keys(anvil, artifacts):  # noqa: F811
    w3 = anvil
    c = _deploy(w3, *artifacts["JunkGetters"])
    p = Prober(w3)
    n = p.probe(c.address)
    assert n.owner is None and n.emergency is None and n.named == {} and n.notes == []
    assert list(p.seen) == [c.address]


def test_catch_all_fallback_does_not_crash_or_read_as_a_safe(anvil, artifacts):  # noqa: F811
    w3 = anvil
    c = _deploy(w3, *artifacts["CatchAll"])
    assert Prober(w3).probe(c.address).kind != "safe"


# ---- walking the controllers --------------------------------------------------------------------------------------

def test_a_key_far_up_the_chain_is_found_whatever_the_root_order(anvil, artifacts):  # noqa: F811
    w3 = anvil
    key = w3.eth.accounts[3]
    a, b, c, d = [_deploy(w3, *artifacts["SettableOwner"]) for _ in range(4)]
    send(w3, a.functions.setOwner(b.address))
    send(w3, b.functions.setOwner(c.address))
    send(w3, c.functions.setOwner(d.address))
    send(w3, d.functions.setOwner(key))
    for roots in ([a.address, c.address], [c.address, a.address]):
        p = Prober(w3)
        for r in roots:
            p.probe(r)
        assert key in p.seen and any("is an EOA" in x for x in p.seen[d.address].notes)


def test_a_delay_parameter_does_not_make_a_timelock(anvil, artifacts):  # noqa: F811
    w3 = anvil
    param = _deploy(w3, *artifacts["DelayParamLike"])
    n = Prober(w3).probe(param.address)
    assert n.kind == "contract" and n.delay is None and any("is an EOA" in x for x in n.notes)


# ---- findings -----------------------------------------------------------------------------------------------------

def test_half_is_not_fewer_than_half_and_modules_are_reported(anvil, artifacts):  # noqa: F811
    w3 = anvil
    safe = _deploy(w3, *artifacts["SafeWithModule"])
    key = w3.eth.accounts[3]
    send(w3, safe.functions.addModule(key))
    n = Prober(w3).probe(safe.address)
    assert n.safe_modules == [key]
    assert "2-of-4 Safe: half the owners are enough" in n.notes
    assert any(f"Safe module {key} (an EOA) can execute without the signers" == x for x in n.notes)


def test_replay_reports_every_powerful_role_and_every_contract_above_the_root(anvil, artifacts, capsys):  # noqa: F811
    w3 = anvil
    box = _deploy(w3, *artifacts["RoleLog"])
    send(w3, box.functions.grantRole(b"\x00" * 32, w3.eth.accounts[3]))
    url = w3.provider.endpoint_uri
    assert main(["probe", "--rpc", url, "--markdown", "--roles-from-logs", "--logs-rpc", url, "--from-block", "0", box.address]) == 0
    assert "DEFAULT_ADMIN_ROLE held by EOA" in capsys.readouterr().out


def test_eoa_proposer_on_a_timelock_is_a_finding(anvil, artifacts):  # noqa: F811
    w3 = anvil
    tl = _deploy(w3, *artifacts["ProposerTimelock"])
    key = w3.eth.accounts[3]
    send(w3, tl.functions.give(bytes(Web3.keccak(text="PROPOSER_ROLE")), key))
    p = Prober(w3)
    n = p.probe(tl.address)
    p.check_roles([key])
    assert any(f"PROPOSER_ROLE held by EOA {key}" in x for x in n.notes)


def test_safe_getter_only_claims_assets_on_a_vault(anvil, artifacts):  # noqa: F811
    w3 = anvil
    key = w3.eth.accounts[3]
    vault, module = _deploy(w3, *artifacts["VaultWithSafe"]), _deploy(w3, *artifacts["ModuleWithSafe"])
    send(w3, vault.functions.set(key))
    send(w3, module.functions.set(key))
    p = Prober(w3)
    assert "safe() (holds the vault's assets)" in p.probe(vault.address).named
    assert "safe()" in p.probe(module.address).named


# ---- AccessManager ------------------------------------------------------------------------------------------------

def am_setup(w3, artifacts):  # noqa: F811
    am, target = _deploy(w3, *artifacts["AccessManagerLike"]), _deploy(w3, *artifacts["ManagedLike"])
    send(w3, target.functions.setAuthority(am.address))
    return am, target


def probe_am(w3, am, target, candidates):
    p = Prober(w3)
    n = p.probe(target.address)
    p.check_roles(candidates)
    return p, n, p.seen[am.address]


def test_any_short_execution_delay_is_still_reported(anvil, artifacts):  # noqa: F811
    w3 = anvil
    am, target = am_setup(w3, artifacts)
    key = w3.eth.accounts[3]
    send(w3, am.functions.grant(0, key, 1))
    _, n, m = probe_am(w3, am, target, [key])
    assert any("only 1s execution delay" in x for x in m.notes) and any("only 1s execution delay" in x for x in n.notes)


def test_long_execution_delay_is_not_a_single_key_finding(anvil, artifacts):  # noqa: F811
    w3 = anvil
    am, target = am_setup(w3, artifacts)
    key = w3.eth.accounts[3]
    send(w3, am.functions.grant(0, key, 7 * 86400))
    _, n, m = probe_am(w3, am, target, [key])
    assert not any("execution delay" in x for x in m.notes)


def test_public_admin_function_and_public_role_admin_are_findings(anvil, artifacts):  # noqa: F811
    w3 = anvil
    am, target = am_setup(w3, artifacts)
    public = 2**64 - 1
    send(w3, am.functions.setFn(target.address, bytes(Web3.keccak(text="upgradeToAndCall(address,bytes)")[:4]), public))
    send(w3, am.functions.setFn(target.address, PAUSE, 7))
    send(w3, am.functions.setAdmin(7, public))
    _, n, m = probe_am(w3, am, target, [])
    assert any("upgradeToAndCall" in x and "anyone can call it" in x for x in n.notes)
    assert "role 7 has PUBLIC_ROLE as its admin: anyone can grant it to themselves" in m.notes


def test_public_user_functions_are_not_a_finding():
    """Found on live IPOR Fusion vaults: ERC-4626 mint and withdraw are public on purpose."""
    from ownerwatch.probe import AM_SENSITIVE_FN
    for fn in ("deposit(uint256,address)", "mint(uint256,address)", "withdraw(uint256,address,address)", "redeem(uint256,address,address)", "pause()"):
        assert not AM_SENSITIVE_FN.match(fn), fn
    for fn in ("upgradeToAndCall(address,bytes)", "setAuthority(address)", "transferOwnership(address)", "mint(address,uint256)"):
        assert AM_SENSITIVE_FN.match(fn), fn


def test_a_grant_to_the_zero_address_is_nobodys_key(anvil, artifacts):  # noqa: F811
    """Found on live IPOR Fusion managers: the zero address holds a role, and no key signs for it."""
    w3 = anvil
    am, target = am_setup(w3, artifacts)
    send(w3, am.functions.grant(0, "0x" + "00" * 20, 0))
    p = Prober(w3)
    n = p.probe(target.address)
    p.check_roles([])
    p.role_history(am.address, 0, w3)
    assert not any("0x" + "00" * 20 in x for x in [*n.notes, *p.seen[am.address].notes])


def test_role_zero_claims_no_functions_nobody_configured(anvil, artifacts):  # noqa: F811
    """Every unset selector reads as ADMIN_ROLE, including functions the target does not have."""
    w3 = anvil
    am, target = am_setup(w3, artifacts)
    key = w3.eth.accounts[3]
    send(w3, am.functions.grant(0, key, 0))
    _, n, m = probe_am(w3, am, target, [key])
    assert 0 not in m.am_gates
    note = next(x for x in m.notes if x.startswith("role 0 held"))
    assert "calls" not in note


def test_closed_target_has_no_callers_and_delays_are_stated(anvil, artifacts):  # noqa: F811
    w3 = anvil
    am, target = am_setup(w3, artifacts)
    key = w3.eth.accounts[3]
    send(w3, am.functions.grant(0, key, 0))
    send(w3, am.functions.setTargetDelay(target.address, 7 * 86400))
    _, _, m = probe_am(w3, am, target, [key])
    assert any("(waits 168h on" in x for x in m.notes)
    am2, target2 = am_setup(w3, artifacts)
    send(w3, am2.functions.setFn(target2.address, PAUSE, 7))
    send(w3, am2.functions.grant(7, key, 0))
    send(w3, am2.functions.close(target2.address))
    _, _, m2 = probe_am(w3, am2, target2, [key])
    assert m2.am_closed == [target2.address] and 7 not in m2.am_gates


def test_grant_delay_is_stated(anvil, artifacts):  # noqa: F811
    w3 = anvil
    am, target = am_setup(w3, artifacts)
    key = w3.eth.accounts[3]
    send(w3, am.functions.setFn(target.address, PAUSE, 7))
    send(w3, am.functions.setAdmin(7, 9))
    send(w3, am.functions.setGrantDelay(7, 7 * 86400))
    send(w3, am.functions.grant(9, key, 0))
    _, n, m = probe_am(w3, am, target, [key])
    assert any("roles 7 (calls pause) after 168h" in x for x in m.notes)


def test_a_role_only_reaches_the_targets_it_guards(anvil, artifacts):  # noqa: F811
    w3 = anvil
    am, v1 = am_setup(w3, artifacts)
    v2 = _deploy(w3, *artifacts["ManagedLike"])
    send(w3, v2.functions.setAuthority(am.address))
    key = w3.eth.accounts[3]
    send(w3, am.functions.setFn(v1.address, PAUSE, 7))
    send(w3, am.functions.grant(7, key, 0))
    p = Prober(w3)
    n1, n2 = p.probe(v1.address), p.probe(v2.address)
    p.check_roles([key])
    assert any("role 7" in x for x in n1.notes) and not any("role 7" in x for x in n2.notes)


def test_contract_owned_by_the_manager_is_a_target(anvil, artifacts):  # noqa: F811
    w3 = anvil
    am = _deploy(w3, *artifacts["AccessManagerLike"])
    owned = _deploy(w3, *artifacts["SettableOwner"])
    send(w3, owned.functions.setOwner(am.address))
    key = w3.eth.accounts[3]
    send(w3, am.functions.setFn(owned.address, bytes(Web3.keccak(text="transferOwnership(address)")[:4]), 7))
    send(w3, am.functions.grant(7, key, 0))
    p = Prober(w3)
    n = p.probe(owned.address)
    p.check_roles([key])
    assert any("role 7 held by EOA" in x for x in n.notes)


def test_replay_finds_guards_and_pending_grants(anvil, artifacts):  # noqa: F811
    import time
    w3 = anvil
    am, target = am_setup(w3, artifacts)
    key, later = w3.eth.accounts[3], w3.eth.accounts[4]
    custom = b"\x12\x34\x56\x78"     # a selector no ABI or fallback list names
    send(w3, am.functions.setFn(target.address, custom, 7))
    send(w3, am.functions.grant(7, key, 0))
    send(w3, am.functions.grantLater(9, later, int(time.time()) + 7 * 86400))
    p = Prober(w3)
    n = p.probe(target.address)
    p.check_roles([])
    p.role_history(am.address, 0, w3)
    m = p.seen[am.address]
    assert m.am_gates[7] == [f"0x12345678 on {target.address}"]
    assert any("role 7 held by EOA" in x for x in n.notes)
    assert any(x.startswith(f"pending grant: role 9 goes to EOA {later}") for x in m.notes)
    assert am.address in p.replayed


def test_report_states_a_manager_finding_once(anvil, artifacts):  # noqa: F811
    w3 = anvil
    am, target = am_setup(w3, artifacts)
    key = w3.eth.accounts[3]
    send(w3, am.functions.grant(0, key, 0))
    p = Prober(w3)
    n = p.probe(target.address)
    p.check_roles([key])
    assert any(x.startswith("AccessManager 0x") for x in n.notes)      # the node keeps it, for --json and describe
    md = markdown_report(p, "T", "x", [n])
    assert md.count(f"role 0 held by EOA {key}") == 1


def test_caveat_stays_until_the_manager_was_replayed(anvil, artifacts):  # noqa: F811
    w3 = anvil
    am, target = am_setup(w3, artifacts)
    key = w3.eth.accounts[3]
    send(w3, am.functions.grant(0, key, 0))
    p = Prober(w3)
    n = p.probe(target.address)
    p.check_roles([key])
    assert "does not list its members" in markdown_report(p, "T", "x", [n])      # a holder was found, others may exist
    p.role_history(am.address, 0, w3)
    assert "does not list its members" not in markdown_report(p, "T", "x", [n])


# ---- disclosure ---------------------------------------------------------------------------------------------------

def test_access_manager_roles_are_drafted_checked_and_caught_when_omitted(anvil, artifacts):  # noqa: F811
    w3 = anvil
    am, target = am_setup(w3, artifacts)
    key = w3.eth.accounts[0]
    send(w3, am.functions.grant(0, key, 0))
    opts = dict(roles_from_logs=True, logs_w3=w3, from_block=0)
    d = draft(w3, [target.address], "T", **opts)
    roles = [p for p in d["powers"] if p["kind"] == "ROLE"]
    assert [p["role"] for p in roles] == ["accessManager:0"]
    assert Checker(w3, **opts).check(d)["summary"]["mismatch"] == 0
    d["powers"] = [p for p in d["powers"] if p["kind"] != "ROLE"]
    d["protocol"].pop("manifestHash")
    report = Checker(w3, **opts).check(d)
    assert [u["role"] for u in report["undisclosed"]] == ["accessManager:0"]


def test_role_on_the_manager_itself_can_be_declared_by_name(anvil, artifacts):  # noqa: F811
    w3 = anvil
    am, target = am_setup(w3, artifacts)
    key = w3.eth.accounts[0]
    send(w3, am.functions.grant(0, key, 0))
    d = {"components": [{"componentId": "m", "address": am.address}], "nodes": [{"nodeId": "k", "type": "EOA", "address": key}],
         "powers": [{"powerId": "p", "kind": "ROLE", "role": "ADMIN_ROLE", "target": "m", "controllerNodeId": "k"},
                    {"powerId": "q", "kind": "ROLE", "role": "SOME_NAME", "target": "m", "controllerNodeId": "k"}]}
    results = {r["id"]: r["status"] for r in Checker(w3).check(d)["results"] if r["record"] == "power"}
    assert results == {"p": "ok", "q": "unverifiable"}


def test_uups_authority_is_unverifiable_never_ok_or_mismatch(anvil, artifacts):  # noqa: F811
    w3 = anvil
    proxy, impl = _deploy(w3, *artifacts["ManagedLike"]), _deploy(w3, *artifacts["ManagedLike"])
    set_slot(w3, proxy.address, IMPL_SLOT, impl.address)
    key = w3.eth.accounts[0]
    d = {"components": [{"componentId": "c", "address": proxy.address, "upgradeable": True, "adminNodeId": "k"}],
         "nodes": [{"nodeId": "k", "type": "EOA", "address": key}],
         "powers": [{"powerId": "up", "kind": "UPGRADE", "target": "c", "controllerNodeId": "k"}]}
    results = {r["id"]: r["status"] for r in Checker(w3).check(d)["results"]}
    assert results["up"] == "unverifiable" and results["c"] == "unverifiable"


def test_power_with_no_bound_controller_is_never_ok(anvil, artifacts):  # noqa: F811
    w3 = anvil
    c = _deploy(w3, *artifacts["ManagedLike"])       # no owner
    d = {"components": [{"componentId": "c", "address": c.address}], "nodes": [],
         "powers": [{"powerId": "own", "kind": "OWNERSHIP", "target": "c", "controllerNodeId": "ghost"}]}
    results = {r["id"]: r["status"] for r in Checker(w3).check(d)["results"]}
    assert results["own"] == "unverifiable"


def test_role_hash_in_the_draft_makes_the_check_independent_of_sourcify(anvil, artifacts):  # noqa: F811
    w3 = anvil
    box = _deploy(w3, *artifacts["RoleLog"])
    send(w3, box.functions.grantRole(b"\x11" * 32, w3.eth.accounts[3]))
    d = draft(w3, [box.address], "T", roles_from_logs=True, from_block=0, logs_w3=w3)
    role = next(p for p in d["powers"] if p["kind"] == "ROLE" and p["roleHash"] == "0x" + "11" * 32)
    role["role"] = "A_NAME_NO_ABI_EXPLAINS"
    d["protocol"].pop("manifestHash")
    results = {r["id"]: r["status"] for r in Checker(w3).check(d)["results"]}
    assert results[role["powerId"]] == "ok"
    del role["roleHash"]        # as a hand-written file, with Sourcify down: nothing can confirm or refute it
    results = {r["id"]: r["status"] for r in Checker(w3).check(d)["results"]}
    assert results[role["powerId"]] == "unverifiable"


def test_vanity_prefixes_do_not_collide_in_the_draft(anvil, artifacts):  # noqa: F811
    w3 = anvil
    a, b = "0x000000" + "aa" * 17, "0x000000" + "bb" * 17
    a, b = Web3.to_checksum_address(a), Web3.to_checksum_address(b)
    x, y = _deploy(w3, *artifacts["SettableOwner"]), _deploy(w3, *artifacts["SettableOwner"])
    send(w3, x.functions.setOwner(a))
    send(w3, y.functions.setOwner(b))
    d = draft(w3, [x.address, y.address], "T")
    assert {n["address"] for n in d["nodes"]} >= {a, b}
    assert Checker(w3).check(d)["summary"]["mismatch"] == 0


def test_node_types_cover_every_kind():
    from ownerwatch.disclosure import NODE_TYPES
    assert NODE_TYPES["aragon-app"] == "CONTRACT" and NODE_TYPES["access-manager"] == "CONTRACT"


def test_manifest_hash_is_over_the_text_as_written():
    a = manifest_hash({"protocol": {"name": "Café"}})
    assert a == "0x" + Web3.keccak(text='{"protocol":{"name":"Café"}}').hex().removeprefix("0x")


# ---- the report and the config path -------------------------------------------------------------------------------

def test_facts_block_carries_full_addresses_and_every_signer(anvil, artifacts):  # noqa: F811
    w3 = anvil
    safe = _deploy(w3, *artifacts["SafeWithModule"])
    key = w3.eth.accounts[3]
    send(w3, safe.functions.addModule(key))
    p = Prober(w3)
    n = p.probe(safe.address)
    md = markdown_report(p, "T", "base", [n])
    facts = md.split("```ownerwatch-facts\n")[1].split("\n```")[0].splitlines()
    assert facts == fact_lines(p, "base") == sorted(facts)
    assert f"base {safe.address} threshold 2" in facts and f"base {safe.address} module {key}" in facts
    assert sum(" signer " in x for x in facts) == 4
    assert f"`ownerwatch probe` {__version__} on base" in md


def test_config_path_honours_roles_from_logs_candidates_and_chain_name(anvil, artifacts, tmp_path, capsys):  # noqa: F811
    w3 = anvil
    url = w3.provider.endpoint_uri
    box = _deploy(w3, *artifacts["RoleLog"])
    send(w3, box.functions.grantRole(b"\x00" * 32, w3.eth.accounts[3]))
    cfg = tmp_path / "c.yaml"
    cfg.write_text(f'rpc_url: "{url}"\ncontracts: [{{address: "{box.address}"}}]\n')
    assert main(["probe", "--config", str(cfg), "--markdown", "--roles-from-logs", "--from-block", "0"]) == 0
    out = capsys.readouterr().out
    assert "DEFAULT_ADMIN_ROLE held by EOA" in out
    assert "admin surface on chain 31337" in out      # chain_name left at its default on another chain
    assert main(["probe", "--config", str(cfg), "--markdown", "--chain-name", "mainnet-fork"]) == 0
    assert "admin surface on mainnet-fork" in capsys.readouterr().out
