"""ownerwatch collateral: markets found from chain state alone, ranked by allocation, every read at one block, and a
failed read never reported as a clean one."""
import json
import shutil

import pytest
import yaml
from web3 import Web3

from ownerwatch.cli import main
from ownerwatch.collateral import NotAVault, build
from ownerwatch.config import load_all
from tests.test_watcher import FIXTURES, _deploy, anvil, artifacts  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(shutil.which("anvil") is None, reason="foundry not installed")
USD = 10**6


@pytest.fixture(autouse=True)
def unpinned(anvil):  # noqa: F811
    """The report pins the client's default block; the anvil fixture is shared between tests."""
    anvil.eth.default_block = "latest"


@pytest.fixture(scope="module")
def morpho(artifacts):  # noqa: F811
    out = {}
    for path in (FIXTURES / "out" / "Morpho.sol").glob("*.json"):
        art = json.loads(path.read_text())
        out[path.stem] = (art["abi"], art["bytecode"]["object"])
    return out


def send(w3, fn, sender=None):
    return w3.eth.wait_for_transaction_receipt(fn.transact({"from": sender or w3.eth.accounts[0]}))


def market(w3, blue, loan, collateral, oracle, lltv=860000000000000000):
    send(w3, blue.functions.createMarket(loan, collateral, oracle, lltv))
    params = (Web3.to_checksum_address(loan), Web3.to_checksum_address(collateral), Web3.to_checksum_address(oracle),
              Web3.to_checksum_address("0x0000000000000000000000000000000000001001"), lltv)
    return bytes(Web3.keccak(w3.codec.encode(["(address,address,address,address,uint256)"], [params])))


def supply(w3, blue, mid, holder, assets):
    """A position worth exactly `assets`: shares at the virtual-share rate of an untouched market."""
    send(w3, blue.functions.setTotals(mid, assets, assets * 10**6))
    send(w3, blue.functions.setShares(mid, holder, assets * 10**6))


@pytest.fixture
def v1(anvil, morpho):  # noqa: F811
    """A V1 vault: OMT (owner mints), RMT (enumerable MINTER_ROLE), PLN (nothing) with no allocation, and an idle market."""
    w3 = anvil
    blue, usdt = _deploy(w3, *morpho["MorphoBlueLike"]), _deploy(w3, *morpho["LoanToken"])
    omt, rmt, pln = _deploy(w3, *morpho["OwnedMintToken"]), _deploy(w3, *morpho["RoleMintToken"]), _deploy(w3, *morpho["PlainToken"])
    oracle = _deploy(w3, *morpho["OracleOwned"])
    feed, feed_oracle = _deploy(w3, *morpho["FeedLike"]), _deploy(w3, *morpho["OracleWithFeed"])
    send(w3, feed_oracle.functions.init(feed.address))
    minter = w3.eth.accounts[2]
    send(w3, rmt.functions.grant(bytes(Web3.keccak(text="MINTER_ROLE")), minter))
    vault = _deploy(w3, *morpho["MetaMorphoLike"])
    send(w3, vault.functions.init(blue.address, usdt.address))
    ids = {"omt": market(w3, blue, usdt.address, omt.address, oracle.address),
           "rmt": market(w3, blue, usdt.address, rmt.address, feed_oracle.address),
           "pln": market(w3, blue, usdt.address, pln.address, oracle.address),
           "idle": market(w3, blue, usdt.address, "0x" + "00" * 20, "0x" + "00" * 20, 0)}
    supply(w3, blue, ids["omt"], vault.address, 5_000_000 * USD)
    supply(w3, blue, ids["rmt"], vault.address, 3_000_000 * USD)
    supply(w3, blue, ids["idle"], vault.address, 1_000 * USD)
    for k, cap in (("rmt", 4_000_000), ("omt", 10_000_000), ("pln", 1_000_000), ("idle", 10**9)):
        send(w3, vault.functions.add(ids[k], cap * USD, k != "pln"))
    send(w3, vault.functions.setTotalAssets(8_001_000 * USD))
    return dict(w3=w3, blue=blue, usdt=usdt, omt=omt, rmt=rmt, pln=pln, oracle=oracle, feed=feed, feed_oracle=feed_oracle,
                vault=vault, minter=minter, ids=ids)


def test_v1_ranks_collateral_by_allocation_at_one_block(v1):
    w3, vault, omt = v1["w3"], v1["vault"], v1["omt"]
    a0, a1 = w3.eth.accounts[0], w3.eth.accounts[1]
    block = w3.eth.block_number
    send(w3, omt.functions.transferOwnership(a1))                     # after the pinned block: must not show
    rep = build(w3, vault.address, block)
    assert rep.version_name == "MetaMorpho V1.1" and rep.block == block
    assert [t.symbol for t in rep.tokens] == ["OMT", "RMT", "PLN"]     # ranked by allocation; the idle market is no token
    assert [t.assets for t in rep.tokens] == [5_000_000 * USD, 3_000_000 * USD, 0]
    assert rep.reconciles and rep.complete and not rep.failed
    o, r, p = rep.tokens
    assert o.powers["owner"][0] == "EOA, no delay" and a0 in o.powers["owner"][1][0] and a1 not in str(o.powers)
    assert any("mint(address,uint256) passes in simulation from" in x and a0 in x for x in o.powers["mint"][1])
    assert o.powers["pause"][0] == "EOA, no delay"
    assert r.powers["mint"][0] == "EOA, no delay" and any(v1["minter"] in x for x in r.powers["mint"][1])
    assert r.role_scope["MINTER_ROLE"] == "listed by the contract"
    assert p.powers["owner"][0] == "none" and p.powers["upgrade"][0] == "not a proxy" and p.powers["mint"][0] == "no mint function found"
    md = rep.markdown()
    assert f"| Pinned block | {block} " in md and "every read in this report is at this block" in md
    assert "| 1 | OMT" in md and "| 5,000,000.00 | 62.5% |" in md and "| 3 | PLN" in md
    assert "Idle markets (no collateral, nothing borrowed): `" in md and "1,000.00 USDT" in md
    assert "reconciles with totalAssets()" in md and "Coverage gaps" not in md
    assert "| 86% | 5,000,000.00 | 10,000,000.00 |" in md                 # the V1 cap, in loan-token units
    assert f"BASE_FEED_1 `{v1['feed'].address}` (OMT / USD): owner EOA `{a0}`" in md
    assert "| none (feeds: EOA, no delay) |" in md and "| EOA, no delay; price source not read |" in md   # oracle owner column, both kinds
    assert "where this oracle takes its price from was not read" in md


def test_failed_read_is_reported_never_clean(v1, monkeypatch):
    import ownerwatch.collateral as col
    import ownerwatch.probe as mod
    w3, omt = v1["w3"], v1["omt"].address
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    monkeypatch.setattr(col.time, "sleep", lambda s: None)
    real = w3.eth.call

    def flaky(tx, *a, **k):
        if tx.get("to") == omt:
            raise ValueError({"code": -32005, "message": "503 Server Error"})
        return real(tx, *a, **k)

    monkeypatch.setattr(w3.eth, "call", flaky)
    rep = build(w3, v1["vault"].address, w3.eth.block_number)
    t = rep.tokens[0]
    assert t.symbol == "?" and t.error and "503" in t.error and not t.powers
    assert not rep.complete and any(omt in x for x in rep.failed)
    assert omt not in rep.prober.seen        # the half-probed node was rolled back, not left to read as "no owner"
    md = rep.markdown()
    row = next(x for x in md.splitlines() if x.startswith("| 1 |"))
    assert "read failed" in row and "none" not in row
    assert "## Coverage gaps" in md and "must not be read as safe" in md
    assert "# NOT COVERED:" in rep.config("http://x")


def test_not_a_vault_fails_cleanly(v1, capsys):
    w3 = v1["w3"]
    with pytest.raises(NotAVault):
        build(w3, v1["pln"].address, w3.eth.block_number)
    for target in (v1["pln"].address, w3.eth.accounts[5]):
        assert main(["collateral", target, "--rpc", w3.provider.endpoint_uri, "--block", str(w3.eth.block_number)]) == 2
        err = capsys.readouterr().err
        assert "is not a Morpho vault" in err and "Only MetaMorpho V1 and Morpho Vault V2 are covered" in err and "Traceback" not in err


def test_v2_adapters_nested_vault_and_unmapped_adapter(v1, morpho):
    w3, blue, usdt = v1["w3"], v1["blue"], v1["usdt"]
    v2 = _deploy(w3, *morpho["VaultV2Like"])
    send(w3, v2.functions.init(usdt.address))
    ma, va = _deploy(w3, *morpho["MarketAdapterLike"]), _deploy(w3, *morpho["VaultAdapterLike"])
    send(w3, ma.functions.init(blue.address))
    supply(w3, blue, v1["ids"]["pln"], ma.address, 2_000_000 * USD)      # PLN market, held by the market adapter
    send(w3, ma.functions.add(v1["ids"]["pln"]))
    send(w3, va.functions.init(v1["vault"].address))
    send(w3, v1["vault"].functions.setShares(va.address, 25, 100))        # a quarter of the V1 vault
    for a in (ma.address, va.address):
        send(w3, v2.functions.addAdapter(a))
    send(w3, v2.functions.setTotalAssets(2_000_000 * USD + 8_001_000 * USD // 4))
    rep = build(w3, v2.address, w3.eth.block_number)
    assert rep.version_name == "Morpho Vault V2"
    assert "| timelock(selector) | addAdapter 72h, increaseAbsoluteCap 0" in rep.markdown()
    assert {t.symbol: t.assets for t in rep.tokens} == {"PLN": 2_000_000 * USD, "OMT": 1_250_000 * USD, "RMT": 750_000 * USD}
    assert rep.reconciles and rep.complete
    nested = next(m for m in rep.markets.values() if m.collateral == v1["omt"].address)
    assert nested.via == [v2.address, va.address, v1["vault"].address]
    other = _deploy(w3, *morpho["OtherAdapterLike"])
    send(w3, v2.functions.addAdapter(other.address))
    rep = build(w3, v2.address, w3.eth.block_number)
    assert not rep.complete and any(other.address in x and "not mapped" in x for x in rep.uncovered)
    assert "Not covered: adapter " + other.address in rep.markdown()


def test_reconciliation_gap_and_open_questions_are_not_clean(v1, morpho):
    w3, blue, usdt, vault = v1["w3"], v1["blue"], v1["usdt"], v1["vault"]
    send(w3, vault.functions.setTotalAssets(9_000_000 * USD))
    rep = build(w3, vault.address, w3.eth.block_number)
    assert not rep.reconciles and not rep.complete
    assert "**does not reconcile with totalAssets()**" in rep.markdown()
    # roles and an upgrade gate held by addresses the report never sees
    hrt, proxy, impl = _deploy(w3, *morpho["HiddenRoleToken"]), _deploy(w3, *morpho["UupsProxy"]), _deploy(w3, *morpho["UupsToken"])
    send(w3, hrt.functions.give(bytes(32), w3.eth.accounts[6]))
    send(w3, hrt.functions.give(bytes(Web3.keccak(text="MINTER_ROLE")), w3.eth.accounts[7]))
    send(w3, proxy.functions.setUp(impl.address, "0x" + "00" * 20, w3.eth.accounts[8]))
    send(w3, vault.functions.setTotalAssets(8_001_000 * USD))
    for token in (hrt.address, proxy.address):
        send(w3, vault.functions.add(market(w3, blue, usdt.address, token, v1["oracle"].address), 1, False))
    rep = build(w3, vault.address, w3.eth.block_number)
    h, u = (next(t for t in rep.tokens if t.address == a) for a in (hrt.address, proxy.address))
    assert h.powers["owner"][0] == "not established" and h.powers["mint"][0] == "not established"
    assert any(x.startswith("DEFAULT_ADMIN_ROLE on") for x in h.open) and any(x.startswith("who can mint") for x in h.open)
    assert u.powers["upgrade"][0] == "not established" and any(x.startswith("who can upgrade") for x in u.open)
    assert not rep.complete and "not established" in rep.markdown()


def test_uups_upgrader_wrapper_and_timelock_path(v1, morpho, artifacts):  # noqa: F811
    w3, blue, usdt, vault, omt = v1["w3"], v1["blue"], v1["usdt"], v1["vault"], v1["omt"]
    a0 = w3.eth.accounts[0]
    proxy, impl = _deploy(w3, *morpho["UupsProxy"]), _deploy(w3, *morpho["UupsToken"])
    send(w3, proxy.functions.setUp(impl.address, a0, a0))                # owner() is also the upgrader
    wrapper = _deploy(w3, *morpho["Wrapper4626"])
    send(w3, wrapper.functions.init(omt.address))
    timelock = _deploy(w3, *artifacts["ProposerTimelock"])
    send(w3, timelock.functions.give(bytes(Web3.keccak(text="PROPOSER_ROLE")), a0))
    send(w3, omt.functions.transferOwnership(timelock.address))
    for token in (proxy.address, wrapper.address):
        send(w3, vault.functions.add(market(w3, blue, usdt.address, token, v1["oracle"].address), 1, False))
    rep = build(w3, vault.address, w3.eth.block_number)
    u = next(t for t in rep.tokens if t.address == proxy.address)
    assert u.powers["upgrade"][0] == "EOA, no delay" and any(a0 in x for x in u.powers["upgrade"][1])
    o = rep.tokens[0]
    assert o.symbol == "OMT" and o.powers["owner"][0] == "48h timelock (proposers found among the addresses tested) → EOA"
    assert any("48h timelock delay on this path" in x for x in o.powers["mint"][1])
    w = next(t for t in rep.tokens if t.address == wrapper.address)
    assert w.powers["mint"][0] == "deposits only" and w.wraps_ranked == omt.address    # OMT is collateral too: no second copy


def test_cli_yaml_markdown_and_default_pin(v1, tmp_path, capsys):
    w3, vault = v1["w3"], v1["vault"]
    w3.provider.make_request("anvil_mine", [8])
    head = w3.eth.block_number
    assert main(["collateral", vault.address, "--rpc", w3.provider.endpoint_uri, "--yaml"]) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"# ownerwatch config for the collateral of tvUSDT {vault.address}, from chain state at block {head - 5}")
    cfg = tmp_path / "c.yaml"
    cfg.write_text(out)
    (c,) = load_all(cfg)
    watched = {x.address for x in c.contracts}
    assert {v1["omt"].address, v1["rmt"].address, v1["pln"].address, v1["oracle"].address, v1["feed_oracle"].address, vault.address} <= watched
    assert not any(a in watched for a in w3.eth.accounts[:3])                  # EOAs emit nothing to watch
    assert yaml.safe_load(out)["contracts"][1]["label"] == "OMT collateral"
    assert main(["collateral", vault.address, "--rpc", w3.provider.endpoint_uri, "--markdown", "--yaml", "--block", str(head)]) == 0
    md = capsys.readouterr().out
    assert md.startswith("# Test USDT Vault collateral report") and "## Watch config" in md and "```yaml" in md
    assert main(["collateral", vault.address, "--rpc", w3.provider.endpoint_uri, "--block", str(head)]) == 0
    assert "#1 OMT" in capsys.readouterr().out
    assert main(["collateral", vault.address, "--rpc", w3.provider.endpoint_uri, "--block", str(head + 100)]) == 2
    assert "ahead of the RPC's head" in capsys.readouterr().err


def test_explorer_grants_are_hints_confirmed_on_chain(v1, morpho, monkeypatch):
    import ownerwatch.collateral as col
    w3, blue, usdt, vault = v1["w3"], v1["blue"], v1["usdt"], v1["vault"]
    admin, minter, revoked = w3.eth.accounts[6], w3.eth.accounts[7], w3.eth.accounts[9]
    hrt = _deploy(w3, *morpho["HiddenRoleToken"])
    send(w3, hrt.functions.give(bytes(32), admin))
    send(w3, hrt.functions.give(bytes(Web3.keccak(text="MINTER_ROLE")), minter))
    send(w3, vault.functions.add(market(w3, blue, usdt.address, hrt.address, v1["oracle"].address), 1, False))
    minter_role = "0x" + bytes(Web3.keccak(text="MINTER_ROLE")).hex()
    # the index also lists a grant that no longer holds: it must not count
    grants = [("0x" + "00" * 32, admin), (minter_role, minter), (minter_role, revoked)]
    asked = []

    class Resp:
        status_code, ok = 200, True

        def __init__(self, rows):
            self.rows = rows

        def json(self):
            return {"status": "1", "message": "OK", "result": self.rows}

    class NotFound:
        status_code, ok = 404, False

    def fake_get(url, params=None, timeout=None):
        if not url.startswith("https://explorer.test"):
            return NotFound()           # Sourcify: no verified ABI on a local chain
        asked.append((url, params))
        rows = [{"topics": [col.ROLE_GRANTED, r, "0x" + "00" * 12 + a[2:].lower(), "0x" + "00" * 32]} for r, a in grants] \
            if params["address"] == hrt.address and params["page"] == 1 else []
        return Resp(rows)

    monkeypatch.setitem(col.EXPLORERS, w3.eth.chain_id, ["https://explorer.test/api"])
    monkeypatch.setattr(col.requests, "get", fake_get)
    block = w3.eth.block_number
    rep = build(w3, vault.address, block)
    h = next(t for t in rep.tokens if t.address == hrt.address)
    assert all(p["toBlock"] == block for _, p in asked)                    # grants up to the pinned block only
    assert h.powers["owner"][0] == "EOA, no delay" and any(admin in x for x in h.powers["owner"][1])
    assert any(minter in x for x in h.powers["mint"][1]) and revoked not in str(h.powers)
    assert "confirmed with hasRole at this block" in h.role_scope["MINTER_ROLE"] and not h.open
    assert "explorer index (explorer.test) saw granted a role" in rep.markdown()


def test_explorer_rate_limit_falls_back_to_tested_addresses(v1, morpho, monkeypatch):
    import ownerwatch.collateral as col
    w3, blue, usdt, vault = v1["w3"], v1["blue"], v1["usdt"], v1["vault"]
    hrt = _deploy(w3, *morpho["HiddenRoleToken"])
    send(w3, hrt.functions.give(bytes(32), w3.eth.accounts[6]))
    send(w3, vault.functions.add(market(w3, blue, usdt.address, hrt.address, v1["oracle"].address), 1, False))

    class Limited:
        status_code, ok, headers = 429, False, {"x-ratelimit-reset": "400000"}

        def json(self):
            return {"message": "Too many requests", "result": None}

    monkeypatch.setitem(col.EXPLORERS, w3.eth.chain_id, ["https://a.test/api", "https://b.test/api"])
    monkeypatch.setattr(col.requests, "get", lambda url, params=None, timeout=None: Limited())
    monkeypatch.setattr(col.time, "sleep", lambda s: None)
    rep = build(w3, vault.address, w3.eth.block_number)
    h = next(t for t in rep.tokens if t.address == hrt.address)
    assert not rep.hinted and h.powers["owner"][0] == "not established" and not rep.complete
    assert "role-grant index could not be fully read (no explorer answered for" in rep.markdown()
    assert "a.test, b.test stopped answering" in rep.markdown()


def test_writing_the_report_reads_nothing(v1, monkeypatch):
    w3 = v1["w3"]
    rep = build(w3, v1["vault"].address, w3.eth.block_number)
    before = (rep.markdown(), rep.text(), rep.config("http://x"))

    def dead(*a, **k):
        raise AssertionError("the report read the chain after the pinned reads were done")

    for name in ("call", "get_code", "get_storage_at"):
        monkeypatch.setattr(w3.eth, name, dead)
    assert (rep.markdown(), rep.text(), rep.config("http://x")) == before


def test_simulated_calls_take_any_plain_arguments(v1):
    rep = build(v1["w3"], v1["vault"].address, v1["w3"].eth.block_number)
    omt = v1["omt"].address
    # selectors nobody implements: every argument kind must encode, and a revert is no holder
    assert rep._passes(omt, "mintWithData(address,uint256,bytes,bytes32,bool,string,int256)",
                       ["address", "uint256", "bytes", "bytes32", "bool", "string", "int256"], [v1["w3"].eth.accounts[0]]) == []


def test_a_shared_role_registry_only_counts_the_tokens_own_roles(v1, morpho, monkeypatch):
    w3, blue, usdt, vault = v1["w3"], v1["blue"], v1["usdt"], v1["vault"]
    a0, other = w3.eth.accounts[0], v1["minter"]
    registry, token = _deploy(w3, *morpho["HiddenRoleToken"]), _deploy(w3, *morpho["RegistryToken"])
    send(w3, token.functions.init(registry.address))
    mint_role, other_role = bytes(Web3.keccak(text="TOKEN_MINT_ROLE")), bytes(Web3.keccak(text="OTHER_TOKEN_MINT_ROLE"))
    send(w3, registry.functions.give(bytes(32), a0))
    send(w3, registry.functions.give(mint_role, a0))
    send(w3, registry.functions.give(other_role, other))       # another token's minter, on the same registry
    send(w3, vault.functions.add(market(w3, blue, usdt.address, token.address, v1["oracle"].address), 1, False))
    import ownerwatch.probe as mod
    abi_names = {token.address: {"0x" + mint_role.hex(): "TOKEN_MINT_ROLE"}, registry.address: {"0x" + other_role.hex(): "OTHER_TOKEN_MINT_ROLE"}}
    monkeypatch.setattr(mod.Prober, "role_names", lambda self, a: abi_names.get(Web3.to_checksum_address(a), {}))
    rep = build(w3, vault.address, w3.eth.block_number)
    t = next(x for x in rep.tokens if x.address == token.address)
    assert t.registry == registry.address
    mint = "\n".join(t.powers["mint"][1])
    assert "TOKEN_MINT_ROLE (on registry" in mint and a0 in mint and "OTHER_TOKEN_MINT_ROLE" not in mint and other not in mint
    assert any("mint(address,uint256) passes in simulation from" in x and a0 in x for x in t.powers["mint"][1])
    assert any(x.startswith("DEFAULT_ADMIN_ROLE on registry") and a0 in x for x in t.powers["owner"][1])


def test_to_dict_is_a_faithful_machine_readable_report(v1):
    w3, vault = v1["w3"], v1["vault"]
    block = w3.eth.block_number
    rep = build(w3, vault.address, block)
    d = rep.to_dict()
    # round-trips through JSON with no loss (precision-safe: amounts are raw-integer strings)
    assert json.loads(json.dumps(d)) == d
    # vault + pin metadata matches the report
    assert d["vault"]["address"] == vault.address and d["block"] == block
    assert d["chain"] and d["chainId"] == w3.eth.chain_id
    assert d["loanAsset"]["symbol"] == "USDT"
    assert d["totalAssetsRaw"] == str(rep.total) == str(8_001_000 * USD)
    assert d["reconciles"] is True and d["complete"] is True and d["coverageGaps"] == []
    # collateral: same tokens, order, allocations and shares as the ranked markdown table
    assert [c["symbol"] for c in d["collateral"]] == ["OMT", "RMT", "PLN"]
    omt = d["collateral"][0]
    # share is precise (markdown rounds 62.4922% to 62.5% for display; the data feed keeps full precision)
    assert omt["allocatedRaw"] == str(5_000_000 * USD) and omt["sharePct"] == round(5_000_000 / 8_001_000 * 100, 4)
    assert set(omt["powers"]) == {"owner", "upgrade", "mint", "pause"}
    assert omt["powers"]["owner"]["summary"] == "EOA, no delay"
    assert isinstance(omt["findings"], list) and isinstance(omt["notEstablished"], list) and omt["wraps"] is None
    assert omt["markets"] and omt["markets"][0]["oracle"] == v1["oracle"].address
