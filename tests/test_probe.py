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
    assert any("controlled by an EOA" in x for x in n.notes)
    assert p.seen[w3.eth.accounts[0]].kind == "eoa"
    out = describe(n)
    assert "owner=" in out and "! controlled by an EOA" in out
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
    assert "| contract |" in md and "controlled by an EOA" in md
    assert "(contract) -> " in md and "(eoa)" in md


def test_probe_from_config(anvil, artifacts, tmp_path, capsys):  # noqa: F811
    from ownerwatch.cli import main
    w3 = anvil
    admin = _deploy(w3, *artifacts["Admin"])
    cfg = tmp_path / "c.yaml"
    cfg.write_text(f"rpc_url: {w3.provider.endpoint_uri}\nchain_name: anvil\ncontracts:\n  - address: '{admin.address}'\n    label: A\n")
    assert main(["probe", "--config", str(cfg), "--markdown", "--label", "Acme"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("# Acme admin surface on anvil") and "controlled by an EOA" in out


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
