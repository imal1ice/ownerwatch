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
