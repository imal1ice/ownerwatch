import shutil

import pytest

from ownerwatch.probe import Prober, describe, suggest_config
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
