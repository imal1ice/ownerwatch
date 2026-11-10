"""EIP-2535 Diamond detection: a Diamond is upgradeable via diamondCut (no ERC-1967 slot), so without
explicit detection it would read as a plain, non-upgradeable owned contract -- a false 'immutable'."""
import shutil

import pytest

from ownerwatch.disclosure import Checker, draft, manifest_hash
from ownerwatch.probe import Prober
from tests.test_watcher import _deploy, anvil, artifacts  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(shutil.which("anvil") is None, reason="foundry not installed")


def test_diamond_is_detected_as_upgradeable(anvil, artifacts):  # noqa: F811
    w3 = anvil
    diamond = _deploy(w3, *artifacts["DiamondLike"])
    n = Prober(w3).probe(diamond.address)
    assert n.diamond is True
    assert n.facet_count == 2
    # the reference implementation gates diamondCut to owner(), so the upgrade admin is the owner
    assert n.owner == w3.eth.accounts[0]
    assert n.proxy_admin == n.owner
    assert any("Diamond" in note for note in n.notes)


def test_plain_and_junk_contracts_are_not_diamonds(anvil, artifacts):  # noqa: F811
    w3 = anvil
    for name in ("RealOwnable", "CatchAll", "JunkGetters"):
        n = Prober(w3).probe(_deploy(w3, *artifacts[name]).address)
        assert n.diamond is False, f"{name} must not be mistaken for a Diamond"
        assert n.facet_count == 0


def test_diamond_disclosure_drafts_and_checks_clean(anvil, artifacts):  # noqa: F811
    w3 = anvil
    diamond = _deploy(w3, *artifacts["DiamondLike"])
    d = draft(w3, [diamond.address], "DiamondProtocol")
    assert d["protocol"]["manifestHash"] == manifest_hash(d)
    # the diamond is disclosed as upgradeable, with both an UPGRADE and an OWNERSHIP power
    assert d["components"][0]["upgradeable"] is True
    assert {p["kind"] for p in d["powers"]} == {"UPGRADE", "OWNERSHIP"}
    report = Checker(w3).check(d)
    upgrade = [r for r in report["results"] if r["record"] == "power" and r["id"].startswith("upgrade-")]
    assert [r["status"] for r in upgrade] == ["ok"]
    assert report["summary"]["mismatch"] == 0
    assert report["undisclosed"] == []
