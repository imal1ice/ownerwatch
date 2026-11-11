"""A Safe transaction guard runs on every Safe transaction and can revert any of them -- a control vector
no owner or module read reveals. The probe reads it from the Safe 1.3.0 guard slot, reports it, and the
drift test pins the slot so a guard change fails forge test."""
import shutil

import pytest
from web3 import Web3

from ownerwatch.foundry import foundry_test
from ownerwatch.probe import Prober, fact_lines
from tests.test_watcher import _deploy, anvil, artifacts  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(shutil.which("anvil") is None, reason="foundry not installed")

GUARD = Web3.to_checksum_address("0x1111111111111111111111111111111111111111")


def test_safe_guard_is_read_and_reported(anvil, artifacts):  # noqa: F811
    w3 = anvil
    safe = _deploy(w3, *artifacts["SafeWithGuardLike"])
    n = Prober(w3).probe(safe.address)
    assert n.kind == "safe"
    assert n.safe_guard == GUARD
    assert any("transaction guard" in note for note in n.notes)


def test_safe_guard_is_in_the_facts_block(anvil, artifacts):  # noqa: F811
    w3 = anvil
    safe = _deploy(w3, *artifacts["SafeWithGuardLike"])
    p = Prober(w3)
    p.probe(safe.address)
    assert f"{safe.address} guard {GUARD}" in "\n".join(fact_lines(p, "ethereum"))


def test_foundry_pins_the_safe_guard(anvil, artifacts):  # noqa: F811
    w3 = anvil
    safe = _deploy(w3, *artifacts["SafeWithGuardLike"])
    p = Prober(w3)
    n = p.probe(safe.address)
    src = foundry_test(p, "ethereum", w3.eth.block_number, [n])
    assert "4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8" in src.lower()
    assert GUARD in src
