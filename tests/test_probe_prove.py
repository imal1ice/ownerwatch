"""probe --prove: every finding backed by a simulation. A finding is proven only when the privileged call succeeds
from the holder and reverts from a stranger; a call that reverts (or succeeds) from both proves nothing and says so."""
import shutil

import pytest
from web3 import Web3

from ownerwatch.probe import STRANGER, Prober, describe, markdown_report
from tests.test_watcher import _deploy, anvil, artifacts  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(shutil.which("anvil") is None, reason="foundry not installed")


@pytest.fixture(autouse=True)
def unpinned(anvil):  # noqa: F811
    """prove() pins the client's default block; the anvil fixture is shared across this module's tests."""
    anvil.eth.default_block = "latest"


def _prove(w3, contract, *extra):
    p = Prober(w3)
    p.probe(contract.address)
    for x in extra:
        p.probe(x)
    p.check_roles(list(p.seen.keys()))
    p.prove()
    return p


def test_grantrole_proves(anvil, artifacts):  # noqa: F811
    """A DEFAULT_ADMIN_ROLE holder: grantRole succeeds from it and reverts from a stranger, so the finding is proven."""
    w3 = anvil
    acl = _deploy(w3, *artifacts["AccessControlLike"])
    holder = w3.eth.accounts[0]
    p = _prove(w3, acl, holder)
    assert p.seen[acl.address].roles == {"DEFAULT_ADMIN_ROLE": [holder]}
    proofs = p.seen[acl.address].proofs
    assert any(pr.proven and pr.fn == "grantRole(bytes32,address)" and pr.holder == holder
               and pr.role == "DEFAULT_ADMIN_ROLE" for pr in proofs)
    assert any(pr.line().startswith("proven: grantRole(bytes32,address) succeeds from DEFAULT_ADMIN_ROLE") for pr in proofs)
    assert "proven: grantRole" in describe(p.seen[acl.address])


def test_owner_transfer_proves(anvil, artifacts):  # noqa: F811
    """owner(): transferOwnership succeeds from the owner and reverts from a stranger."""
    w3 = anvil
    own = _deploy(w3, *artifacts["RealOwnable"])
    p = _prove(w3, own)
    proofs = p.seen[own.address].proofs
    assert any(pr.proven and pr.fn == "transferOwnership(address)" and pr.role == "owner()"
               and pr.holder == w3.eth.accounts[0] for pr in proofs)


def test_state_gated_is_not_simulated(anvil, artifacts):  # noqa: F811
    """A call gated by state as well as the caller reverts for everyone: never proven, reported as gated by state."""
    w3 = anvil
    locked = _deploy(w3, *artifacts["LockedOwnable"])
    p = _prove(w3, locked)
    proofs = p.seen[locked.address].proofs
    assert proofs and all(not pr.proven for pr in proofs)
    gated = next(pr for pr in proofs if pr.fn == "transferOwnership(address)")
    assert "gated by state" in gated.why
    assert gated.line().startswith("not simulated: transferOwnership(address)")


def test_open_function_is_not_simulated(anvil, artifacts):  # noqa: F811
    """The Admin fixture's transferOwnership checks no caller: it succeeds from a stranger too, so it proves nothing."""
    w3 = anvil
    admin = _deploy(w3, *artifacts["Admin"])
    p = _prove(w3, admin)
    proofs = p.seen[admin.address].proofs
    owner_proof = next(pr for pr in proofs if pr.fn == "transferOwnership(address)")
    assert not owner_proof.proven and "stranger too" in owner_proof.why


def test_timelock_proposer_proves(anvil, artifacts):  # noqa: F811
    """A timelock proposer: schedule(...) at the minimum delay succeeds from the proposer and reverts from a stranger."""
    w3 = anvil
    tl = _deploy(w3, *artifacts["ScheduleTimelockLike"])
    proposer = w3.eth.accounts[3]
    w3.eth.wait_for_transaction_receipt(
        tl.functions.give(bytes(Web3.keccak(text="PROPOSER_ROLE")), proposer).transact({"from": w3.eth.accounts[0]}))
    p = _prove(w3, tl, proposer)
    assert p.seen[tl.address].kind == "timelock"
    proofs = p.seen[tl.address].proofs
    assert any(pr.proven and pr.fn.startswith("schedule(") and pr.role == "PROPOSER_ROLE"
               and pr.holder == proposer for pr in proofs)


def test_proposer_without_schedule_is_not_simulated(anvil, artifacts):  # noqa: F811
    """A timelock with no OpenZeppelin schedule(...): the proposer finding is reported, not proven."""
    w3 = anvil
    tl = _deploy(w3, *artifacts["ProposerTimelock"])
    proposer = w3.eth.accounts[4]
    w3.eth.wait_for_transaction_receipt(
        tl.functions.give(bytes(Web3.keccak(text="PROPOSER_ROLE")), proposer).transact({"from": w3.eth.accounts[0]}))
    p = _prove(w3, tl, proposer)
    proofs = p.seen[tl.address].proofs
    sched = next(pr for pr in proofs if pr.role == "PROPOSER_ROLE")
    assert not sched.proven and "schedule" in sched.why


def test_stranger_is_a_dead_address():
    assert STRANGER.lower().endswith("dead")


def test_prove_in_markdown_and_cli(anvil, artifacts, capsys):  # noqa: F811
    """--prove adds a Proofs section to the report, and the proof shows up end to end through the CLI."""
    from ownerwatch.cli import main
    w3 = anvil
    own = _deploy(w3, *artifacts["RealOwnable"])
    p = _prove(w3, own)
    md = markdown_report(p, "Test", "anvil", [p.seen[own.address]], prove=True)
    assert "## Proofs" in md and "proven: transferOwnership(address)" in md
    # without prove the section is absent
    assert "## Proofs" not in markdown_report(p, "Test", "anvil", [p.seen[own.address]])
    assert main(["probe", "--rpc", w3.provider.endpoint_uri, "--prove", "--markdown", "--label", "Acme", own.address]) == 0
    out = capsys.readouterr().out
    assert "## Proofs" in out and "proven: transferOwnership(address)" in out


def test_prove_rejects_foundry(anvil, artifacts):  # noqa: F811
    from ownerwatch.cli import main
    w3 = anvil
    own = _deploy(w3, *artifacts["RealOwnable"])
    with pytest.raises(SystemExit):
        main(["probe", "--rpc", w3.provider.endpoint_uri, "--prove", "--foundry", own.address])
