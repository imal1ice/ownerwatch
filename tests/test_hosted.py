"""Hosted runner against anvil: deploy Subscriptions + mock USDC from the Foundry
project, subscribe one customer, check the runner starts and stops its watcher."""
import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from web3 import Web3

from ownerwatch.hosted import HostedRunner
from tests.test_watcher import anvil  # noqa: F401

CONTRACTS = Path(__file__).parent.parent / "contracts"
pytestmark = pytest.mark.skipif(shutil.which("anvil") is None or shutil.which("forge") is None
                                or not (CONTRACTS / "lib" / "forge-std").exists(), reason="foundry/forge-std missing")


def _art(name, file):
    return json.loads((CONTRACTS / "out" / file / f"{name}.json").read_text())


def test_hosted_lifecycle(anvil, tmp_path):  # noqa: F811
    subprocess.run(["forge", "build", "--root", str(CONTRACTS)], check=True, capture_output=True)
    w3 = anvil
    op, cust = w3.eth.accounts[0], w3.eth.accounts[1]
    usdc_a = _art("MockUSDC", "Subscriptions.t.sol")
    usdc = w3.eth.contract(abi=usdc_a["abi"], bytecode=usdc_a["bytecode"]["object"])
    usdc = w3.eth.contract(address=w3.eth.wait_for_transaction_receipt(usdc.constructor().transact({"from": op}))["contractAddress"], abi=usdc_a["abi"])
    sub_a = _art("Subscriptions", "Subscriptions.sol")
    subs = w3.eth.contract(abi=sub_a["abi"], bytecode=sub_a["bytecode"]["object"])
    subs = w3.eth.contract(address=w3.eth.wait_for_transaction_receipt(subs.constructor(usdc.address, 200 * 10**6).transact({"from": op}))["contractAddress"], abi=sub_a["abi"])

    cfgdir = tmp_path / "configs"
    cfgdir.mkdir()
    (cfgdir / f"{cust}.yaml").write_text(f"rpc_url: {w3.provider.endpoint_uri}\nchain_name: anvil\nconfirmations: 0\n"
                                        f"contracts:\n  - address: '{subs.address}'\n    label: subs\n")
    runner = HostedRunner(w3.provider.endpoint_uri, subs.address, cfgdir, check_interval=1)
    runner.reconcile()
    assert cust not in runner.customers          # not subscribed yet

    usdc.functions.mint(cust, 10**9).transact({"from": op})
    usdc.functions.approve(subs.address, 10**9).transact({"from": cust})
    w3.eth.wait_for_transaction_receipt(subs.functions.subscribe(1, b"\x00" * 32).transact({"from": cust}))
    runner.reconcile()
    assert cust in runner.customers and runner.customers[cust].threads[0].is_alive()

    # lapse: jump 31 days ahead
    w3.provider.make_request("evm_increaseTime", [31 * 86400])
    w3.provider.make_request("evm_mine", [])
    runner.reconcile()
    assert cust not in runner.customers
