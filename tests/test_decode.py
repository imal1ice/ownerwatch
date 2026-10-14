import socket

import pytest

from ownerwatch.decode import describe_call


def _online():
    try:
        socket.create_connection(("sourcify.dev", 443), timeout=3).close()
        return True
    except OSError:
        return False


def test_selector_offline_fallback():
    assert describe_call(b"") == "empty calldata"
    assert describe_call("0xdeadbeef00").endswith("[0xdeadbeef]") or describe_call("0xdeadbeef00").startswith("selector")


@pytest.mark.skipif(not _online(), reason="no network")
def test_verified_abi_decode_uni_token():
    # UNI token on mainnet is verified on Sourcify: transfer(address,uint256)
    data = "0xa9059cbb" + "00" * 12 + "11" * 20 + (1000).to_bytes(32, "big").hex()
    out = describe_call(data, 1, "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984")
    assert out.startswith("transfer(") and "verified" in out and "rawAmount=1000" in out


def test_signature_call_decode():
    from ownerwatch.decode import describe_signature_call
    data = "0x" + "00" * 12 + "11" * 20 + (5).to_bytes(32, "big").hex()
    assert describe_signature_call("transfer(address,uint256)", data) == "transfer(0x" + "11" * 20 + ", 5)"
    assert describe_signature_call("transfer(address,uint256)", "0xa9059cbb" + data[2:]) == "transfer(0x" + "11" * 20 + ", 5)"
    assert describe_signature_call("resume()", "0x") == "resume()"
    assert describe_signature_call("broken", "0x") == "broken"
