from ownerwatch.probe import chain_name_for


def test_chain_name_for_known_and_unknown_ids():
    assert chain_name_for(1) == "ethereum"
    assert chain_name_for(8453) == "base"
    assert chain_name_for(42161) == "arbitrum"
    assert chain_name_for(10) == "optimism"
    assert chain_name_for(999999) == "chain 999999"
