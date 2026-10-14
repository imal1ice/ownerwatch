# Contributing

- Run the tests: `python3 -m venv .venv && .venv/bin/pip install -e . pytest && .venv/bin/pytest`. They need Foundry (`anvil`, `forge`).
- New events go in `ownerwatch/events.py` with the exact indexed layout of the source contract, plus a fixture in `tests/fixtures/src/Admin.sol` and an assertion in `tests/test_watcher.py`.
- Keep the poller boring: no new network dependencies in the hot loop, everything optional and cached.
- One pull request per change. Explain what alert a protocol team would now get that they didn't before.
