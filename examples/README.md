# Example configs

Real, verified mainnet addresses. Copy one, add your alert target, run.
Each was checked on-chain on 2026-10-14 (bytecode present, delay/threshold/implementation read back).

| File | What it watches |
|---|---|
| `uniswap-mainnet.yaml` | Uniswap governance Timelock (legacy Compound-style, 2-day delay) |
| `compound-mainnet.yaml` | Compound governance Timelock (legacy, 2-day delay) |
| `arbitrum-l1-mainnet.yaml` | Arbitrum DAO L1 Timelock (OZ TimelockController behind an ERC-1967 proxy, 3-day delay) |
| `aave-mainnet.yaml` | Aave Governance V3 Executor Lvl 1, the Collector proxy, and large stablecoin outflows from the Collector |
| `optimism-mainnet.yaml` | Optimism Foundation Safe: on-chain owner/threshold changes plus the pending transaction queue |

```bash
ownerwatch backfill --config examples/uniswap-mainnet.yaml --from-block 22000000 --to-block 22100000
```
