# Admin-surface review — Uniswap V3 Factory, Ethereum

*A worked example of an ownerwatch [admin-surface review](../../docs/review-template.md), run on a public, well-governed protocol so you can see the shape of the deliverable. Public chain data only; nothing here is a judgement about Uniswap or its contributors.*

## 1. Summary

- **Protocol / scope:** Uniswap V3 on Ethereum — the `UniswapV3Factory` (`0x1F98…F984`) and the ownership chain that governs it.
- **Chains & block:** Ethereum @ block **26394023** (2026-11-11T20:17Z).
- **Headline:** The Factory's code is **immutable** — there is no proxy and no upgrade path. The only privileged powers (add a fee tier, set and collect the per-pool protocol fee, transfer ownership) sit behind Uniswap's **48-hour governance Timelock**. There is **no single-key or zero-delay path** to any of them.
- **Findings:** **0 critical · 0 high · 0 medium** — a clean result. The control graph in §3 is the evidence.
- **Tooling:** ownerwatch 0.16.0 (`pip install ownerwatch`); reproducible from the command in §7.

## 2. Control surface

The addresses that hold power over the contracts in scope, read at the pinned block.

| Contract | Type | Controller | Kind | Delay |
|---|---|---|---|---|
| `UniswapV3Factory` `0x1F98431c8aD98523631AE4a59f267346ea31F984` | immutable contract (no proxy) | Factory owner `0xf2371551Fe3937Db7c750f4DfABe5c2fFFdcBf5A` | contract | — |
| Factory owner `0xf237…Bf5A` | contract (governance-held) | Uniswap Timelock `0x1a9C8182C09F50C8318d769245beA52c32BE35BC` | legacy timelock | **48h** |
| Uniswap Timelock `0x1a9C…35BC` | timelock (delay 172800s) | its admin `0x408ED6354d4973f66138C91495F2f2FCbd8724C3` (Uniswap governance) | contract | — |

Notes: the Factory exposes no ERC-1967 implementation slot and is not a proxy — its bytecode cannot be replaced. The pools it deploys are likewise immutable. The owner's entire authority is three `onlyOwner` levers: `enableFeeAmount` (register a new fee tier), `setFeeProtocol` / `collectProtocol` on a pool (the 0–10 % protocol-fee switch), and `setOwner` (hand ownership on). Every one of them is reachable only through the 48-hour Timelock. No address in scope holds power over the Factory as a bare EOA or a Safe.

## 3. Control graph

Every edge that can exercise an owner power carries the 48-hour delay:

```
UniswapV3Factory (immutable)  ─▶  Factory owner 0xf237…Bf5A  ─▶  Uniswap Timelock (48h)  ─▶  governance 0x408E…24C3
```

**Shortest undelayed path to funds or code:** none. The code is immutable, so there is no path to it at all. The only state an owner can change — fee tiers and the protocol-fee switch — must be queued through the Timelock and can be watched for 48 hours before it executes. The protocol fee is itself bounded by the contract to at most 10 % of swap fees; it cannot touch principal.

## 4. Findings

**0 critical · 0 high · 0 medium.** No single-key or zero-delay control path was found among the probed addresses, and `probe --prove` had nothing to simulate because no owner, admin or role holder in scope is an EOA or a Safe — control terminates in governance behind the Timelock.

This is the shape a well-governed, immutable protocol produces: the headline is what the owner *cannot* do (change code, move funds, act without delay), established from chain state rather than from the docs.

## 5. Docs vs chain

Uniswap's documentation describes the Factory as owned by Uniswap governance, with changes enacted through the Governor and its Timelock. The chain agrees: the Factory's `owner()` resolves, in two hops, to the 48-hour Timelock whose admin is the governance contract, and the Factory carries no upgrade mechanism. No drift found between the documented control model and the on-chain one.

## 6. Monitoring handed off

A ready-to-run ownerwatch config for this scope watches the one thing that can change here — Factory ownership — plus the Timelock's queue, so any `setOwner`, any change to the Timelock's delay or admin, and every operation queued through the Timelock alerts before (or as) it happens:

```bash
ownerwatch probe --rpc "$RPC" --yaml --label "Uniswap V3" \
  0x1F98431c8aD98523631AE4a59f267346ea31F984 \
  0x1a9C8182C09F50C8318d769245beA52c32BE35BC > uniswap-v3.yaml
ownerwatch run --config uniswap-v3.yaml   # point `alerts` at your Slack/Discord/Telegram
```

## 7. Appendix — reproduce it

Every line above comes from one command, at the pinned block, against any Ethereum RPC:

```bash
pip install ownerwatch
ownerwatch probe --prove --markdown --rpc https://ethereum-rpc.publicnode.com \
  0x1F98431c8aD98523631AE4a59f267346ea31F984
```

The `--prove` run reports "nothing to simulate" here precisely because there is no EOA or Safe in the control path to prove a power against — which is the point. Re-run it at any block to confirm the graph is unchanged.
