# Admin-surface review — Compound III (Comet) USDC market, Ethereum

*A worked example of an ownerwatch [admin-surface review](../../docs/review-template.md), run on a public, well-governed protocol so you can see the shape of the deliverable. Public chain data only; nothing here is a judgement about Compound or its contributors.*

## 1. Summary

- **Protocol / scope:** Compound III (Comet) USDC market on Ethereum — the market proxy (`cUSDCv3`) and its Configurator.
- **Chains & block:** Ethereum @ block **26371301** (2026-11-08T16:18Z).
- **Headline:** Every upgrade to the USDC market and its Configurator routes through one ProxyAdmin that is owned by Compound's **48-hour Timelock under GovernorBravo**. There is **no single-key or zero-delay path** to the market's code or parameters.
- **Findings:** **0 critical · 0 high · 0 medium** — a clean result. The control graph in §3 is the evidence.
- **Tooling:** ownerwatch 0.14.0 (`pip install ownerwatch`); reproducible from the command in §7.

## 2. Control surface

The addresses that hold power over the contracts in scope, read at the pinned block.

| Contract | Type | Controller | Kind | Delay |
|---|---|---|---|---|
| Comet `cUSDCv3` `0xc3d688B66703497DAA19211EEdff47f25384cdc3` | proxy (impl `0x0B07…3255`) | CometProxyAdmin `0x1EC63B5883C3481134FD50D5DAebc83Ecd2E8779` | contract | — |
| Configurator `0x316f9708bB98af7dA9c68C1C3b5e79039cD336E3` | proxy (impl `0xcFC1…DF4F`) | CometProxyAdmin `0x1EC6…8779` | contract | — |
| CometProxyAdmin `0x1EC6…8779` | ProxyAdmin | Compound Timelock `0x6d903f6003cca6255D85CcA4D3B5E5146dC33925` | legacy timelock | **48h** |
| Compound Timelock `0x6d90…3925` | timelock (delay 172800s) | GovernorBravo `0x309a862bbC1A00e45506cB8A802D1ff10004c8C0` | proxy (COMP governance) | — |
| GovernorBravo `0x309a…c8C0` | proxy (impl `0x501E…6752`) | admin `0x725ED7F44F0888aeC1b7630AB1ACdced91E0591A`, owned by the Timelock `0x6d90…3925` | contract | **48h** (via the Timelock) |

Notes: the market and the Configurator are Transparent proxies behind one shared `CometProxyAdmin`. That admin is owned by the Timelock, whose admin is GovernorBravo; the Governor's own upgrade path loops back to the Timelock. No address in scope holds power over funds as a bare EOA or a Safe.

## 3. Control graph

Both proxies reach the ultimate controller the same way, and every edge that can change code or parameters carries the 48-hour delay:

```
cUSDCv3 (market proxy)  ─┐
                         ├─▶ CometProxyAdmin ─▶ Compound Timelock (48h) ─▶ GovernorBravo (COMP holders)
Configurator (proxy)    ─┘
```

**Shortest undelayed path to funds:** none. There is no leaf that an EOA or a Safe controls without the 48-hour Timelock in front of it. A change to the market's implementation, or to any parameter the Configurator sets, must be queued through the Timelock and can be watched for 48 hours before it executes.

## 4. Findings

**None — clean result.** The probe found no owner, upgrade admin, proposer or role holder in scope that is an EOA or a Safe, so there was nothing to simulate: every privileged path ends at the Timelock and GovernorBravo. For a deployment governed this way, "we checked and found no unintended or undelayed power over the market" is the finding, and §3 is its proof.

Context (disclosed design, not flagged): the 48-hour Timelock and COMP-token governance are Compound's documented control model; they are protections, noted here, not gaps.

## 5. Docs vs chain

| Docs say | Chain shows | Matters because |
|---|---|---|
| Compound III is governed by COMP holders through GovernorBravo, with a Timelock that executes approved proposals after a delay. | `cUSDCv3` and the Configurator → `CometProxyAdmin` → Timelock (**48h**, `172800s`) → GovernorBravo. | The documented governance *is* the on-chain reality: the stated protection is actually in the control path, with the stated delay. |

No discrepancy between the public governance model and chain state for the contracts in scope. (A machine-checkable version of this is an [ERC-8241](../../docs/erc-8241.md) disclosure, verifiable with `ownerwatch disclosure check`.)

## 6. Monitoring handed off

A ready ownerwatch config so the team (or a user) keeps watch after this snapshot — owner/admin/implementation changes on the market, Configurator and ProxyAdmin; Timelock schedule/execute with the decoded call; and GovernorBravo proposal events:

- Config: `compound-iii-usdc-ethereum.yaml` — generate with `ownerwatch probe … --yaml` and confirm with `ownerwatch validate`.
- Delivery: the [ownerwatch GitHub Action](https://github.com/imal1ice/ownerwatch-action) on an hourly schedule → your webhook, or the hosted operator ([docs/hosted.md](../../docs/hosted.md)) — self-run free, or we-run-it.

## 7. Appendix — reproduce it

Every row above comes from one command (chain is inferred from the RPC's chain id; the probe pins its own block):

```
pip install ownerwatch
ownerwatch probe 0xc3d688B66703497DAA19211EEdff47f25384cdc3 0x316f9708bB98af7dA9c68C1C3b5e79039cD336E3 \
  --rpc https://ethereum-rpc.publicnode.com --prove --markdown --label "Compound III USDC (Ethereum)"
```

Read-only; nothing was sent on-chain. Scope, block and RPC are fixed so this can be re-run and checked independently.

---

ownerwatch is free and MIT-licensed. For a review like this of your own deployment — or continuous monitoring that alerts on any owner, role or implementation change — see **[Work with me](../../README.md#work-with-me)**. Before anything is paid, I share the terms, including where I am based.
