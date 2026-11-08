# Admin-surface review — report template

This is the structure of an ownerwatch **admin-surface review**: a point-in-time map of who controls a protocol's funds, every privileged power proven by simulation, the gaps between the docs and the chain, and a ready monitoring config. It is meant to be filled from the tool's own output so two reviews read the same way. A worked example on a public, well-governed protocol: [examples/reviews/compound-iii-usdc.md](../examples/reviews/compound-iii-usdc.md).

Every finding is **pinned to a block** and backed by an `eth_call` simulation — a privileged call that *succeeds from the holder and reverts from a stranger* proves the holder controls it. Facts are public on-chain state; a review of a team's private contracts stays confidential to that team.

> How to fill each section is noted in `<!-- comments -->` with the exact command. Commands read public RPCs; swap in an archive/log-capable RPC for the role replay. Pin one block (`--block N`) and use it everywhere so the report is reproducible.

---

## 1. Summary

- **Protocol / scope:** <what was reviewed — contracts, vaults, chains>
- **Chains & block:** <chain> @ block <N> (<UTC timestamp>) <!-- one pinned block per chain -->
- **Headline:** <one sentence: e.g. "Funds are governed by a 3-of-5 Safe behind a 48h timelock; two exceptions below.">
- **Findings:** <counts> — <n> critical · <n> high · <n> medium
- **Tooling:** ownerwatch <version> (`pip install ownerwatch`), results reproducible from the commands in the appendix.

## 2. Control surface

The addresses that hold power over the contracts in scope.
<!-- ownerwatch probe <addr...> --rpc <url> --prove --markdown   (chain is inferred from the RPC; probe pins its own block).
     For the full role-holder list add --roles-from-logs --logs-rpc <log-capable url>. Add the protocol's Safes/keys with --role-candidates. -->

| Contract | Type | Controller | Kind (EOA / Safe / timelock / contract) | Delay |
|---|---|---|---|---|
| <name> `0x…` | <proxy / token / vault> | <owner/admin> `0x…` | <EOA / 3-of-5 Safe / TimelockController> | <none / 48h> |

Notes: proxy pattern (UUPS / Transparent / Beacon), whether role grants are gated by a timelock, and any address that holds power on more than one contract.

## 3. Control graph

How control flows from the funds to the ultimate key(s): contract → admin → timelock → Safe → signers, with each delay on the edge. Call out the **shortest undelayed path to funds** explicitly.
<!-- the probe walks this (follows owner/admin into the Safe or timelock behind it); render it as a short list or diagram. Flag any leaf an EOA controls with no delay. -->

## 4. Findings

One block per finding. A finding is an *unintended or under-protected* power, not a disclosed design choice — disclosed, timelocked, multi-sig powers are noted as context, not flagged.

**A clean result is a valid outcome.** For a well-governed deployment the probe finds no single-key or zero-delay control path and reports nothing to simulate (e.g. every upgrade sits behind a timelock and a multisig). Say so plainly, and back it with the control graph in §3 — the honest "we checked and found no unintended power" is as much a deliverable as a list of findings, and more credible for it.

### F<n> — <title> · **<severity>**
- **What:** <the power — e.g. "The STONE OFT owner can set any trusted remote.">
- **Who holds it:** <address> (<EOA / Safe n-of-m / timelock>)
- **Proof (simulated, block <N>):** <!-- from probe --prove --> `<fn>` **succeeds from** the holder and **reverts from a stranger** → the holder controls it. <if not proven, say why and treat as unconfirmed.>
- **Consequence:** <what the holder can do to user funds / the protocol.>
- **Fix:** <concrete: put it behind the existing timelock / raise the Safe threshold / renounce the slot / document it.>

## 5. Docs vs chain

Where the project's public governance/security docs and the on-chain reality differ. Each row is a claim in the docs and what the chain shows.
<!-- ownerwatch disclosure draft <addr...> --rpc <url> --block <N>  → then compare by hand to the docs.
     ownerwatch disclosure check <file.json> --rpc <url> --block <N> verifies a machine-readable (ERC-8241) disclosure against chain state (exit 1 on any mismatch or undisclosed power). -->

| Docs say | Chain shows | Matters because |
|---|---|---|
| "governed by a multisig" | single EOA on the owner slot | the stated protection isn't there |

## 6. Monitoring handed off

A ready ownerwatch config so the team keeps watch after this snapshot: owner/admin/role/implementation changes, Safe signer & threshold changes, timelock queue/execute, and any team-specific events (limit changes, forced burns, custody moves).
<!-- ownerwatch validate <config.yaml> must pass; ship the GitHub Action (ownerwatch-action) + a webhook; see docs/hosted.md for self-run (free) vs we-run-it. -->

- Config: `<slug>-<chain>.yaml` (passes `ownerwatch validate`)
- Delivery: GitHub Action on an hourly schedule → webhook; or the hosted operator (see `docs/hosted.md`).

## 7. Appendix — reproduce it

Every number above comes from these commands (chain is inferred from the RPC's chain id; pin the same block everywhere):

```
pip install ownerwatch
ownerwatch probe <addr...> --rpc <url> --prove --markdown
ownerwatch probe <addr...> --rpc <url> --roles-from-logs --logs-rpc <log-capable url>   # full role-holder list
ownerwatch collateral <vault> --rpc <url> --block <N> --json        # for a Morpho lending/curator vault
ownerwatch disclosure draft <addr...> --rpc <url> --block <N>
ownerwatch validate <config.yaml>
```

Public chain data only; nothing here is a judgement about the project or its team. Scope, block and RPC are fixed so the report can be re-run and checked independently.
