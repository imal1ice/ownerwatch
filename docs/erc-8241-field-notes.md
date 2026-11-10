# ERC-8241 in practice: field notes from disclosing four protocols

After drafting and chain-verifying [ERC-8241](https://ethereum-magicians.org/t/erc-8241-protocol-control-disclosure/28343) control disclosures for four deliberately different protocols — Aave V3, Compound III, Uniswap V3 and Morpho Blue — here is what the standard captures cleanly, the traps that catch an implementer, and a couple of suggestions. Every disclosure below checks clean against chain state at a pinned block; the files are in [`examples/erc-8241/`](https://github.com/imal1ice/ownerwatch/tree/main/examples/erc-8241).

## One standard, four control shapes

The point of picking these four was to stress four unrelated control patterns. The standard — and `disclosure check` — handled all of them:

| Protocol | Shape | What the disclosure states |
|---|---|---|
| Aave V3 (Ethereum core) | **role-heavy** | Pool, addresses provider, ACLManager; 24 role holders and two timelocks, replayed from the logs. 89 records. |
| Compound III (USDC) | **proxy behind a timelock** | Comet + Configurator upgradeable only through a proxy admin owned by the 48-hour Timelock. 12 records. |
| Uniswap V3 Factory | **pure ownership chain** | owner → … → the 48-hour Uniswap Timelock; no roles, no proxy. 8 records. |
| Morpho Blue | **immutable, multisig-owned** | no upgrade path at all; control is the owner multisig and nothing else. 6 records. |

A disclosure format that settles ownership, AccessControl roles, ERC-1967 proxies, timelock delays and multisig thresholds in one file — and lets a reader *check* each claim — is the thing the ecosystem has been missing.

## Traps an implementer hits

**The entry point is the whole game.** Draft from a *token* address (stETH, rETH) and you read the token's own admin, not the DAO that governs the protocol — a timelock that exists elsewhere reads as "none." The honest disclosure is drafted from the protocol's governance or core contract, never a token. (It is also why a fair public control-surface reference omits protocols whose real governance delay it cannot resolve from the given address, rather than publish a misleading "no timelock.")

**Role holders hide from a sweep.** `hasRole` only answers for addresses you already name; a holder nobody names is invisible to a sweep. Replaying `RoleGranted`/`RoleRevoked` from the logs finds them, and the checker reports any it finds that the disclosure omits as **undisclosed** — the difference between "we disclosed our admins" and "we disclosed the admins we remembered."

**Some powers chain state cannot settle.** An oracle-update authority whose source lives in off-chain configuration is `unverifiable`, never `ok`. A checker that silently promotes an unverifiable power to `ok` is worse than no checker; keeping the three states distinct (`ok` / `mismatch` / `unverifiable`) is what makes the clean result mean something.

## What makes a disclosure falsifiable, not just published

A published disclosure a reader cannot refute is marketing. The useful property is that `check` does not only verify what's *declared* — it also lists control it **observes** on the declared components that no power declares. That turns a completeness claim ("these are all the ways this protocol can change") into something mechanically checkable, scoped to the declared components, across upgrade admins, `owner()` and every AccessControl role holder. "Not disclosed" and "not present" stop looking the same.

## Two suggestions for the standard

1. **A positive "immutable" assertion.** Morpho Blue's safety is partly that its core *cannot* be upgraded — but a disclosure expresses that as the *absence* of an upgrade power, which reads the same as simply forgetting to declare one. A canonical way to assert "this component is immutable by construction" (which a checker can confirm: no proxy, no admin slot, no upgrade entry point) would make the strongest property a protocol can have a positive, checkable claim rather than a silence.
2. **Make the scoped completeness claim explicit.** The checker already relies on completeness being scoped to the *declared* components; the spec would be stronger if it said so, so an integrator knows a clean check means "nothing undisclosed on these components," not "nothing undisclosed anywhere."

---

The tooling that produced all of this is open-source and free: [`ownerwatch disclosure draft`/`check`](https://github.com/imal1ice/ownerwatch/blob/main/docs/erc-8241.md), with a [10-minute quickstart](https://github.com/imal1ice/ownerwatch/blob/main/docs/disclosure-quickstart.md) from zero to a CI-checked disclosure with a live badge. If you publish a governance or security page and want a machine-checkable disclosure drafted, chain-verified and wired into your CI, it's the kind of work I do — see **[Work with me](https://github.com/imal1ice/ownerwatch#work-with-me)**; the terms, including where I am based, are shared before anything is paid.
