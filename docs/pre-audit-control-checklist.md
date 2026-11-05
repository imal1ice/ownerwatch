# Pre-audit control checklist

A short, practical checklist for the **control surface** of a protocol: who owns
it, who can upgrade it, who holds the privileged roles, and how fast they can
act. This is the part an audit often spends the least time on and the part that
actually holds the funds — most losses after a clean audit come from an admin
key or an upgrade, not from a function-level bug.

Run this before you book an audit (so the auditors spend their time on logic,
not on mapping your access control), and again before every mainnet deploy. Each
item is a yes/no you can settle from chain state and your own docs. Where
[ownerwatch](https://github.com/imal1ice/ownerwatch) automates a check, the
command is noted; nothing here needs it, and nothing here is sent on-chain.

> A read of chain state tells you what an address *can* do, not how its key is
> held. An EOA may be one laptop or an MPC quorum; a Safe's signers may be one
> person. Treat every "who" below as "which address", then confirm the custody
> behind it yourself.

## 1. Ownership

- [ ] Every contract's `owner()` / `Ownable2Step` pending owner is an address you
      recognise and still control.
- [ ] No contract is owned by a plain EOA that moves real value or can upgrade.
      If one is, there is a single key between an attacker and the protocol.
- [ ] Ownership that should have been renounced actually is (`owner()` is the
      zero address), and ownership that should *not* be renounced is not.
- [ ] Two-step ownership transfers have no pending `acceptOwnership` left open to
      a stale or wrong address.

## 2. Upgradeability

- [ ] You can name, for every upgradeable contract, the exact address that can
      change its implementation (the ERC-1967 proxy admin, the UUPS authority in
      the implementation's own `_authorizeUpgrade`, or a beacon's owner).
- [ ] That upgrade right sits behind a timelock or a multisig, not a single EOA.
- [ ] A UUPS proxy's upgrade authority is in the implementation code you shipped,
      not an older implementation still reachable.
- [ ] Beacon proxies: the beacon's owner is as locked down as any other upgrade
      admin — one beacon upgrades every proxy behind it at once.

      `ownerwatch probe --markdown --rpc <rpc> 0xProxy` reads the owner, the
      upgrade admin, the beacon and the Safe/timelock above each, and flags EOAs
      and powers with no delay.

## 3. Access-control roles

- [ ] You have the full list of role holders from the chain, not from the
      deploy script — roles granted after deployment, or from an admin console,
      are easy to forget. Replay `RoleGranted` / `RoleRevoked` since deployment
      and confirm each holder with `hasRole`.
- [ ] `DEFAULT_ADMIN_ROLE` (and any `*_ADMIN_ROLE` that is a role's admin) is held
      only by a timelock or multisig. Whoever holds it can grant themselves every
      other role.
- [ ] You have **simulated**, not just reasoned about, each privileged grant: a
      role-admin that points at `DEFAULT_ADMIN_ROLE` does not prove the holder can
      grant it, because `grantRole` can be overridden by a custom guard. Run the
      call as `eth_call` from the holder (it should succeed) and from a stranger
      (it should revert) before you believe either.
- [ ] For an OpenZeppelin `AccessManager`: every target function's required role,
      the role admins, the per-role execution delays, and which contracts are
      bound to the manager are all what you intend.

      `ownerwatch probe --markdown --roles-from-logs --rpc <rpc> 0xContract` lists
      every current holder; `ownerwatch probe --prove --rpc <rpc> 0xContract`
      simulates each privileged call from the holder and a stranger.

## 4. Multisig / Safe hygiene

- [ ] No Safe that controls real value or an upgrade is 1-of-N. A 1-of-N Safe is
      an EOA with extra steps.
- [ ] The threshold and signer set match your published security docs exactly
      (count and addresses), and every signer is still a person you can reach.
- [ ] You know every enabled Safe **module** and **guard** — a module can move
      funds or change owners without meeting the threshold.
- [ ] Signer changes are watched: a signer swap can be queued and collect
      signatures quietly. (A decoding trap in some tooling hides Safe 1.4.1
      `AddedOwner`/`RemovedOwner` events — confirm yours surfaces them.)

## 5. Timelocks and delays

- [ ] Every power that can move funds, mint, pause, or upgrade is either
      genuinely immutable or sits behind a delay long enough for users to react.
- [ ] The delay you read from the chain matches the delay your docs promise
      (OpenZeppelin, Compound-style, Solady, Ownable-delay, and AccessManager
      delays are all readable on-chain).
- [ ] The timelock's own admin / canceller / proposer roles are themselves not a
      single EOA — a timelock whose proposer is one key is not a delay.
- [ ] Someone actually reads the timelock queue. A delay only protects users if a
      queued call is seen before it executes.

## 6. Mint, pause and emergency powers

- [ ] You can name every address that can mint the token, pause the system, or
      trigger any emergency/guardian path, and each is behind the control you
      intend.
- [ ] Emergency powers that bypass the timelock (a guardian pause, a fast-path
      upgrade) are documented as such and held by a multisig, not one key.
- [ ] Any "forced" user-facing action (force-burn, force-transfer, forced
      redemption) is disclosed and gated.

## 7. Docs vs. chain

- [ ] Your public security/governance page names the same owners, roles, signers,
      thresholds and delays that the chain shows today — not what was true at
      launch. Documented control that the chain contradicts is a finding of its
      own.
- [ ] Anything controlled off-chain (an MPC wallet, a custody provider, a
      multisig the chain sees only as one address) is stated, with the provider
      and threshold, because the chain cannot show it.
- [ ] If you publish an [ERC-8241](https://ethereum-magicians.org/t/erc-8241-protocol-control-disclosure/28343)
      control disclosure, it is checked against the chain at a pinned block and
      lists no undisclosed power.

      `ownerwatch disclosure check disclosure.json --rpc <rpc>` settles the
      parts chain state can, and lists control the disclosure left out.

## 8. After deploy: keep it true

- [ ] You get an alert the block any owner, role, implementation, signer or
      threshold on your admin path changes — a one-time audit cannot see a change
      made next month.
- [ ] The alert covers your contracts' **own** admin events, not only the
      standard ones, so a protocol-specific handover (`AdminProposed`,
      `LimitsUpdated`, a custom role event) is not missed.

      `ownerwatch probe --yaml ... > config.yaml` writes a monitor for the whole
      surface above; `ownerwatch run --config config.yaml` (or the
      `imal1ice/ownerwatch-action@v1` GitHub Action for a weekly CI check) runs
      it against a Discord, Slack or Telegram webhook.

---

Settling these from the chain is exactly what ownerwatch is for — it walks the
control graph, flags the EOAs, 1-of-N Safes and undelayed powers, and proves each
finding with a simulation — but the checklist stands on its own. The point is to
reach your audit with the control surface already mapped, and to keep it mapped
after the auditors leave.
