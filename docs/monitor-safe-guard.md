# Check and monitor a Safe's transaction guard

A Gnosis Safe can have a **transaction guard**: a contract that runs on *every* Safe transaction and can revert it. Its `checkTransaction` is called before the Safe executes, and `checkAfterExecution` after. A guard is a policy or veto layer — it can enforce allowlists, spending limits or cooldowns — but a guard that is malicious, buggy, or simply reverts unconditionally **blocks every transaction the Safe tries to make**, which can brick the Safe or gate the funds it controls until the guard is removed. (Removing the guard itself goes through `setGuard`, which the guard's `checkTransaction` can also block.)

The guard is easy to miss. It is not an owner, not a signer, and not a module, so reading the Safe's owners, threshold and modules tells you nothing about it. It lives in its own storage slot — `keccak256("guard_manager.guard.address")` = `0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8` — and most contract-control tools never look there. A guard is uncommon, so most Safes have none set (the slot reads zero); the point is to know, for the Safes you rely on, whether one is set and to hear about it the moment it changes.

ownerwatch reads it, pins it, and alerts on it.

## Check it now

Point `probe` at the Safe. It reports the owners, threshold and modules, and — when a guard is set — the guard, with a note that it runs on every transaction:

```bash
pip install ownerwatch
ownerwatch probe --rpc https://ethereum-rpc.publicnode.com 0xYourSafe
```

If a guard is set, the report includes a line like:

```
- 0xYourSafe: Safe transaction guard 0x1111…1111: it runs on every Safe transaction and can revert any of them
```

No line means no guard is set on that Safe. The guard address is a contract in its own right — probe it too (`ownerwatch probe <guardAddress>`) to see who controls *it*, since whoever can change the guard's behaviour can change what the Safe is allowed to do.

## Pin it in CI

`probe --foundry` writes a self-contained Foundry test that records the Safe's control surface at one block, including the guard slot. Run on a fork of the live chain, it fails and names what changed — so a guard that is **added, changed, or removed** breaks the build:

```bash
ownerwatch probe --foundry --rpc "$RPC" 0xYourSafe > test/AdminSurface.t.sol
OWNERWATCH_RPC_URL="$RPC" forge test --match-contract AdminSurface
```

## Monitor it live

A guard change emits `ChangedGuard(address)`, which is in ownerwatch's default catalog as a **critical** event. A config that watches the Safe alerts the moment the guard changes:

```bash
ownerwatch probe --rpc "$RPC" --yaml --label "Treasury Safe" 0xYourSafe > safe.yaml
ownerwatch run --config safe.yaml      # point `alerts` at your Slack/Discord/Telegram
```

The alert reads `Safe guard changed to 0x…`. The same config also catches signer, threshold and module changes (see [monitor Safe signer and threshold changes](https://github.com/imal1ice/ownerwatch/blob/main/docs/monitor-safe-signers.md)); run `backfill` over a block you know changed the guard to see the exact alert text first.

## Notes

- The drift test and the facts block both carry a `guard` line, so a monthly `probe` report and the CI pin agree on what the guard was at each check.
- Safe 1.4.1 and 1.5.0 index the `ChangedGuard` argument; 1.3.0 does not. ownerwatch decodes both.
- This is a chain view, not a verdict: it shows whether a guard is set and when it changes. It does not judge what a given guard does — read the guard contract for that.
