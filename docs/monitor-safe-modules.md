# Audit and monitor a Safe's modules

A Gnosis Safe can have **modules**: contracts that are allowed to execute transactions *through the Safe without collecting any owner signatures*. A module calls `execTransactionFromModule`, and the Safe runs it — no threshold, no signer queue, no approval. Modules power legitimate things (account recovery, automation, Zodiac's governance and delay modifiers), but an enabled module is, by construction, a path to the Safe's funds that **bypasses the multisig entirely**. A module that is malicious, compromised, or simply more powerful than intended can move everything the Safe holds while the owners and threshold look untouched.

Modules are easy to miss for the same reason a guard is: a module is not an owner and not a signer, so reading the Safe's owners and threshold tells you nothing about what modules can do — and a module is a *larger* hole than a guard, because a guard can only *block* transactions while a module can *send* them. The owners could be a pristine 4-of-7 and a single enabled module can still drain the Safe on one unsigned call. Enabling a module is itself a Safe transaction (`enableModule`), so it goes through the owners once — but after that the module stands on its own until someone disables it.

ownerwatch reads the module set, follows each module to see who controls it, pins the set, and alerts when it changes.

## Check it now

Point `probe` at the Safe. It lists the enabled modules and, for each, says plainly that it can execute without the signers — and it walks into the module to show who controls *that*:

```bash
pip install ownerwatch
ownerwatch probe --rpc https://ethereum-rpc.publicnode.com 0xYourSafe
```

For each enabled module the report carries a line like:

```
- 0xYourSafe: Safe module 0x2222…2222 (an EOA) can execute without the signers
```

An EOA module is the sharpest version of the risk — one key, no delay, full execution rights over the Safe. No module lines means no modules are enabled (the common case). The module is a contract in its own right: whoever controls the module controls that bypass path, so probe tells you whether it is an EOA, another Safe, or a timelock, and you can probe it directly (`ownerwatch probe <moduleAddress>`) to go further.

ownerwatch also recognises a **Zodiac Delay modifier** and describes it differently — as transactions queued by its enablers that execute *after a cooldown*, a time-delayed recovery path rather than an instant bypass. That distinction matters: not every module is an emergency. The tool names the mechanism so you can judge it, instead of flagging every module the same.

## Pin it in CI

`probe --foundry` writes a self-contained Foundry test that records the Safe's control surface at one block, the enabled module set included. Run on a fork of the live chain, it fails and names what changed — so a module that is **enabled or disabled** breaks the build:

```bash
ownerwatch probe --foundry --rpc "$RPC" 0xYourSafe > test/AdminSurface.t.sol
OWNERWATCH_RPC_URL="$RPC" forge test --match-contract AdminSurface
```

A newly enabled module is the change you most want this test to catch, because it is the one that adds a signer-free path to the funds without touching the owners or threshold.

## Monitor it live

Enabling a module emits `EnabledModule(address)`, which is in ownerwatch's default catalog as a **critical** event; disabling one emits `DisabledModule(address)` (**high**). A config that watches the Safe alerts the moment the module set changes:

```bash
ownerwatch probe --rpc "$RPC" --yaml --label "Treasury Safe" 0xYourSafe > safe.yaml
ownerwatch run --config safe.yaml      # point `alerts` at your Slack/Discord/Telegram
```

The alert reads `Safe module enabled 0x…`. The catalog also carries `ExecutionFromModuleSuccess` (**high**) — a module *actually* executed a transaction, bypassing the signer queue — so you hear not only when a bypass path is added but when one is used. The same config catches signer, threshold and guard changes too (see [monitor Safe signer and threshold changes](https://github.com/imal1ice/ownerwatch/blob/main/docs/monitor-safe-signers.md) and [check and monitor a Safe's transaction guard](https://github.com/imal1ice/ownerwatch/blob/main/docs/monitor-safe-guard.md)); run `backfill` over a block you know enabled a module to see the exact alert text first.

## Notes

- A module is a feature, not a bug — recovery and automation need one. The point is to know which modules are enabled on the Safes you rely on, that each one can move funds without a signature, and to hear the instant the set changes.
- ownerwatch distinguishes a Zodiac Delay modifier (queued, time-delayed, a recovery path) from a module that can execute immediately, so a legitimate delayed-recovery setup does not read the same as an instant bypass.
- This is a chain view, not a verdict: it shows which modules are enabled and who controls them, not what a given module's code is allowed to do. Read the module contract for that — an enabled module is only as safe as the contract behind it and the key behind that.
