# Alert on Safe signer and threshold changes

How to get a Discord, Slack or Telegram message when a Safe (formerly Gnosis Safe) multisig adds, removes or replaces a signer, or changes its threshold, and how to see that change while it is still collecting signatures.

## What fires

| Change | Safe function | Event | Severity |
|---|---|---|---|
| Signer added | `addOwnerWithThreshold` | `AddedOwner`, plus `ChangedThreshold` if the threshold changes | critical |
| Signer removed | `removeOwner` | `RemovedOwner`, plus `ChangedThreshold` if the threshold changes | critical |
| Signer replaced | `swapOwner` | `RemovedOwner` then `AddedOwner` | critical |
| Threshold changed | `changeThreshold` | `ChangedThreshold` | critical |
| Module enabled or disabled | `enableModule`, `disableModule` | `EnabledModule`, `DisabledModule` | critical, high |
| Guard changed | `setGuard` | `ChangedGuard` | critical |
| Fallback handler changed | `setFallbackHandler` | `ChangedFallbackHandler` | high |

The function-to-event mapping is from Safe's [OwnerManager.sol](https://github.com/safe-fndn/safe-smart-account/blob/v1.4.1/contracts/base/OwnerManager.sol). Run `ownerwatch events` for the full catalog.

## Config

```yaml
# Safe signer and threshold changes on Ethereum. Replace the Safes with yours.
rpc_url: "https://ethereum-rpc.publicnode.com"
chain_name: ethereum
explorer_url: "https://etherscan.io"
confirmations: 2
max_block_range: 1000
state_file: "state/safe-signers.json"

# On-chain events: fire once a change has executed.
contracts:
  - address: "0xFFe21561251c49AdccFad065C94Fb4931dF49081"
    label: "Lido Reseal committee (Safe)"
  - address: "0xCe52ab41C40575B072A18C9700091Ccbe4A06710"
    label: "Aave Governance Guardian (Safe)"

# The queue: fires while a change is still waiting for signatures.
safes:
  - address: "0xFFe21561251c49AdccFad065C94Fb4931dF49081"
    label: "Lido Reseal committee (Safe)"
    chain: eth
  - address: "0xCe52ab41C40575B072A18C9700091Ccbe4A06710"
    label: "Aave Governance Guardian (Safe)"
    chain: eth

alerts:
  min_severity: high     # ExecutionSuccess (info) and ExecutionFailure (medium) still print to stdout
  discord_webhook: ""    # or slack_webhook, telegram_bot_token + telegram_chat_id, webhook_url
```

```bash
pip install ownerwatch
ownerwatch validate --config safe-signers.yaml
ownerwatch test-alert --config safe-signers.yaml
ownerwatch run --config safe-signers.yaml
```

The two Safes are public examples: the Lido Reseal committee (5 of 6 at the time of writing) and the Aave Governance Guardian (5 of 9). `ownerwatch probe --rpc <rpc> <safe>` prints the current threshold and signers of any Safe.

## Before and after execution

- **`contracts:`** reads the Safe's own events from your RPC. You hear about a change once it has executed, `confirmations` blocks later.
- **`safes:`** polls the [Safe Transaction Service](https://docs.safe.global/core-api/transaction-service-overview). You get a `SafeTxProposed` alert (high) when a transaction is proposed and a `SafeTxExecutable` alert (critical) when it has enough signatures. The call is decoded, so a pending signer swap reads `swapOwner(prevOwner=…, oldOwner=…, newOwner=…)` with its signature count.

The queue only shows transactions submitted to the Safe Transaction Service. Signatures collected elsewhere and executed directly appear only as on-chain events, which is why the config uses both. On the first run, ownerwatch records the current queue without alerting.

## What the alert looks like

The Lido Reseal committee replaced a signer on 30 October 2026 ([tx](https://etherscan.io/tx/0x55a55d9ed600f6bc8e6af298a8c9ca2483ae0df54b7cc37138d35d61124f3d4c), block 26306594): `swapOwner` emitted `RemovedOwner(0x9A3f…83D4)` then `AddedOwner(0xC80C…4fF9)`, two critical alerts. Reproduce the alert text with:

```bash
ownerwatch backfill --config safe-signers.yaml --from-block 26306594 --to-block 26306594
```

## Notes

- Safe 1.4.1 and 1.5.0 index the first argument of `AddedOwner`, `RemovedOwner` and the module and guard events; 1.3.0 does not. ownerwatch decodes both layouts. Why this matters: [docs/safe-1-4-1-events.md](https://github.com/imal1ice/ownerwatch/blob/main/docs/safe-1-4-1-events.md).
- `ExecutionFromModuleSuccess` is high. A Safe with a module that executes often sends one alert per module call.
- Another chain: change `rpc_url`, `chain_name` and `explorer_url`, and set `chain:` to the Safe service key (`base`, `arb1`, `oeth`, `pol`, `gno`, `bnb`, ...).
- `ethereum-rpc.publicnode.com` worked for this config. It rejects `eth_getLogs` without an address and rate-limits bursts, so for long backfills use an RPC that serves wide log ranges, and check any RPC with `ownerwatch backfill` against a block you know had an event.
