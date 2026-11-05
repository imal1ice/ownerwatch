# See scheduled timelock calls before they run

A timelock exists so that people can see a privileged call before it executes. That only helps if someone reads the schedule. This guide sends every scheduled call, decoded, to Discord, Slack or Telegram the block it is queued.

## What fires

| Timelock | Event | Severity | What the alert carries |
|---|---|---|---|
| OpenZeppelin TimelockController | `CallScheduled` | high | target, value, delay, operation id, decoded call |
| | `CallExecuted` | high | target, value, operation id, decoded call |
| | `Cancelled` | medium | operation id |
| | `MinDelayChange` | critical | old and new delay |
| | `RoleGranted`, `RoleRevoked` | high | proposer, executor and canceller changes (they are AccessControl roles) |
| Compound-style Timelock (Compound, Uniswap and forks) | `QueueTransaction` | high | target, value, signature, ETA, decoded call |
| | `ExecuteTransaction`, `CancelTransaction` | high, medium | the same |
| | `NewDelay`, `NewAdmin`, `NewPendingAdmin` | critical, critical, high | the change |

A `scheduleBatch` emits one `CallScheduled` per call with the same id, so a batch of five calls is five alerts.

The catalog also covers other schedule-then-execute systems: Governor `ProposalQueued`, AccessManager `OperationScheduled`, Aave Governance V3 `PayloadQueued`, Sky's DSPause `plot`, and Lido's Emergency Protected Timelock `ProposalScheduled`. Run `ownerwatch events` for the list.

## Config

```yaml
# Timelock schedules on Ethereum. Replace the timelocks with yours.
rpc_url: "https://ethereum-rpc.publicnode.com"
chain_name: ethereum
explorer_url: "https://etherscan.io"
confirmations: 2
max_block_range: 1000
state_file: "state/timelock-queue.json"

contracts:
  - address: "0xFe89cc7aBB2C4183683ab71653C4cdc9B02D44b7"
    label: "ENS DAO Timelock (TimelockController)"
  - address: "0xE6841D92B0C345144506576eC13ECf5103aC7f49"
    label: "Arbitrum DAO L1 Timelock (TimelockController)"
  - address: "0x6d903f6003cca6255D85CcA4D3B5E5146dC33925"
    label: "Compound Timelock (Compound-style)"

alerts:
  min_severity: medium
  discord_webhook: ""    # or slack_webhook, telegram_bot_token + telegram_chat_id, webhook_url
```

```bash
pip install ownerwatch
ownerwatch validate --config timelock-queue.yaml
ownerwatch run --config timelock-queue.yaml
```

Delays at the time of writing: ENS 2 days, Arbitrum L1 3 days, Compound 2 days. `ownerwatch probe --rpc <rpc> <timelock>` reads the current delay.

## What the alert looks like

ENS governance scheduled a batch of 15 calls on 25 October 2026 ([tx](https://etherscan.io/tx/0xc1bbf09ac6e3b81c8c93d98980ff88ba5da77112015c675538e9347b01562d0e), block 26267764) and executed it two days later; one of the 15 was an `upgradeTo` on the ENS universal resolver, with a 2-day delay. Each `CallScheduled` is one high alert with the decoded call. Reproduce the alert text with:

```bash
ownerwatch backfill --config timelock-queue.yaml --from-block 26267764 --to-block 26267764
```

## How the call is decoded

ownerwatch tries, in order: the target's verified ABI on [Sourcify](https://sourcify.dev), the ABI of the target's implementation if the target is a proxy, the function name from the openchain and 4byte signature databases, and finally the raw selector. The host needs outbound HTTPS to those services; without it, alerts still arrive with the selector.

## When will it run?

- TimelockController: the alert gives the delay in seconds. The call can run from the block time of the alert plus that delay.
- Compound-style: the alert gives `eta` as a Unix timestamp.

ownerwatch does not send a second alert when the delay expires, and it does not judge whether a call is harmful. It tells you what was scheduled; someone has to read it.

## Notes

- Watching the timelock is not enough if the timelock can be bypassed. Check who else can upgrade or call the targets with `ownerwatch probe`.
- For a Safe that proposes to the timelock, the proposal is visible even earlier in the Safe queue. See [monitor-safe-signers.md](https://github.com/imal1ice/ownerwatch/blob/main/docs/monitor-safe-signers.md).
