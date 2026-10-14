# ownerwatch

Self-hosted monitor that alerts you the moment the **admin surface** of your EVM contracts changes.

Most protocol losses in 2025-2026 started with a key, a role or a proxy changing hands, not with a clever exploit. ownerwatch watches the events that mean "someone just gained control" and pushes them to Discord, Telegram or any webhook within seconds. No account, no SaaS, no third party holding your contract list. One YAML file and a Docker container.

## What it watches

Every address in your config gets the full catalog:

| Standard | Events | Severity |
|---|---|---|
| Ownable / Ownable2Step | OwnershipTransferred, OwnershipTransferStarted | critical / high |
| AccessControl | RoleGranted, RoleRevoked, RoleAdminChanged | high / critical |
| ERC-1967 proxies | Upgraded, AdminChanged, BeaconUpgraded | critical |
| Pausable | Paused, Unpaused | medium |
| TimelockController | CallScheduled, CallExecuted, Cancelled, MinDelayChange | high / critical |
| Safe | AddedOwner, RemovedOwner, ChangedThreshold, EnabledModule, DisabledModule, ChangedGuard, ChangedFallbackHandler | critical / high |
| ERC-20 treasuries | Transfer out above a threshold you set | high |
| NFT treasuries | Any ERC-721 or ERC-1155 transfer out | high |
| Native balance | ETH balance of a treasury falls by more than a threshold between polls | high |

Timelock `CallScheduled` / `CallExecuted` alerts also show the function being called, resolved through the openchain and 4byte selector databases (falls back to the raw selector offline).

Run `ownerwatch events` to print the catalog.

## Quick start

```bash
pip install git+https://github.com/imal1ice/ownerwatch
cp config.example.yaml config.yaml   # add your contracts and a Discord/Telegram target
ownerwatch run --config config.yaml
```

Or with Docker:

```bash
docker build -t ownerwatch .
docker run -v $PWD/config.yaml:/app/config.yaml -v ownerwatch-state:/app/state ownerwatch
```

Other commands:

```bash
ownerwatch run --once                       # single scan, for cron
ownerwatch backfill --from-block N --to-block M   # replay history, prints what you would have seen
ownerwatch events                           # list the catalog
```

## How it works

- Polls `eth_getLogs` for the catalog's topic hashes on your addresses, in chunks that fit public RPCs.
- Waits `confirmations` blocks behind the head so small reorgs don't produce ghost alerts.
- Persists a block cursor to `state/`, so a restart resumes where it left off with no duplicates.
- Alert delivery never stops the poller: a dead webhook is logged and skipped.
- Works on any EVM chain. Run one instance per chain.

## Roadmap

- Full timelock calldata decoding with verified ABIs (Sourcify)
- Multi-chain in one process
- Safe transaction queue watching (pending, not just executed)
- A hosted tier for teams that don't want to run infra, paid in USDC on-chain

## Support the project

ownerwatch is free and MIT licensed. If it saves you a 3am incident, fund the work:

- Drips: https://www.drips.network/app/projects/github/imal1ice/ownerwatch
- Giveth: https://giveth.io/project/ownerwatch
- Direct: `0x874D018623EeBb398B898AC7AB0c97506244141B` (Ethereum and all major L2s)

Need it deployed, extended or integrated with your alerting stack? Open an issue or reach out on GitHub.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e . pytest
.venv/bin/pytest        # end-to-end test against a local anvil node; needs foundry
```
