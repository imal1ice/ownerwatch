# ownerwatch

[![ci](https://github.com/imal1ice/ownerwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/imal1ice/ownerwatch/actions/workflows/ci.yml) [![release](https://img.shields.io/github/v/release/imal1ice/ownerwatch)](https://github.com/imal1ice/ownerwatch/releases) ![license](https://img.shields.io/github/license/imal1ice/ownerwatch)

Self-hosted monitor that alerts you the moment the **admin surface** of your EVM contracts changes.

Most protocol losses in 2025-2026 started with a key, a role or a proxy changing hands, not with a clever exploit. ownerwatch watches the events that mean "someone just gained control" and pushes them to Discord, Slack, Telegram or any webhook within seconds. No account, no SaaS, no third party holding your contract list. One YAML file and a Docker container.

## What it watches

Every address in your config gets the full catalog:

| Standard | Events | Severity |
|---|---|---|
| Ownable / Ownable2Step | OwnershipTransferred, OwnershipTransferStarted | critical / high |
| AccessControl | RoleGranted, RoleRevoked, RoleAdminChanged | high / critical |
| ERC-1967 proxies | Upgraded, AdminChanged, BeaconUpgraded | critical |
| Pausable | Paused, Unpaused | medium |
| TimelockController | CallScheduled, CallExecuted, Cancelled, MinDelayChange | high / critical |
| Legacy Timelock (Compound, Uniswap and forks) | NewAdmin, NewPendingAdmin, NewDelay, QueueTransaction, ExecuteTransaction, CancelTransaction | medium to critical |
| Governor (OpenZeppelin and GovernorBravo) | ProposalCreated, ProposalQueued, ProposalExecuted, ProposalCanceled, VotingDelaySet, VotingPeriodSet, ProposalThresholdSet, QuorumNumeratorUpdated, TimelockChange, NewImplementation | medium to critical |
| Aragon OS (Lido and others) | SetApp, SetPermission, ChangePermissionManager, StartVote, ExecuteVote | medium to critical |
| Safe | AddedOwner, RemovedOwner, ChangedThreshold, EnabledModule, DisabledModule, ChangedGuard, ChangedFallbackHandler, ExecutionFromModuleSuccess, ExecutionSuccess, ExecutionFailure | info to critical |
| ERC-20 treasuries | Transfer out above a threshold you set | high |
| NFT treasuries | Any ERC-721 or ERC-1155 transfer out | high |
| Native balance | ETH balance of a treasury falls by more than a threshold between polls | high |

**Safe queues.** Add a Safe under `safes:` and ownerwatch polls the Safe Transaction Service: you get an alert when a transaction is proposed, and a critical one when it has collected enough signatures to execute. That is the moment to act; the on-chain events above are the record of what already happened.

Timelock and Safe-queue alerts show the call being made: full function and arguments when the target is verified on Sourcify, otherwise the signature from the openchain and 4byte databases, otherwise the raw selector. Set `explorer_url` and every alert carries a clickable transaction link.

Run `ownerwatch events` to print the catalog.

## Quick start

```bash
pip install git+https://github.com/imal1ice/ownerwatch
cp config.example.yaml config.yaml   # add your contracts and a Discord/Telegram target
ownerwatch run --config config.yaml
```

Or with Docker:

```bash
docker compose up -d        # uses ./config.yaml, keeps state in a named volume
```

A hardened systemd unit is in `deploy/ownerwatch.service`.

Several chains in one process: put shared settings at the top level and a `chains:` list underneath, see `examples/multichain.yaml`.

**Don't know what to watch?** Point `probe` at your main contract and it walks the owner/admin/proxy chain, tells you who can upgrade or pause it, flags EOAs and 1-of-N Safes, and prints a config:

```bash
ownerwatch probe --rpc https://eth.drpc.org --safe-chain eth --label Acme 0xYourProxy 0xYourSafe
ownerwatch probe --rpc https://eth.drpc.org --roles-from-logs 0xAccessControlContract   # every current role holder, replayed from logs since deployment
ownerwatch probe --config config.yaml --markdown --label Acme > admin-surface.md   # monthly report of everything you watch
```

`--roles-from-logs` finds the creation block on Sourcify and reads the history from a free public log gateway on Ethereum, Optimism, Arbitrum, Gnosis and Polygon; on Base (and for any chain without one) pass `--logs-rpc` with an RPC that serves wide `eth_getLogs` ranges, or `--from-block` to bound the scan.

Want that check in CI? `examples/github-action-drift.yml` re-probes weekly and fails when a signer, delay or proxy admin changes from the committed report.

```bash
```

Other commands:

```bash
ownerwatch validate                         # check the config, the RPC and that every address has code
ownerwatch test-alert                       # push a test message through your sinks
ownerwatch run --once                       # single scan, for cron
ownerwatch backfill --from-block N --to-block M   # replay history, prints what you would have seen
ownerwatch events                           # list the catalog
```

See [docs/what-to-watch.md](docs/what-to-watch.md) for the control-graph model behind the catalog, and [docs/sample-alerts.md](docs/sample-alerts.md) for real alerts replayed from mainnet history.

## Examples

`examples/` has verified configs for Uniswap, Compound, Arbitrum, Aave and the Optimism Foundation Safe on mainnet. Backfill one to see what alerts look like on real history:

```bash
ownerwatch backfill --config examples/aave-mainnet.yaml --from-block 22000000 --to-block 22050000
```

## How it works

- Polls `eth_getLogs` for the catalog's topic hashes on your addresses, in chunks that fit public RPCs.
- Waits `confirmations` blocks behind the head so small reorgs don't produce ghost alerts.
- Persists a block cursor to `state/`, so a restart resumes where it left off with no duplicates.
- Alert delivery never stops the poller: a dead webhook is logged and skipped.
- Set `heartbeat_url` to a dead-man's-switch (healthchecks.io or similar) and you get paged when ownerwatch itself stops polling. Quiet and dead must not look the same.
- Works on any EVM chain, one process can watch several.

## Hosted tier

Don't want to run it? I run it for you, per chain, paid in USDC on-chain through `contracts/src/Subscriptions.sol`: approve, call `subscribe(periods, chains, maxCost, configRef)`, send me the config. No invoices, no accounts, no KYC either way. Details in [docs/hosted.md](docs/hosted.md). Deployment address will be listed here once live; until then open an issue. The operator side is `ownerwatch hosted --rpc ... --subscriptions 0x... --configs configs/`: it starts a watcher for every address with an active subscription and stops it when the subscription lapses.

```bash
cd contracts && forge install foundry-rs/forge-std --no-git && forge test
```

## Roadmap

- Native balance and NFT alerts for Safe queues (currently on-chain only)

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

## Services

ownerwatch is free and self-hosted. If you would rather have someone do the work:

- **Admin-surface review**: every owner, proxy admin, role holder and Safe signer in your deployment, replayed from logs, with a written report and a ready-to-run ownerwatch config. Flat $400 in USDC, delivered within 48 hours.
- **Hosted monitoring**: I run ownerwatch for you and alert your Discord, Slack or Telegram. $200 per month per chain, paid in USDC on-chain.

Contact: imal1ice@proton.me. Wallet for payments: `0x874D018623EeBb398B898AC7AB0c97506244141B`.
