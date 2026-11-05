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
| OpenZeppelin AccessManager | RoleGranted, RoleRevoked, RoleAdminChanged, TargetFunctionRoleUpdated, TargetClosed, TargetAdminDelayUpdated, RoleGrantDelayChanged, OperationScheduled; AuthorityUpdated on managed contracts | high / critical |
| ERC-1967 proxies | Upgraded, AdminChanged, BeaconUpgraded | critical |
| Pausable | Paused, Unpaused | medium |
| TimelockController | CallScheduled, CallExecuted, Cancelled, MinDelayChange | high / critical |
| Legacy Timelock (Compound, Uniswap and forks) | NewAdmin, NewPendingAdmin, NewDelay, QueueTransaction, ExecuteTransaction, CancelTransaction | medium to critical |
| Governor (OpenZeppelin and GovernorBravo) | ProposalCreated, ProposalQueued, ProposalExecuted, ProposalCanceled, VotingDelaySet, VotingPeriodSet, ProposalThresholdSet, QuorumNumeratorUpdated, TimelockChange, NewImplementation | medium to critical |
| Aave Governance V3 PayloadsController | PayloadCreated (with decoded actions), PayloadQueued, PayloadExecuted, PayloadCancelled, ExecutorSet, GuardianUpdated | medium to critical |
| Aragon OS (Lido and others) | SetApp, SetPermission, ChangePermissionManager, StartVote, ExecuteVote | medium to critical |
| Sky (MakerDAO) governance | DSPause spells plotted, executed and dropped, pause delay, owner and authority; DSChief Lift (new hat) | medium to critical |
| Lido Dual Governance and Emergency Protected Timelock | proposals submitted, scheduled and executed, Dual Governance state changes, proposers, committees, delays, emergency mode | medium to critical |
| Rocket Pool DAOs | proposals added, executed and destroyed (protocol DAO, oDAO, security council), contract upgrades pending and applied, RocketStorage guardian | medium to critical |
| CoW Protocol allow-list | SolverAdded, SolverRemoved, ManagerChanged, proxy upgrades | high / critical |
| Gearbox ACL | pausable and unpausable admins added or removed | high |
| 0x Settler deployer | Deployed, Removed, RemovedAll, Authorized | high / critical |
| Safe | AddedOwner, RemovedOwner, ChangedThreshold, EnabledModule, DisabledModule, ChangedGuard, ChangedFallbackHandler, ExecutionFromModuleSuccess, ExecutionSuccess, ExecutionFailure | info to critical |
| ERC-20 treasuries | Transfer out above a threshold you set | high |
| NFT treasuries | Any ERC-721 or ERC-1155 transfer out | high |
| Native balance | ETH balance of a treasury falls by more than a threshold between polls | high |

**Safe queues.** Add a Safe under `safes:` and ownerwatch polls the Safe Transaction Service: you get an alert when a transaction is proposed, and a critical one when it has collected enough signatures to execute. That is the moment to act; the on-chain events above are the record of what already happened.

Timelock and Safe-queue alerts show the call being made: full function and arguments when the target is verified on Sourcify, otherwise the signature from the openchain and 4byte databases, otherwise the raw selector. Set `explorer_url` and every alert carries a clickable transaction link.

Run `ownerwatch events` to print the catalog. Your own admin events go under `custom_events` in the config, by Solidity signature or, for an unverified contract, by topic0; see [config.example.yaml](https://github.com/imal1ice/ownerwatch/blob/main/config.example.yaml).

**ERC-8241 disclosures.** `ownerwatch disclosure draft` writes an [ERC-8241](https://ethereum-magicians.org/t/erc-8241-protocol-control-disclosure/28343) control disclosure from chain state, and `ownerwatch disclosure check` verifies one at a pinned block, including powers observed on-chain that the disclosure leaves out. See [docs/erc-8241.md](https://github.com/imal1ice/ownerwatch/blob/main/docs/erc-8241.md).

## Quick start

```bash
pip install ownerwatch
ownerwatch probe --rpc https://eth.drpc.org --yaml --label Acme 0xYourProxy 0xYourSafe > config.yaml   # a config written from chain state
ownerwatch run --config config.yaml
```

Add a Discord, Slack or Telegram target under `alerts` in `config.yaml`. Every option is in [config.example.yaml](https://github.com/imal1ice/ownerwatch/blob/main/config.example.yaml).

Or with Docker, from a clone of this repository:

```bash
docker compose up -d        # uses ./config.yaml, keeps state in a named volume
```

A hardened systemd unit is in `deploy/ownerwatch.service`.

Several chains in one process: put shared settings at the top level and a `chains:` list underneath, see `examples/multichain.yaml`.

**Don't know what to watch?** Point `probe` at your main contract and it walks the owner/admin/proxy chain, tells you who can upgrade or pause it, flags EOAs and 1-of-N Safes, and prints a config:

```bash
ownerwatch probe --rpc https://eth.drpc.org --safe-chain eth --label Acme 0xYourProxy 0xYourSafe
ownerwatch probe --rpc https://eth.drpc.org --roles-from-logs 0xAccessControlContract   # every current role holder, replayed from logs since deployment
ownerwatch probe --config config.yaml --markdown --label Acme > admin-surface.md   # monthly report of everything you watch; set probe_rpc_url per chain if rpc_url rejects eth_call
```

`--roles-from-logs` finds the creation block on Sourcify and reads the history from a free public log gateway on Ethereum, Optimism, Arbitrum, Gnosis and Polygon; on Base (and for any chain without one) pass `--logs-rpc` with an RPC that serves wide `eth_getLogs` ranges, or `--from-block` to bound the scan.

Want that check in CI? Add one step: `uses: imal1ice/ownerwatch-action@v1` ([ownerwatch-action](https://github.com/imal1ice/ownerwatch-action)) re-probes weekly and fails when a signer, delay or proxy admin changes from the committed report. `examples/github-action-drift.yml` is the full workflow.

**Or pin it in `forge test`.** `probe --foundry` prints `AdminSurface.t.sol`, a self-contained Foundry test (no forge-std) that pins what the probe read at one block: `owner()`, the ERC-1967 implementation, admin and beacon slots, each ProxyAdmin's owner, `hasRole` for every holder found, each Safe's threshold, signers and modules, each timelock's delay, and AccessManager roles and function guards. Run on a fork of the live chain, it fails and names what changed:

```bash
ownerwatch probe --foundry --rpc "$RPC" 0xYourProxy 0xYourSafe > test/AdminSurface.t.sol
OWNERWATCH_RPC_URL="$RPC" forge test --match-contract AdminSurface
# [FAIL: 0x5FbDB2315678afecb367f032d93F642f64180aa3 (contract) changed:
#   owner(): pinned 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266, now 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC] test_contract_5fbdb231()
```

The file records state; it does not judge it, and no RPC URL is written to it. What it cannot pin, such as a role granted to an address it has never seen on a contract that does not list its members, is spelled out in `// not pinned:` lines. Regenerate it after an intended change.

**Or prove it.** `probe --prove` backs every finding with a simulation. It runs the privileged call as an `eth_call` from the holder and from a stranger (`0x…dEaD`), at one block, and reports `proven` only when the call succeeds from the holder and reverts from the stranger: the owner's `transferOwnership`/`setOwner`, the upgrade admin's `upgradeTo`/`upgradeToAndCall`, a `DEFAULT_ADMIN_ROLE` holder's `grantRole`, a mint or pause role, an OpenZeppelin timelock proposer's `schedule`. The function and its calldata come from the verified ABI with safe dummy arguments; nothing is ever sent. A call that reverts from both (gated by state, not the caller), succeeds from both, or whose arguments cannot be guessed is reported `not simulated: <why>`, never proven.

```bash
ownerwatch probe --prove --rpc https://ethereum-rpc.publicnode.com 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
# proven: transferOwnership(address) succeeds from owner() 0xFcb1…AE3a, reverts from a stranger
# proven: upgradeTo(address) succeeds from upgrade admin 0x807a…95d2, reverts from a stranger
```

Other commands:

```bash
ownerwatch validate                         # check the config, the RPC and that every address has code
ownerwatch test-alert                       # push a test message through your sinks
ownerwatch run --once                       # single scan, for cron
ownerwatch backfill --from-block N --to-block M   # replay history: prints what you would have seen, and writes jsonl_path if set; never posts to webhooks
ownerwatch events                           # list the catalog
```

See [docs/what-to-watch.md](https://github.com/imal1ice/ownerwatch/blob/main/docs/what-to-watch.md) for the control-graph model behind the catalog, [docs/safe-1-4-1-events.md](https://github.com/imal1ice/ownerwatch/blob/main/docs/safe-1-4-1-events.md) for a decoding trap that silently hides Safe signer changes, and [docs/sample-alerts.md](https://github.com/imal1ice/ownerwatch/blob/main/docs/sample-alerts.md) for real alerts replayed from mainnet history.

## Guides

- [Moving admin-event monitors off OpenZeppelin Defender](https://github.com/imal1ice/ownerwatch/blob/main/docs/migrate-from-defender.md): what maps, what does not, and OpenZeppelin's own recommended path
- [Alert on Safe signer and threshold changes](https://github.com/imal1ice/ownerwatch/blob/main/docs/monitor-safe-signers.md)
- [Alert on proxy and beacon upgrades](https://github.com/imal1ice/ownerwatch/blob/main/docs/monitor-proxy-upgrades.md)
- [Alert on role grants: AccessControl and AccessManager](https://github.com/imal1ice/ownerwatch/blob/main/docs/monitor-role-grants.md)
- [See scheduled timelock calls before they run](https://github.com/imal1ice/ownerwatch/blob/main/docs/monitor-timelock-queue.md)
## Curator collateral report

A Morpho vault lends its depositors' money against collateral tokens, so whoever can mint, upgrade or pause those tokens is part of the vault's risk. `ownerwatch collateral` maps that for one vault, from chain state alone:

```bash
ownerwatch collateral 0xVault --rpc https://ethereum-rpc.publicnode.com --markdown > collateral.md
ownerwatch collateral 0xVault --rpc https://ethereum-rpc.publicnode.com --yaml > config.yaml   # watch every collateral token
```

- **Markets.** MetaMorpho V1: `withdrawQueue` and `supplyQueue`. Morpho Vault V2: each market adapter's market ids, and through a vault adapter the markets of the vault it holds shares in. Allocations come from Morpho Blue `position` and `market`, in loan-token units, and their sum is checked against `totalAssets()`. Any other adapter is reported as not mapped.
- **Each collateral token, ranked by allocation:** owner and `DEFAULT_ADMIN_ROLE` holders, upgrade admin, who can mint and who can pause, each walked up to a key or a Safe with any timelock delay on the way, plus the probe's findings. Wrappers are followed to what they wrap: ERC-4626 `asset()`, wstETH, Pendle PT to SY to the yield token.
- **Who can mint or pause** comes from roles, getters (`minter()`, `masterMinter()`, `pauser()`, `isMinter`), and `eth_call` simulations at the pinned block from every controller found. A simulated success is shown; a revert proves nothing and is not reported. On AccessControl contracts that do not list their members, every account the Blockscout or Routescan log index saw granted a role is tested with `hasRole` at the pinned block, so a stale index cannot add a holder.
- **Oracles:** each market's oracle with its owner and upgrade admin, and the owners of the feeds a MorphoChainlinkOracleV2 reads.
- **One block.** Every read is at one pinned block, printed at the top (default: 5 behind the head; `--block N` to choose). A non-archive RPC keeps recent state only (about 120 blocks on publicnode's Ethereum endpoint), which a run normally fits in; a read past that fails and says so.
- **Failures are never clean.** A read that fails, an adapter it cannot map, books that do not reconcile, and anything it could not establish (a role nobody in the report holds, an upgrade gate no controller passes) are listed in the report, and the command exits 2.
- `--yaml` writes a config that watches the vault, every collateral and wrapped token, the contracts and Safes above them, and the oracles. With `--markdown --yaml` the config follows the report.

Not covered: Vault V2 caps (a market the curator has capped but not funded may not appear), AccessManager role holders beyond the addresses in the report, and adapters other than Morpho market and vault adapters.

## Examples

`examples/` has verified configs for Uniswap, Compound, Arbitrum, Aave and the Optimism Foundation Safe on mainnet. Backfill one to see what alerts look like on real history:

```bash
git clone https://github.com/imal1ice/ownerwatch && cd ownerwatch
ownerwatch backfill --config examples/compound-mainnet.yaml --from-block 25768000 --to-block 25790000
```

## How it works

- Polls `eth_getLogs` for the catalog's topic hashes on your addresses, in chunks that fit public RPCs.
- Pick the logs RPC carefully. Some public endpoints return *incomplete* logs without an error: rpc.flashbots.net returned none for the Aave PayloadsController over a week in which Tenderly's gateway returned ten. The examples use `mainnet.gateway.tenderly.co`; verify any other endpoint with `ownerwatch backfill` against a block you know had an event.
- Waits `confirmations` blocks behind the head so small reorgs don't produce ghost alerts.
- Persists a block cursor to `state/`, so a restart resumes where it left off with no duplicates.
- Alert delivery never stops the poller. A failed delivery is kept in the state file and retried on every poll, oldest first, until the sink takes it. A 429 waits out `Retry-After`.
- Set `alerts.jsonl_path` and every alert is also appended to a file as one JSON line: a free archive, and the input for a static page or feed (see [admin-feed](https://github.com/imal1ice/admin-feed)).
- Set `heartbeat_url` to a dead-man's-switch (healthchecks.io or similar) and you get paged when ownerwatch itself stops polling. It pings only after a fully healthy poll: every scan and Safe check worked and no alert is waiting for delivery. Chains that share one URL ping only when all of them are healthy. Quiet and dead must not look the same.
- Works on any EVM chain, one process can watch several.

## Hosted tier

ownerwatch includes what it takes to run it as a paid service for others: a subscription contract, `contracts/src/Subscriptions.sol` (approve USDC, call `subscribe(periods, chains, maxCost, configRef)`), and an operator runner, `ownerwatch hosted --rpc ... --subscriptions 0x... --configs configs/`, which starts a watcher for every address with an active subscription and stops it when the subscription lapses. Details in [docs/hosted.md](https://github.com/imal1ice/ownerwatch/blob/main/docs/hosted.md). No deployment is operated from this repository.

```bash
cd contracts && forge install foundry-rs/forge-std --no-git && forge test
```

## Roadmap

- Native balance and NFT alerts for Safe queues (currently on-chain only)

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e . pytest
.venv/bin/pytest        # end-to-end test against a local anvil node; needs foundry
```

## Work with me

ownerwatch is free and self-hosted. If you would rather have someone do the work, I do admin-surface reviews (every owner, proxy admin, role holder and Safe signer in a deployment, replayed from logs, with findings, fixes and a ready-to-run config), monitoring setups, and ERC-8241 disclosures drafted from chain state and checked in CI.

Write to imal1ice@proton.me. Before anything is paid, I share the terms, including where I am based, so you can decide whether you are able to work with me.
