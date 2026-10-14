# What to watch, and why

Every EVM protocol has a control graph: contracts, the addresses that can change them, and the addresses that can change those. ownerwatch is a set of tripwires on the edges of that graph. This page explains which edges matter and which event fires when one moves.

## The control graph

```
users ──> Proxy ──(implementation)──> Logic
           │
           └─ proxyAdmin ──> ProxyAdmin ──owner──> Timelock ──proposer──> Safe (k-of-n) ──owners──> EOAs
```

Three questions decide how exposed a protocol is:

1. **How many keys does it take** to reach the top of the chain? One EOA, a 1-of-n Safe, or a majority Safe.
2. **How long does it take.** A timelock delay is the window in which users and the team can react. No timelock means zero window.
3. **Who is watching the window.** A 48-hour delay is worthless if nobody reads the `CallScheduled` event.

`ownerwatch probe` answers 1 and 2. `ownerwatch run` is the answer to 3.

## Events by what they mean

| Someone just... | Event(s) | Standard |
|---|---|---|
| took over a contract | OwnershipTransferred, OwnershipTransferStarted, NewAdmin, SetOwner | Ownable, legacy Timelock, Morpho |
| swapped the code behind a proxy | Upgraded, BeaconUpgraded, AddressSetAsProxy, PoolUpdated, NewImplementation | ERC-1967, Aave, GovernorBravo |
| changed who can administer a proxy | AdminChanged, ACLAdminUpdated, ACLManagerUpdated | ERC-1967, Aave |
| granted or took a privileged role | RoleGranted, RoleRevoked, RoleAdminChanged, SetPermission, ChangePermissionManager, SetIsAllocator, SetCurator | AccessControl, Aragon, MetaMorpho |
| changed a multisig's signers or rules | AddedOwner, RemovedOwner, ChangedThreshold, EnabledModule, DisabledModule, ChangedGuard | Safe |
| acted through a path that skips the signers | ExecutionFromModuleSuccess | Safe |
| queued a privileged action (the window opens) | CallScheduled, QueueTransaction, ProposalQueued, SafeTxProposed (queue), SubmitTimelock, SubmitCap | TimelockController, legacy Timelock, Governor, Safe service, MetaMorpho |
| shortened or removed the window | MinDelayChange, NewDelay, SetTimelock, VotingDelaySet, VotingPeriodSet, TimelockChange | timelocks, Governor, MetaMorpho |
| changed the oracle | PriceOracleUpdated | Aave |
| paused or froze | Paused, Unpaused, ReservePaused, ReserveFrozen, Stopped, StakingPaused | Pausable, Aave, Lido |
| moved treasury funds | Transfer above threshold, NFT transfers, BalanceDrop | ERC-20/721/1155, native |

## The 2026 incidents, as alerts

- **Compromised admin key pushes an upgrade** (Wasabi, April 2026). The first on-chain event is `Upgraded` on each vault proxy. With a timelock it would have been `CallScheduled` days earlier. Either way, ownerwatch fires at the block.
- **Safe signers compromised** (Humanity Protocol, June 2026). Attackers typically add themselves or lower the threshold first: `AddedOwner`, `ChangedThreshold`. If they already hold enough keys, the queue watcher still shows `SafeTxProposed` then `SafeTxExecutable` before execution.
- **Pre-signed or stale authorisation reused** (Drift, April 2026, on Solana but the pattern is universal). The tell is a privileged call that nobody on the team remembers approving. The queue alert names the proposer and decodes the call.
- **Single key with root role** (several of the protocols probed for this project). Nothing has gone wrong yet; the alert you want is `RoleGranted` or `OwnershipTransferred` from that key to anywhere, because that is what a thief does first.

## What ownerwatch deliberately does not do

- No heuristics about "suspicious" transactions. Every alert is a concrete control-surface event with a transaction hash.
- No custody, no signing, no transactions.
- No accounts. The config is a file on your machine.

If you want behavioural detection on top of this, run it alongside Forta or Hypernative. ownerwatch is the part that must never be silent.
