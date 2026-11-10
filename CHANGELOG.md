# Changelog

## Unreleased

- `probe` and `disclosure draft`/`check` recognize EIP-2535 Diamonds. A Diamond's code is replaceable through `diamondCut`, an upgrade path no ERC-1967 implementation/admin/beacon slot reveals, so a Diamond previously read as a plain, non-upgradeable owned contract — a false "immutable", the one thing the tool must never report. The probe detects a Diamond from its loupe (`facetAddresses()` confirmed by the IDiamondLoupe ERC-165 id or a self-consistent `facetAddress()`), marks it upgradeable, and names the diamondCut gate as `owner()` (the reference implementation's restriction; a note flags that a non-standard diamond should be confirmed). A disclosure then carries the Diamond's `UPGRADE` power and `check` verifies it; a diamond with no readable `owner()` is reported upgradeable-but-unverifiable, never immutable.

## 0.15.1 - 2026-11-09

- `probe` names Injective's native EVM (chain id 1776) `injective`, so `probe --rpc <injective-rpc>` and suggested configs label the chain instead of `chain 1776`. Injective EVM is standard EVM; the probe already reads its proxies, Safes and roles.
- Docs: a [10-minute control-disclosure quickstart](docs/disclosure-quickstart.md) that chains `disclosure draft` → review → `disclosure check` → the CI Action with a status badge → the shields.io embed, taking a protocol from zero to a published, chain-checked ERC-8241 disclosure.

## 0.15.0 - 2026-11-09

- `ownerwatch collateral --json` prints the report as a stable, machine-readable JSON object (vault and pin metadata, loan asset, `totalAssets`, each collateral ranked by allocation with its `owner`/`upgrade`/`mint`/`pause` summary, findings, what it wraps, its markets and oracles, and the coverage gaps). Amounts are raw-integer strings so a JavaScript reader keeps full precision; shares are exact. For a risk dashboard or a feed, next to the existing `--markdown` and `--yaml`.
- `disclosure check --badge <path>` writes a [shields.io](https://shields.io/badges/endpoint-badge) endpoint-badge JSON ("control disclosure: verified", or "N issues" in red) in the same run, so a protocol's CI turns an ERC-8241 disclosure into a live, self-hosted README badge that reddens on control drift — one command, no mapper script and no backend.
- `probe --markdown` ends with a short, price-free pointer to the written control-audit and monitoring service. When the report found a critical control gap — an EOA on a control path, a zero-delay or absent timelock, a 1-of-N Safe, or a Safe module that can act without the signers — the pointer names that risk class. Suppress it with `OWNERWATCH_NO_FOOTER=1`; the terse and JSON output never carry it.
- Documentation: a migration-from-Defender guide and four admin-monitoring how-tos (Safe signers, proxy upgrades, role grants, timelock queue); a pre-audit control checklist; a repeatable admin-surface review template with a worked example (Compound III USDC, honest negative); a self-serve control-disclosure status-badge guide; and a second chain-verified ERC-8241 disclosure example (Compound III USDC).

## 0.14.0 - 2026-11-05

- `probe --prove` backs each finding with a simulation. It runs the privileged call as an `eth_call` at one block, once from the holder and once from a stranger (`0x…dEaD`), and reports `proven: <fn> succeeds from <holder>, reverts from a stranger` only when the holder's call succeeds and the stranger's reverts. Owners (`transferOwnership`/`setOwner`/`setPeer`), upgrade admins (`upgradeTo`/`upgradeToAndCall`), `DEFAULT_ADMIN_ROLE` holders (`grantRole`), mint and pause role holders, and OpenZeppelin timelock proposers (`schedule`) that are an EOA or a Safe are tested; the function and calldata come from the verified ABI with safe dummy arguments. A call that reverts from both (gated by state, not the caller), succeeds from both, or whose arguments cannot be guessed is reported `not simulated: <why>`, never proven. `eth_call` only; nothing is sent. The report gains a Proofs section (`markdown_report(..., prove=True)`); `--prove` cannot be combined with `--foundry`.

## 0.13.1 - 2026-11-05

- `ownerwatch collateral <vault>`: a curator collateral report for MetaMorpho V1 and Morpho Vault V2. Finds the vault's markets from chain state, ranks its collateral by allocation, and shows who can mint, upgrade or pause each token (and what it wraps) with any timelock delay, each market's oracle and its owner, and a config that watches all of it. Every read is at one pinned block; a failed read is reported, never clean. `make_w3` keeps the chain id after the first request: web3 asked for it before every `eth_call`.
- `probe` reports a Safe module that is a Zodiac Delay modifier with its cooldown and the modules that can queue through it, instead of only "can execute without the signers".

## 0.13.0 - 2026-11-05

- `probe` reads `getAdmin()` when a contract has no `admin()`: some UUPS proxies gate upgrades on it, and the path was invisible.
- `probe --foundry` prints `AdminSurface.t.sol`, a self-contained Foundry test pinning the admin surface the probe read at one block: owners, ERC-1967 slots, role holders, Safe signers, thresholds and modules, timelock delays, AccessManager roles. On a fork (`OWNERWATCH_RPC_URL`) `forge test` fails naming what changed; anything it cannot pin is listed as `// not pinned: <why>`.

## 0.12.1 - 2026-11-05

- `probe` tests a plain `ADMIN_ROLE` by name, so a probe without a log replay finds its holders.
- EOA findings state what the chain shows ("no timelock or multisig on-chain") and no longer say "one private key": the chain shows an address, not how its key is held, and an EOA may be an MPC wallet. Reports with an EOA finding say so in one line.

## 0.12.0 - 2026-11-03

- `custom_events` in the config: alert on a protocol's own admin events, by Solidity signature or, for an unverified contract, by topic0. A log that does not match its declared layout still alerts, raw.
- `backfill` reports a failed read in one line and exits 2, without a traceback or the RPC key.

## 0.11.1 - 2026-11-03

Documentation only; no code changes. The PyPI page now shows the quick start that works from an empty directory and the demo that prints alerts, and its links to the docs resolve.

## 0.11.0 - 2026-11-02

A full audit of the watcher, the probe and the disclosure checker. The theme: a quiet result must mean nothing happened, never that something failed.

### Watcher
- Safe 1.4.1 and 1.5.0 index `AddedOwner`, `RemovedOwner`, `EnabledModule`, `DisabledModule`, `ChangedGuard`, `ChangedFallbackHandler` and `ExecutionSuccess/Failure`. These logs matched the catalog and then failed to decode, so signer changes on current Safes produced no alert. They decode now. So does `Upgraded` with the implementation in the data, as USDC's proxy emits it.
- A log whose topic is in the catalog can no longer vanish: if it will not decode, it alerts raw, at its usual severity. Invalid UTF-8 in a proposal description no longer hides the proposal.
- Failed deliveries go to an outbox in the state file and are retried every poll, oldest first. 429 responses wait out `Retry-After`. A payload the sink rejects (400, 413, 422) is dropped with an error so it cannot block the rest.
- The heartbeat pings only after a fully healthy poll: scans, Safe checks and deliveries all worked. Chains sharing one URL ping only when all of them are healthy.
- `eth_getLogs` ranges shrink to what the RPC accepts and progress is saved per chunk, so a 10-block cap no longer wedges a backlog. A getLogs failure no longer skips Safe queues and native balances. `start_block: latest` is fixed on the first poll, so an outage straight after start loses nothing.
- A native-only treasury reads the head, not a frozen block. One failing Safe no longer silences the others. Safe state is per chain: state files from earlier versions are read and upgraded.
- Token `decimals` left out of a config are read from the token. They were assumed to be 18, which hid a 50M USDC transfer.
- Timelock calls with an empty signature are decoded from their calldata, and tuple signatures keep their arguments. Queued Safe transactions already seen cost no more RPC reads.
- `run --once` polls every chain and exits 1 if any failed; before, the first dead chain stopped the rest.
- Webhook, Telegram and RPC secrets no longer reach the logs. Clipped alerts keep their block and transaction. On-chain text is escaped for Slack. Cursor writes are atomic.

### Config and CLI
- **Stricter configs:** an unknown key, a bad `min_severity`, `start_block`, `max_block_range`, `confirmations` or `poll_interval_seconds`, half a Telegram setup, `min_native_drop: 0` and two chains sharing a state file are now errors. A misspelt `discord_webhok` used to mean a watcher that never alerted anyone.
- A Safe with no `chain:` uses the config's own chain, not Ethereum's service. Safe chain keys match the live service (`pol`; `matic` still works).
- `validate` exits 1 when the RPC fails or an address has no code, and also checks tokens, collections and Safes. `test-alert` ignores `min_severity` and exits 1 on a dead sink. `backfill` never posts to webhooks, as documented. `python -m ownerwatch` passes on the exit code.

### Probe
- **A failed read is not a clean report.** Only a revert means "no such function". Rate limits, pruned state and dead RPCs are retried and then exit 2; a failed role replay says so in the report and exits 2.
- Beacon proxies: the beacon's owner is the upgrade authority, and the beacon is in the report and the suggested config. A clone of a beacon proxy is upgradeable through that beacon.
- ZeppelinOS and EIP-1822 proxy slots are read, so USDC and other early proxies are proxies.
- Controllers are followed to the end of the chain, not two hops, and the result no longer depends on the order of the targets.
- A getter that returns a bool, a number, a string or a hash no longer invents a key at `0x...01`. Junk in a proxy slot is not a proxy. Catch-all fallbacks no longer crash the Safe check.
- Role replay covers every AccessControl contract found, not only the targets, and reports every powerful role, not only `DEFAULT_ADMIN_ROLE`. A zero-valued getter like `merkleRoot()` no longer renames `DEFAULT_ADMIN_ROLE`. An EOA proposer on a timelock is a finding.
- Safe modules are read and reported: a module executes without the signers.
- AccessManager: an implementation's ABI is used behind a verified proxy; contracts the manager owns count as targets; replay also reads guards from `TargetFunctionRoleUpdated`. New findings: a sensitive function or a role admin open to `PUBLIC_ROLE`, a short execution delay (any delay used to hide the holder), a pending grant. Claims are now true: no `calls deposit` from selectors nobody configured, grant and guard delays are stated, closed targets have no callers, a role only reaches the targets it guards.
- `delay()`, `getDelay()` and `minDelay()` make a timelock only with timelock functions behind them, so a parameter named `delay` no longer hides the owner's key. Wording fixed: 2-of-4 is half, not fewer than half; 1800s is 30m, not 0h; a timelock with an EOA admin is not "no timelock".
- `--config` now honours `--roles-from-logs`, `--role-candidates`, `--logs-rpc` and `--chain-name`, and names the chain from its id when `chain_name` was left at its default.
- Reports gain a **Full facts** block: every control fact with full addresses, one line each. The ownerwatch Action compares it. Owner and pending owner also appear in the table.
- A report states each AccessManager finding once, on the manager, not once per target.

### ERC-8241
- AccessManager roles are drafted, checked and counted for completeness (`accessManager:<id>`). Node kinds `aragon-app` and `access-manager` map to `CONTRACT`, so a real stETH draft checks clean.
- A UUPS proxy's authority is `unverifiable`, never `ok` or a false mismatch. A power with no bound controller is `unverifiable`, never `ok`.
- Drafts store `roleHash`, so a check does not depend on Sourcify being up; a name with neither a hash nor an ABI is `unverifiable` when it misses. Node ids use whole addresses, since vanity prefixes collided. The manifest hash is over the text as written, for non-ASCII names too.
- `check` exits 2 when the chain cannot be read, and blocks with long `extraData` no longer crash it.

### Hosted
- A customer's YAML cannot write outside its state directory, write files, or reach private networks and cloud metadata. A typo in a running customer's config keeps the old watcher running. Stop requests are honoured during catch-up.
- `Subscriptions.sol`: adding chains to an active subscription pays for them over the time left, and reducing them waits for expiry. Before, a one-period renewal changed the chain count for the whole remaining term.

## 0.10.1 - 2026-11-01
- probe: an EIP-7702 delegated account is classified as an EOA (one private key still controls it) and its delegate is shown; before, its 23-byte code made it look like a contract with "no recognised timelock".
- probe: operational keys that control assets or pricing without being an owner are read and classified: `fundsHolder()`, Lagoon `safe()` and `valuationManager()`, `curator()`, `guardian()`. An EOA or 1-of-N Safe in one of these seats is a finding.
- probe: the Ownable-timelock heuristic (`delay()` + `owner()`) now needs a delay of at least one hour, so a price-update parameter named `delay()` is no longer reported as a "0h timelock".

## 0.10.0 - 2026-11-01
- probe: OpenZeppelin AccessManager. A contract's `authority()` is followed to its AccessManager; the roles guarding the target's functions (from its verified ABI) and every role admin above them are mapped, and holders are found among probed addresses, `--role-candidates` and the signers of every Safe found, iterating as new holders appear, or with `--roles-from-logs` by replaying RoleGranted/RoleRevoked and confirming with hasRole. A single key or 1-of-N Safe holding ADMIN_ROLE, a role-admin role or a function role with no execution delay is a finding, written as what it unlocks ("can grant itself or others roles 200 (calls execute)").
- probe: EIP-1167 minimal-proxy clones are recognised and shown as non-upgradeable clones of their implementation.
- watch: AccessManager events (role grants and revokes with execution delay, role admin, function-role, target-closed and delay changes, scheduled operations) and AuthorityUpdated on managed contracts.

## 0.9.3 - 2026-11-01
- README: "Support the project" section removed with FUNDING.json and .github/FUNDING.yml (no donation address or Drips link).

## 0.9.2 - 2026-10-29
- probe: the report and config chain name is inferred from the RPC chain id when `--chain-name` is not given. Before, it defaulted to "ethereum", so an L2 report run without the flag was titled "on ethereum".
- probe: `--role-candidates` tests extra addresses (a protocol's Safes and keys from its docs or other chains) for AccessControl roles without probing them as targets; a role holder found by enumeration or by a candidate is classified before its finding is written.
- README: services without prices or a payment wallet (terms are shared before anything is paid); the hosted tier is described as operator-neutral software; dead Giveth link removed.
- probe: DEFAULT_ADMIN_ROLE, MINTER_ROLE and UPGRADER_ROLE held by a multisig that acts outside any timelock are now findings ("it takes effect immediately, while upgrades wait 48h"), as they already were for single keys. Before, a deployment whose upgrades were timelocked but whose roles sat on a bare Safe was summarised as having no zero-delay paths. Pause roles on a Safe stay out on purpose.

## 0.9.1 - 2026-10-29
- disclosure: completeness replays RoleGranted/RoleRevoked logs up to the pinned block by default (every role holder, confirmed with hasRole at that block); roles are compared by hash and named from the contract's own bytes32 getters. `--no-roles-from-logs`, `--logs-rpc`, `--from-block`.
- probe: governance shapes of large protocols, each checked on mainnet: Aragon apps (Lido stETH, Curve's DAO agent) recognised through `kernel()`/`appId()` and treated as DAO-governed; Balancer-style `getAuthorizer()` followed to the actual authorizer; AccessControlEnumerable role members listed directly (no candidates needed); Euler-style `upgradeAdmin()`; Curve-style `dao()` and `emergency()`; Maker/Sky `wards` with the Sky pause proxy, and DSPause (`delay()` + `authority()`) as a timelock (Spark resolves to the 48h pause).
- probe: after role holders are known, "no recognised timelock" findings are re-evaluated, counting an owner-less AccessControl contract's DEFAULT_ADMIN_ROLE holders as its controllers (Euler's FactoryGovernor behind its 4-day timelock).
- probe: fixed a crash when an enumerable role had no members.

## 0.9.0 - 2026-10-29
- `ownerwatch disclosure draft|check`: ERC-8241 (Protocol Control Disclosure) support. `draft` writes a disclosure from chain state (components, nodes, powers, and the controller chain as edges); `check` verifies one at a pinned block, record by record (ok, mismatch, unverifiable), and lists observed control over the declared components that no power declares. Exit code 1 on any mismatch or undisclosed power. See docs/erc-8241.md; Aave V3 examples in examples/erc-8241/.
- probe: Aave V3 is read correctly. Immutable-admin proxies (the Pool, answering `admin()` only to their admin) resolve to their admin, found by asking as each address embedded in the bytecode. The Governance V3 PayloadsController counts as a timelock, with the shortest delay in its executor settings. A contract counts as timelocked when every controller it has leads to a timelock within four hops, so the Executor and the PoolAddressesProvider no longer get a false "no recognised timelock" finding.
- Tests: Aave-pattern fixtures (immutable-admin proxy, provider, executor, PayloadsController); the full suite, including the anvil tests, passes locally.

## 0.8.0 - 2026-10-29
- Governance systems that ownerwatch could not read before, each checked against 90 days of mainnet logs (tests/fixtures/governance_logs.json):
  - Sky: DSPause spells as DSNote call logs (plot, exec, drop, setDelay, read from the calldata the note carries), LogSetOwner, LogSetAuthority, DSChief Lift.
  - Lido: Dual Governance and the Emergency Protected Timelock (proposals submitted, scheduled, executed; proposers, committees, delays, emergency mode, state changes).
  - Rocket Pool: DAO proposals added, executed, destroyed; contract upgrades pending and applied; RocketStorage guardian.
  - CoW Protocol solver allow-list, Gearbox ACL admins, 0x Settler deployer deployments and authorizations.
- A topic can now have more than one layout: the Emergency Protected Timelock's `ProposalExecuted(uint256 indexed)` shares its topic with Governor's unindexed one, and was silently dropped before.
- Alerts carry the block's own time (`block_time`); the JSONL `ts` uses it, so events are dated when they happened, not when a poll or backfill saw them.

## 0.7.6 - 2026-10-21
- probe: proxies whose upgrade admin is stored in their factory (Solady `ERC1967Factory` and forks, empty ERC-1967 admin slot) now resolve to the real admin via `adminOf(proxy)`, found from addresses embedded in the proxy bytecode plus Solady's canonical factory. Before, such proxies were reported as controlled by `owner()`, which overstated upgrade risk.
- probe: recognises Solady `Timelock` (`minDelay()`) and custom Ownable timelocks (`delay()` + `owner()`).
- probe: every finding names the link it concerns (upgrade admin, `owner()`, `admin()`); an `owner()` without a timelock is reported as owner-level settings, separate from the upgrade path.
- Examples and help text use the Tenderly public gateway for logs instead of rpc.flashbots.net, which was found to return incomplete logs silently

## 0.7.5 - 2026-10-21
- Aave Governance V3 PayloadsController: PayloadCreated (actions decoded like proposals), PayloadQueued, PayloadExecuted, PayloadCancelled, ExecutorSet, GuardianUpdated

## 0.7.4 - 2026-10-21
- `alerts.jsonl_path`: append every alert as a JSON line to a file, for feeds and archives
- README and example workflow point at the new `imal1ice/ownerwatch-action@v1` composite action

## 0.7.3
- `probe --config` honours `--rpc` (single-chain configs) and a new per-chain `probe_rpc_url`, and exits cleanly when the RPC rejects eth_call; examples carry `probe_rpc_url` so the drift check works out of the box
- probe: role replay no longer duplicates the "DEFAULT_ADMIN_ROLE held by EOA" finding

## 0.7.2
- `probe --roles-from-logs` works on free RPCs: the scan starts at the contract's creation block (Sourcify, else a code binary search), uses a public full-history log gateway per chain (Ethereum, Optimism, Arbitrum, Gnosis, Polygon; Base is range-limited) or `--logs-rpc`, splits ranges adaptively and remembers the working chunk size, and names roles from the verified ABI's bytes32 getters

## 0.7.1
- Decoded arguments format structs and bytes readably and clip long lists; calls on proxies decode via the implementation's verified ABI (Safe singletons included); Safe service timeouts are retried
- Fix: a Safe added to an existing config had its whole pending backlog alerted as new; seeding is now per Safe
- `daily_digest`: once-a-day summary of alerts by severity, so quiet and alive are distinguishable in the channel

## 0.7.0
- `probe --json`
- `examples/github-action-drift.yml`: weekly admin-surface drift check for a protocol's own repo
- `probe --config`: report on every contract and Safe in a config, per chain
- Discord alerts are colour-coded embeds with contract, chain, block and tx fields
- Safe execution events, including module executions that bypass the signer queue
- Governor ProposalCreated alerts list each action's target and decoded call

## 0.6.0
- `heartbeat_url`: dead-man's-switch ping after every successful poll
- Slack sink; Discord, Slack and Telegram messages clipped to their limits; one failing sink no longer blocks the others
- Subscriptions contract hardened after review: price slippage guard (`maxCost`), per-chain pricing enforced on-chain and by the runner, two-step ownership, zero-address checks, USDT-style tokens handled, fee-on-transfer rejected, effects before interactions, `PERIOD` naming
- Aave V3 (addresses provider, configurator), Morpho Blue, MetaMorpho and Lido core events
- `ownerwatch validate`, `docs/sample-alerts.md`, PyPI publish workflow (trusted publishing)

## 0.5.0
- `ownerwatch probe`: AccessControl role detection, `--roles-from-logs`, open-executor detection, `--markdown` report
- `ownerwatch hosted`: run a watcher per active on-chain subscriber
- `ownerwatch test-alert`
- Sourcify-verified calldata decoding, explorer links, backoff on 429s

## 0.4.0
- `probe` command, Governor and Aragon events, multi-chain process, docker-compose and systemd

## 0.3.0
- Safe queue watching, legacy Timelock events, verified example configs, Subscriptions contract

## 0.2.0
- NFT and native-balance outflows, timelock call decoding, CI

## 0.1.0
- Initial release
