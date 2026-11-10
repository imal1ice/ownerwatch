# Alert on proxy and beacon upgrades

How to get an alert when the implementation behind an upgradeable contract changes: ERC-1967 transparent and UUPS proxies, beacon proxies, and the contracts that hold the right to upgrade them.

## Which address emits what

| Pattern | Watch | Event | Fires when |
|---|---|---|---|
| Transparent proxy | the proxy | `Upgraded(implementation)` | the implementation changes |
| | the ProxyAdmin | `OwnershipTransferred`, `OwnershipTransferStarted` | someone else gets the right to upgrade |
| | the proxy | `AdminChanged` | the proxy admin changes (OpenZeppelin 5 sets it once, at deployment) |
| UUPS proxy | the proxy | `Upgraded(implementation)` | the implementation changes |
| | the proxy | owner and role events | the upgrade right lives in the implementation, so it is the proxy's own `owner()` or role that moves |
| Beacon proxy | the **beacon** | `Upgraded(implementation)` | every proxy behind the beacon gets new code |
| | the beacon | `OwnershipTransferred` | someone else gets the right to upgrade the beacon |
| | the proxy | `BeaconUpgraded(beacon)` | this proxy points to a different beacon |

A beacon upgrade emits `Upgraded` on the beacon ([UpgradeableBeacon.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.4.0/contracts/proxy/beacon/UpgradeableBeacon.sol)), not on the proxies behind it. Watching only the proxies misses it. Put the beacon in the config.

Every address under `contracts:` gets the whole catalog, so listing the proxy and its admin covers all the rows above. All are critical except `OwnershipTransferStarted` (high).

## Config

```yaml
# Proxy and beacon upgrades on Ethereum. Replace the addresses with yours.
rpc_url: "https://ethereum-rpc.publicnode.com"
chain_name: ethereum
explorer_url: "https://etherscan.io"
confirmations: 2
max_block_range: 1000
state_file: "state/proxy-upgrades.json"

contracts:
  # Transparent proxy and the ProxyAdmin that upgrades it (owned by the Compound Timelock)
  - address: "0xc3d688B66703497DAA19211EEdff47f25384cdc3"
    label: "Compound III cUSDCv3 (proxy)"
  - address: "0x1EC63B5883C3481134FD50D5DAebc83Ecd2E8779"
    label: "Compound III CometProxyAdmin"
  # Beacon behind every Lido stVault (owned by the Lido Aragon Agent)
  - address: "0x5FbE8cEf9CCc56ad245736D3C5bAf82ad54Ca789"
    label: "Lido Staking Vault beacon"

alerts:
  min_severity: high
  discord_webhook: ""    # or slack_webhook, telegram_bot_token + telegram_chat_id, webhook_url
```

```bash
pip install ownerwatch
ownerwatch validate --config proxy-upgrades.yaml
ownerwatch run --config proxy-upgrades.yaml
```

Not sure which addresses hold the upgrade right? `ownerwatch probe --rpc <rpc> --yaml <proxy>` follows the implementation, admin and beacon slots up to the owner and prints a config with every address on the way.

## What the alert looks like

Compound governance upgraded the cUSDCv3 Comet on 4 September 2026 ([tx](https://etherscan.io/tx/0xd6cfe9b49e659649961f350721ea52b42107293e4b0eed2671259d7b328d33f3), block 25904935), through `deployAndUpgradeTo` on the CometProxyAdmin, which upgrades the proxy's implementation. Reproduce the alert text with:

```bash
ownerwatch backfill --config proxy-upgrades.yaml --from-block 25904935 --to-block 25904935
```

## What this does not catch

- **Upgrades that emit no event.** A custom proxy that writes its implementation slot without an event is invisible to any log-based monitor. The [ownerwatch Action](https://github.com/imal1ice/ownerwatch-action) re-probes on a schedule and fails when the implementation, upgrade admin, owner or signers differ from a committed report.
- **Other upgrade events.** The catalog also has EIP-173 `ProxyImplementationUpdated`, Aave's `AddressSetAsProxy`, GovernorBravo's `NewImplementation`, Rocket Pool's `ContractUpgraded`, and an EIP-2535 diamond's `DiamondCut` — a facet replacement is a code upgrade no ERC-1967 slot reveals, so it is monitored out of the box (critical; the alert names how many facet changes the cut carried). No custom entry is needed.
- **The warning before the upgrade.** If upgrades go through a timelock, the upgrade call is visible days earlier as a scheduled call. See [monitor-timelock-queue.md](https://github.com/imal1ice/ownerwatch/blob/main/docs/monitor-timelock-queue.md).
