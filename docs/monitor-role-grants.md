# Alert on role grants: AccessControl and AccessManager

How to get an alert when a privileged role is granted, revoked or re-parented on an OpenZeppelin AccessControl contract or an OpenZeppelin AccessManager, and when a contract is moved to a different manager.

## What fires

| Standard | Watch | Events in the catalog | Severity |
|---|---|---|---|
| AccessControl (`bytes32` roles) | the contract | `RoleGranted`, `RoleRevoked` | high |
| | | `RoleAdminChanged` | critical |
| AccessManager (`uint64` roles) | the manager | `RoleGranted`, `RoleRevoked`, `RoleAdminChanged`, `RoleGrantDelayChanged`, `TargetFunctionRoleUpdated`, `TargetClosed`, `TargetAdminDelayUpdated`, `OperationScheduled` | high |
| AccessManaged | each managed contract | `AuthorityUpdated` (moved to another manager) | critical |

`AuthorityUpdated` is emitted by the managed contract, not by the manager, so list the managed contracts too.

Not in the catalog, added below under `custom_events`:

- AccessManager `RoleGuardianChanged`: a different role can now cancel scheduled operations for that role.
- AccessControlDefaultAdminRules `DefaultAdminTransferScheduled` and `DefaultAdminDelayChangeScheduled`: a new default admin, or a shorter wait for one, has been scheduled.

Event definitions: [IAccessManager.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.4.0/contracts/access/manager/IAccessManager.sol), [IAccessControlDefaultAdminRules.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.4.0/contracts/access/extensions/IAccessControlDefaultAdminRules.sol).

## Config

```yaml
# Role changes on Ethereum. Replace the addresses with yours.
rpc_url: "https://ethereum-rpc.publicnode.com"
chain_name: ethereum
explorer_url: "https://etherscan.io"
confirmations: 2
max_block_range: 1000
state_file: "state/role-grants.json"

contracts:
  # AccessControl
  - address: "0xc2aaCf6553D20d1e9d78E365AAba8032af9c85b0"
    label: "Aave V3 ACLManager"
  - address: "0x3ffFbAdAF827559da092217e474760E2b2c3CeDd"
    label: "Arbitrum L1 UpgradeExecutor"
  # AccessManager and a contract it manages
  - address: "0x08aE3BE30958cDd1847ec58fFfd4C451a87fDF01"
    label: "Aave V4 AccessManager"
  - address: "0xCca852Bc40e560adC3b1Cc58CA5b55638ce826c9"
    label: "Aave V4 Core Hub"

custom_events:
  - event: "RoleGuardianChanged(uint64 indexed roleId, uint64 indexed guardian)"
    severity: high
  - event: "DefaultAdminTransferScheduled(address indexed newAdmin, uint48 acceptSchedule)"
    severity: critical
  - event: "DefaultAdminDelayChangeScheduled(uint48 newDelay, uint48 effectSchedule)"
    severity: critical

alerts:
  min_severity: high
  discord_webhook: ""    # or slack_webhook, telegram_bot_token + telegram_chat_id, webhook_url
```

```bash
pip install ownerwatch
ownerwatch validate --config role-grants.yaml
ownerwatch run --config role-grants.yaml
```

The Aave addresses are from Aave's [address book](https://github.com/aave-dao/aave-address-book); Aave's [permissions book](https://github.com/aave-dao/aave-permissions-book/blob/main/out/ETHEREUM-V4.md) lists who holds each role.

## Reading the alert

- AccessControl roles are `bytes32` hashes. `0x00…00` is `DEFAULT_ADMIN_ROLE`, which can grant and revoke every role whose admin it is. Other roles are usually `keccak256` of the role name: `0xd8aa0f31…9e63` is `keccak256("EXECUTOR_ROLE")`.
- AccessManager roles are numbers. `0` is `ADMIN_ROLE`, `18446744073709551615` is `PUBLIC_ROLE`; the rest are chosen by the deployer.
- An AccessManager `RoleGranted` alert carries the execution delay (seconds the new member must wait between scheduling and running a call) and `effective`, the Unix time the grant takes effect.
- To list everyone who holds a role now: `ownerwatch probe --rpc <rpc> --roles-from-logs <contract>`. It replays grants and revokes from the contract's creation block and names roles from the contract's own getters.

## What the alert looks like

Arbitrum's L1 UpgradeExecutor granted `EXECUTOR_ROLE` (`0xd8aa0f31…9e63`) to `0x3066…39b9` on 2 October 2026 ([tx](https://etherscan.io/tx/0x30732bb7d2fe35e3ada0929ad5ab603c59355ad71a3f75d109bba0d3db97d11f), block 26105547), a high alert. Reproduce the alert text with:

```bash
ownerwatch backfill --config role-grants.yaml --from-block 26105547 --to-block 26105547
```

## Notes

- Every role change alerts, including routine ones. There is no filter by role or account; `min_severity` is the only filter.
- A role used only through a timelock or AccessManager delay is announced earlier, when the call is scheduled. See [monitor-timelock-queue.md](https://github.com/imal1ice/ownerwatch/blob/main/docs/monitor-timelock-queue.md).
- Custom role systems with their own events (for example `setRole(...)`-style registries) need `custom_events`; see `config.example.yaml`.
