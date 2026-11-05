# Moving admin-event monitors off OpenZeppelin Defender

For teams that used Defender Monitor to watch admin events: ownership, roles, proxy upgrades, Safe signers, timelocks and pauses. It maps those monitors to ownerwatch and says plainly what ownerwatch does not do.

ownerwatch covers admin-surface monitoring. It is not a Defender replacement: it has no Relayer, no Actions, no conditions on decoded values, no function-call or transaction monitoring, and no hosted dashboard. If you need those, read OpenZeppelin's own path first.

## Defender's status, from OpenZeppelin

On 30 June 2025 OpenZeppelin [announced](https://www.openzeppelin.com/news/doubling-down-on-open-source-and-phasing-out-defender):

> we're now officially announcing a phased sunset of the Defender platform, with its final shutdown planned for July 1, 2026.

> June 30, 2025: As of today, new user sign-ups have been disabled.
>
> July 1, 2026: The Defender platform will officially retire.

OpenZeppelin's [docs](https://docs.openzeppelin.com/chainlink-cre) now say: "Defender has been shut down."

## OpenZeppelin's recommended path

From the [announcement](https://www.openzeppelin.com/news/doubling-down-on-open-source-and-phasing-out-defender) and the [Defender Sunset FAQ](https://www.openzeppelin.com/news/defender-sunset-faq):

- **Self-host the open source tools.** "You can self-host the open source versions of Relayer, Monitor, and our upcoming tools to maintain current features in your own environment." [OpenZeppelin Monitor](https://github.com/OpenZeppelin/openzeppelin-monitor) ([docs](https://docs.openzeppelin.com/monitor)) and [OpenZeppelin Relayer](https://github.com/OpenZeppelin/openzeppelin-relayer) ([docs](https://docs.openzeppelin.com/relayer)) are AGPL-3.0. "Instead of a hosted dashboard, you'll use CLI, SDK and API's to interact with the infrastructure instances."
- **Managed service.** "For teams preferring to delegate operational management, we offer customized Managed Service solutions, providing hosted infrastructure as well as deployment, monitoring, and maintenance of your Relayer and Monitor instances." Requests go through [this form](https://www.openzeppelin.com/request).
- **Chainlink CRE.** OpenZeppelin's docs have a guide, [Mapping Your Defender Setup](https://docs.openzeppelin.com/chainlink-cre), for moving Monitors, Actions and Relayers to Chainlink Runtime Environment.
- **Questions:** defender-support@openzeppelin.com, per the FAQ and the CRE guide.

The archived [defender-sdk](https://github.com/OpenZeppelin/defender-sdk) README links a "Defender Migration Guide" at `docs.openzeppelin.com/defender/migration`; on 5 November 2026 that URL redirected to the docs home page.

OpenZeppelin Monitor's docs list conditions on functions, events and transactions with expressions, Email and custom-script notifications, and Stellar, Solana and (partly) Midnight networks. If your monitors depend on any of those, OpenZeppelin Monitor is the closer fit. You can run ownerwatch next to it.

## What ownerwatch covers

- **Admin events, without writing conditions.** Every address in the config gets a fixed catalog: Ownable, AccessControl, OpenZeppelin AccessManager, ERC-1967 proxies and beacons, Pausable, TimelockController, Compound-style timelocks, Governor, Safe, and several protocol-specific sets (Aave, Lido, Sky, Rocket Pool and others). `ownerwatch events` prints it. Each event has a fixed severity: info, medium, high or critical.
- **Your own admin events,** by Solidity signature or by topic0, under `custom_events` (up to 50).
- **Safe queues.** Alerts when a Safe transaction is proposed and when it has enough signatures, read from the Safe Transaction Service.
- **Decoded calls** in timelock, Governor and Safe-queue alerts.
- **Treasury outflows:** ERC-20 transfers out above a threshold, any NFT transfer out, native balance drops.
- **Sinks:** Discord, Slack, Telegram, a generic JSON webhook, a JSONL file, stdout. A heartbeat URL is pinged only after a fully healthy poll, so you hear when the watcher itself stops.
- **Several EVM chains** in one process.
- **A starting config from chain state.** `ownerwatch probe` walks owner, admin, proxy and Safe links from an address and prints a config.

## What ownerwatch does not do

- No conditions on decoded values. Every matching event alerts; `min_severity` is the only filter.
- No function-call or transaction monitoring. ownerwatch reads event logs (plus the Safe service and balances), so an admin change that emits no event is not seen. The [ownerwatch Action](https://github.com/imal1ice/ownerwatch-action) re-probes on a schedule and catches drift in state, but not at the block.
- No automated response. ownerwatch never signs or sends a transaction. `webhook_url` can call a service of your own.
- No alert thresholds, rate windows or deduplication windows. Each event is one alert.
- No custom message templates.
- No email, PagerDuty, Opsgenie or Datadog sinks built in.
- No `safe` or `finalized` confirmation levels; `confirmations` is a block count.
- No non-EVM chains, no hosted dashboard, no relayer, no scheduled jobs.

## Field mapping

Defender Monitor fields as named in OpenZeppelin's [defender-sdk monitor model](https://github.com/OpenZeppelin/defender-sdk/blob/main/packages/monitor/src/models/monitor.ts):

| Defender Monitor | ownerwatch |
|---|---|
| `network` | `rpc_url` and `chain_name`; several chains under `chains:` |
| `addresses` | `contracts:` (each address gets the whole catalog) |
| `abi` | not needed for catalog events; `custom_events` for others |
| `eventConditions` (event signature) | the catalog, or `custom_events` |
| `eventConditions` (expression) | none |
| `functionConditions` | none |
| `txCondition` | none |
| `confirmLevel` | `confirmations` (blocks only) |
| `notificationChannels` | `alerts:` sinks |
| `severityLevel` | fixed per event; `min_severity` decides what reaches the sinks |
| `alertThreshold`, `alertTimeoutMs` | none |
| `alertMessageBody`, `alertMessageSubject` | none; fixed format |
| `actionTrigger`, `actionCondition` | none; `webhook_url` posts each alert as JSON |
| `riskCategory` | none |
| `paused` | stop the process, or remove the address |

## Steps

1. Collect the addresses your admin monitors watched, from wherever you kept the monitor definitions.
2. Generate a config from chain state and compare it with that list. `probe` often finds admins, ProxyAdmins and Safes a hand-written monitor missed.

   ```bash
   pip install ownerwatch
   ownerwatch probe --rpc https://ethereum-rpc.publicnode.com --safe-chain eth --yaml --label MyProtocol 0xYourProxy 0xYourSafe > config.yaml
   ```

3. Add the admin events of your own contracts under `custom_events`, and a sink and `heartbeat_url` under `alerts`.
4. Check it: `ownerwatch validate`, then `ownerwatch test-alert`.
5. Replay a block where you know an admin event happened: `ownerwatch backfill --from-block N --to-block N`. If the alert you expect does not print, the RPC is not returning those logs; use another one.
6. Run it: `ownerwatch run`, `docker compose up -d` from a clone of this repository, or the systemd unit in `deploy/ownerwatch.service`.

## A config to copy

Aave V4's admin surface on Ethereum, from Aave's [address book](https://github.com/aave-dao/aave-address-book) and [permissions book](https://github.com/aave-dao/aave-permissions-book/blob/main/out/ETHEREUM-V4.md): a hub behind a transparent proxy, the ProxyAdmin that upgrades it, the AccessManager that gates its functions, and the Security Council Safe that owns the ProxyAdmin. Replace the addresses with yours.

```yaml
rpc_url: "https://ethereum-rpc.publicnode.com"
chain_name: ethereum
explorer_url: "https://etherscan.io"
confirmations: 2
max_block_range: 1000
state_file: "state/ethereum.json"

contracts:
  - address: "0xCca852Bc40e560adC3b1Cc58CA5b55638ce826c9"
    label: "Aave V4 Core Hub (proxy, AccessManaged)"
  - address: "0x55b71C0aeD3c616162eE7c608c089A1055CEA3Bf"
    label: "Aave V4 Core Hub ProxyAdmin"
  - address: "0x08aE3BE30958cDd1847ec58fFfd4C451a87fDF01"
    label: "Aave V4 AccessManager"
  - address: "0x187AAE17d4931310B3fc75743e7F16Bdc9eD77e9"
    label: "Aave V4 Security Council (Safe)"

safes:
  - address: "0x187AAE17d4931310B3fc75743e7F16Bdc9eD77e9"
    label: "Aave V4 Security Council (Safe)"
    chain: eth

custom_events:
  - event: "RoleGuardianChanged(uint64 indexed roleId, uint64 indexed guardian)"
    severity: high

alerts:
  min_severity: high
  discord_webhook: ""
  slack_webhook: ""
  telegram_bot_token: ""
  telegram_chat_id: ""
  webhook_url: ""          # JSON POST of every alert, for your own handler
  heartbeat_url: ""        # healthchecks.io or similar: silence means the watcher is down
```

What each line catches: [proxy upgrades](https://github.com/imal1ice/ownerwatch/blob/main/docs/monitor-proxy-upgrades.md), [role grants](https://github.com/imal1ice/ownerwatch/blob/main/docs/monitor-role-grants.md), [Safe signers](https://github.com/imal1ice/ownerwatch/blob/main/docs/monitor-safe-signers.md), [timelock schedules](https://github.com/imal1ice/ownerwatch/blob/main/docs/monitor-timelock-queue.md).
