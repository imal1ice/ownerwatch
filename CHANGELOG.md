# Changelog

## Unreleased
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
