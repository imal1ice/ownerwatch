# Changelog

## Unreleased
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
