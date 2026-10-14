# Hosted ownerwatch

For teams that want the alerts without running the container.

## What you get
- The same monitor as the open-source release, run and updated by the maintainer, one process per chain.
- Alerts to your Discord, Telegram or webhook within one poll interval (15 to 30 seconds) of the block.
- A monthly `probe --markdown` report of your admin surface, so drift is caught even when no event fires.

## What it costs
A flat amount of USDC per chain per month, set in the `Subscriptions` contract (`pricePerMonth()`), paid on-chain. No invoices, no account, no identity on either side. Cancel by not renewing; the watcher stops when your expiry passes.

## How to subscribe
1. Approve USDC for the Subscriptions contract on Base: `USDC.approve(SUBSCRIPTIONS, months * pricePerMonth)`.
2. Call `subscribe(months, configRef)` from the wallet you want associated with the service. `configRef` can be `0x0`; it is only a hash you choose to label your config.
3. Send your config YAML (same format as `config.example.yaml`, with your sinks filled in) to the maintainer through a GitHub issue using the "Setup help" template, or by the contact on the GitHub profile. For a private webhook URL, open the issue without it and ask for an encrypted channel.
4. Within one day you receive a `test-alert` on your sink. Alerts start from that block.

The contract address will be published in the README once deployed. Until then, open an issue and the maintainer will set you up on the honor system.

## Operator side
```bash
ownerwatch hosted --rpc https://mainnet.base.org --subscriptions 0x... --configs configs/
```
Drop `configs/<customer-wallet>.yaml` in that directory. The runner checks `isActive` once a minute, starts or stops watchers accordingly, and reloads a file when it changes.
