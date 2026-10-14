# Hosted ownerwatch

For teams that want the alerts without running the container.

## What you get
- The same monitor as the open-source release, run and updated by the maintainer, one process per chain.
- Alerts to your Discord, Telegram or webhook within one poll interval (15 to 30 seconds) of the block.
- A monthly `probe --markdown` report of your admin surface, so drift is caught even when no event fires.

## What it costs
A flat amount of USDC per chain per 30-day period, read from the `Subscriptions` contract (`pricePerPeriod()`), paid on-chain. No invoices, no account, no identity on either side. Cancel by not renewing; the watcher stops when your expiry passes. "12 periods" is 360 days, not a calendar year.

## How to subscribe
1. Read `pricePerPeriod()` and compute `cost = periods * chains * price`.
2. Approve USDC for the Subscriptions contract on Base: `USDC.approve(SUBSCRIPTIONS, cost)`.
3. Call `subscribe(periods, chains, cost, configRef)` from the wallet you want associated with the service. The third argument is the most you agree to pay; if the price changed in between, the call reverts instead of charging more. `configRef` can be `0x0`; it is only a label for the config you send.
4. Send your config YAML (same format as `config.example.yaml`, with your sinks filled in) to the maintainer through a GitHub issue using the "Setup help" template, or by the contact on the GitHub profile. For a private webhook URL, open the issue without it and ask for an encrypted channel.
5. Within one day you receive a `test-alert` on your sink. Alerts start from that block.

The contract address will be published in the README once deployed. Until then, open an issue and the maintainer will set you up on the honor system.

## Operator side
```bash
ownerwatch hosted --rpc https://mainnet.base.org --subscriptions 0x... --configs configs/
```
Drop `configs/<customer-wallet>.yaml` in that directory. The runner checks `isActive` and `chainCount` once a minute, starts or stops watchers accordingly, runs at most the paid number of chains, and reloads a file when it changes.
