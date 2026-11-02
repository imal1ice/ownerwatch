# Safe 1.4.1 indexes its events, and older decoders go quiet

Safe 1.4.1 and 1.5.0 mark the first argument of these events as `indexed`. Safe 1.3.0 leaves it in the data:

`AddedOwner`, `RemovedOwner`, `EnabledModule`, `DisabledModule`, `ChangedGuard`, `ChangedFallbackHandler`, `ExecutionSuccess`, `ExecutionFailure`

`indexed` is not part of an event's signature, so topic0 is the same in both versions. A monitor that filters on topic0 still receives the log. Then it decodes with the older ABI, the decode fails, and the signer change is gone. Nothing errors unless the decoder logs its failures. The same thing happens with `Upgraded(address)` on early proxies such as USDC's, which keep the implementation in the data rather than in a topic.

## What it cost

ownerwatch made this mistake until 0.11.0. Its public [admin feed](https://imal1ice.github.io/admin-feed/) watches seven Safes on 1.4.1 on Ethereum, and on 30 October 2026 one of them, Lido's Reseal committee, [replaced a signer](https://etherscan.io/tx/0x55a55d9ed600f6bc8e6af298a8c9ca2483ae0df54b7cc37138d35d61124f3d4c). The feed showed nothing. An audit of the watcher found the bug with Safe's real bytecode on a local chain, and rescanning the 90-day window with the fix brought the event back.

## How to check your own monitor

- Run a real 1.4.1 Safe on a local chain, add an owner, and see whether an alert arrives. A synthetic log built from your own ABI proves nothing here.
- Treat a log whose topic you know but cannot decode as an alert, not a warning. That turns this whole class of bug into a noisy message with the raw topics and data.
- Rescan history after any change to a decoder, and compare with what you already published.
