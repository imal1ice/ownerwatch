# Buy a one-time control-surface review (on-chain, no account)

## Before you pay

I am an independent developer based in a sanctioned jurisdiction (a comprehensively sanctioned US/EU/UK/UN regime). I state this up front so you can make your own compliance decision **before** paying. If your organisation cannot pay a resident of such a jurisdiction, please don't buy — the tool itself is free and MIT-licensed, and you can run it yourself.

## What you get

A written control-surface review of one EVM deployment: every owner, proxy and upgrade admin, role holder and Safe signer in the control graph, replayed from logs; each privileged power proven by an `eth_call` simulation at a pinned block; the findings, the fixes, and a ready-to-run ownerwatch monitoring config. It is the deliverable described in [docs/review-template.md](review-template.md), on the contract you choose. Delivered within 48 hours of payment. A clean result (nothing centralised found) is a valid outcome and is delivered as such.

## Price

**$400 in USDC, one-time and flat.** No subscription, no invoice.

## How to buy

The purchase is a single on-chain call — no account to pay. On **Base**:

1. Approve the fee: `USDC.approve(<ReviewPurchases address>, 400000000)` (400 USDC, 6 decimals).
2. Call `buy(target, chainId, maxCost, ref)`:
   - `target` — the contract you want reviewed
   - `chainId` — its chain
   - `maxCost` — `400000000` (protects you if the price changes before your tx is mined)
   - `ref` — optional `bytes32`: a label you choose (e.g. a hash of your contact), or `0x0` and email imal1ice@proton.me with your transaction hash.
3. The call emits `ReviewPurchased(you, target, chainId, 400000000, ref)`. I watch for it, review `target` on `chainId`, and deliver within 48 hours to the contact you give.

No KYC, no screening — you pay on-chain and I deliver. The contract holds the fee until I withdraw it; there is no on-chain refund, which is why the jurisdiction note above matters: read it before you pay.

## The contract

[`contracts/src/ReviewPurchases.sol`](https://github.com/imal1ice/ownerwatch/blob/main/contracts/src/ReviewPurchases.sol) (MIT): a flat fee in USDC, owner-only withdraw, two-step ownership, tolerant of USDT-style tokens, and it rejects fee-on-transfer tokens (the full fee must arrive). It holds no logic beyond collecting the fee and emitting the order. Deployed address: _to be filled in on deployment_.
