# Publish a verifiable control disclosure in ~10 minutes

An [ERC-8241](erc-8241.md) control disclosure is a small JSON file, committed to your repo, that states who can change your contracts — owners, upgrade admins, roles, Safe signers and thresholds, timelock delays. ownerwatch drafts it from chain state, checks it against the chain at a pinned block, keeps it honest in CI, and (optionally) turns it into a live README badge that reddens the moment your on-chain control drifts from what you disclosed. No backend, nothing sent on-chain — every step is a read.

This is the fast path. For the field-by-field format see [erc-8241.md](erc-8241.md); for the badge alone see [disclosure-badge.md](disclosure-badge.md).

> **One command:** `ownerwatch disclosure init <addresses> --rpc <rpc>` drafts the disclosure, writes the CI workflow below, and prints the badge snippet in one step. Review the drafted JSON, then follow steps 2 and 5. The rest of this page is what that command sets up.

## 1. Draft it from the chain (2 min)

Install and draft a starting disclosure for your contracts:

```sh
pip install ownerwatch
ownerwatch disclosure draft 0xYourContract 0xYourProxyAdmin --rpc "$RPC" --name "YourProtocol" > erc-8241.json
```

`draft` reads each address and writes what it finds: the control graph, roles replayed from logs, Safe signers and thresholds, timelock delays. Pass every contract whose control you want to state.

## 2. Review and edit (3 min)

Open `erc-8241.json`. It is your disclosure, not an oracle: correct any label, drop an address that is out of scope, and add context a reader needs. The goal is a file that says exactly what your control surface is.

## 3. Check it against the chain (1 min)

```sh
ownerwatch disclosure check erc-8241.json --rpc "$RPC"
```

It pins every read to one block and exits non-zero on any mismatch, or on a power the chain shows that your disclosure leaves out. Fix the disclosure (or the contracts) until it passes, then commit `erc-8241.json`.

## 4. Keep it honest in CI (2 min)

Add the [ownerwatch Action](https://github.com/imal1ice/ownerwatch-action) so a drift between your disclosure and the chain fails CI — and, with `badge`, writes a live status badge in the same step:

```yaml
# .github/workflows/control-disclosure.yml
on: { push: { branches: [main] }, schedule: [{ cron: "0 */6 * * *" }] }
jobs:
  disclosure:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: imal1ice/ownerwatch-action@v1
        with:
          disclosure: erc-8241.json
          rpc: ${{ secrets.RPC_URL }}   # any endpoint that serves eth_call
          badge: badge.json
          version: "0.15.0"             # badge needs ownerwatch >= 0.15.0
          fail-on-drift: false          # keep CI green; the badge still reddens on drift
```

The schedule re-checks every few hours, so the badge tracks the chain even between pushes.

## 5. Show the badge (2 min)

Publish `badge.json` at a stable URL — commit it, push it to a GitHub Pages branch, or have a deploy step serve it — then embed it, replacing the URL with yours:

```md
[![control disclosure](https://img.shields.io/endpoint?url=https://YOURORG.github.io/YOURREPO/badge.json)](https://github.com/YOURORG/YOURREPO/blob/main/erc-8241.json)
```

A green badge is a one-glance, chain-checked claim that your control surface is what you say it is. It costs one CI step and a static file.

## Want it done for you?

ownerwatch and the checker are free and MIT-licensed. If you would rather not draft and maintain the disclosure yourself, I draft your ERC-8241 control disclosure from chain state, verify every record against the chain, and wire the check and badge into your CI so it stays honest as the contracts change. Write to imal1ice@proton.me — before anything is paid I share the terms, including where I am based, so you can decide whether you are able to work with me.
