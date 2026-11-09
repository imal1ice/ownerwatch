# A "control disclosure" status badge (self-serve, no backend)

> New to disclosures? The [10-minute quickstart](disclosure-quickstart.md) wires the badge in at the end of the whole flow (draft → check → CI → badge). This page is the badge itself in detail.

If you publish an [ERC-8241](erc-8241.md) control disclosure, you can show a live **status badge** in your README that turns red the moment your on-chain control stops matching what you disclosed. It is rendered by [shields.io](https://shields.io/badges/endpoint-badge) from a small JSON file you host yourself — ownerwatch and shields do the work; there is no service to sign up for and nothing of yours leaves your infrastructure.

![control disclosure: verified](https://img.shields.io/badge/control%20disclosure-verified-brightgreen) ![control disclosure: 2 issues](https://img.shields.io/badge/control%20disclosure-2%20issues-red)

## How it works

`ownerwatch disclosure check` already exits non-zero on any mismatch or undisclosed power and, with `--json`, prints a summary:

```json
{ "summary": { "ok": 9, "mismatch": 0, "unverifiable": 1, "undisclosed": 0 }, "...": "..." }
```

A disclosure is **verified** when `mismatch` and `undisclosed` are both `0`. Map that to a [shields.io endpoint](https://shields.io/badges/endpoint-badge) object and publish it; shields reads it and draws the badge.

## One CI step

Run this wherever you already run the checker (the same job that keeps your disclosure honest in CI). The `--badge` flag writes the shields.io JSON for you:

```sh
ownerwatch disclosure check disclosure.json --rpc "$RPC" --badge badge.json || true
```

That writes `badge.json` (`control disclosure: verified`, or `N issues` in red) regardless of the check's exit code, so the badge always reflects the latest run. On a release without `--badge` yet, map it yourself from `--json`:

```sh
ownerwatch disclosure check disclosure.json --rpc "$RPC" --json > check.json || true
python - <<'PY'
import json
s = json.load(open("check.json"))["summary"]
bad = s["mismatch"] + s["undisclosed"]
json.dump({"schemaVersion": 1, "label": "control disclosure",
    "message": "verified" if bad == 0 else f"{bad} issue{'s' if bad != 1 else ''}",
    "color": "brightgreen" if bad == 0 else "red"}, open("badge.json", "w"))
PY
```

Publish `badge.json` at a stable URL — GitHub Pages, a raw file on a branch, or a gist. Then embed, replacing the URL with yours:

```md
[![control disclosure](https://img.shields.io/endpoint?url=https://YOURORG.github.io/YOURREPO/badge.json)](https://github.com/imal1ice/ownerwatch)
```

Re-run the step on a schedule (or on every deploy). The badge flips to a red "N issues" the moment your owners, admins, roles, thresholds or timelocks drift from the disclosure — so your README never quietly over-claims.

## Why bother

A green badge is a credible, one-glance signal that your control surface is what you say it is, checked against the chain rather than asserted. It costs you one CI step and a static file.

## Work with me

ownerwatch and the checker are free and MIT-licensed. If you would rather not draft and maintain the disclosure yourself, I draft your ERC-8241 control disclosure from chain state, verify every record against the chain, and wire the check (and this badge) into your CI so it stays honest as the contracts change. Write to imal1ice@proton.me — before anything is paid I share the terms, including where I am based, so you can decide whether you are able to work with me.
