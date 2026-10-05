# atpp — check an ATPP badge claim without trusting Millenniums.AI

Any README badge is an image fetched from somebody's server, and the picture can show whatever that
server decides. So an **ATPP** (Agentic Trust & Protection Platform) claim does not live in the image.
It lives in a signed file:

- an [in-toto Statement v1](https://github.com/in-toto/attestation) in a
  [DSSE envelope](https://github.com/secure-systems-lab/dsse), signed with **Ed25519**;
- bound to the **sha256 of the exact MCP registry manifest** that was scanned, which you can re-hash
  yourself from `registry.modelcontextprotocol.io`;
- signed on our scan host. The servers behind `trust.millenniums.ai` hold only the public key, so a
  compromised web server, DNS record or deploy cannot mint a claim that verifies.

A level-1 claim is a **static scan of a published manifest** ("passed N of M published checks on
DATE"). It is not a runtime claim and says nothing about what a server does once installed.

## Verify

```bash
pip install cryptography
curl -sO https://raw.githubusercontent.com/bl014h/atpp/main/atpp.py
python3 atpp.py verify io.github.example/server      # the current claim for a registry listing
python3 atpp.py verify path/to/a/repo                # a repo with a pinned .atpp/ folder
python3 atpp.py verify path/to/a/repo --offline      # signature, badge and expiry only
```

It checks, in order:

1. the signature against the key pinned inside `atpp.py`, and that the key is not revoked;
2. that the registry manifest still hashes to what was scanned;
3. for a repo: that the claim belongs to **this** repository (the server's registry listing must declare
   this repo's GitHub remote), so `.atpp/` files copied from another server fail;
4. that a committed `.atpp/badge.svg` is byte-for-byte the badge whose hash was signed;
5. that the claim is in the latest daily manifest, that the manifest matches the hash committed to
   [`log/`](log/) here, and that the day is anchored in the Sigstore Rekor transparency log, so a
   compromised server cannot replay an older, better-scoring claim;
6. the expiry.

Options: `--offline` (1, 4 and 6 only) · `--no-log` · `--expect <namespace>/<server>`.

Exit codes: `0` valid and current · `1` invalid · `2` valid but expired · `3` could not check.

## Let your agent check before it installs (MCP)

`atpp_mcp.py` is an MCP server (stdio, only needs `cryptography`) that gives an agent two tools:
`verify_mcp_server` (the current signed claim for a registry listing) and `verify_repo_atpp` (a repo's pinned
`.atpp/` files). They run the same checks as `atpp.py verify` and return a verdict: `valid`, `expired`,
`invalid`, `no_signed_claim` or `could_not_check`.

```json
{"mcpServers": {"atpp": {"command": "python3", "args": ["/path/to/atpp_mcp.py"]}}}
```

A valid result means "this exact registry manifest passed N of M published static checks on DATE", never
"safe". Text a server's publisher controls comes back only as `detail_untrusted`, with control characters
stripped and length capped, and nothing from a rejected claim is echoed.

## Pinned badges (the default)

```bash
python3 atpp.py badge io.github.example/server .     # verifies first, then writes .atpp/
```

writes `.atpp/badge.svg` and `.atpp/attestation.dsse.json` and prints the README line. Commit both.
Your README then renders with no request to us, every change is a commit you review, and the badge
states its version and date, so at worst it is old and says how old. A live badge
(`https://trust.millenniums.ai/badge/mcp/<namespace>/<server>.svg`) is available if you prefer one
that follows each re-scan; on GitHub it lags by about 10 minutes because of the image cache.

## Runtime agents (levels 2/3)

```bash
python3 atpp.py verify-runtime <tenant>/<agent> --pin .atpp/workspace-key.json
```

A runtime claim is signed by the workspace's key, which our app serves. The first run pins that key in the
file you name (commit it); any later run fails if the served key differs, so a compromised server cannot
swap the key to vouch for an agent. Exit `1` if the agent is revoked, `2` if there is no current claim.

## Disputes

```bash
python3 atpp.py disputes [<namespace>/<server>]
```

Every disputed score and its outcome is a signed, append-only record in [`disputes/`](disputes/).

## Keep it current in CI

```yaml
# .github/workflows/atpp.yml — refresh the pinned badge weekly; the PR is yours to review
on: { schedule: [{ cron: "0 6 * * 1" }], workflow_dispatch: {} }
permissions: { contents: write, pull-requests: write }
jobs:
  atpp:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
      - uses: bl014h/atpp@<commit-sha>        # pin by SHA: a tag can be moved, which is the problem badges have
        with: { server: io.github.you/your-server }        # mode: verify fails the job instead
```

The action uses no third-party actions and passes inputs through environment variables only.

## Watched from outside

- [`canary`](https://github.com/bl014h/atpp/actions/workflows/canary.yml), hourly: live badges are
  well-formed plain SVG, print exactly the signed claim, verify end to end, carry security headers; a signed
  publish landed within the last day; the camo-proxied copies GitHub readers see are safe.
- [`redteam`](https://github.com/bl014h/atpp/actions/workflows/redteam.yml), daily: replays the README-badge
  proof of concept and every attack we know against production. See [`redteam/`](redteam/).

## Keys

Trust is pinned to one **offline root key**. It signs nothing but the scan-key list
([`atpp-keylist.dsse.json`](atpp-keylist.dsse.json)): which scan keys are valid, for which dates, and which
are revoked, with a serial number. `atpp.py` embeds a root-signed copy and pins only the root, so a scan key
can be rotated or revoked without anyone updating the script; an older list (lower serial) is refused.

| role | keyid | Ed25519 public key | sha256 fingerprint | valid |
|---|---|---|---|---|
| root (offline) | `atpp-root-2026` | `s/lMHiubuPh/z/YWGNcxkvqL+o7KcY0WFdKWq3s7Nuc=` | `f5ba2588c2767bb8` | — |
| scan | `atpp-scan-2026-10` | `20P9I6y6X6mQztS3IJTU/4CNaqg/FjcpouXkPsrCyVo=` | `a210db7bf7f8b382` | 2026-10-05 → 2027-10-05 |

A claim signed by a scan key outside its validity window fails. The unsigned
`https://trust.millenniums.ai/.well-known/atpp-keys.json` mirrors this for humans and can only revoke.

## Log

Every day the scanner signs a manifest listing the sha256 of every envelope it issued, commits that
manifest's sha256 to [`log/`](log/) (`log/latest.json` and `log/<date>.json`), and records a signed anchor of
it in [Sigstore Rekor](https://search.sigstore.dev/), a public transparency log nobody here controls. The
manifest itself is served at `https://trust.millenniums.ai/v/log/<date>.json`. A swapped, backdated or
rolled-back claim will not match a manifest whose hash is already in this repo's history and in Rekor.

## Report a problem

security@millenniums.ai · [disclosure policy](https://trust.millenniums.ai/security)
