# MCP registry scanner (`mcp_scan.py`)

The reference scanner behind Redthread's daily signed scan of the official
[Model Context Protocol registry](https://registry.modelcontextprotocol.io). It scores every
server from its **published manifest** and emits a per-server result plus an aggregate report.

It is deliberately small and auditable. This is the open methodology behind the signed scan at
[trust.redthreadsec.com](https://trust.redthreadsec.com); the signing keys, which turn a local
score into a dated, transparency-logged attestation, are the only part that is not open (see
[Signing & the daily service](#signing--the-daily-service)).

## What it does, and does not

- **Static. Manifest-only.** Every check is decided from the publisher's own `server.json`.
  Nothing is fetched from the server and **no server code is fetched or executed** — which is what
  makes a result safe to print on a badge: *"passed N of M checks on `<date>`"*, never a runtime
  safety claim.
- It is a **cheap, shared hint**, never a verdict. A clean score is not "this server is safe." A
  client must still pin and re-consent against its own exact target and live tool contract (see
  [registry#1706](https://github.com/modelcontextprotocol/registry/issues/1706) and
  [`research/listing-swap/fixtures`](research/listing-swap/fixtures)).

## Run it

Python 3.9+. The local scan needs only the standard library; `cryptography` is required only if you
sign (operator path).

```bash
# score the whole registry and write results locally — no credentials needed
python3 mcp_scan.py --out out

# re-run against a saved registry dump instead of refetching
python3 mcp_scan.py --out out --cache out/registry-dump.json
```

Outputs under `--out`:

| file | contents |
|------|----------|
| `scores.json` | one record per server: which checks passed/failed, with a one-line reason each |
| `aggregate.json` | the recurring public report (the same shape served at `/mcp-scan.json`): totals, per-check pass/fail, drift counts, listing swaps, source-sharing concentration, exemplars |
| `state.json` | per-server manifest hash — the drift baseline; keep it between runs so the next run can tell what changed |

## The checks

Each check applies only when the manifest carries the field it inspects; checks that cannot apply
are dropped from a server's total, so a remote-only server is never marked down for having no
package to pin.

| check | fails when |
|-------|------------|
| `static-secrets` | the server authenticates with a long-lived secret (env var / header marked `isSecret`) — not scoped or rotatable per action |
| `secret-no-default` | a declared secret ships a default value |
| `transport-tls` | a remote endpoint is not `https://` |
| `version-pinned` | a package version is missing, `latest`, or a range |
| `source-published` | no `repository` is declared — the code cannot be reviewed |
| `artifact-hash` | an MCPB package publishes no `fileSha256` |
| `oci-digest` | a container image is referenced by a movable tag rather than an immutable `@sha256:` digest |
| `artifact-resolves` | a named package/version does not resolve on its registry (npm/PyPI/OCI) |
| `build-provenance` | a package's Sigstore build record names a different repository than the listing declares |
| `target-stable` | the remote domain or package owner now differs from the first published version (a *listing swap*) |
| `unchanged-since-last-scan` | the manifest changed since the previous scan (exists from the second scan on) — the one that means "re-review your approval" |

### Rules version

This snapshot is **`atf-5`**. The live service currently runs **`atf-6`**, which adds
tool-definition drift detection (a server that changed a tool's schema or annotations, or added a
write-capable tool, without a version bump). That addition is tracked in the project CHANGELOG and
will land here; the scoring above is otherwise identical. `rules_version` is written into every
aggregate so a consumer always knows which rule set produced a number.

## How a listing swap is detected

For each server the scanner keeps the **newest** version (by `updatedAt`) and the **first**
(earliest `publishedAt`). `target-stable` compares the newest against the first:

- remote URLs compare origin, port, path, and query **keys** — never query **values**;
- packages compare owner identity; a new `version` under the same owner is a routine change, not a
  target change.

Most swaps are legitimate (a rebrand, a hosting move, a handover), but a takeover looks identical —
which is the entire point of surfacing the change rather than judging it.

## Signing & the daily service

The local scan above is complete and needs no credentials. Redthread additionally runs it daily and
publishes each score as a signed [in-toto](https://in-toto.io)/DSSE attestation whose subject is the
sha256 of the scanned manifest, co-signed via Sigstore keyless and anchored in Rekor; the public
verifier is [`atpp.py`](atpp.py) in this repo, and the daily manifests live under [`log/`](log).

The `--publish` / `--sign` flags in `mcp_scan.py` are that operator path: they push scores to an edge
KV store (via `wrangler`) and sign with an Ed25519 key loaded from `ATPP_SIGNING_KEY`. A third party
cannot — and does not need to — reproduce the *signature*; the value of the signed service is the
dated, logged claim, which is Redthread's to make. Anyone can reproduce the **score** with the local
run above and check ours with the verifier.

## License

Apache-2.0. Copyright 2026 Redthread Security Inc. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
