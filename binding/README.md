# Redthread agent passport verifier binding

The relying-party verifier Redthread runs (draft-le-agent-passport-01: passports, delegation receipts, status,
exposure, the before-effect re-check), behind a small HTTP interface. It is meant for other implementations' test
harnesses, such as the IETF 127 AI2II matrix, which had to block every case that needed a Redthread verifier.
Licence: Apache-2.0 (LICENSE).

## Run

    docker build -t redthread-verifier .
    docker run --rm -p 8080:8080 redthread-verifier
    curl -s localhost:8080/v1/info

`/v1/info` returns the version and the source commit the image was built from (`REVISION`).

## Interface

The harness owns the world. Each call sends the clock (`now`) and every document the verifier may fetch, by URL:
issuer metadata, controller documents and status lists (`documents: {"issuer": {url: doc}, "controller": {url: doc},
"status": {url: compact JWS}}`; `null` makes a document unavailable from then on). Nothing is fetched from the network.
A `session` keeps one verifier's state across calls: cached status lists, nonces, limit counters.

    POST /v1/verify  {"session", "now", "value": "high"|"low", "policy", "documents", "request", "transport",
                      "tool", "tool_digest", "spend", "revalidate"}
                     -> {"decision", "reasons", "record", "exposure", "exposure_by_event", "chain"}
    POST /v1/run     the same, plus "between": {"now", "documents"}, applied after authorisation and before the
                     re-check; returns {"effect": "ran"|"none", "lines": [one record per step]}

`request` is `{"method", "authority", "target_uri", "headers": {lowercase name: value}, "body_b64"}`, as the request
arrived. `transport` defaults to HTTPS over TLS 1.3 with no intermediary. `policy` takes the verifier's policy keys,
for example `{"pinned": [build digest], "rp_id": "...", "authorization_servers": ["..."]}`.

## Samples

`samples/P1.json` to `samples/P6.json` hold, for each case, the exact calls and the responses the binding returns,
generated on Redthread's simulated world. Replaying them is a conformance check of a deployed binding:

| Scenario | Cases | Final reason |
|---|---|---|
| P1 status list unreachable | revoked, stale, unavailable | `status-revoked` (logged `revoked`), `status-stale`, `status-unavailable` |
| P2 revocation before effect | revoked between authorisation and effect, no revocation | effect `none`, effect `ran` |
| P3 delegation that widens | narrower child, wider methods, wider host | `ok`, `attenuation:methods`, `attenuation:host` |
| P4 cumulative limit | single accounting RP (2 calls, then a third), two audiences | `limit-exceeded`, `limit-aud-not-single` |
| P5 request rewritten in transit | unchanged, target rewritten, method rewritten | `ok`, `signature-invalid`, `signature-invalid` |
| P6 tool changes between hops | same tool, swapped tool | `ok`, `tool-digest-mismatch` |

These are Redthread's results on a simulated clock and network. A harness's own run of them is the harness's result.
