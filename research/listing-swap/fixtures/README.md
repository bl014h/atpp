# Target-drift matched-pair fixtures

Sanitized, fully synthetic `server.json` A/B pairs for the target-drift signal discussed in
[modelcontextprotocol/registry#1706](https://github.com/modelcontextprotocol/registry/issues/1706).
No real publishers, no token-bearing URLs, no real tool arguments — registry-schema-shaped only.

Each case directory holds:
- `a.server.json` — the earlier version (by `publishedAt`). Absent in the UNKNOWN case.
- `b.server.json` — the current version.
- `expected.json` — the `targetDrift` signal the **Registry** should emit (server.json-derivable only), and the action a **client** must take.

A registry reference diff and a client gate (e.g. the matched-pair suite in
[peach420fuzz/objekts-production-desk](https://github.com/peach420fuzz/objekts-production-desk)) should
consume the same pairs; mismatches become reproducible cases.

## The through-line

The registry signal is **necessary, not sufficient.** It is a cheap shared hint that lets a client skip
re-diffing history. It never replaces the client re-pinning against its own exact target and its live
`tools/list`. A `false` from the registry must never suppress client re-consent, and a missing signal is
`UNKNOWN`, never "unchanged."

## Cases

| # | Case | Registry sees | Client action | Point |
|---|------|---------------|---------------|-------|
| 01 | query-key-set-change | `remotesChanged: true` | re-consent | Registry can report query **keys** (not values) safely. |
| 02 | query-value-rotation | `remotesChanged: false` | **re-consent** | Same key, new value. Registry sees nothing; pinned target still changed. The invariant case. |
| 03 | same-scope-package-rename | `packageOwnersChanged: false` (+ identifier change) | re-consent | Owner scope unchanged, installed identity changed. |
| 04 | non-semver-ordering | `remotesChanged: true` | re-consent | "Previous" resolved by `publishedAt`, not the text version sort. |
| 05 | tools-only-drift | all `false` | re-consent | Target byte-identical; tool contract changed — only the client (via `tools/list`) can see it. |
| 06 | unknown-no-baseline | `UNKNOWN` (absent) | ask | No parseable prior version. Absent ≠ unchanged; never auto-pass. |
| 07 | version-ordering-record | `remotesChanged: true` (by `publishedAt`) | re-consent | A 3-version history where a naive version-string sort picks the wrong current+previous and **silently passes**, while `publishedAt` ordering catches the real origin change. |

### Case 05 — executable `tools/list` arrays

Case 05's drift lives only in `tools/list`, so the pair ships client-side arrays alongside the server.json:
- `05-tools-only-drift/a.tools.json` / `b.tools.json` — the `result.tools` arrays a client observes (A = baseline, B = current).
- `05-tools-only-drift/tools.expected.json` — the tool delta a client must act on: `send_email` added (write/destructive) and `read_doc`'s `readOnlyHint` flipped `true → false` under the same name and `inputSchema`. The registry cannot see any of it.

### Case 07 — version-ordering record

- `07-version-ordering-record/versions.json` — a synthetic `GET /servers/{name}/versions` record for one server, listed in **descending version-string order on purpose** to bait a text/semver-sort consumer. Current is the latest `publishedAt`, not the highest version string.
- `07-version-ordering-record/expected.json` — correct resolution by `publishedAt` (`remotesChanged: true`) vs the naive version-desc trap (`remotesChanged: false`, a dangerous silent pass). The divergence is the test.

## Comparison policy encoded here

- `comparedTo.previousPublished` and `comparedTo.first` are resolved by `publishedAt`
  (`GET /servers/{id}/versions` is ordered by publication date; `publishedAt` is a first-class field),
  not by the text version sort the list endpoint uses.
- Remote URLs compare origin, port, path, and query **keys** — never query **values**.
- Packages compare owner scope (`packageOwnersChanged`) and identifier; a new `version` under the same
  identifier is a routine version change, not a target change.
