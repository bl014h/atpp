# Disputes

Every disputed ATPP score and its outcome, as signed records (`<id>.dsse.json` when opened,
`<id>-closed.dsse.json` when decided). Records are append-only: a decision is a new signed record, never an
edit. Check them with `python3 atpp.py disputes [namespace/server]`.

To dispute a score: security@millenniums.ai or trust@millenniums.ai with the server name, the check, and why
it is wrong. Paying changes nothing about a score or a dispute.
