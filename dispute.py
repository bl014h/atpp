#!/usr/bin/env python3
"""Record a dispute about an ATPP score, and its outcome, in the public signed disputes log.

The charter promises disputes are logged. Each record is a DSSE envelope signed with the scan key and
committed to github.com/bl014h/atpp under disputes/, so the history of what was disputed and what changed
can be checked by anyone (`atpp disputes`) and cannot be quietly edited.

  dispute.py open  --server ns/name --check static-secrets --by "publisher" --claim "why the check is wrong"
  dispute.py close --id 2026-0001 --outcome upheld|rejected|rule-changed --summary "what we did and why"

Records are written to tools/atpp/public/disputes/<id>.dsse.json (mirrored by sync-public.sh). Closing
appends a second, signed record for the same id; nothing is overwritten.
"""
import argparse, glob, json, os, sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import atpp  # noqa: E402

DIR = os.path.join(HERE, "public", "disputes")
DISPUTE_TYPE = atpp.DISPUTE_TYPE
KEY = os.environ.get("ATPP_SIGNING_KEY", os.path.expanduser("~/.secrets/atpp-scan-ed25519.pem"))
KID = "atpp-scan-2026-10"


def _write(body, suffix):
    os.makedirs(DIR, exist_ok=True)
    path = os.path.join(DIR, f"{body['id']}{suffix}.dsse.json")
    if os.path.exists(path):
        sys.exit(f"{path} exists; records are append-only")
    env = atpp.sign(DISPUTE_TYPE, body, atpp.load_private_key(KEY), KID)
    open(path, "w").write(json.dumps(env, indent=1) + "\n")
    print(f"wrote {os.path.relpath(path)}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("open"); o.add_argument("--server", required=True); o.add_argument("--check", required=True)
    o.add_argument("--by", required=True); o.add_argument("--claim", required=True)
    c = sub.add_parser("close"); c.add_argument("--id", required=True)
    c.add_argument("--outcome", required=True, choices=["upheld", "rejected", "rule-changed"]); c.add_argument("--summary", required=True)
    a = ap.parse_args()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if a.cmd == "open":
        n = len([p for p in glob.glob(os.path.join(DIR, f"{today[:4]}-*.dsse.json")) if "-closed" not in p]) + 1
        _write({"_type": "https://millenniums.ai/atpp/dispute/v1", "id": f"{today[:4]}-{n:04d}", "event": "opened",
                "date": today, "server": a.server, "check": a.check, "raised_by": a.by, "claim": a.claim}, "")
    else:
        _write({"_type": "https://millenniums.ai/atpp/dispute/v1", "id": a.id, "event": "closed", "date": today,
                "outcome": a.outcome, "summary": a.summary}, "-closed")


if __name__ == "__main__":
    main()
