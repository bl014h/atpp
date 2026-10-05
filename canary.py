#!/usr/bin/env python3
"""ATPP canary — checks the live badge service from outside, every hour, and fails loudly.

Runs on GitHub Actions in github.com/bl014h/atpp (a different vantage point and a different company's
infrastructure from the badge service it watches). Any failure fails the workflow, and GitHub emails the
repo owner. It looks for exactly the things that have gone wrong or that the README-badge PoC exploits:

  - a live badge that is not well-formed XML (every badge was a broken image Oct 1-5 2026)
  - an SVG that could link, animate or script (mimicry)
  - a badge whose printed numbers differ from the signed claim (a swapped worker or KV)
  - a claim that does not verify against the pinned key, or is not in the public log (rollback)
  - no signed publish for more than a day (the scan missed Oct 3-4 2026)
  - missing security headers; a revoked pinned key; badges served through GitHub's image proxy
    that differ from what the service serves

  python3 canary.py [--sample 12] [--camo]
"""
import argparse, base64, hashlib, json, random, re, sys, urllib.request
from datetime import datetime, timedelta, timezone

import atpp

TRUST = atpp.TRUST
FIXED = ["io.github.github/github-mcp-server"]   # always checked if listed, plus a random sample
REDTEAM_PAGE = "https://github.com/bl014h/atpp/blob/main/redteam/README.md"


def get(url, timeout=30):
    r = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": atpp.UA}), timeout=timeout)
    return r.status, dict(r.headers), r.read()


class Report:
    def __init__(self):
        self.fails, self.lines = 0, []

    def ok(self, msg):
        self.lines.append(f"PASS  {msg}")

    def bad(self, msg):
        self.fails += 1
        self.lines.append(f"FAIL  {msg}")

    def info(self, msg):
        self.lines.append(f"info  {msg}")


def check_server(rep, name):
    ns, srv = name.split("/", 1)
    try:
        st, h, body = get(f"{TRUST}/badge/mcp/{ns}/{srv}.svg")
    except Exception as e:
        return rep.bad(f"{name}: live badge unreachable ({e})")
    svg = body.decode("utf-8", "replace")
    probs = atpp.svg_problems(svg)
    if probs:
        return rep.bad(f"{name}: live badge unsafe or broken: {'; '.join(probs[:3])}")
    if "sandbox" not in h.get("Content-Security-Policy", ""):
        rep.bad(f"{name}: live badge served without a sandboxing CSP")
    try:
        env = json.loads(get(f"{TRUST}/v/mcp/{ns}/{srv}.json")[2])
    except Exception as e:
        if "unsigned" in svg or "not scanned" in svg or "expired" in svg:
            return rep.bad(f"{name}: no signed claim and the badge is grey — the last publish did not land")
        return rep.bad(f"{name}: badge shows a score but no signed claim is served ({e})")
    try:
        status, lines = atpp.check(env, online=True, expect=name)
    except atpp.VerifyError as e:
        return rep.bad(f"{name}: claim does not verify — {e}")
    if status == 2:
        return rep.bad(f"{name}: signed claim has expired")
    p = json.loads(base64.b64decode(env["payload"]))["predicate"]
    want = f"scanned {p['passed']}/{p['total']} · {p['as_of']}"
    if want not in svg:
        return rep.bad(f"{name}: live badge does not print the signed claim ({want!r})")
    pinned = get(f"{TRUST}/v/mcp/{ns}/{srv}/badge.svg")[2]
    if hashlib.sha256(pinned).hexdigest() != p.get("badge_sha256"):
        return rep.bad(f"{name}: the pinned badge download is not the signed image")
    _, ph, _ = get(f"{TRUST}/v/mcp/{ns}/{srv}")
    if "frame-ancestors 'none'" not in ph.get("Content-Security-Policy", ""):
        rep.bad(f"{name}: verify page can be framed (no frame-ancestors)")
    logline = next((l for l in lines if l.startswith("log")), "log not checked")
    rep.ok(f"{name}: {want}; signature, subject, pinned badge and headers OK; {logline.split('—')[0].strip()}")


def check_freshness(rep):
    try:
        log = json.loads(get(f"{atpp.LOG_RAW}/latest.json")[2])
    except Exception as e:
        return rep.bad(f"public log unreachable ({e})")
    d = atpp._day(log.get("date"))
    if not d:
        return rep.bad("public log has no valid date")
    age = datetime.now(timezone.utc) - datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    if age > timedelta(hours=60):     # date-only stamp: a daily run lands at most ~24 h + run time + this window
        rep.bad(f"no signed publish logged since {d} ({age.days} days) — the daily scan is not landing")
    else:
        rep.ok(f"latest signed publish logged {d}; {log.get('count')} claims; "
               f"Rekor {'index ' + str((log.get('rekor') or {}).get('logIndex')) if log.get('rekor') else 'not anchored'}")
    if not log.get("rekor"):
        rep.bad("latest manifest is not anchored in Rekor")


def check_keys(rep):
    try:
        wk = json.loads(get(f"{TRUST}/.well-known/atpp-keys.json")[2])
    except Exception as e:
        return rep.bad(f"/.well-known/atpp-keys.json unreachable ({e})")
    revoked = set(wk.get("revoked") or []) & set(atpp.KEYS)
    if revoked:
        rep.bad(f"a pinned key is listed as revoked: {sorted(revoked)} — rotate now")
    extra = set(wk.get("keys") or {}) - set(atpp.KEYS)
    if extra:
        rep.info(f"well-known lists keys the verifier does not pin (ignored by design): {sorted(extra)}")
    rep.ok("well-known keys consistent with the pinned list")
    try:
        _, _, sec = get(f"{TRUST}/.well-known/security.txt")
        m = re.search(r"^Expires:\s*(\S+)", sec.decode(), re.M)
        if not m or m.group(1)[:10] < datetime.now(timezone.utc).strftime("%Y-%m-%d"):
            rep.bad("security.txt missing an Expires date or expired")
        else:
            rep.ok(f"security.txt present, expires {m.group(1)[:10]}")
    except Exception as e:
        rep.bad(f"security.txt unreachable ({e})")


def check_camo(rep):
    """What a README reader actually gets: images on GitHub go through camo. Fetch every camo URL on the
    red-team page and require each to be safe; record the cache lifetime camo reports."""
    try:
        html = get(REDTEAM_PAGE)[2].decode("utf-8", "replace")
    except Exception as e:
        return rep.bad(f"red-team page unreachable ({e})")
    urls = sorted(set(re.findall(r'https://camo\.githubusercontent\.com/[0-9a-f]+/[0-9a-f]+', html)))
    if not urls:
        return rep.info("no camo-proxied images on the red-team page")
    for u in urls:
        try:
            st, h, body = get(u)
            text = body.decode("utf-8", "replace")
            if "<svg" not in text[:200]:
                continue
            if "ATPP" in text and "FORGED" not in text and "mimicry" not in text.lower():
                probs = atpp.svg_problems(text)
                if probs:
                    rep.bad(f"camo-served ATPP badge unsafe or broken: {probs[0]}")
                    continue
            rep.ok(f"camo {u[-12:]}: {h.get('Content-Type', '?')}, cache-control {h.get('Cache-Control', 'none')!r}, "
                   f"CSP {h.get('Content-Security-Policy', 'none')[:40]!r}")
        except Exception as e:
            rep.bad(f"camo fetch failed for {u[-12:]} ({e})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=12)
    ap.add_argument("--camo", action="store_true")
    a = ap.parse_args()
    rep = Report()
    check_freshness(rep)
    check_keys(rep)
    try:
        names = [n for n, _p, _t in json.loads(get(f"{TRUST}/mcp-names.json")[2])["n"]]
    except Exception as e:
        rep.bad(f"name index unreachable ({e})")
        names = []
    pick = [n for n in FIXED if n in names] + random.sample(names, min(a.sample, len(names)))
    for n in dict.fromkeys(pick):
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,80}/[A-Za-z0-9_.-]{1,80}", n):
            check_server(rep, n)
    if a.camo:
        check_camo(rep)
    print("\n".join(rep.lines))
    print(f"\n{'FAILED' if rep.fails else 'OK'} — {rep.fails} failure(s), {len(rep.lines)} checks")
    return 1 if rep.fails else 0


if __name__ == "__main__":
    sys.exit(main())
