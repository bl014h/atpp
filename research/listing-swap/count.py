#!/usr/bin/env python3
"""Count "listing swaps" in the official MCP registry: servers whose current version points at a different
remote-endpoint domain or package owner than the first version published under the same name.

Reads only public registry data and prints aggregate counts. It never prints a list of servers: the point is
the size of the gap, not any one publisher. Most swaps are probably legitimate (a rebrand, moved hosting, a
package handed to a new maintainer). The risk is that nothing in a client asks again when it happens.

    python3 count.py                        # fetch the registry (about 1,400 pages; be patient)
    python3 count.py --cache registry.json  # reuse a saved dump (the list of entries the API returns)
"""
import argparse, collections, json, re, sys, time, urllib.parse, urllib.request

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"


def fetch():
    out, cursor = [], None
    while True:
        q = {"limit": 100, **({"cursor": cursor} if cursor else {})}
        req = urllib.request.Request(REGISTRY + "?" + urllib.parse.urlencode(q),
                                     headers={"User-Agent": "atpp-listing-swap/1 (+https://github.com/bl014h/atpp)"})
        for i in range(6):
            try:
                d = json.load(urllib.request.urlopen(req, timeout=60))
                break
            except Exception:
                time.sleep(3 * (i + 1))
        else:
            sys.exit("registry fetch failed")
        out += d.get("servers", [])
        cursor = (d.get("metadata") or {}).get("nextCursor")
        if not cursor:
            return out
        time.sleep(0.15)


def domain(url):
    host = (urllib.parse.urlparse(url or "").hostname or "").lower()
    p = host.split(".")
    if len(p) >= 3 and len(p[-1]) == 2 and len(p[-2]) <= 3:
        return ".".join(p[-3:])
    return ".".join(p[-2:]) if host else None


def pkg_owner(pk):
    i, t = (pk.get("identifier") or "").lower(), pk.get("registryType")
    if t == "npm":
        return i.split("/")[0] if i.startswith("@") else i.split("@")[0]
    if t == "oci":
        ref = i.split("@")[0].split(":")[0]
        return "/".join(ref.split("/")[:-1]) or ref
    return re.split(r"[=<>@]", i)[0]


def targets(sv):
    rem = {d for d in (domain(r.get("url")) for r in sv.get("remotes") or []) if d}
    pkg = {(pk.get("registryType"), pkg_owner(pk)) for pk in sv.get("packages") or []}
    return rem, pkg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache")
    a = ap.parse_args()
    entries = json.load(open(a.cache)) if a.cache else fetch()
    first, latest = {}, {}
    for e in entries:
        sv = e.get("server") or {}
        meta = (e.get("_meta") or {}).get("io.modelcontextprotocol.registry/official") or {}
        n = sv.get("name")
        if not n or meta.get("status") == "deleted":
            continue
        if n not in latest or (meta.get("updatedAt") or "") >= latest[n][1]:
            latest[n] = (sv, meta.get("updatedAt") or "", meta.get("publishedAt") or "")
        if n not in first or (meta.get("publishedAt") or "~") < first[n][1]:
            first[n] = (sv, meta.get("publishedAt") or "~")
    c = collections.Counter(servers=len(latest))
    month = collections.Counter()
    for n, (sv, _u, pub) in latest.items():
        f = first[n][0]
        if f is sv:
            continue
        c["servers_with_history"] += 1
        r1, p1 = targets(f)
        r2, p2 = targets(sv)
        rem = bool(r1 and r2 and not r1 & r2)
        pkg = bool(p1 and p2 and not p1 & p2)
        sw = bool(r1) != bool(r2) and bool(p1) != bool(p2)
        if rem or pkg or sw:
            c["listing_swaps"] += 1
            c["remote_domain_changed"] += rem
            c["package_owner_changed"] += pkg
            c["switched_local_and_remote"] += sw
            c["same_title_and_description"] += (f.get("title"), f.get("description")) == (sv.get("title"), sv.get("description"))
            month[pub[:7]] += 1
    print(json.dumps({**c, "swapped_version_published_by_month": dict(sorted(month.items()))}, indent=1))


if __name__ == "__main__":
    main()
