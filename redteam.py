#!/usr/bin/env python3
"""ATPP red team — replay the README-badge PoC (and the attacks that follow from it) against production.

Eirik Rune's PoC showed two things about any README badge: (1) whoever serves the image can swap it after
it is embedded, and (2) an SVG can mimic anything and be wrapped in a link. This runs those, plus every
attack we could think of against the signed-claim design, against the live service, read-only. Attacker
keys are generated on the fly; nothing is written to production. A "compromised server" is simulated by
intercepting what the verifier downloads, which is exactly the position a real one would be in.

  python3 redteam.py [--out RESULTS.md]

Exit status 1 if any attack that should be blocked was not.
"""
import argparse, base64, contextlib, hashlib, json, os, random, re, subprocess, sys, tempfile, unicodedata, urllib.parse, urllib.request
from datetime import datetime, timedelta, timezone

import atpp
from cryptography.hazmat.primitives.asymmetric import ed25519

PAGE = "https://github.com/bl014h/atpp/blob/main/redteam/README.md"
HERE = os.path.dirname(os.path.abspath(__file__))
ALLOWED_HOSTS = {"trust.millenniums.ai", "registry.modelcontextprotocol.io", "raw.githubusercontent.com", "rekor.sigstore.dev"}
results = []


def record(rid, attack, expect, ok, detail, kind="block"):
    results.append((rid, attack, expect, "PASS" if ok else ("INFO" if kind == "info" else "FAIL"), detail))


@contextlib.contextmanager
def intercept(fn):
    """Let a test play a compromised server: fn(url, real_get) returns the bytes the verifier receives."""
    real = atpp._get
    atpp._get = lambda url, timeout=20: fn(url, real)
    try:
        yield
    finally:
        atpp._get = real


def attacker():
    return ed25519.Ed25519PrivateKey.generate()


def blocked(fn):
    """Run a verification; return (blocked?, message)."""
    try:
        status, lines = fn()
        return status != 0, f"not blocked: status {status}; " + "; ".join(lines[-2:])
    except atpp.VerifyError as e:
        return True, f"INVALID — {e}"


def pick_target(names):
    """A server with a current signed claim whose registry listing declares a GitHub repo (for the copy test)."""
    random.shuffle(names)
    for n in names[:60]:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}/[A-Za-z0-9_.-]{1,80}", n):
            continue
        try:
            env = atpp.fetch_envelope(n)
            p = json.loads(base64.b64decode(env["payload"]))["predicate"]
            url = f"{atpp.REGISTRY}/{urllib.parse.quote(n, safe='')}/versions/{urllib.parse.quote(p['version'], safe='')}"
            repo = atpp._gh_slug((json.loads(atpp._get(url))["server"].get("repository") or {}).get("url"))
            if repo and repo != "bl014h/atpp":
                return n, env, p, repo
        except Exception:
            continue
    raise SystemExit("no suitable target with a signed claim found")


def write_atpp(d, env, svg, remote="https://github.com/bl014h/atpp.git"):
    os.makedirs(os.path.join(d, ".atpp"), exist_ok=True)
    json.dump(env, open(os.path.join(d, ".atpp", "attestation.dsse.json"), "w"))
    if svg is not None:
        open(os.path.join(d, ".atpp", "badge.svg"), "wb").write(svg if isinstance(svg, bytes) else svg.encode())
    subprocess.run(["git", "init", "-q", d], check=True)
    subprocess.run(["git", "-C", d, "remote", "add", "origin", remote], check=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    a = ap.parse_args()
    names = [n for n, _p, _t in json.loads(atpp._get(f"{atpp.TRUST}/mcp-names.json"))["n"]]
    name, env, pred, repo = pick_target(names)
    svg = atpp.render_badge(name, pred["version"], pred["passed"], pred["total"], pred["as_of"], pred["rules_version"])
    tmp = tempfile.mkdtemp(prefix="atpp-redteam-")

    # ---- control: the genuine claim, bound to its own repo, verifies
    good = os.path.join(tmp, "genuine")
    write_atpp(good, env, svg, remote=f"https://github.com/{repo}.git")
    try:
        st, lines = atpp.check(env, svg.encode(), repo_dir=good, expect=name)
        record("C0", f"Control: genuine claim for `{name}` in a repo whose remote is `{repo}`", "verifies",
               st == 0, "; ".join(l.split("—")[0].strip() for l in lines), kind="block")
    except atpp.VerifyError as e:
        record("C0", f"Control: genuine claim for `{name}`", "verifies", False, str(e))

    # ---- Eirik demo 1: swap the image after it is embedded
    try:
        html = atpp._get(PAGE).decode("utf-8", "replace")
        srcs = re.findall(r'<img[^>]+src="([^"]+)"', html)
        pinned = [s for s in srcs if "genuine/.atpp/badge.svg" in s]
        live = [s for s in srcs if "camo.githubusercontent.com" in s]
        record("E1", "PoC demo 1 — swap a **pinned** badge after it is embedded",
               "impossible without a commit: the image is served from the repo itself",
               bool(pinned) and all("camo.githubusercontent.com" not in s for s in pinned),
               f"rendered src: {pinned[0][:90] if pinned else 'pinned badge not found on page'}")
        record("E2", "PoC demo 1 — swap a **live** badge after it is embedded",
               "possible for whoever controls trust.millenniums.ai (that is why live is opt-in); the claim behind it still has to verify",
               True, f"{len(live)} camo-proxied image(s) on the page; live badges are labelled as such", kind="info")
    except Exception as e:
        record("E1", "PoC demo 1 — pinned badge rendering", "served from the repo", False, f"page unreachable: {e}")

    # ---- Eirik demo 2: mimicry — a lookalike badge with a forged attestation
    k = attacker()
    forged_pred = dict(pred, passed=pred["total"], checks=[[c[0], True, c[2]] for c in pred["checks"]])
    forged = {"_type": atpp.STATEMENT_TYPE, "predicateType": atpp.PREDICATE_TYPE,
              "subject": [{"name": f"mcp:{name}", "digest": {"sha256": json.loads(base64.b64decode(env['payload']))['subject'][0]['digest']['sha256']}}],
              "predicate": forged_pred}
    fsvg = atpp.render_badge(name, pred["version"], pred["total"], pred["total"], pred["as_of"], pred["rules_version"])
    forged["predicate"]["badge_sha256"] = hashlib.sha256(fsvg.encode()).hexdigest()
    fenv = atpp.sign(atpp.PAYLOAD_TYPE, forged, k, "atpp-scan-2026-10")      # even reusing the real keyid
    d = os.path.join(tmp, "forged")
    write_atpp(d, fenv, fsvg, remote=f"https://github.com/{repo}.git")
    ok, msg = blocked(lambda: atpp.check(fenv, fsvg.encode(), repo_dir=d, expect=name))
    record("E3", "PoC demo 2 — lookalike badge + attestation signed by an attacker (claims a perfect score, reuses our keyid)",
           "INVALID", ok, msg)
    nod = os.path.join(tmp, "mimicry"); os.makedirs(nod)
    r = subprocess.run([sys.executable, os.path.join(HERE, "atpp.py"), "verify", nod], capture_output=True, text=True)
    record("E4", "PoC demo 2 — README text-mimicry SVG wrapped in a link (no attestation at all)",
           "no claim — the verifier reads signed files, never README images or links", r.returncode != 0,
           (r.stdout + r.stderr).strip().splitlines()[-1][:120] if (r.stdout + r.stderr).strip() else f"exit {r.returncode}")

    # ---- the rest of the attack surface
    d = os.path.join(tmp, "copied")
    write_atpp(d, env, svg)                                                  # remote = bl014h/atpp
    ok, msg = blocked(lambda: atpp.check(env, svg.encode(), repo_dir=d))
    record("A1", f"Copy another server's genuine `.atpp/` into your repo (`{name}`'s files in bl014h/atpp)", "INVALID", ok, msg)

    edited = svg.replace(f"scanned {pred['passed']}/", f"scanned {pred['total']}/")
    if edited == svg:
        edited = svg.replace("scanned", "verified")
    ok, msg = blocked(lambda: atpp.check(env, edited.encode(), online=False))
    record("A2", "Edit the committed badge image to show a better score", "INVALID", ok, msg)

    body = json.loads(base64.b64decode(env["payload"])); body["predicate"]["passed"] = body["predicate"]["total"]
    tampered = dict(env, payload=base64.b64encode(atpp.canonical(body)).decode())
    ok, msg = blocked(lambda: atpp.check(tampered, online=False))
    record("A3", "Rewrite the score inside a genuine envelope (keep our signature)", "INVALID", ok, msg)

    def fake_registry(url, real):
        if url.startswith(atpp.REGISTRY):
            srv = json.loads(real(url)); srv["server"]["description"] = (srv["server"].get("description") or "") + " (changed)"
            return json.dumps(srv).encode()
        return real(url)
    with intercept(fake_registry):
        ok, msg = blocked(lambda: atpp.check(env, expect=name, log=False))
    record("A4", "Publisher changes the registry listing after the scan (claim no longer describes it)", "INVALID", ok, msg)

    def evil_manifest(url, real):
        if "/v/log/" in url:
            m = json.loads(real(url)); b = json.loads(base64.b64decode(m["payload"]))
            b["entries"][name] = "0" * 64
            return json.dumps(atpp.sign(atpp.MANIFEST_TYPE, b, k, "atpp-scan-2026-10")).encode()
        return real(url)
    with intercept(evil_manifest):
        ok, msg = blocked(lambda: atpp.check(env, expect=name))
    record("A5", "Compromised trust.millenniums.ai serves a doctored daily manifest", "INVALID (manifest ≠ public log)", ok, msg)

    hist = sorted(f for f in os.listdir(os.path.join(HERE, "redteam", "history")) if f.endswith(".json")) \
        if os.path.isdir(os.path.join(HERE, "redteam", "history")) else []
    old = None
    for f in hist:
        e = json.load(open(os.path.join(HERE, "redteam", "history", f)))
        if json.loads(base64.b64decode(e["payload"]))["predicate"]["as_of"] < json.loads(atpp._get(f"{atpp.LOG_RAW}/latest.json"))["date"]:
            old = e
    if old:
        oname = json.loads(base64.b64decode(old["payload"]))["subject"][0]["name"].removeprefix("mcp:")
        ok, msg = blocked(lambda: atpp.check(old, expect=oname))
        record("A6", "Rollback: a compromised server replays an older, still-unexpired genuine claim", "INVALID (superseded)", ok, msg)
    else:
        record("A6", "Rollback: replay an older genuine claim", "INVALID (superseded)", True,
               "skipped — needs a second day of signed history in redteam/history/ (the daily sync archives one)", kind="info")

    def inject_key(url, real):
        if url.endswith("/.well-known/atpp-keys.json"):
            wk = json.loads(real(url)); wk["keys"]["attacker"] = {"public_key": "AAAA"}; wk["revoked"] = []
            return json.dumps(wk).encode()
        return real(url)
    akey = atpp.sign(atpp.PAYLOAD_TYPE, forged, k, "attacker")
    with intercept(inject_key):
        ok, msg = blocked(lambda: atpp.check(akey, expect=name, log=False))
    record("A7", "Add an attacker key to /.well-known/atpp-keys.json and sign with it", "INVALID (that file can only revoke)", ok, msg)

    def revoke(url, real):
        if url.endswith("/.well-known/atpp-keys.json"):
            wk = json.loads(real(url)); wk["revoked"] = list(atpp.KEYS)
            return json.dumps(wk).encode()
        return real(url)
    with intercept(revoke):
        ok, msg = blocked(lambda: atpp.check(env, expect=name, log=False))
    record("A8", "Revocation works: the issuer revokes the signing key", "INVALID (revoked)", ok, msg)

    spoof = atpp.render_badge(name, "1.0‮7/7 dennacs​", 3, 6, pred["as_of"], "atf-3")
    bad = [c for c in spoof if unicodedata.category(c) in ("Cc", "Cf")]
    record("A9", "Bidi-override spoof in a publisher-controlled version string (`1.0\\u202e7/7 dennacs`)",
           "control/format characters stripped before rendering", not bad, f"{len(bad)} control/format chars left in the SVG")

    long = atpp.render_badge(name, "9" * 5000, 3, 6, pred["as_of"], "atf-3")
    w = int(re.search(r'width="(\d+)"', long).group(1))
    record("A10", "Oversized version string (5,000 chars) to blow up the badge", "width capped", w <= 450, f"badge width {w}px")

    status, lines = atpp.check(env, svg.encode(), online=False, now=(datetime.strptime(pred["valid_until"], "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d"))
    record("A11", "Use a claim after its expiry", "reported EXPIRED (exit 2)", status == 2, lines[-1])

    hosts = set()
    def spy(url, real):
        hosts.add(urllib.parse.urlparse(url).hostname)
        return real(url)
    with intercept(spy):
        try:
            atpp.check(env, expect=name)
        except atpp.VerifyError:
            pass
    record("A12", "Lookalike verify domain (README links to `trust-millenniums.ai`)",
           "the verifier ignores README links; it only talks to pinned hosts", hosts <= ALLOWED_HOSTS, f"hosts contacted: {sorted(hosts)}")

    ns, srv = name.split("/", 1)
    bad_svgs, no_csp = [], 0
    for n in random.sample(names, min(10, len(names))) + [name]:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}/[A-Za-z0-9_.-]{1,80}", n):
            continue
        a1, b1 = n.split("/", 1)
        resp = urllib.request.urlopen(urllib.request.Request(f"{atpp.TRUST}/badge/mcp/{a1}/{b1}.svg", headers={"User-Agent": atpp.UA}), timeout=30)
        if atpp.svg_problems(resp.read().decode("utf-8", "replace")):
            bad_svgs.append(n)
        if "sandbox" not in resp.headers.get("Content-Security-Policy", ""):
            no_csp += 1
    record("A13", "Our own live SVGs: could any link, animate, script, or fail to parse?", "none", not bad_svgs and not no_csp,
           f"{len(bad_svgs)} unsafe/broken, {no_csp} without a sandboxing CSP")
    resp = urllib.request.urlopen(urllib.request.Request(f"{atpp.TRUST}/v/mcp/{ns}/{srv}", headers={"User-Agent": atpp.UA}), timeout=30)
    record("A14", "Clickjacking: frame the verify page inside a lookalike site", "refused (frame-ancestors 'none')",
           "frame-ancestors 'none'" in resp.headers.get("Content-Security-Policy", ""), resp.headers.get("Content-Security-Policy", "none")[:80])

    # ---- report
    fails = [r for r in results if r[3] == "FAIL"]
    md = [f"# ATPP red team — {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC", "",
          f"Target for the claim-level attacks: `{name}` (signed {pred['as_of']}). "
          f"{len(results)} checks, **{len(fails)} failed**.", "",
          "| ID | Attack | Expected | Result | Detail |", "|---|---|---|---|---|"]
    md += [f"| {r[0]} | {r[1]} | {r[2]} | **{r[3]}** | {r[4].replace('|', '/')[:220]} |" for r in results]
    text = "\n".join(md) + "\n"
    print(text)
    if a.out:
        open(a.out, "w").write(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        open(os.environ["GITHUB_STEP_SUMMARY"], "a").write(text)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
