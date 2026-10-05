#!/usr/bin/env python3
"""atpp — check an Agentic Trust & Protection Platform (ATPP) scan claim without trusting Millenniums.AI.

A badge image is a pointer, never proof. The claim is an in-toto Statement in a DSSE envelope,
signed with Ed25519, bound to the sha256 of the exact MCP registry manifest that was scanned.
The public key is embedded below, so a hijacked domain cannot swap it.

  atpp verify <repo-dir>                    # reads <dir>/.atpp/attestation.dsse.json (+ badge.svg)
  atpp verify <namespace>/<server>          # fetches the current attestation from trust.millenniums.ai
  atpp report mcp-scan|mcp-names              # the public aggregate report / search index match their signed copies
  options: --offline (signature, badge, expiry only) · --no-log · --expect <namespace>/<server>
  atpp badge  <namespace>/<server> [dir]    # verifies, then writes <dir>/.atpp/badge.svg + attestation

Exit codes: 0 valid and current · 1 invalid (signature, digest or badge mismatch) · 2 valid but
expired · 3 could not check (usage, network).

Needs Python 3.9+ and `pip install cryptography`. Source and key history:
https://github.com/bl014h/atpp
"""
import base64, hashlib, json, os, sys, urllib.parse, urllib.request
from datetime import datetime, timezone

# Pinned verification keys: keyid -> raw Ed25519 public key (base64). A rotation adds a key here and
# in https://trust.millenniums.ai/.well-known/atpp-keys.json; a compromised key is removed here and
# listed under "revoked" there. The well-known file can only ever revoke, never add.
KEYS = {"atpp-scan-2026-10": "20P9I6y6X6mQztS3IJTU/4CNaqg/FjcpouXkPsrCyVo="}

PAYLOAD_TYPE = "application/vnd.in-toto+json"
MANIFEST_TYPE = "application/vnd.millenniums.atpp-manifest+json"
REPORT_TYPE = "application/vnd.millenniums.atpp-report+json"
REPORTS = {"mcp-scan": "/mcp-scan.json", "mcp-names": "/mcp-names.json"}
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://millenniums.ai/atpp/scan/v1"
TRUST = "https://trust.millenniums.ai"
REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
UA = "atpp/1.0 (+https://github.com/bl014h/atpp)"


class VerifyError(Exception):
    pass


# ------------------------------------------------------------------ primitives
def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def manifest_sha256(server):
    """sha256 of a registry `server` object exactly as the scanner hashes it (ASCII-escaped JSON)."""
    return hashlib.sha256(json.dumps(server, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def pae(payload_type, body):
    """DSSE pre-authentication encoding: the exact bytes that are signed."""
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def envelope_sha256(env):
    return hashlib.sha256(canonical(env)).hexdigest()


def _pub(keyid, keys):
    from cryptography.hazmat.primitives.asymmetric import ed25519
    if keyid not in keys:
        raise VerifyError(f"signed with unknown key {keyid!r}")
    return ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(keys[keyid]))


def sign(payload_type, obj, private_key, keyid):
    body = canonical(obj)
    sig = private_key.sign(pae(payload_type, body))
    return {"payloadType": payload_type, "payload": base64.b64encode(body).decode(),
            "signatures": [{"keyid": keyid, "sig": base64.b64encode(sig).decode()}]}


def open_envelope(env, payload_type=PAYLOAD_TYPE, keys=None, revoked=()):
    """Check the signature and return the decoded payload. Raises VerifyError."""
    from cryptography.exceptions import InvalidSignature
    keys = KEYS if keys is None else keys
    if not isinstance(env, dict) or env.get("payloadType") != payload_type:
        raise VerifyError("not an ATPP envelope")
    try:
        body = base64.b64decode(env["payload"], validate=True)
    except Exception:
        raise VerifyError("payload is not base64")
    for s in env.get("signatures") or []:
        kid = s.get("keyid")
        if kid in revoked:
            raise VerifyError(f"key {kid} is revoked")
        try:
            _pub(kid, keys).verify(base64.b64decode(s.get("sig", "")), pae(payload_type, body))
            return json.loads(body)
        except InvalidSignature:
            continue
        except VerifyError:
            raise
        except Exception:
            continue
    raise VerifyError("signature does not verify")


def load_private_key(path):
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_private_key(open(path, "rb").read(), None)


# ------------------------------------------------------------------ pinned badge
# Byte-identical to pinnedBadge() in workers/atf-badge/src/index.js (tests compare both).
VERSION_SHOWN = 24   # code points of the publisher-controlled version shown on a badge


def clean(s, limit=None):
    """Drop control and format characters (Unicode Cc/Cf: bidi overrides, zero-width joiners, ...) from
    publisher-controlled text, then cap its length. A version like "1.0\\u202e7/7 dennacs" would otherwise
    render reversed and make a badge read differently from its claim. Same rule as clean() in the Worker."""
    import unicodedata
    out = "".join(c for c in str(s) if unicodedata.category(c) not in ("Cc", "Cf"))
    return out if limit is None or len(out) <= limit else out[:limit - 1] + "…"


def _esc(s):
    return "".join({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}.get(c, c) for c in clean(s))


def _w(text):
    return len(text) * 7 + 14


def render_badge(name, version, passed, total, as_of, rules):
    version = clean(version, VERSION_SHOWN)
    right = f"scanned {passed}/{total} · v{version} · {as_of}"
    lw, rw = _w("ATPP"), _w(right)
    w = lw + rw
    title = (f"Static scan of {name} @ {version}: passed {passed} of {total} published checks "
             f"(rules {rules}) on {as_of}. Not a runtime claim.")
    desc = ("This image is a pointer, not proof. The signed claim is .atpp/attestation.dsse.json; "
            "check it offline with https://github.com/bl014h/atpp")
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" '
            f'aria-label="ATPP: {_esc(right)}">'
            f"<title>{_esc(title)}</title><desc>{_esc(desc)}</desc>"
            f'<clipPath id="r"><rect width="{w}" height="20" rx="3" fill="#fff"/></clipPath>'
            f'<g clip-path="url(#r)"><rect width="{lw}" height="20" fill="#0b111f"/>'
            f'<rect x="{lw}" width="{rw}" height="20" fill="#f2b64b"/></g>'
            f'<g text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
            f'<text x="{lw // 2}" y="14" fill="#ffffff" font-weight="700">ATPP</text>'
            f'<text x="{lw + rw // 2}" y="14" fill="#1a1200">{_esc(right)}</text></g></svg>')


# ------------------------------------------------------------------ statements (scanner side)
def statement(name, score, issuer=TRUST):
    """The signed claim for one level-1 score (a dict from scanner/mcp_scan.py score())."""
    pred = {"version": score.get("version") or "latest", "rules_version": score["rules_version"],
            "passed": score["passed"], "total": score["total"],
            "checks": [[c["id"], bool(c["pass"]), c["detail"]] for c in score["checks"]],
            "as_of": score["as_of"], "valid_until": score["valid_until"], "issuer": issuer,
            "registry": "registry.modelcontextprotocol.io", "scope": "static manifest scan — not a runtime claim"}
    svg = render_badge(name, pred["version"], pred["passed"], pred["total"], pred["as_of"], pred["rules_version"])
    pred["badge_sha256"] = hashlib.sha256(svg.encode("utf-8")).hexdigest()
    return {"_type": STATEMENT_TYPE, "predicateType": PREDICATE_TYPE, "predicate": pred,
            "subject": [{"name": f"mcp:{name}", "digest": {"sha256": score["sha256"]}}]}


# ------------------------------------------------------------------ SVG safety
SVG_ALLOWED = {"svg", "title", "desc", "linearGradient", "stop", "clipPath", "rect", "g", "text"}


def svg_problems(src):
    """Why an SVG we serve would be unsafe or broken: malformed XML (renders as a broken image), or any
    element/attribute that could link, animate, script or pull in content — the levers of the README-badge
    mimicry PoC. Returns a list; empty means plain shapes and text only."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(src)
    except ET.ParseError as e:
        return [f"not well-formed XML ({e})"]
    out = []
    for el in root.iter():
        tag = el.tag.split("}")[-1]
        if tag not in SVG_ALLOWED:
            out.append(f"<{tag}> is not allowed")
        for attr in el.attrib:
            a = attr.split("}")[-1].lower()
            if a.startswith("on") or a in ("href", "style", "src"):
                out.append(f"{tag}@{a} is not allowed")
    return out


# ------------------------------------------------------------------ anchors (scanner side)
ANCHOR_TYPE = "application/vnd.millenniums.atpp-anchor+json"
REKOR = "https://rekor.sigstore.dev"
LOG_RAW = "https://raw.githubusercontent.com/bl014h/atpp/main/log"


def anchor(manifest_env, date, keyid):
    """A tiny signed statement committing to one day's manifest. It goes into the Sigstore Rekor
    transparency log, which we do not control, so a day's claims cannot be backdated or rewritten."""
    body = canonical(manifest_env)
    return {"_type": "https://millenniums.ai/atpp/anchor/v1", "date": date, "keyid": keyid,
            "manifest_sha256": hashlib.sha256(body).hexdigest(),
            "count": json.loads(base64.b64decode(manifest_env["payload"])).get("count")}


def public_pem(private_key):
    from cryptography.hazmat.primitives import serialization
    return private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def rekor_upload(anchor_env, pem, timeout=60):
    """Record a signed anchor in Rekor (DSSE entry). Returns {uuid, logIndex, integratedTime}."""
    req = {"apiVersion": "0.0.1", "kind": "dsse", "spec": {"proposedContent": {
        "envelope": json.dumps(anchor_env), "verifiers": [base64.b64encode(pem).decode()]}}}
    r = urllib.request.Request(f"{REKOR}/api/v1/log/entries", data=json.dumps(req).encode(), method="POST",
                               headers={"Content-Type": "application/json", "User-Agent": UA})
    with urllib.request.urlopen(r, timeout=timeout) as resp:
        (uuid, e), = json.loads(resp.read()).items()
    return {"uuid": uuid, "logIndex": e.get("logIndex"), "integratedTime": e.get("integratedTime")}


# ------------------------------------------------------------------ verify (reader side)
def _get(url, timeout=20):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=timeout) as r:
        return r.read()


def _revoked():
    """Revocations published by the issuer. This list can only ever REMOVE trust in a pinned key; a key
    that appears here but not in KEYS above is never trusted."""
    try:
        return set(json.loads(_get(f"{TRUST}/.well-known/atpp-keys.json")).get("revoked") or [])
    except Exception:
        return set()            # offline: the embedded key list is the authority


def _day(s):
    """A strict YYYY-MM-DD, or None. A missing or malformed date in a claim counts as expired."""
    try:
        return datetime.strptime(str(s), "%Y-%m-%d").strftime("%Y-%m-%d")
    except Exception:
        return None


def _gh_slug(url):
    import re
    m = re.search(r"github\.com[:/]+([^/\s]+)/([^/\s#?]+?)(?:\.git)?/?$", str(url or ""))
    return f"{m.group(1)}/{m.group(2)}".lower() if m else None


def _git_remote(repo_dir):
    import subprocess
    try:
        r = subprocess.run(["git", "-C", repo_dir, "remote", "get-url", "origin"], capture_output=True, text=True, timeout=10)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:
        return None


def check_log(env, pred):
    """Is this envelope in the latest day's manifest, and does that manifest match the public log and
    its Rekor anchor? Catches a compromised trust.millenniums.ai replaying an older, better-scoring
    claim (rollback) or serving a manifest that differs from the one committed publicly. Returns lines."""
    lines = []
    try:
        log = json.loads(_get(f"{LOG_RAW}/latest.json"))
    except Exception as e:
        return [f"log         not checked — public log unreachable ({e.__class__.__name__})"]
    date = log.get("date")
    try:
        man_env = json.loads(_get(f"{TRUST}/v/log/{date}.json"))
    except Exception as e:
        return [f"log         not checked — manifest for {date} unreachable ({e.__class__.__name__})"]
    if envelope_sha256(man_env) != log.get("manifest_sha256"):
        raise VerifyError(f"trust.millenniums.ai serves a {date} manifest that differs from the one committed to "
                          f"the public log — do not trust its claims")
    man = open_envelope(man_env, MANIFEST_TYPE)
    mine = envelope_sha256(env)
    name = next(iter(json.loads(base64.b64decode(env["payload"]))["subject"]))["name"].removeprefix("mcp:")
    listed = (man.get("entries") or {}).get(name)
    if listed == mine:
        lines.append(f"log         OK — listed in the {date} manifest committed to github.com/bl014h/atpp")
    elif str(pred.get("as_of", "")) < str(date):
        raise VerifyError(f"superseded — a newer scan of {name} is in the {date} manifest; this older claim "
                          f"(as of {pred.get('as_of')}) is being replayed")
    else:
        lines.append(f"log         newer than the public log ({date}); it will be listed after the next sync")
    rk = log.get("rekor") or {}
    if rk.get("uuid") and log.get("anchor"):
        try:
            a = open_envelope(log["anchor"], ANCHOR_TYPE)
            if a.get("manifest_sha256") != log.get("manifest_sha256"):
                raise VerifyError("the public log's Rekor anchor does not commit to its manifest")
            entry = json.loads(_get(f"{REKOR}/api/v1/log/entries/{rk['uuid']}"))
            body = json.loads(base64.b64decode(next(iter(entry.values()))["body"]))
            want = hashlib.sha256(base64.b64decode(log["anchor"]["payload"])).hexdigest()
            if body.get("spec", {}).get("payloadHash", {}).get("value") != want:
                raise VerifyError("the Rekor entry named by the public log is not this day's anchor")
            lines.append(f"rekor       OK — anchored at log index {rk.get('logIndex')} "
                         f"({datetime.fromtimestamp(int(rk.get('integratedTime') or 0), timezone.utc):%Y-%m-%d %H:%M} UTC)")
        except VerifyError:
            raise
        except Exception as e:
            lines.append(f"rekor       not checked — {e.__class__.__name__}")
    return lines


def check(env, badge_svg=None, online=True, now=None, repo_dir=None, expect=None, log=True):
    """Return (status, lines). status 0 valid+current, 1 invalid (raises VerifyError), 2 expired."""
    lines = []
    st = open_envelope(env, revoked=_revoked() if online else ())
    pred, subj = st.get("predicate") or {}, (st.get("subject") or [{}])[0]
    if st.get("_type") != STATEMENT_TYPE or st.get("predicateType") != PREDICATE_TYPE:
        raise VerifyError("not an ATPP scan statement")
    name = str(subj.get("name", "")).removeprefix("mcp:")
    if expect and name != expect:
        raise VerifyError(f"this claim is for {name}, not {expect}")
    digest = (subj.get("digest") or {}).get("sha256", "")
    kid = env["signatures"][0]["keyid"]
    lines.append(f"signature   OK — {kid} (sha256 {hashlib.sha256(base64.b64decode(KEYS[kid])).hexdigest()[:16]})")
    lines.append(f"claim       {name} @ {clean(pred.get('version'), 64)}: passed {pred.get('passed')}/{pred.get('total')} "
                 f"checks (rules {pred.get('rules_version')}) on {pred.get('as_of')} — static scan, not runtime")
    status, server = 0, None
    if online:
        try:
            url = (f"{REGISTRY}/{urllib.parse.quote(name, safe='')}/versions/"
                   f"{urllib.parse.quote(str(pred.get('version')), safe='')}")
            server = json.loads(_get(url))["server"]
            live = manifest_sha256(server)
            if live != digest:
                raise VerifyError(f"registry manifest for {name} @ {pred.get('version')} has changed since the "
                                  f"scan (signed {digest[:12]}…, live {live[:12]}…) — the claim no longer describes it")
            lines.append(f"subject     OK — registry manifest sha256 {digest[:16]}… matches what was scanned")
        except VerifyError:
            raise
        except Exception as e:
            lines.append(f"subject     not checked — registry unreachable ({e.__class__.__name__})")
    else:
        lines.append("subject     not checked (--offline)")
    if repo_dir is not None:
        # A repo can copy another server's .atpp/ files: the signature and badge would both check out.
        # Bind the claim to THIS repo through the source repository its registry listing declares.
        mine = _gh_slug(_git_remote(repo_dir))
        theirs = _gh_slug(((server or {}).get("repository") or {}).get("url")) if server else None
        if mine and theirs and mine != theirs:
            raise VerifyError(f"these .atpp/ files are the claim for {name}, whose registry listing points at "
                              f"github.com/{theirs} — not this repository (github.com/{mine}). They were copied.")
        lines.append(f"binding     OK — {name} declares github.com/{theirs}, this repository" if mine and theirs and mine == theirs
                     else "binding     not checked — " + ("no git remote" if not mine else "registry listing unavailable or declares no GitHub repo"))
    if badge_svg is not None:
        if hashlib.sha256(badge_svg).hexdigest() != pred.get("badge_sha256"):
            raise VerifyError(".atpp/badge.svg is not the badge that was signed — it was edited or is from another scan")
        lines.append("badge       OK — .atpp/badge.svg is the signed image")
    if online and log:
        lines += check_log(env, pred)
    now = now or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    until = _day(pred.get("valid_until"))
    if not until or until < now:
        status = 2
        lines.append(f"freshness   EXPIRED — valid until {pred.get('valid_until')}; the claim is historical only")
    else:
        lines.append(f"freshness   current — valid until {until}")
    return status, lines


def check_report(kind):
    """The public aggregate report or search index: the plain JSON the site reads must be exactly what was
    signed, and the signed envelope must be the one listed in the latest manifest committed to the public log."""
    path = REPORTS[kind]
    plain = json.loads(_get(f"{TRUST}{path}"))
    env = json.loads(_get(f"{TRUST}{path}.dsse"))
    signed = open_envelope(env, REPORT_TYPE)
    if signed != plain:
        raise VerifyError(f"{path} differs from its signed copy — the served report was altered")
    lines = [f"report      OK — {path} matches its signed copy ({env['signatures'][0]['keyid']})"]
    try:
        log = json.loads(_get(f"{LOG_RAW}/latest.json"))
        man_env = json.loads(_get(f"{TRUST}/v/log/{log['date']}.json"))
        if envelope_sha256(man_env) != log.get("manifest_sha256"):
            raise VerifyError("the served manifest differs from the one committed to the public log")
        listed = (open_envelope(man_env, MANIFEST_TYPE).get("reports") or {}).get(kind)
        if listed == envelope_sha256(env):
            lines.append(f"log         OK — listed in the {log['date']} manifest committed to github.com/bl014h/atpp")
        elif listed is None:
            lines.append(f"log         the {log['date']} manifest predates signed reports")
        else:
            raise VerifyError(f"{path} is not the report listed in the {log['date']} manifest (stale or replaced)")
    except VerifyError:
        raise
    except Exception as e:
        lines.append(f"log         not checked — {e.__class__.__name__}")
    return 0, lines


def fetch_envelope(name):
    ns, _, srv = name.partition("/")
    if not ns or not srv:
        raise ValueError("expected <namespace>/<server>")
    return json.loads(_get(f"{TRUST}/v/mcp/{ns}/{srv}.json"))


def _opt(a, flag):
    if flag in a:
        i = a.index(flag)
        v = a[i + 1] if i + 1 < len(a) else None
        del a[i:i + 2]
        return v
    return None


def main(argv=None):
    a = list(sys.argv[1:] if argv is None else argv)
    online, log = "--offline" not in a, "--no-log" not in a
    a = [x for x in a if x not in ("--offline", "--no-log")]
    expect = _opt(a, "--expect")
    if len(a) == 2 and a[0] == "report" and a[1] in REPORTS:
        try:
            _, lines = check_report(a[1])
        except VerifyError as e:
            print(f"INVALID — {e}")
            return 1
        except Exception as e:
            print(f"could not check: {e}", file=sys.stderr)
            return 3
        print("\n".join(lines))
        return 0
    if len(a) < 2 or a[0] not in ("verify", "badge"):
        print(__doc__.strip().split("\n\n")[1], file=sys.stderr)
        return 3
    cmd, target = a[0], a[1]
    try:
        repo = None
        if cmd == "verify" and os.path.isdir(target):
            repo, d = target, os.path.join(target, ".atpp")
            env = json.load(open(os.path.join(d, "attestation.dsse.json")))
            bp = os.path.join(d, "badge.svg")
            svg = open(bp, "rb").read() if os.path.exists(bp) else None
        else:
            env, svg = fetch_envelope(target), None
            expect = expect or target
        status, lines = check(env, svg, online=online, repo_dir=repo, expect=expect, log=log)
    except VerifyError as e:
        print(f"INVALID — {e}")
        return 1
    except Exception as e:
        print(f"could not check: {e}", file=sys.stderr)
        return 3
    print("\n".join(lines))
    if cmd == "badge":
        if status != 0:
            print("not writing a badge for an expired claim", file=sys.stderr)
            return status
        st = json.loads(base64.b64decode(env["payload"]))
        p = st["predicate"]
        out = os.path.join(a[2] if len(a) > 2 else ".", ".atpp")
        os.makedirs(out, exist_ok=True)
        name = st["subject"][0]["name"].removeprefix("mcp:")
        svg_out = render_badge(name, p["version"], p["passed"], p["total"], p["as_of"], p["rules_version"])
        if hashlib.sha256(svg_out.encode("utf-8")).hexdigest() != p.get("badge_sha256"):
            # The claim was signed by a different badge renderer than this one; writing would produce a
            # badge that fails verification. The next daily scan re-signs with the current renderer.
            print("not writing: this claim was signed with a different badge renderer; retry after the next daily scan", file=sys.stderr)
            return 3
        open(os.path.join(out, "badge.svg"), "w", encoding="utf-8").write(svg_out)
        json.dump(env, open(os.path.join(out, "attestation.dsse.json"), "w"), indent=1)
        ns, _, srv = name.partition("/")
        print(f"\nwrote {out}/badge.svg and {out}/attestation.dsse.json — README line:\n"
              f"[![ATPP scanned {p['passed']}/{p['total']} · v{clean(p['version'], VERSION_SHOWN)} · {p['as_of']}](.atpp/badge.svg)]"
              f"({TRUST}/v/mcp/{ns}/{srv})")
    return status


if __name__ == "__main__":
    sys.exit(main())
