#!/usr/bin/env python3
"""Agent Trust Fabric — level-1 publisher scan of the official MCP registry.

Unasked, static, and published: every server listed at registry.modelcontextprotocol.io is
scored against the checks below and the result is written to the edge KV the badge Worker
reads (`mcp:<namespace>/<name>`). No code is fetched or executed — every check is decided
from the publisher's own manifest, which is what makes the claim safe to print on a badge:
"passed N of M published checks on <date>", never a runtime claim.

  ./scanner/mcp_scan.py --out scanner/out            # scan, write scores + aggregate
  ./scanner/mcp_scan.py --out scanner/out --publish  # also push every score to KV (256 shards)

State lives in <out>/state.json (manifest hash per server) so the next run can tell which
listings drifted. Every run publishes every score, grouped into 256 KV shards (~260 writes),
so no badge outlives the run that scored it.
"""
import argparse, base64, json, os, re, subprocess, sys, time, urllib.parse, urllib.request
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools", "atpp"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import atpp  # noqa: E402  — the public verifier; signing, statements and the pinned badge live there
import artifacts  # noqa: E402  — exact digests and build provenance behind each package
import tooldefs  # noqa: E402  — fingerprints of the tool definitions remote servers advertise

SIGN_KEY_ID = os.environ.get("ATPP_SCAN_KEY_ID") or "atpp-scan-2026-10"   # must be listed in the root-signed key list
SIGN_KEY_PATH = os.environ.get("ATPP_SIGNING_KEY", os.path.expanduser("~/.secrets/atpp-scan-ed25519.pem"))
MANIFEST_KEY = "atf:manifest:latest"   # the Worker serves it at /v/log/latest.json
INDEX_KEY = "atf:index:latest"         # small signed pointer to the current publish; the Worker checks every shard against it
PREV_INDEX_MAX_AGE = timedelta(days=3)  # a previous index older than this is not carried as `prev`

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
RULES_VERSION = "atf-6"   # atf-2: artifact-hash scoped to MCPB; atf-3: + oci-digest; atf-4: + target-stable;
                          # atf-5: + artifact-resolves, build-provenance, resolved digests in the claim;
                          # atf-6: + tools-stable (remote tool-definition fingerprints)
VALID_DAYS = 7          # a scan expires; past valid_until the badge renders grey
KV_TTL_DAYS = 21        # keep an expired score around so /v/ can still explain it
KV_BINDING = "ATF_SCORES"
AGG_KEY = "atf:aggregate"       # the Worker serves this at /mcp-scan.json, so a run needs no redeploy
NAMES_KEY = "atf:names"         # the Worker serves this at /mcp-names.json for the badge search
FETCH_TIMEOUT = 75               # seconds per registry page
FETCH_RETRIES = 12               # consecutive failures before a run gives up (~10 min of backoff)
SIGN_CHUNK = 1000               # envelopes signed per sign_many call: bounds memory, one signer round trip each
SHARDS = 256                    # every score, every run, in SHARDS KV values: ~260 writes a day,
                                # inside the free plan, and no badge can outlive the run that scored it

# ---------------------------------------------------------------- signing key
def load_signing_key(path=None):
    """What atpp.sign / atpp.sign_many sign with, or None when no key is configured. With ATPP_SIGNER_ADDR
    (+ ATPP_SIGNER_TOKEN) set it is a RemoteKey: the key stays in the ATPP signer (app/signer.py) and this
    process can only ask for signatures. Otherwise the PEM file at `path`, as before. The signer's public key
    for SIGN_KEY_ID must be the one in the pinned root-signed key list, or we refuse before doing any work.
    Raises SystemExit with a message (never one containing key material or the token)."""
    addr = os.environ.get("ATPP_SIGNER_ADDR")
    if addr:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))
        try:
            import signer
        except ImportError:
            sys.exit("ATPP_SIGNER_ADDR is set but app/signer.py is not next to this scanner (deploy/vm/sync-scan.sh copies it)")
        key = signer.Client(addr, token=os.environ.get("ATPP_SIGNER_TOKEN") or None, keep=True).remote_key(SIGN_KEY_ID)
        try:
            from cryptography.hazmat.primitives import serialization as _ser   # public_bytes_raw() needs cryptography>=40; the scan VM has 3.4
            pub = base64.b64encode(key.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)).decode()
        except signer.SignerError as e:
            sys.exit(f"signer at {addr} cannot sign as {SIGN_KEY_ID}: {e}")
        if pub != atpp.KEYS.get(SIGN_KEY_ID):
            sys.exit(f"the signer's public key for {SIGN_KEY_ID} is not the one in the pinned key list: refusing to sign")
        print(f"signing through the signer at {addr} as {SIGN_KEY_ID}")
        return key
    if path and os.path.exists(path):
        print(f"signing with the key file {path} as {SIGN_KEY_ID}")
        return atpp.load_private_key(path)
    return None


def selftest_sign(n, key):
    """Sign `n` synthetic scores (one batched call, plus one single sign) and verify each envelope with the
    public verifier against the pinned key list, offline. Publishes nothing, writes nothing. Returns True on success."""
    scores = {}
    for i in range(n):
        sc = score({"name": f"selftest/server-{i}", "version": "1.0.0", "remotes": [{"type": "streamable-http", "url": f"https://selftest-{i}.example/mcp"}]})
        scores[f"selftest/server-{i}"] = sc
    shards = build_shards(scores, datetime.now(timezone.utc).strftime("%Y-%m-%d"), "9999-12-31", key)
    envs = [e for sh in shards for e in sh["s"].values()]
    envs.append(atpp.sign(atpp.PAYLOAD_TYPE, atpp.statement("selftest/single", next(iter(scores.values()))), key, SIGN_KEY_ID))
    bad = 0
    for e in envs:
        try:
            status, _ = atpp.check(e, online=False)
            bad += status != 0
        except atpp.VerifyError as ex:
            bad += 1
            print(f"selftest: envelope did not verify: {ex}")
    print(f"selftest: {len(envs) - bad} of {len(envs)} envelopes signed as {SIGN_KEY_ID} verify against the pinned key list")
    return bad == 0 and len(envs) == n + 1


# ---------------------------------------------------------------- checks
# Each check: (id, title, fn(server_manifest) -> (pass: bool, detail: str)).
# A check that cannot apply to this server returns None and is dropped from the total,
# so a remote-only server is never marked down for having no package to pin.

def _secrets(sv):
    out = []
    for p in sv.get("packages", []):
        for e in p.get("environmentVariables", []) or []:
            out.append(("env", e))
    for r in sv.get("remotes", []):
        for h in r.get("headers", []) or []:
            out.append(("header", h))
    return out


def chk_static_secret(sv):
    secrets = [(k, s) for k, s in _secrets(sv) if s.get("isSecret")]
    if not secrets:
        return True, "declares no long-lived secret"
    names = ", ".join(sorted({s.get("name", "?") for _, s in secrets})[:4])
    return False, f"authenticates with a static secret ({names}) — not scoped or rotatable per action"


def chk_secret_no_default(sv):
    secrets = [(k, s) for k, s in _secrets(sv) if s.get("isSecret")]
    if not secrets:
        return None
    bad = [s.get("name", "?") for _, s in secrets if s.get("default")]
    if bad:
        return False, f"secret ships a default value: {', '.join(sorted(set(bad))[:4])}"
    return True, "no secret carries a shipped default"


def chk_transport_tls(sv):
    remotes = sv.get("remotes") or []
    if not remotes:
        return None
    bad = [r.get("url", "") for r in remotes if not str(r.get("url", "")).startswith("https://")]
    if bad:
        return False, f"remote endpoint is not https: {bad[0][:60]}"
    return True, f"all {len(remotes)} remote endpoint(s) over TLS"


def chk_version_pinned(sv):
    pkgs = sv.get("packages") or []
    if not pkgs:
        return None
    bad = [p.get("identifier", "?") for p in pkgs
           if not p.get("version") or str(p.get("version")).lower() in ("latest", "*", "")
           or any(c in str(p.get("version")) for c in "^~><")]
    if bad:
        return False, f"package version is not an exact pin: {', '.join(bad[:3])}"
    return True, "every package pinned to an exact version"


def chk_source_published(sv):
    repo = sv.get("repository") or {}
    url = repo.get("url") if isinstance(repo, dict) else None
    if url:
        return True, f"source published at {str(url)[:70]}"
    return False, "no source repository declared — the code behind this server cannot be reviewed"


def _gh_repo(sv):
    """owner/repo for a declared GitHub source, else None. Display case is kept; callers lowercase to group."""
    repo = sv.get("repository") or {}
    url = repo.get("url") if isinstance(repo, dict) else None
    m = re.search(r"github\.com[:/]+([^/\s]+)/([^/\s#?]+?)(?:\.git)?/?$", str(url or ""))
    return f"{m.group(1)}/{m.group(2)}" if m else None


def _ptype(p):
    return str(p.get("registryType") or p.get("registry_name") or "").lower()


def chk_artifact_hash(sv):
    """MCPB bundles only.

    `fileSha256` is an MCPB-only field: sampled against the live registry, npm, PyPI and OCI packages
    populate it 0% of the time, so requiring it of every package scored "is not an MCPB package" rather
    than "the publisher pinned a hash" -- and auto-failed every npm/PyPI server. An MCPB bundle is a loose
    file with no registry integrity behind it, so there the hash is the only thing to verify against.
    npm and PyPI carry their own integrity and are covered by `version-pinned`; OCI integrity is a digest
    question (a mutable tag vs `@sha256:`) and belongs in its own rule, not this one.
    """
    pkgs = [p for p in (sv.get("packages") or []) if _ptype(p) == "mcpb"]
    if not pkgs:
        return None                 # inapplicable -> score() drops it from the total, never fails it
    have = [p for p in pkgs if p.get("fileSha256")]
    if len(have) == len(pkgs):
        return True, "every MCPB bundle pinned to a content hash"
    return False, f"{len(pkgs) - len(have)} of {len(pkgs)} MCPB bundle(s) publish no fileSha256"


def chk_oci_digest(sv):
    """OCI images only.

    A tag is mutable: `ghcr.io/x/y:1.2.3` can be repointed at different bytes after you approve the
    listing, and nothing in the manifest would change. Only an immutable `@sha256:` digest makes the
    image verifiable. Unlike the MCPB hash field, a digest IS expressible here — publishers can write
    `ghcr.io/x/y@sha256:...` and mostly do not — so this is a real publisher choice, not a category
    error. npm/PyPI carry their own registry integrity; MCPB is covered by artifact-hash.
    """
    pkgs = [p for p in (sv.get("packages") or []) if _ptype(p) == "oci"]
    if not pkgs:
        return None
    loose = [p for p in pkgs
             if "@sha256:" not in f'{p.get("identifier") or ""}{p.get("version") or ""}']
    if not loose:
        return True, "every OCI image pinned to an immutable digest"
    return False, (f"{len(loose)} of {len(pkgs)} OCI image(s) reference a mutable tag rather than an "
                   f"@sha256: digest — the tag can be repointed after you approve the listing")


CHECKS = [
    ("static-secrets", chk_static_secret),
    ("secret-no-default", chk_secret_no_default),
    ("transport-tls", chk_transport_tls),
    ("version-pinned", chk_version_pinned),
    ("source-published", chk_source_published),
    ("artifact-hash", chk_artifact_hash),
    ("oci-digest", chk_oci_digest),
]


def _domain(url):
    host = (urllib.parse.urlparse(url or "").hostname or "").lower()
    p = host.split(".")
    if len(p) >= 3 and len(p[-1]) == 2 and len(p[-2]) <= 3:      # co.uk, com.vn, ...
        return ".".join(p[-3:])
    return ".".join(p[-2:]) if host else None


def _pkg_owner(pk):
    i, t = (pk.get("identifier") or "").lower(), pk.get("registryType")
    if t == "npm":
        return i.split("/")[0] if i.startswith("@") else i.split("@")[0]
    if t == "oci":
        ref = i.split("@")[0].split(":")[0]
        return "/".join(ref.split("/")[:-1]) or ref
    return re.split(r"[=<>@]", i)[0]


def targets(sv):
    """Who the listing points at: remote endpoint domains and package owners (not versions or paths)."""
    rem = {d for d in (_domain(r.get("url")) for r in sv.get("remotes") or []) if d}
    pkg = {(pk.get("registryType"), _pkg_owner(pk)) for pk in sv.get("packages") or []}
    return rem, pkg


def install_keys(sv):
    """How an MCP client config names this server (atpp.install_key), so `atpp check-config` can find it."""
    keys = {atpp.install_key(pk.get("registryType"), pk.get("identifier")) for pk in sv.get("packages") or []}
    keys |= {atpp.install_key("url", r.get("url")) for r in sv.get("remotes") or []}
    return sorted(k for k in keys if k)


def first_record(sv):
    """What target-stable needs from the first published version, small enough to keep in state.json."""
    return {"version": sv.get("version"),
            "remotes": [{"url": r.get("url")} for r in sv.get("remotes") or []],
            "packages": [{"registryType": p.get("registryType"), "identifier": p.get("identifier")}
                         for p in sv.get("packages") or []]}


def chk_target_stable(sv, first):
    """Listing swap: same name, but the endpoint domain or package owner is not the one first published.
    Trust attaches to the name; nothing in an MCP client asks again when what it points at changes."""
    if not first or first is sv or (first.get("version") and first.get("version") == sv.get("version")):
        return None
    r1, p1 = targets(first)
    r2, p2 = targets(sv)
    moved = []
    if r1 and r2 and not (r1 & r2):
        moved.append("remote endpoint moved from %s to %s" % (", ".join(sorted(r1)), ", ".join(sorted(r2))))
    if p1 and p2 and not (p1 & p2):
        moved.append("package owner changed from %s to %s" % (", ".join(sorted(o for _t, o in p1)), ", ".join(sorted(o for _t, o in p2))))
    if bool(r1) != bool(r2) and bool(p1) != bool(p2):
        moved.append("switched between a local package and a remote endpoint")
    v = first.get("version") or "the first version"
    if moved:
        return False, "listing swap: " + "; ".join(moved) + f" since {v} — re-review before trusting it by name"
    return True, f"points at the same domain and package owner as {v}"


def manifest_hash(sv):
    return atpp.manifest_sha256(sv)


def chk_artifacts(sv, arts):
    """The listing names a version; does it exist, and which repo built it? Returns (checks, artifact rows).
    Missing provenance is recorded in the claim but not scored: about a quarter of npm and under half of PyPI
    MCP packages have it today. # ponytail: score absence too once adoption makes it a fair bar."""
    rows, missing, foreign = [], [], []
    declared = (_gh_repo(sv) or "").lower() or None
    for pk in sv.get("packages") or []:
        k = artifacts.key(pk)
        r = arts.get(k) if k else None
        if not r:
            continue
        t, i, v = k.split("|", 2)
        if "error" in r:
            if "404" in r["error"]:
                missing.append(f"{t} {i}@{v}")
            continue
        rows.append([t, i, v, r.get("digest"), r.get("provenance")])
        if r.get("provenance") and declared and r["provenance"] != declared:
            foreign.append(f"{t} {i} was built from {r['provenance']}, not the declared {declared}")
    checks = []
    if missing or rows:
        checks.append(("artifact-resolves", not missing, "listed version not published: " + ", ".join(missing) if missing
                       else "every listed package version exists; its digest is in this claim"))
    built = [r for r in rows if r[4] and r[0] in ("npm", "pypi")]
    if built:
        checks.append(("build-provenance", not foreign, "; ".join(foreign) if foreign
                       else "Sigstore build provenance from " + ", ".join(sorted({r[4] for r in built}))))
    return checks, rows


def chk_tools_stable(sv, prev, now):
    """The server's advertised tool definitions changed while its version did not. Hosted servers redeploy
    without bumping their registry version all the time, so on its own this is a prompt to re-review the tool
    descriptions, not a failure: `score` fails it only alongside a listing swap or a build the scan could not
    vouch for, which is the rug-pull pattern (OWASP MCP03). A change that comes with a new version passes;
    there is nothing to compare on first sight. Returns (ok, detail, review)."""
    was = (prev or {}).get("tools")
    if not now or "sha256" not in now or not was or not was.get("sha256"):
        return None
    if was["sha256"] == now["sha256"]:
        return True, f"tool definitions ({now['count']}) unchanged since {was.get('as_of', 'the previous scan')}", False
    if was.get("version") != (sv.get("version") or "latest"):
        return True, f"tool definitions changed with the new version {sv.get('version')} (was {was.get('version')})", False
    return True, (f"tool definitions changed since {was.get('as_of', 'the previous scan')} without a new version "
                  f"({sv.get('version')}): re-review the tool descriptions"), True


def score(sv, prev=None, first=None, arts=None, tools=None):
    checks, passed = [], 0
    for cid, fn in CHECKS:
        r = fn(sv)
        if r is None:
            continue
        ok, detail = r
        passed += bool(ok)
        checks.append({"id": cid, "pass": bool(ok), "detail": detail})
    r = chk_target_stable(sv, first)
    if r is not None:
        passed += bool(r[0])
        checks.append({"id": "target-stable", "pass": bool(r[0]), "detail": r[1]})
    rows = None
    if arts is not None:
        extra, rows = chk_artifacts(sv, arts)
        for cid, ok, detail in extra:
            passed += bool(ok)
            checks.append({"id": cid, "pass": bool(ok), "detail": detail})
    r = chk_tools_stable(sv, prev, tools)
    if r is not None:
        ok, detail, review = r
        risky = [c["id"] for c in checks if not c["pass"] and c["id"] in ("target-stable", "artifact-resolves", "build-provenance")]
        if review and risky:            # a tool change on top of a swapped target or an unvouched build: the rug-pull pattern
            ok, detail = False, f"{detail}, and {', '.join(risky)} failed: the rug-pull pattern, do not trust it by name"
        passed += bool(ok)
        checks.append({"id": "tools-stable", "pass": bool(ok), "detail": detail, **({"review": True} if review else {})})
    h = manifest_hash(sv)
    if prev and prev.get("sha256"):
        ok = prev["sha256"] == h
        checks.append({"id": "unchanged-since-last-scan", "pass": ok,
                       "detail": "manifest unchanged since the previous scan" if ok
                       else f"manifest changed since {prev.get('as_of', 'the previous scan')} — re-review before trusting the prior approval"})
        passed += bool(ok)
    now = datetime.now(timezone.utc)
    return {
        "passed": passed, "total": len(checks),
        "as_of": now.strftime("%Y-%m-%d"),
        "valid_until": (now + timedelta(days=VALID_DAYS)).strftime("%Y-%m-%d"),
        "version": sv.get("version") or "latest",
        "sha256": h,
        "rules_version": RULES_VERSION,
        "checks": checks,
        **({"artifacts": rows} if rows else {}),
        **({"tools": {"sha256": tools["sha256"], "count": tools["count"]}} if tools and "sha256" in tools else {}),
    }


# ---------------------------------------------------------------- registry
def fetch_registry(cache=None, limit=100, all_versions=False):
    """Latest version of every server, or with all_versions every version ever published (~3x the pages)."""
    if cache and os.path.exists(cache):
        return json.load(open(cache))
    out, cur, fails = [], None, 0
    while True:
        u = f"{REGISTRY}?{'' if all_versions else 'version=latest&'}limit={limit}" + (f"&cursor={urllib.parse.quote(cur)}" if cur else "")
        try:
            d = json.load(urllib.request.urlopen(u, timeout=FETCH_TIMEOUT))
            fails = 0
        except Exception:               # the registry 500s and stalls (~40 s pages seen) intermittently
            fails += 1
            if fails > FETCH_RETRIES:
                raise
            time.sleep(min(60, 3 * 2 ** (fails - 1)))   # 3, 6, 12, 24, 48, 60, 60 ... seconds; resumes at this cursor
            continue
        out += d.get("servers", [])
        cur = (d.get("metadata") or {}).get("nextCursor")
        if not cur:
            break
    if cache:
        json.dump(out, open(cache, "w"))
    return out


def kv_key(name):
    """Registry names are `<namespace>/<name>`; the badge route is /badge/mcp/<ns>/<name>.svg."""
    return "mcp:" + name


def shard_of(name):
    """FNV-1a (32-bit) over the UTF-8 name, mod SHARDS. workers/atf-badge/src/index.js must match."""
    h = 0x811C9DC5
    for b in name.encode("utf-8"):
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h % SHARDS


def shard_key(i):
    return f"atf:shard:{i:03d}"


def build_shards(scores, as_of, valid_until, key=None):
    """Every current score, grouped by shard. A server that left the registry simply is not in
    any shard, so its badge goes grey on the next run instead of staying green on an old score.

    With a signing key each entry is a DSSE envelope (an in-toto Statement signed with Ed25519) and
    the Worker renders nothing but grey unless the signature verifies. Without one the entry is the
    old unsigned tuple, which the Worker now treats as "unsigned" (grey) — so it is only for tests."""
    shards = [{"as_of": as_of, "valid_until": valid_until, "rules_version": RULES_VERSION, "s": {}}
              for _ in range(SHARDS)]
    names = list(scores)
    if key is not None:
        for i in range(0, len(names), SIGN_CHUNK):       # a remote signer signs each chunk in a few round trips
            part = names[i:i + SIGN_CHUNK]
            envs = atpp.sign_many(atpp.PAYLOAD_TYPE, [atpp.statement(n, scores[n]) for n in part], key, SIGN_KEY_ID)
            for n, env in zip(part, envs):
                shards[shard_of(n)]["s"][n] = env
    else:
        for n, sc in scores.items():
            shards[shard_of(n)]["s"][n] = [sc["passed"], sc["total"], sc.get("version"), sc.get("sha256"),
                                           [[c["id"], int(c["pass"]), c["detail"]] for c in sc["checks"]]]
    return shards


def build_manifest(shards, as_of, key, reports=None):
    """The day's commitment: every envelope's sha256, signed. Its own sha256 goes into the public
    git log (bl014h/atpp), so a claim swapped or backdated later shows up as a mismatch."""
    entries = {n: atpp.envelope_sha256(e) for sh in shards for n, e in sh["s"].items()}
    body = {"_type": "https://millenniums.ai/atpp/manifest/v1", "date": as_of, "keyid": SIGN_KEY_ID,
            "count": len(entries), "entries": dict(sorted(entries.items()))}
    if reports:                       # the public aggregate report and search index, signed and committed too
        body["reports"] = {k: atpp.envelope_sha256(v) for k, v in sorted(reports.items())}
    env = atpp.sign(atpp.MANIFEST_TYPE, body, key, SIGN_KEY_ID)
    return env, {"date": as_of, "keyid": SIGN_KEY_ID, "count": len(entries),
                 "manifest_sha256": atpp.envelope_sha256(env)}


def attach_shard_manifests(shards, manifest_sha256, issued, key):
    """Sign each shard's slice of the day's manifest INTO the shard (field `m`): the sorted sha256 of every
    envelope in it, the publish time and the full manifest's hash. The Worker can then check the envelope it
    serves against its own shard, with no second KV read to disagree with it. Names are not repeated: each
    envelope's signed subject already names its server. A no-op without a key (tests only)."""
    if key is None:
        return
    for i, sh in enumerate(shards):
        body = {"_type": "https://millenniums.ai/atpp/shardman/v1", "shard": i, "issued": issued, "keyid": SIGN_KEY_ID,
                "manifest_sha256": manifest_sha256, "h": sorted(atpp.envelope_sha256(e) for e in sh["s"].values())}
        sh["m"] = atpp.sign(atpp.SHARDMAN_TYPE, body, key, SIGN_KEY_ID)


def build_index(manifest_sha256, count, as_of, issued, valid_until, key, prev=None):
    """The small signed pointer (~0.7 KB) to the current publish: which manifest is current and which one it
    replaced. `prev` lets the Worker keep accepting last publish's shards for a short grace while edge caches
    and a non-atomic KV write catch up; it is {issued, manifest_sha256} of the index it replaced, or None."""
    body = {"_type": "https://millenniums.ai/atpp/index/v1", "date": as_of, "issued": issued, "valid_until": valid_until,
            "keyid": SIGN_KEY_ID, "manifest_sha256": manifest_sha256, "count": count, "shards": SHARDS, "prev": prev}
    return atpp.sign(atpp.INDEX_TYPE, body, key, SIGN_KEY_ID)


def prev_from_index(doc, now):
    """{issued, manifest_sha256} from an index document read back from KV, or None unless it carries our
    signature, is not from the future and is younger than PREV_INDEX_MAX_AGE. KV is writable by anyone holding the
    Cloudflare token, so what we read back is checked before it is signed into the next index."""
    try:
        b = atpp.open_envelope(doc, atpp.INDEX_TYPE)
        t = datetime.strptime(b["issued"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        if b.get("_type") != "https://millenniums.ai/atpp/index/v1" or not t < now or now - t > PREV_INDEX_MAX_AGE:
            return None
        return {"issued": b["issued"], "manifest_sha256": b["manifest_sha256"]}
    except Exception:
        return None


def _cf_env():
    env = dict(os.environ, CLOUDFLARE_ACCOUNT_ID=os.environ.get("CLOUDFLARE_ACCOUNT_ID", ""))
    env.pop("CLOUDFLARE_API_TOKEN", None)   # on the Mac the cached wrangler login is the one that works
    if os.environ.get("ATF_CF_TOKEN"):      # in CI: a token scoped to Workers KV, passed under its own name
        env["CLOUDFLARE_API_TOKEN"] = os.environ["ATF_CF_TOKEN"]
    return env


def fetch_prev_index(env, now):
    """The index live in KV right now, as `prev` for the next one. Any failure (first publish, network) -> None:
    the only cost is that last publish's shards are not tolerated for the grace window."""
    r = subprocess.run(["npx", "wrangler", "kv", "key", "get", INDEX_KEY, "--binding", KV_BINDING, "--remote"],
                       cwd="workers/atf-badge", env=env, capture_output=True, text=True)
    try:
        prev = prev_from_index(json.loads(r.stdout), now) if r.returncode == 0 else None
    except ValueError:
        prev = None
    if prev is None:
        print("no previous index carried (first indexed publish, or KV's copy did not verify): the Worker will not "
              "tolerate last publish's shards during the grace window")
    return prev


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="scanner/out")
    ap.add_argument("--cache", help="reuse a saved registry dump instead of refetching")
    ap.add_argument("--no-tools", action="store_true", help="skip fetching remote tool lists (tools-stable)")
    ap.add_argument("--all-versions", action="store_true",
                    help="fetch every version, not just the latest: rebuilds each server's first-published record "
                         "for target-stable (daily runs keep it in state.json)")
    ap.add_argument("--publish", action="store_true", help="push changed scores to KV via wrangler")
    ap.add_argument("--report", help="also write the aggregate here (the subsite reads trust/mcp-scan.json)")
    ap.add_argument("--max-writes", type=int, default=900, help="ignored since sharding (a run is ~260 writes); kept so old callers still work")
    ap.add_argument("--sign-key", default=SIGN_KEY_PATH, help="Ed25519 PEM that signs every score (--publish needs it, or the signer: ATPP_SIGNER_ADDR)")
    ap.add_argument("--selftest-sign", type=int, metavar="N", help="sign N synthetic scores with the configured key or signer, verify "
                    "them against the pinned key list, and exit; publishes and writes nothing")
    a = ap.parse_args()
    key = None
    if a.publish or a.selftest_sign:     # never publish an unsigned claim: the Worker would render it grey anyway
        key = load_signing_key(a.sign_key)
        if key is None:
            sys.exit(f"--publish needs a signing key: the signer (ATPP_SIGNER_ADDR) or the key file {a.sign_key} (ATPP_SIGNING_KEY); refusing to publish unsigned scores")
    if a.selftest_sign:
        sys.exit(0 if selftest_sign(a.selftest_sign, key) else 1)
    os.makedirs(a.out, exist_ok=True)
    state_path = os.path.join(a.out, "state.json")
    state = json.load(open(state_path)) if os.path.exists(state_path) else {}

    servers = fetch_registry(a.cache, all_versions=a.all_versions)
    latest, first = {}, {}
    for s in servers:                    # the registry returns every version; keep the newest per name
        sv = s.get("server") or {}
        name = sv.get("name")
        meta = (s.get("_meta") or {}).get("io.modelcontextprotocol.registry/official") or {}
        if not name or meta.get("status") == "deleted":
            continue
        cur = latest.get(name)
        if not cur or (meta.get("updatedAt") or "") >= (cur[1].get("updatedAt") or ""):
            latest[name] = (sv, meta)
        f = first.get(name)                # and the oldest, to see whether the name now points somewhere else
        if not f or (meta.get("publishedAt") or "~") < (f[1].get("publishedAt") or "~"):
            first[name] = (sv, meta)

    arts = artifacts.resolve_all([sv for sv, _m in latest.values()], os.path.join(a.out, "artifacts.json"))
    tools = {} if a.no_tools or a.cache else tooldefs.fetch_all([sv for sv, _m in latest.values()])
    firsts = {}
    scores, first_seen, drifted, exemplars = {}, [], [], []
    # Who else claims this repo? `source-published` only checks that a repository URL is PRESENT, so a
    # listing can declare anyone's repo -- including the registry's own. Counting distinct servers per
    # repo, and comparing the repo owner against an io.github.<user> namespace, turns that into a number.
    src_claims, owner_mismatch, src_declared = {}, 0, 0
    agg = {"servers": 0, "checks": {}, "passed_all": 0}
    for name, (sv, _meta) in sorted(latest.items()):
        # A daily run sees only the latest version, so the first-published record comes from state, where an
        # --all-versions run (or the server's first appearance) put it. A full fetch is the authority.
        seen = (first.get(name) or (None,))[0]
        firstsv = seen if a.all_versions or a.cache else ((state.get(name) or {}).get("first") or seen)
        firsts[name] = first_record(firstsv) if firstsv else None
        sc = score(sv, state.get(name), firstsv, arts, tools.get(name))
        scores[name] = sc
        agg["servers"] += 1
        gh = _gh_repo(sv)
        if gh:
            src_declared += 1
            # group case-insensitively (GitHub is), but display the first-seen casing
            src_claims.setdefault(gh.lower(), {"display": gh, "names": set()})["names"].add(name)
            ns = name.split("/")[0]
            if ns.startswith("io.github.") and ns[len("io.github."):].lower() != gh.split("/")[0].lower():
                owner_mismatch += 1
        if sc["passed"] == sc["total"]:
            agg["passed_all"] += 1
            exemplars.append({"name": name, "passed": sc["passed"], "total": sc["total"],
                              "version": sc["version"]})
        for c in sc["checks"]:
            b = agg["checks"].setdefault(c["id"], {"pass": 0, "fail": 0})
            b["pass" if c["pass"] else "fail"] += 1
        prev = state.get(name)
        # Sharding republishes every score every run, so a rules bump needs no help here — counting it
        # as drift would report the whole registry as "changed". Keep NEW listings apart from DRIFTED
        # ones: only a rewritten manifest means "the thing you approved changed underneath you".
        if not prev:
            first_seen.append(name)
        elif prev.get("sha256") != sc["sha256"]:
            drifted.append(name)

    json.dump(scores, open(os.path.join(a.out, "scores.json"), "w"), indent=1)
    agg["as_of"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    agg["rules_version"] = RULES_VERSION
    changed = first_seen + drifted
    agg["changed_since_last_scan"] = len(changed)      # kept: older readers of the aggregate
    agg["new_since_last_scan"] = len(first_seen)
    agg["drifted_since_last_scan"] = len(drifted)      # the only one that means "re-review your approval"
    shared = sorted(((v["display"], len(v["names"])) for v in src_claims.values() if len(v["names"]) > 1),
                    key=lambda x: -x[1])
    agg["listing_swaps"] = sum(1 for sc in scores.values() for c in sc["checks"] if c["id"] == "target-stable" and not c["pass"])
    agg["tools_fingerprinted"] = sum(1 for v in tools.values() if "sha256" in v)
    agg["tools_changed_without_version_bump"] = sum(1 for sc in scores.values() for c in sc["checks"] if c["id"] == "tools-stable" and c.get("review"))
    cards = [v["sd_card"] for v in tools.values() if "sd_card" in v]
    agg["sd_cards"] = sum(1 for c in cards if "error" not in c)
    agg["sd_card_tools_changed"] = sum(1 for c in cards if c.get("changed"))
    agg["tools_rug_pull_pattern"] = sum(1 for sc in scores.values() for c in sc["checks"] if c["id"] == "tools-stable" and not c["pass"])
    agg["source_declared"] = src_declared
    agg["source_owner_mismatch"] = owner_mismatch
    agg["source_shared_servers"] = sum(n for _r, n in shared)
    agg["source_shared_top"] = [{"repo": r, "servers": n} for r, n in shared[:8]]
    def build_report(published):
        """The report links a badge per exemplar, so only ever name servers already in KV —
        an exemplar whose badge reads "not scanned" is exactly the UI-implies-nothing failure."""
        live = [e for e in exemplars if e["name"] in published]
        agg["exemplars"] = sorted(live, key=lambda e: (-e["total"], e["name"]))[:12]
        agg["published"] = len(published)
        json.dump(agg, open(os.path.join(a.out, "aggregate.json"), "w"), indent=1)
        if a.report:
            json.dump(agg, open(a.report, "w"), indent=1)
    agg["registry"] = "registry.modelcontextprotocol.io"
    build_report(set(state))
    print(f"scanned {agg['servers']} servers · {agg['passed_all']} passed every check · {len(changed)} changed")
    for cid, b in agg["checks"].items():
        t = b["pass"] + b["fail"]
        print(f"  {cid:26} {b['pass']:5}/{t:5}  {100*b['pass']//max(t,1):3}% pass")

    if not a.publish:
        return                       # report already written from what is live in KV
    # Publish every score, every run, as SHARDS values rather than one key per server. The old
    # per-server writes were capped at ~900/day, so an unchanged server was never re-written and
    # its badge went grey seven days after the seed even though every run re-scored it.
    as_of = agg["as_of"]
    valid_until = (datetime.now(timezone.utc) + timedelta(days=VALID_DAYS)).strftime("%Y-%m-%d")
    shards = build_shards(scores, as_of, valid_until, key)
    build_report(set(scores))        # final aggregate: every scored server is published in this same write
    names_doc = {"as_of": as_of, "n": sorted([n, sc["passed"], sc["total"], install_keys(latest[n][0])]
                                             for n, sc in scores.items())}
    reports = {"mcp-scan": atpp.sign(atpp.REPORT_TYPE, agg, key, SIGN_KEY_ID),
               "mcp-names": atpp.sign(atpp.REPORT_TYPE, names_doc, key, SIGN_KEY_ID)}
    manifest, log_entry = build_manifest(shards, as_of, key, reports)
    # Everything the signer has to sign is signed before the first KV write, so a signer that dies mid-run
    # leaves KV and state untouched (the anchor used to be signed after the write).
    anc = atpp.sign(atpp.ANCHOR_TYPE, atpp.anchor(manifest, as_of, SIGN_KEY_ID), key, SIGN_KEY_ID)
    anchor_pem = atpp.public_pem(key)
    env = _cf_env()
    now = datetime.now(timezone.utc)
    issued = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    attach_shard_manifests(shards, log_entry["manifest_sha256"], issued, key)
    index = build_index(log_entry["manifest_sha256"], log_entry["count"], as_of, issued, valid_until, key,
                        fetch_prev_index(env, now))
    c = lambda o: json.dumps(o, separators=(",", ":"))
    bulk = [{"key": shard_key(i), "value": c(d)} for i, d in enumerate(shards)]
    bulk.append({"key": NAMES_KEY, "value": c(names_doc)})
    bulk.append({"key": NAMES_KEY + ":dsse", "value": c(reports["mcp-names"])})
    bulk.append({"key": AGG_KEY, "value": c(agg)})
    bulk.append({"key": AGG_KEY + ":dsse", "value": c(reports["mcp-scan"])})
    bulk.append({"key": MANIFEST_KEY, "value": json.dumps(manifest, separators=(",", ":"))})
    bulk.append({"key": f"atf:manifest:{as_of}", "value": json.dumps(manifest, separators=(",", ":")),
                 "expiration_ttl": KV_TTL_DAYS * 86400})
    # The index goes last in the file, but nothing depends on it: the Worker accepts a shard from this publish, from
    # the previous one (for a grace window) or from a newer one, so every interleaving of this non-atomic write is safe.
    bulk.append({"key": INDEX_KEY, "value": c(index)})
    bulk_path = os.path.join(a.out, "kv-bulk.json")
    json.dump(bulk, open(bulk_path, "w"))
    r = subprocess.run(["npx", "wrangler", "kv", "bulk", "put", os.path.abspath(bulk_path),
                        "--binding", KV_BINDING, "--remote"],
                       cwd="workers/atf-badge", env=env)
    if r.returncode:
        sys.exit(f"KV bulk put failed ({r.returncode}); state not advanced")
    # Anchor the day's manifest in Sigstore Rekor — a public transparency log we do not control — so a day's
    # claims cannot be backdated or rewritten later even with full control of our own servers and repo.
    log_entry["anchor"] = anc
    try:
        log_entry["rekor"] = atpp.rekor_upload(anc, anchor_pem)
        print(f"anchored in Rekor: log index {log_entry['rekor']['logIndex']}")
    except Exception as e:                                  # never lose a publish over the anchor
        log_entry["rekor"] = None
        print(f"Rekor anchor failed ({e}); the public git log still commits to the manifest")
    json.dump(log_entry, open(os.path.join(a.out, "log-entry.json"), "w"), indent=1)   # only after a successful publish
    def tools_state(n, sc):                 # today's fingerprint, or yesterday's carried forward if the fetch failed
        t = tools.get(n) or {}
        if "sha256" in t:
            return {"sha256": t["sha256"], "version": sc.get("version"), "as_of": sc["as_of"]}
        return (old_state.get(n) or {}).get("tools")
    old_state = state
    state = {n: {"sha256": sc["sha256"], "as_of": sc["as_of"], "first": firsts.get(n), "tools": tools_state(n, sc)}
             for n, sc in scores.items()}
    json.dump(state, open(state_path, "w"), indent=1)
    print(f"published {len(scores)} scores in {SHARDS} shards + signed report and name index ({len(bulk)} KV writes)")

def run():
    try:
        main()
    except Exception as e:
        if type(e).__name__ != "SignerError":       # app/signer.py is imported lazily, so match by name
            raise
        # all signing happens before the first KV write, so a signer that dies or refuses leaves KV and state untouched
        sys.exit(f"signer failed: {e}; nothing was published and state was not advanced")


if __name__ == "__main__":
    run()
