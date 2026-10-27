"""What a listing's packages actually are: the exact bytes and who built them.

A registry listing names a package and a version. That is a pointer, not the code. For each package this
resolves, at scan time:
  - the artifact digest: npm `dist.integrity` (sha512), the PyPI file sha256s, or the OCI manifest digest
    behind the tag (tags can be repointed, so OCI is re-resolved every scan);
  - build provenance: the Sigstore-signed SLSA attestation npm and PyPI keep for packages published from CI,
    reduced to the source repository it names.

npm and PyPI check the Sigstore signature when the attestation is uploaded, so here we read the repository
the registry vouched for rather than re-verifying the bundle. # ponytail: registry-verified, add local
sigstore-python verification if a registry is ever shown to accept a bad bundle.

npm/PyPI results are cached per exact version (immutable once published); OCI is never cached.
"""
import base64, concurrent.futures, json, os, re, urllib.error, urllib.parse, urllib.request

UA = "atpp-scan/1.0 (+https://trust.redthreadsec.com/mcp-scan.html)"
EXACT = re.compile(r"^v?\d+(\.\d+)*([-+.][0-9A-Za-z.-]+)?$")
OCI_ACCEPT = ", ".join(["application/vnd.oci.image.index.v1+json", "application/vnd.oci.image.manifest.v1+json",
                        "application/vnd.docker.distribution.manifest.list.v2+json",
                        "application/vnd.docker.distribution.manifest.v2+json"])


def _req(url, method="GET", headers=None, timeout=20):
    h = {"User-Agent": UA, **(headers or {})}
    return urllib.request.urlopen(urllib.request.Request(url, method=method, headers=h), timeout=timeout)


def _json(url):
    with _req(url) as r:
        return json.load(r)


def _repo(url):
    """github.com/owner/repo → owner/repo (lowercase), else the bare host+path."""
    s = str(url or "").lower().strip()
    m = re.search(r"github\.com[:/]+([^/\s]+)/([^/\s#?]+?)(?:\.git)?/?$", s)
    return f"{m.group(1)}/{m.group(2)}" if m else (s or None)


def npm(name, version):
    d = _json(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}/{urllib.parse.quote(version)}")
    dist = d.get("dist") or {}
    prov = None
    att = dist.get("attestations") or {}
    if att.get("url"):
        for a in (_json(att["url"]).get("attestations") or []):
            if "slsa.dev/provenance" not in str(a.get("predicateType")):
                continue
            st = json.loads(base64.b64decode(a["bundle"]["dsseEnvelope"]["payload"]))
            wf = ((st.get("predicate") or {}).get("buildDefinition") or {}).get("externalParameters", {}).get("workflow", {})
            prov = _repo(wf.get("repository"))
    return {"digest": dist.get("integrity") or (("sha1-" + dist["shasum"]) if dist.get("shasum") else None),
            "provenance": prov}


def pypi(name, version):
    d = _json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json")
    files = sorted((u["filename"], u["digests"]["sha256"]) for u in d.get("urls") or [])
    prov = None
    for fn, _sha in files:
        try:
            p = _json(f"https://pypi.org/integrity/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/{urllib.parse.quote(fn)}/provenance")
        except urllib.error.HTTPError:
            continue
        for b in p.get("attestation_bundles") or []:
            pub = b.get("publisher") or {}
            if pub.get("repository"):
                prov = _repo("github.com/" + pub["repository"]) if pub.get("kind") == "GitHub" else _repo(pub["repository"])
                break
        if prov:
            break
    return {"digest": ";".join(f"sha256:{s}" for _f, s in files) or None, "provenance": prov}


def _oci_ref(ident):
    """(registry host, repository, reference) for an image reference; Docker Hub defaults applied."""
    ref = ident.strip()
    if "@sha256:" in ref:
        name, digest = ref.split("@", 1)
        tag = digest
    else:
        name, _, tag = ref.rpartition(":") if ":" in ref.rsplit("/", 1)[-1] else (ref, "", "latest")
        tag = tag or "latest"
    parts = name.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        host, repo = parts[0], "/".join(parts[1:])
    else:
        host, repo = "registry-1.docker.io", name if "/" in name else "library/" + name
    if host == "docker.io":
        host = "registry-1.docker.io"
    return host, repo, tag


def oci(ident, version=None):
    host, repo, tag = _oci_ref(ident if ":" in ident.rsplit("/", 1)[-1] or "@" in ident or not version
                               else f"{ident}:{version}")
    if tag.startswith("sha256:"):
        return {"digest": tag, "provenance": None}
    url = f"https://{host}/v2/{repo}/manifests/{tag}"
    h = {"Accept": OCI_ACCEPT}
    try:
        with _req(url, "HEAD", h) as r:
            return {"digest": r.headers.get("Docker-Content-Digest"), "provenance": None}
    except urllib.error.HTTPError as e:
        if e.code != 401:
            raise
        ch = e.headers.get("WWW-Authenticate") or ""
    kv = dict(re.findall(r'(\w+)="([^"]*)"', ch))
    if not kv.get("realm"):
        raise RuntimeError("registry wants auth with no bearer realm")
    q = {"service": kv.get("service", ""), "scope": kv.get("scope") or f"repository:{repo}:pull"}
    tok = _json(kv["realm"] + "?" + urllib.parse.urlencode({k: v for k, v in q.items() if v}))
    h["Authorization"] = "Bearer " + (tok.get("token") or tok.get("access_token") or "")
    with _req(url, "HEAD", h) as r:
        return {"digest": r.headers.get("Docker-Content-Digest"), "provenance": None}


RESOLVERS = {"npm": npm, "pypi": pypi, "oci": oci}


def key(pk):
    t, i, v = (pk.get("registryType") or "").lower(), pk.get("identifier") or "", str(pk.get("version") or "")
    if t not in RESOLVERS or not i:
        return None
    if t != "oci" and not EXACT.match(v):        # a range or "latest" has no single artifact to name
        return None
    return f"{t}|{i}|{v}"


def resolve_all(servers, cache_path, workers=16):
    """{key: {"digest", "provenance"} | {"error"}} for every package of every server. npm/PyPI from cache
    when already resolved; OCI every run."""
    try:
        cache = json.load(open(cache_path))
    except Exception:
        cache = {}
    want = {k for sv in servers for k in (key(p) for p in sv.get("packages") or []) if k}
    todo = [k for k in want if k.startswith("oci|") or k not in cache or "error" in cache[k]]

    def one(k):
        t, i, v = k.split("|", 2)
        try:
            return k, RESOLVERS[t](i, v)
        except Exception as e:
            return k, {"error": f"{e.__class__.__name__}: {str(e)[:80]}"}

    with concurrent.futures.ThreadPoolExecutor(workers) as ex:
        for k, r in ex.map(one, todo):
            cache[k] = r
    tmp = cache_path + ".tmp"
    json.dump({k: cache[k] for k in cache if not k.startswith("oci|")}, open(tmp, "w"))
    os.replace(tmp, cache_path)
    return {k: cache[k] for k in want}


if __name__ == "__main__":
    assert key({"registryType": "npm", "identifier": "@a/b", "version": "1.2.3"}) == "npm|@a/b|1.2.3"
    assert key({"registryType": "npm", "identifier": "@a/b", "version": "^1.2"}) is None
    assert _oci_ref("ghcr.io/o/i:1.0") == ("ghcr.io", "o/i", "1.0")
    assert _oci_ref("mcp/fetch") == ("registry-1.docker.io", "mcp/fetch", "latest")
    assert _oci_ref("redis") == ("registry-1.docker.io", "library/redis", "latest")
    assert _repo("git+https://github.com/Microsoft/Playwright-MCP.git") == "microsoft/playwright-mcp"
    print("ok")
