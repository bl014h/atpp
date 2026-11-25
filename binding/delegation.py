"""Delegation Receipts (draft-le-agent-passport-01, "Delegation Receipts"): grants, the attenuation test, request
matching, limit counting and receipt issuance.

Pure and offline, like rp_policy.py: keys, the clock and the counters are arguments. app/atpp_verify.py does chain
validation (signatures, passports, status) and calls these for the decisions. Reasons are the scenario names in
docs/hackathon/ietf127 (`attenuation:<member>`, `limit-aud-not-single`, `limit-exceeded`).

Run `python3 app/delegation.py` for a self-check."""
import hashlib
import posixpath
import re
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit

try:
    import passport as pp     # digests and issuance only; grants and matching are stdlib, so the gateway ships this alone
except ImportError:
    pp = None

DLG_TYP = "agent-delegation+jwt"
MAX_CHAIN = 8
GRANT_MEMBERS = frozenset({"host", "port", "methods", "paths", "tools", "max_body_bytes"})
LIMIT_MEMBERS = frozenset({"max_calls", "max_spend"})
DEFAULTS = {"port": 443, "methods": ["GET", "HEAD"], "paths": ["/*"], "max_body_bytes": 0}
_UNRESERVED = re.compile(r"%([0-9A-Fa-f]{2})")
APPROVAL_MEMBERS = frozenset({"method", "at", "action_digest", "display_digest", "authenticator_sig", "kid",
                              "checked_by", "profile", "webauthn"})
WEBAUTHN_MEMBERS = frozenset({"authenticator_data", "client_data_json"})
PRINCIPAL_MEMBERS = frozenset({"ev_iss", "assurance", "ev_time", "res_process"})
ROOT_ONLY = ("dlg_approval", "dlg_principal")           # a child carries neither; validation carries the root's
_DIGEST = re.compile(r"sha-256:([A-Za-z0-9_-]{43}|[0-9a-f]{64})")


def digest(text):
    """Digest Object over the ASCII bytes of a JWS Compact Serialization (`dlg_parent`)."""
    return {"alg": "sha-256", "val": pp.b64u(hashlib.sha256(text.encode("ascii")).digest())}


# --- grants -------------------------------------------------------------------------------------------------
def norm_host(h):
    """Lowercase, one trailing dot removed, A-labels. A `*.` prefix is kept and the rest normalised."""
    if not isinstance(h, str) or not h:
        raise ValueError("host")
    star = h.startswith("*.")
    rest = h[2:] if star else h
    rest = rest.lower()
    if rest.endswith("."):
        rest = rest[:-1]
    if not rest or "*" in rest:
        raise ValueError("host")
    rest = rest.encode("idna").decode("ascii")      # ponytail: IDNA 2003 codec; swap for the `idna` package if a test needs UTS 46
    return "*." + rest if star else rest


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def grant_problem(g):
    """None for a well-formed grant, else the reason. An unknown member is refused: dropping it would widen."""
    if not isinstance(g, dict):
        return "grant-malformed"
    if set(g) - GRANT_MEMBERS:
        return "unknown-member"
    try:
        h = norm_host(g.get("host")) if g.get("host") != "*" else "*"
    except (ValueError, UnicodeError):
        return "grant-malformed"
    # ponytail: no Public Suffix List bundled, so `*.` over a single label (`*.com`) is the public-suffix case refused;
    # load the PSL here if multi-label suffixes (`*.co.uk`) must be refused too.
    if h.startswith("*.") and "." not in h[2:]:
        return "grant-public-suffix"
    if "port" in g and not (_int(g["port"]) and 0 < g["port"] < 65536):
        return "grant-malformed"
    for k in ("methods", "paths", "tools"):
        if k in g and not (isinstance(g[k], list) and all(isinstance(x, str) and x for x in g[k])):
            return "grant-malformed"
    if any(not p.startswith("/") for p in g.get("paths", [])):
        return "grant-malformed"
    if "max_body_bytes" in g and not (_int(g["max_body_bytes"]) and g["max_body_bytes"] >= 0):
        return "grant-malformed"
    return None


def full(g):
    """The grant with absent members compared as their defaults (-01) and the host normalised."""
    d = dict(DEFAULTS, **g)
    d["host"] = "*" if g["host"] == "*" else norm_host(g["host"])
    return d


def _host_covered(c, p):
    if p == "*" or c == p:
        return True
    return p.startswith("*.") and (c[2:] if c.startswith("*.") else c).endswith(p[1:])


def _path_covered(c, p):
    if not p.endswith("/*"):
        return c == p
    base = p[:-2]
    return c == base or c.startswith(base + "/")


def covers(c, p):
    """None if grant C is covered by grant P (both from full()), else the first member that is wider."""
    if not _host_covered(c["host"], p["host"]):
        return "host"
    if c["port"] != p["port"]:
        return "port"
    if not set(c["methods"]) <= set(p["methods"]):
        return "methods"
    if not all(any(_path_covered(cp, pp_) for pp_ in p["paths"]) for cp in c["paths"]):
        return "paths"
    if "tools" in p and not ("tools" in c and set(c["tools"]) <= set(p["tools"])):
        return "tools"
    if c["max_body_bytes"] > p["max_body_bytes"]:
        return "max_body_bytes"
    return None


def limits_problem(lim):
    if lim is None:
        return None
    if not isinstance(lim, dict) or not lim:
        return "limits-malformed"
    if set(lim) - LIMIT_MEMBERS:
        return "unknown-member"
    if "max_calls" in lim and not (_int(lim["max_calls"]) and lim["max_calls"] > 0):
        return "limits-malformed"
    if "max_spend" in lim:
        s = lim["max_spend"]
        if isinstance(s, dict) and set(s) - {"currency", "amount"}:
            return "unknown-member"
        if not isinstance(s, dict) or not re.fullmatch(r"[A-Z]{3}", str(s.get("currency"))) or _amount(s.get("amount")) is None:
            return "limits-malformed"
    return None


def _amount(a):
    if not isinstance(a, str) or not re.fullmatch(r"\d+(\.\d+)?", a):
        return None
    try:
        return Decimal(a)
    except InvalidOperation:
        return None


def approval_problem(a):
    """None for a well-formed `dlg_approval`, else `approval-malformed`. `authenticator_sig` and `kid` come together:
    the signature is checked against the key the root's authorisation server vouches for under that kid."""
    if not isinstance(a, dict) or set(a) - APPROVAL_MEMBERS:
        return "approval-malformed"
    if not (isinstance(a.get("method"), str) and a["method"] and _int(a.get("at")) and a["at"] >= 0
            and all(isinstance(a.get(k), str) and _DIGEST.fullmatch(a[k]) for k in ("action_digest", "display_digest"))):
        return "approval-malformed"
    if ("authenticator_sig" in a) != ("kid" in a):
        return "approval-malformed"
    if any(k in a and not (isinstance(a[k], str) and a[k]) for k in ("authenticator_sig", "kid", "profile")):
        return "approval-malformed"
    if "checked_by" in a and not (isinstance(a["checked_by"], str) and a["checked_by"].startswith("https://")):
        return "approval-malformed"
    w = a.get("webauthn")
    if w is not None and not ("authenticator_sig" in a and isinstance(w, dict) and set(w) == WEBAUTHN_MEMBERS
                              and all(isinstance(v, str) and v for v in w.values())):
        return "approval-malformed"
    return None


def approval_message(a):
    """The bytes the person's authenticator signs: action digest, display digest and time, dot-separated (a digest
    string never contains a dot). Proves that authenticator approved that action shown as that display; whether the
    display matches the action is checked only by a verifier that holds the action."""
    return ("%s.%s.%d" % (a["action_digest"], a["display_digest"], a["at"])).encode("ascii")


def sign_approval(priv, kid, method, at, action_digest, display_digest, **extra):
    """A `dlg_approval` signed by an authenticator key (for tests and for authorisation servers that relay one)."""
    a = dict(extra, method=method, at=int(at), action_digest=action_digest, display_digest=display_digest, kid=kid)
    a["authenticator_sig"] = pp.b64u(priv.sign(approval_message(a)))
    return a


# --- WebAuthn assertions ------------------------------------------------------------------------------------
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _authenticator_key(jwk):
    """An Ed25519 (OKP) or P-256 (EC, ES256) public key from a JWK, or ValueError."""
    if isinstance(jwk, dict) and jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        from cryptography.hazmat.primitives.asymmetric import ec
        x, y = pp.unb64u(jwk.get("x")), pp.unb64u(jwk.get("y"))
        if len(x) != 32 or len(y) != 32:
            raise ValueError("jwk length")
        return ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                             ec.SECP256R1()).public_key()
    return pp.key_of(jwk)


def _verify(pub, sig, data):
    """Ed25519, or ES256 as WebAuthn sends it (ASN.1 DER) with a high S refused (Paul Williams, PACE thread)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    try:
        if isinstance(pub, ec.EllipticCurvePublicKey):
            if utils.decode_dss_signature(sig)[1] > P256_N // 2:
                return False
            pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        else:
            pub.verify(sig, data)
        return True
    except (InvalidSignature, ValueError):
        return False


def webauthn_problem(a, jwk, rp_id, origins):
    """None when `dlg_approval.webauthn` is a WebAuthn assertion {{WEBAUTHN}} over this approval, else the reason:
    clientDataJSON type `webauthn.get`, challenge = SHA-256 of approval_message(a), origin among the authorisation
    server's `authenticator_origins`, rpIdHash = SHA-256 of its `authenticator_rp_id`, user present (UP), and the
    signature over authenticatorData || SHA-256(clientDataJSON) by the `kid` key. Second value: user verified (UV)."""
    import json
    w = a["webauthn"]
    try:
        cd_raw, ad = pp.unb64u(w["client_data_json"]), pp.unb64u(w["authenticator_data"])
        cd = json.loads(cd_raw)
        pub = _authenticator_key(jwk)
    except (ValueError, TypeError):
        return "approval-webauthn-malformed", False
    if not isinstance(cd, dict) or len(ad) < 37:
        return "approval-webauthn-malformed", False
    if cd.get("type") != "webauthn.get":
        return "approval-webauthn-type", False
    if cd.get("challenge") != pp.b64u(hashlib.sha256(approval_message(a)).digest()):
        return "approval-webauthn-challenge", False
    if not isinstance(origins, list) or cd.get("origin") not in origins:
        return "approval-webauthn-origin", False
    if not isinstance(rp_id, str) or ad[:32] != hashlib.sha256(rp_id.encode()).digest():
        return "approval-webauthn-rp", False
    if not ad[32] & 0x01:
        return "approval-webauthn-up", False
    try:
        sig = pp.unb64u(a["authenticator_sig"])
    except (ValueError, TypeError):
        return "approval-signature", False
    if not _verify(pub, sig, ad + hashlib.sha256(cd_raw).digest()):
        return "approval-signature", False
    return None, bool(ad[32] & 0x04)


def sign_webauthn_approval(priv, kid, rp_id, origin, at, action_digest, display_digest, flags=0x05, cd_type="webauthn.get",
                           **extra):
    """A `dlg_approval` carrying a WebAuthn assertion as an authenticator would make it (tests; flags 0x05 = UP|UV)."""
    import json
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    a = dict(extra, method="webauthn", at=int(at), action_digest=action_digest, display_digest=display_digest, kid=kid)
    cd = json.dumps({"type": cd_type, "challenge": pp.b64u(hashlib.sha256(approval_message(a)).digest()),
                     "origin": origin, "crossOrigin": False}).encode()
    ad = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + (1).to_bytes(4, "big")
    data = ad + hashlib.sha256(cd).digest()
    if isinstance(priv, ec.EllipticCurvePrivateKey):
        from cryptography.hazmat.primitives.asymmetric import utils
        r, s = utils.decode_dss_signature(priv.sign(data, ec.ECDSA(hashes.SHA256())))
        sig = utils.encode_dss_signature(r, min(s, P256_N - s))                  # low S, as authenticators send
    else:
        sig = priv.sign(data)
    a["webauthn"] = {"authenticator_data": pp.b64u(ad), "client_data_json": pp.b64u(cd)}
    a["authenticator_sig"] = pp.b64u(sig)
    return a


def principal_problem(p):
    """None for a well-formed `dlg_principal` (Principal Evidence), else `principal-malformed`. It may carry nothing
    about the principal: an unknown member is refused, never passed on."""
    if not isinstance(p, dict) or set(p) - PRINCIPAL_MEMBERS:
        return "principal-malformed"
    if not all(isinstance(p.get(k), str) and p[k] for k in ("ev_iss", "assurance")) or not (_int(p.get("ev_time"))
                                                                                         and p["ev_time"] >= 0):
        return "principal-malformed"
    if "res_process" in p and not (isinstance(p["res_process"], str) and p["res_process"].startswith("https://")):
        return "principal-malformed"
    return None


def receipt_problems(claims):
    """Shape of one receipt's delegation claims; reasons in the `attenuation:` namespace for unknown members."""
    g = claims.get("dlg_grants")
    if not isinstance(g, list) or not g:
        return ["grants-missing"]
    why = [p for k, fn in (("dlg_approval", approval_problem), ("dlg_principal", principal_problem))
           if k in claims for p in [fn(claims[k])] if p]
    for x in g:
        p = grant_problem(x)
        if p:
            why.append("attenuation:unknown-member" if p == "unknown-member" else p)
    p = limits_problem(claims.get("dlg_limits"))
    if p:
        why.append("attenuation:unknown-member" if p == "unknown-member" else p)
    aud = claims.get("aud")
    if aud is not None and not (isinstance(aud, list) and aud and all(isinstance(a, str) for a in aud)):
        why.append("aud-malformed")
    return sorted(set(why))


def attenuation(child, parent):
    """Reasons the child receipt does not attenuate its parent (empty when it does). Both are claim sets that passed
    receipt_problems(). Conservative, as the draft requires: a child that is narrower in a way this test cannot see is
    refused, never one that is wider accepted."""
    why = []
    pg = [full(g) for g in parent["dlg_grants"]]
    for c in (full(g) for g in child["dlg_grants"]):
        misses = [covers(c, p) for p in pg]
        if None in misses:
            continue
        hosted = [m for m, p in zip(misses, pg) if _host_covered(c["host"], p["host"])]
        why.append("attenuation:" + (hosted[0] if hosted else "host"))
    pl, cl = parent.get("dlg_limits") or {}, child.get("dlg_limits") or {}
    if "max_calls" in pl and not ("max_calls" in cl and cl["max_calls"] <= pl["max_calls"]):
        why.append("attenuation:max_calls")
    if "max_spend" in pl:
        ps, cs = pl["max_spend"], cl.get("max_spend")
        if not cs or cs["currency"] != ps["currency"] or _amount(cs["amount"]) > _amount(ps["amount"]):
            why.append("attenuation:max_spend")
    if child["exp"] > parent["exp"]:
        why.append("attenuation:exp")
    if parent.get("aud") is not None and not (child.get("aud") is not None and set(child["aud"]) <= set(parent["aud"])):
        why.append("attenuation:aud")
    return sorted(set(why))


# --- request matching ---------------------------------------------------------------------------------------
def norm_path(path):
    """RFC 3986 6.2.2 in order: case of percent-encodings, decoding of unreserved characters, dot segments. None for a
    path that must match no grant (`%2F`, `%5C` or `%00` left after normalisation)."""
    def fix(m):
        ch = chr(int(m.group(1), 16))
        return ch if re.fullmatch(r"[A-Za-z0-9._~-]", ch) else "%" + m.group(1).upper()
    p = _UNRESERVED.sub(fix, path or "/")
    if re.search(r"%(2F|5C|00)", p):
        return None
    out = posixpath.normpath(p) if p not in ("", "/") else "/"
    if p.endswith("/") and out != "/":
        out += "/"
    return "/" + out.lstrip("/")


def match(grants, method, url, body_len=0, tool=None):
    """True when the request matches at least one of the leaf receipt's grants."""
    u = urlsplit(url)
    if u.scheme != "https" or not u.hostname:
        return False
    try:
        port = u.port or 443
    except ValueError:
        return False
    return match_parts(grants, method, u.hostname, port, u.path, body_len, tool)


def match_parts(grants, method, host, port, path, body_len=0, tool=None, inspected=True):
    """match() on a request already split, as an egress gateway sees it. `inspected=False` (a tunnel the gateway does
    not open, ATF R14): host and port are all it can see, so only they are compared."""
    try:
        host = norm_host(host)
    except (ValueError, UnicodeError):
        return False
    path = norm_path(path) if inspected else "/"
    if path is None:
        return False
    for g in (full(x) for x in grants):
        if not (g["host"] == "*" or host == g["host"] or (g["host"].startswith("*.") and host.endswith(g["host"][1:]))):
            continue
        if port != g["port"]:
            continue
        if not inspected:
            return True
        if method not in g["methods"] or body_len > g["max_body_bytes"]:
            continue
        if not any(_path_covered(path, p) for p in g["paths"]):
            continue
        if tool is not None and "tools" in g and tool not in g["tools"]:
            continue
        return True
    return False


# --- limits -------------------------------------------------------------------------------------------------
def limit_check(receipts, rp_id, counts, spend=None):
    """Reasons a request under this chain would exceed a limit, counting it. `counts`: {(iss, jti): {"calls": int,
    "spend": Decimal}} held by this RP. A receipt with limits must name exactly this RP as its only audience: separate
    RPs cannot hold one total between them."""
    why = []
    for r in receipts:
        lim = r.get("dlg_limits")
        if not lim:
            continue
        if r.get("aud") != [rp_id]:
            why.append("limit-aud-not-single")
            continue
        n = counts.get((r["iss"], r["jti"]), {"calls": 0, "spend": Decimal(0)})
        if "max_calls" in lim and n["calls"] + 1 > lim["max_calls"]:
            why.append("limit-exceeded")
        if "max_spend" in lim:
            amt = _amount((spend or {}).get("amount", "0"))
            if (spend and spend.get("currency") != lim["max_spend"]["currency"]) or amt is None \
                    or n["spend"] + amt > _amount(lim["max_spend"]["amount"]):
                why.append("limit-exceeded")
    return sorted(set(why))


def limit_commit(receipts, counts, spend=None):
    """Count an accepted request against every limited receipt in the chain."""
    for r in receipts:
        if r.get("dlg_limits"):
            n = counts.setdefault((r["iss"], r["jti"]), {"calls": 0, "spend": Decimal(0)})
            n["calls"] += 1
            n["spend"] += _amount((spend or {}).get("amount", "0")) or 0


# --- issuance -----------------------------------------------------------------------------------------------
def issue_receipt(*, iss, priv, kid, sub, delegate_jwk, grants, now, exp, jti, parent=None, limits=None, aud=None,
                  build=None, status=None, purp=None, approval=None, principal=None):
    """A signed receipt. `parent` is the parent's compact JWS for a child receipt, None for a root receipt.
    `approval` (`dlg_approval`) and `principal` (`dlg_principal`) belong on a root receipt only."""
    c = {"iss": iss, "sub": sub, "cnf": {"jkt": pp.thumbprint(delegate_jwk)}, "dlg_grants": grants,
         "iat": int(now), "exp": int(exp), "jti": jti}
    for k, v in (("dlg_parent", parent and digest(parent)), ("dlg_limits", limits), ("aud", aud), ("dlg_build", build),
                 ("status", status), ("purp", purp), ("dlg_approval", approval), ("dlg_principal", principal)):
        if v is not None:
            c[k] = v
    return pp.jws_sign(c, priv, kid, DLG_TYP)


def demo():
    p = {"dlg_grants": [{"host": "api.b.example", "methods": ["GET"], "paths": ["/orders/*"], "tools": ["list_orders"]}],
         "exp": 100, "aud": ["https://api.b.example"]}
    ok = dict(p, dlg_grants=[{"host": "API.b.example.", "methods": ["GET"], "paths": ["/orders/1"], "tools": ["list_orders"]}])
    assert attenuation(ok, p) == []
    assert attenuation(dict(ok, dlg_grants=[dict(ok["dlg_grants"][0], host="*.b.example")]), p) == ["attenuation:host"]
    assert attenuation(dict(ok, dlg_grants=[dict(ok["dlg_grants"][0], methods=["GET", "POST"])]), p) == ["attenuation:methods"]
    assert attenuation(dict(ok, exp=101), p) == ["attenuation:exp"]
    assert attenuation(dict(ok, dlg_grants=[{"host": "api.b.example", "methods": ["GET"], "paths": ["/orders/1"]}]), p) \
        == ["attenuation:tools"]
    assert attenuation({"dlg_grants": [{"host": "a.example", "methods": ["GET"]}], "exp": 1},
                       {"dlg_grants": [{"host": "a.example"}], "exp": 1}) == []                    # absent = default
    assert receipt_problems({"dlg_grants": [{"host": "a.example", "colour": "red"}]}) == ["attenuation:unknown-member"]
    assert grant_problem({"host": "*.com"}) == "grant-public-suffix"
    assert norm_path("/a/%7euser/../b") == "/a/b" and norm_path("/a%2fb") is None
    assert match(ok["dlg_grants"], "GET", "https://api.b.example/orders/1", tool="list_orders")
    assert not match(ok["dlg_grants"], "GET", "https://api.b.example/orders/1/../../admin")
    counts, r = {}, [{"iss": "as", "jti": "r1", "dlg_limits": {"max_calls": 2}, "aud": ["S1"]}]
    for _ in range(2):
        assert limit_check(r, "S1", counts) == []
        limit_commit(r, counts)
    assert limit_check(r, "S1", counts) == ["limit-exceeded"]
    assert limit_check([dict(r[0], aud=["S1", "S2"])], "S1", {}) == ["limit-aud-not-single"]
    d = "sha-256:" + "a" * 43
    ap = {"method": "webauthn", "at": 1, "action_digest": d, "display_digest": d}
    assert approval_problem(ap) is None and approval_problem(dict(ap, kid="k")) == "approval-malformed"
    assert approval_message(ap) == ("%s.%s.1" % (d, d)).encode()
    pr = {"ev_iss": "https://ev.example", "assurance": "high", "ev_time": 1}
    assert principal_problem(pr) is None and principal_problem(dict(pr, name="Alice")) == "principal-malformed"
    assert receipt_problems(dict(p, dlg_principal=dict(pr, ev_time="x"))) == ["principal-malformed"]
    print("delegation self-check ok")


if __name__ == "__main__":
    demo()
