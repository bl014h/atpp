"""Relying-party checks for the agent passport spec: fail-closed revocation, bounded caches, exposure bound,
build assurance, transport and intermediary rules (draft-le-agent-passport-01, R38-R42).

Pure and offline. Every function takes the clock (`now`) and the data it needs as arguments; nothing here
fetches, signs or stores. The verifiers (Python SDK, Go filter) call these so the rules live in one place and the
vectors in tools/atpp/vectors/ can pin them. Passport issuance and request signing are separate modules; this one only decides, from what a relying party has in hand, whether to trust it.


Run `python3 app/rp_policy.py` for a self-check.
"""
import base64
import hashlib

# --- the numbers the spec names -------------------------------------------------------------------------
CACHE_CEILING = 3600          # R39: controller documents and issuer metadata, seconds
REVALIDATE_WITHIN = 60        # R39: a high-value operation re-fetches unless the copy is this fresh
PASSPORT_CEILING = 86400      # R40: 24 h is a ceiling, not a default
HIGH_VALUE_LIFETIME = 3600    # R40: default for agents that perform high-value operations
TLS_OK = ("TLSv1.2", "TLSv1.3")
REQUIRED_COMPONENTS = ("@method", "@authority", "@target-uri", "agent-passport")   # R42
HIGH, LOW = "high", "low"


# --- R38: revocation fails closed -----------------------------------------------------------------------
def status_state(fresh, cached, now, value=HIGH, grace=0):
    """State of one passport or receipt from its status list.

    `fresh`: a status record just obtained, or None if the fetch failed or the list was invalid.
    `cached`: the last good record, or None. A record is {"revoked": bool, "fetched_at": float, "ttl": float}.
    Returns {"state": "good"|"revoked", "reason": str, "relaxed": bool}. An undeterminable status is "revoked"
    (R38). It is "good" with relaxed=True only for a low-value operation, only when the last good record said
    not-revoked, and only inside `grace` seconds after its time-to-live ended."""
    if fresh is not None:
        return {"state": "revoked" if fresh["revoked"] else "good", "reason": "fresh", "relaxed": False}
    age = None if cached is None else now - cached["fetched_at"]
    if age is not None and 0 <= age <= cached["ttl"]:       # a clock that stepped back is not "fresh" (age < 0)
        return {"state": "revoked" if cached["revoked"] else "good", "reason": "cached", "relaxed": False}
    if (value == LOW and grace > 0 and age is not None and not cached["revoked"]
            and 0 <= age <= cached["ttl"] + grace):
        return {"state": "good", "reason": "grace", "relaxed": True}
    return {"state": "revoked", "reason": "status-unavailable", "relaxed": False}


def chain_status(items, now, value=HIGH, grace=0):
    """`items`: one (fresh, cached) pair per passport and receipt in the chain. One undeterminable or revoked
    status invalidates the chain. A relaxation applies only if the request is low-value and every element is
    eligible for it. Returns {"valid": bool, "reasons": [...], "relaxed": bool}."""
    states = [status_state(f, c, now, value, grace) for f, c in items]
    bad = [s["reason"] if s["reason"] == "status-unavailable" else "revoked" for s in states if s["state"] == "revoked"]
    return {"valid": not bad, "reasons": bad, "relaxed": any(s["relaxed"] for s in states)}


# --- R39: controller documents and issuer metadata -------------------------------------------------------
def cache_bound(doc):
    """Seconds a retrieved controller document may be relied on: the smaller of its `max_age` and 3600. A
    `max_age` that is not a positive integer is ignored, so a controller cannot lengthen the bound."""
    m = doc.get("max_age") if isinstance(doc, dict) else None
    ok = isinstance(m, int) and not isinstance(m, bool) and m > 0
    return min(m, CACHE_CEILING) if ok else CACHE_CEILING


def cache_action(entry, now, value=HIGH):
    """`entry`: {"doc": {...}, "fetched_at": float} or None. Returns "use" or "fetch". A high-value
    operation re-fetches unless the copy is at most 60 seconds old."""
    if entry is None:
        return "fetch"
    age = now - entry["fetched_at"]
    if age < 0 or age > cache_bound(entry["doc"]):
        return "fetch"
    if value == HIGH and age > REVALIDATE_WITHIN:
        return "fetch"
    return "use"


def issuer_metadata_action(fetched_at, now, value=LOW, revalidate_high=False):
    """Issuer metadata and JWK Sets are refreshed at least hourly (R39). Optionally a high-value operation also
    re-fetches unless the copy is at most 60 seconds old, which closes the key-compromise window for those
    operations (docs/ATPP_VERIFIER_EVALUATION.md)."""
    bound = REVALIDATE_WITHIN if revalidate_high and value == HIGH else CACHE_CEILING
    return "fetch" if fetched_at is None or now - fetched_at > bound or now < fetched_at else "use"


def controller_authorises(doc, controller, iss):
    """The issuer is the controller itself or is listed. Sharing an origin is not enough."""
    if not isinstance(doc, dict) or not isinstance(iss, str):
        return False
    listed = doc.get("issuers")
    return iss == controller or (isinstance(listed, list) and iss in listed)


# --- R40: exposure bound ---------------------------------------------------------------------------------
def default_lifetime(value=HIGH):
    return HIGH_VALUE_LIFETIME if value == HIGH else PASSPORT_CEILING


def lifetime_ok(iat, exp):
    return 0 < exp - iat <= PASSPORT_CEILING


def exposure_bound(exp, now, mechanism, status_ttl=0, grace=0, value=LOW, revalidate_issuer_high=False):
    """Longest time an RP may still accept a passport after a revocation event: the smaller of the passport's
    remaining life and the refresh bound of the mechanism that carries the event. A high-value operation
    revalidates the controller document (R39) and, if the RP chooses, issuer keys."""
    high = value == HIGH
    bound = {"status": status_ttl + grace,
             "controller": REVALIDATE_WITHIN if high else CACHE_CEILING,
             "issuer_key": REVALIDATE_WITHIN if high and revalidate_issuer_high else CACHE_CEILING}[mechanism]
    return max(0, min(exp - now, bound))


def principal_bound(B, L, R=None, T=None, M=None):
    """Seconds after `t0`, the event the evidence issuer measures its own bound from, by which a conforming RP
    refuses requests that rely on a withdrawn principal (root receipt with `dlg_principal`, draft -01 "Principal
    Standing"): t0 + B + L. `B` is the evidence issuer's stated bound, `L` the root receipt's lifetime. If the
    authorisation server re-obtains evidence every `R` seconds and revokes affected roots through a status list with
    time-to-live `T`, L becomes min(L, R + T). If the RP sets a maximum principal-evidence age `M`, L becomes
    min(L, M). Returns None when the evidence issuer states no bound: then there is none here either."""
    if B is None:
        return None
    life = min(L, M) if M is not None else L
    if R is not None and T is not None:
        life = min(life, R + T)
    return B + life


def exposure_by_event(exp, now, status_ttl=0, grace=0, value=LOW, revalidate_issuer_high=False, outside=None,
                      principal=None):
    """The exposure bound for each kind of revocation event, kept apart: each answers a different event, and none
    bounds another. `outside`: {name: seconds} as the outside verifiers state them (their promise, never our
    measurement). `principal`: arguments for principal_bound, when the root carries `dlg_principal`."""
    out = {m: exposure_bound(exp, now, m, status_ttl, grace, value, revalidate_issuer_high)
           for m in ("status", "controller", "issuer_key")}
    if principal is not None:
        out["principal"] = principal_bound(**principal)
    if outside:
        out["outside"] = {str(k): v for k, v in outside.items()}
    return out


# --- R41: build assurance --------------------------------------------------------------------------------
def build_assurance(build_digest, pinned, issuer_policy, value=HIGH, accept_unattested=False):
    """High-value operations need a pinned build digest, and an issuer whose published policy says it includes
    runtime attestation. Accepting without that evidence is allowed only by explicit local policy and is
    returned in `record` so the caller logs it. Returns {"allow": bool, "reasons": [...], "record": [...]}."""
    if value != HIGH:
        return {"allow": True, "reasons": [], "record": []}
    reasons, record = [], []
    if build_digest not in (pinned or ()):
        reasons.append("build-not-pinned")
    if not (issuer_policy or {}).get("runtime_attestation"):
        if accept_unattested:
            record.append("accepted-without-attestation")
        else:
            reasons.append("issuer-not-attested")
    return {"allow": not reasons, "reasons": reasons, "record": record}


# --- R42: transport and intermediaries ------------------------------------------------------------------
def check_transport(req):
    """`req`: {"scheme", "tls_version", "covered": [...], "intermediary": None | {"authenticated": bool,
    "rewrote": bool, "tls_version": str}, "target_uri_from": "request"|"forwarded"}.
    Returns {"allow": bool, "reasons": [...]}. Never loosens the covered components because a proxy was in
    the path."""
    reasons = []
    inter = req.get("intermediary")
    if req.get("scheme") != "https":
        reasons.append("not-https")
    tls = req.get("tls_version")
    if inter and inter.get("authenticated"):
        tls = inter.get("tls_version") or tls     # the intermediary terminated TLS and reports its leg
    if tls not in TLS_OK:
        reasons.append("tls-version")
    covered = set(req.get("covered") or ())
    missing = [c for c in REQUIRED_COMPONENTS if c not in covered]
    if missing:
        reasons.append("covered-components-missing:" + ",".join(missing))
    if inter and not inter.get("authenticated"):
        if inter.get("rewrote"):
            reasons.append("unauthenticated-intermediary-rewrote")
        if req.get("target_uri_from") == "forwarded":
            reasons.append("forwarded-target-uri-unauthenticated")
    return {"allow": not reasons, "reasons": reasons}




def demo():
    good = {"revoked": False, "fetched_at": 1000, "ttl": 60}
    assert status_state(None, good, 1030)["reason"] == "cached"
    assert status_state(None, good, 1100)["state"] == "revoked"                      # R38: fail closed
    assert status_state(None, good, 1100, LOW, grace=120)["relaxed"]                 # low-value, in grace
    assert status_state(None, good, 1100, HIGH, grace=120)["state"] == "revoked"     # never for high-value
    assert not chain_status([(None, good), ({"revoked": False, "fetched_at": 1100, "ttl": 60}, None)], 1100)["valid"]
    assert cache_bound({"max_age": 600}) == 600 and cache_bound({"max_age": 99999}) == CACHE_CEILING
    assert cache_action({"doc": {}, "fetched_at": 1000}, 1030, HIGH) == "use"
    assert cache_action({"doc": {}, "fetched_at": 1000}, 1100, HIGH) == "fetch"
    assert exposure_bound(exp=1000 + 90000, now=1000, mechanism="status", status_ttl=60) == 60
    assert not build_assurance("d1", {"d1"}, {})["allow"]
    assert not check_transport({"scheme": "https", "tls_version": "TLSv1.1", "covered": REQUIRED_COMPONENTS})["allow"]
    print("rp_policy self-check ok")


if __name__ == "__main__":
    demo()
