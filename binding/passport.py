"""Agent passport primitives (docs/spec/draft-le-agent-passport-01.md): compact JWS with EdDSA, the JWK
thumbprint, the build digest, signed status lists, and issuance with the lifetime rules (draft-le-agent-passport-01).

Pure: keys and the clock are arguments, nothing is fetched or stored. Verification of a whole request, with
caches and policy, is app/atpp_verify.py."""
import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

import rp_policy as rp

PASSPORT_TYP = "agent-passport+jwt"
STATUS_TYP = "statuslist+jwt"
THUMB_URI = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:"
BUILD_MEMBERS = frozenset({"model", "config", "tools", "code"})


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    """Strict: only the base64url alphabet, no padding, and the value must be the canonical encoding."""
    if not isinstance(s, str) or not s or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in s):
        raise ValueError("base64url")
    b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if b64u(b) != s:
        raise ValueError("base64url not canonical")
    return b


def jwk_of(pub_raw):
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u(pub_raw)}


def thumbprint(jwk):
    """RFC 7638 over the required members of an OKP key."""
    return b64u(hashlib.sha256(canon({k: jwk[k] for k in ("crv", "kty", "x")})).digest())


def key_of(jwk):
    """Ed25519 public key from a JWK, or ValueError."""
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("jwk")
    raw = unb64u(jwk.get("x"))
    if len(raw) != 32:
        raise ValueError("jwk length")
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


def build_digest(build):
    return "sha-256:" + b64u(hashlib.sha256(canon(build)).digest())


# --- compact JWS ------------------------------------------------------------------------------------------
def jws_sign(claims, priv, kid, typ):
    h = b64u(canon({"alg": "EdDSA", "kid": kid, "typ": typ})) + "." + b64u(canon(claims))
    return h + "." + b64u(priv.sign(h.encode()))


def jws_parse(token, typ):
    """(header, claims, signing_input, signature) or ValueError. Header is exactly alg/kid/typ (RFC 8725): no
    `jku`, `jwk`, `x5u` or `crit`, no other algorithm."""
    if not isinstance(token, str) or len(token) > 16384:
        raise ValueError("token")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("parts")
    header, claims = json.loads(unb64u(parts[0])), json.loads(unb64u(parts[1]))
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ValueError("shape")
    if set(header) != {"alg", "kid", "typ"} or header["alg"] != "EdDSA" or header["typ"] != typ or not isinstance(header["kid"], str):
        raise ValueError("header")
    return header, claims, (parts[0] + "." + parts[1]).encode(), unb64u(parts[2])


def jws_check(signing_input, sig, pub):
    try:
        pub.verify(sig, signing_input)
        return True
    except InvalidSignature:
        return False


# --- issuance ---------------------------------------------------------------------------------------------
def issue_passport(*, iss, kid, priv, holder_pub, controller, build, now, value=rp.HIGH, lifetime=None,
                   status=None, aliases=None, card=None, jti):
    """A signed passport. `lifetime` defaults to the value-based default (R40) and is refused above 24 h.
    `card` is the Digest Object of an Agent SD-Card (sdcard.card_digest), carried as `agent_card`."""
    life = rp.default_lifetime(value) if lifetime is None else lifetime
    if not rp.lifetime_ok(now, now + life):
        raise ValueError("lifetime")
    jwk = jwk_of(holder_pub)
    claims = {"iss": iss, "sub": THUMB_URI + thumbprint(jwk), "cnf": {"jwk": jwk}, "agent_controller": controller,
              "agent_build": build, "iat": int(now), "exp": int(now + life), "jti": jti}
    if status:
        claims["status"] = status
    if aliases:
        claims["agent_aliases"] = aliases
    if card:
        claims["agent_card"] = card
    return jws_sign(claims, priv, kid, PASSPORT_TYP)


def issue_status_list(*, iss, kid, priv, now, ttl, revoked):
    return jws_sign({"iss": iss, "iat": int(now), "ttl": int(ttl), "revoked": sorted(set(revoked))}, priv, kid, STATUS_TYP)


def demo():
    priv = ed25519.Ed25519PrivateKey.generate()
    holder = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    t = issue_passport(iss="https://i.example", kid="k1", priv=priv, holder_pub=holder, controller="https://c.example",
                       build={"model": "v/m", "config": {"alg": "sha-256", "value": "x"}}, now=1000, jti="j1")
    h, c, si, sig = jws_parse(t, PASSPORT_TYP)
    assert jws_check(si, sig, priv.public_key()) and c["exp"] - c["iat"] == 3600
    assert not jws_check(si + b"x", sig, priv.public_key())
    assert c["sub"] == THUMB_URI + thumbprint(c["cnf"]["jwk"])
    print("passport self-check ok")


if __name__ == "__main__":
    demo()
