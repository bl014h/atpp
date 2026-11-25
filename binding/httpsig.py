"""RFC 9421 HTTP Message Signatures with Ed25519, the one shape the agent passport draft uses (-01, Signing).

Strict on purpose: one signature named `sig1`, a fixed parameter grammar, derived components limited to
@method, @authority and @target-uri. Anything else is an error, not a feature. `req` is
{"method", "authority", "target_uri", "headers": {lowercase-name: value}}."""
import re

from passport import b64u, unb64u

REQUIRED = ("@method", "@authority", "@target-uri", "agent-passport")
MAX_LIFETIME = 300
_INPUT = re.compile(r'^sig1=\(((?:"[a-z@][a-z0-9@-]*"(?: |(?=\))))+)\)((?:;[a-z-]+=(?:\d+|"[A-Za-z0-9_.:=/+-]*"))*)$')
_PARAM = re.compile(r';([a-z-]+)=(\d+|"[^"]*")')


def _value(req, name):
    if name == "@method":
        return req["method"].upper()
    if name == "@authority":
        return req["authority"].lower()
    if name == "@target-uri":
        return req["target_uri"]
    v = req["headers"].get(name)
    if v is None or "\n" in v or "\r" in v:
        raise ValueError("component " + name)
    return v.strip()


def _base(req, covered, params):
    lines = ['"%s": %s' % (c, _value(req, c)) for c in covered]
    lines.append('"@signature-params": (%s)%s' % (" ".join('"%s"' % c for c in covered), params))
    return "\n".join(lines).encode()


def _params_str(created, expires, nonce, keyid, extra, tag="agent-passport"):
    p = ';created=%d;expires=%d;nonce="%s";keyid="%s";tag="%s"' % (created, expires, nonce, keyid, tag)
    for k, v in (extra or {}).items():
        p += ';%s="%s"' % (k, v)
    return p


def sign(req, priv, keyid, now, nonce, covered=REQUIRED, ttl=MAX_LIFETIME, extra=None, tag="agent-passport"):
    """Headers {"signature-input", "signature"} to add to the request."""
    params = _params_str(int(now), int(now) + ttl, nonce, keyid, extra, tag)
    sig = priv.sign(_base(req, covered, params))
    return {"signature-input": "sig1=(%s)%s" % (" ".join('"%s"' % c for c in covered), params),
            "signature": "sig1=:%s:" % b64u(sig)}


def parse(headers):
    """(covered, params, signature, params_string). ValueError on anything outside the grammar."""
    m = _INPUT.match(headers.get("signature-input", ""))
    s = re.match(r"^sig1=:([A-Za-z0-9_-]+):$", headers.get("signature", ""))
    if not m or not s:
        raise ValueError("signature headers")
    covered = tuple(re.findall(r'"([^"]+)"', m.group(1)))
    if len(set(covered)) != len(covered):
        raise ValueError("duplicate component")
    params = {}
    for k, v in _PARAM.findall(m.group(2)):
        if k in params:
            raise ValueError("duplicate parameter")
        params[k] = int(v) if v.isdigit() else v[1:-1]
    return covered, params, unb64u(s.group(1)), m.group(2)


def verify(req, pub, now, skew=60):
    """(reasons, covered, params). Reasons are empty when the signature holds. Checks the parameters the draft's Verification names,
    then the signature over the base rebuilt from the request as received."""
    try:
        covered, params, sig, pstr = parse(req["headers"])
        base = _base(req, covered, pstr)
    except (ValueError, KeyError):
        return ["signature-malformed"], (), {}
    why = []
    c, e = params.get("created"), params.get("expires")
    if not isinstance(c, int) or not isinstance(e, int) or not params.get("nonce") or not params.get("keyid"):
        return ["signature-params"], covered, params
    if c > now + skew:
        why.append("signature-from-future")
    if now > e:
        why.append("signature-expired")
    if not 0 < e - c <= MAX_LIFETIME:
        why.append("signature-lifetime")
    if params.get("tag") != "agent-passport":
        why.append("signature-tag")
    try:
        pub.verify(sig, base)
    except Exception:
        why.append("signature-invalid")
    return why, covered, params
