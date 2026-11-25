#!/usr/bin/env python3
"""Redthread's agent passport verifier behind a small HTTP interface, for other implementations' harnesses
(draft-le-agent-passport-01; IETF 127 scenarios P1 to P6). Apache-2.0.

The harness owns the world: it sends the clock (`now`) and every document the verifier would fetch (`documents`:
issuer metadata, controller documents, status lists by URL), so a case is deterministic and offline. A `session`
keeps one verifier's state (cached lists, nonces, limit counters) across calls, which P1 (cache past its ttl) and
P4 (cumulative limits) need. Nothing is fetched from the network.

    POST /v1/verify   {"session", "now", "value": "high"|"low", "policy", "documents", "request", "transport",
                       "tool", "tool_digest", "spend", "revalidate"}
                      -> {"decision", "reasons", "record", "exposure", "exposure_by_event", "chain"}
    POST /v1/run      the same, plus "between": {"now", "documents"} applied after authorisation and before the
                      re-check (scenario P2, before-effect) -> {"effect", "lines": [one per step]}
    GET  /v1/info     -> {"name", "version", "revision", "draft", "license"}

`request` is {"method", "authority", "target_uri", "headers": {lowercase name: value}, "body_b64"}.

    python3 verifier_http.py [PORT]      # default 8080
"""
import base64
import collections
import http.server
import json
import pathlib
import sys
import threading

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))                  # the verifier modules sit beside this file, even under `python -I`

import atpp_verify as av  # noqa: E402
import protected_op  # noqa: E402
import rp_policy as rp  # noqa: E402
MAX_SESSIONS = 1000
MAX_BODY = 1 << 20
LOCK = threading.Lock()                # one verifier state per session; calls are handled one at a time
TRANSPORT = {"scheme": "https", "tls_version": "TLSv1.3"}   # as this binding's own TLS terminator reports it


class Session:
    def __init__(self, policy):
        self.now, self.docs = 0, {"issuer": {}, "controller": {}, "status": {}}
        self.v = av.Verifier(self.fetch, lambda: self.now, policy=policy)

    def fetch(self, kind, url):
        return self.docs.get(kind, {}).get(url)

    def update(self, body):
        if "now" in body:
            self.now = body["now"]
        for kind, docs in (body.get("documents") or {}).items():
            if kind in self.docs and isinstance(docs, dict):
                for url, doc in docs.items():                # null: that document is now unavailable
                    if doc is None:
                        self.docs[kind].pop(url, None)
                    else:
                        self.docs[kind][url] = doc


sessions = collections.OrderedDict()


def session(body):
    key = str(body.get("session") or "default")
    s = sessions.get(key)
    if s is None:
        s = sessions[key] = Session(_policy(body.get("policy")))
        while len(sessions) > MAX_SESSIONS:
            sessions.popitem(last=False)
    sessions.move_to_end(key)
    s.update(body)
    return s


def _policy(p):
    p = dict(p or {})
    p.pop("approval_expect", None)                  # a callable; not expressible over HTTP
    return p


def _request(r):
    req = {k: r[k] for k in ("method", "authority", "target_uri")}
    req["headers"] = {str(k).lower(): v for k, v in (r.get("headers") or {}).items()}
    if r.get("body_b64"):
        req["body"] = base64.b64decode(r["body_b64"])
    return req


def _value(body):
    return rp.LOW if body.get("value") == "low" else rp.HIGH


def _public(r):
    return {k: r.get(k) for k in ("decision", "reasons", "record", "exposure", "exposure_by_event", "chain")}


def verify(body):
    s = session(body)
    r = s.v.verify(_request(body["request"]), _value(body), body.get("transport") or TRANSPORT, tool=body.get("tool"),
                   spend=body.get("spend"), revalidate=bool(body.get("revalidate")), tool_digest=body.get("tool_digest"))
    return _public(r)


def run(body, between=None):
    """`between`: replaces applying body["between"] (the sample generator uses it to change its own world)."""
    s = session(body)
    lines = []
    op = protected_op.ProtectedOperation(s.v, lambda req: "ran", lines.append, case=str(body.get("case") or ""),
                                         scenario=str(body.get("scenario") or "P2"), clock="harness")

    def apply():
        if between:
            between(s)
        elif body.get("between"):
            s.update(body["between"])
    r = op.run(_request(body["request"]), _value(body), body.get("transport") or TRANSPORT, str(body.get("txn_id") or "t1"),
               before_effect=apply, tool=body.get("tool"))
    return {"effect": r["effect"], "lines": lines}


def info():
    rev = (HERE / "REVISION").read_text().split() if (HERE / "REVISION").exists() else ["unknown", "unknown"]
    return {"name": "redthread-agent-passport-verifier", "version": rev[0], "revision": rev[1],
            "draft": "draft-le-agent-passport-01", "license": "Apache-2.0"}


def handle(method, path, body):
    """(status, response) for one call; the HTTP handler and the tests both go through here."""
    if method == "GET" and path == "/v1/info":
        return 200, info()
    routes = {"/v1/verify": verify, "/v1/run": run}
    if method != "POST" or path not in routes:
        return 404, {"error": "not-found"}
    try:
        return 200, routes[path](body)
    except (KeyError, TypeError, ValueError) as e:
        return 400, {"error": "bad-request", "detail": type(e).__name__}


class Handler(http.server.BaseHTTPRequestHandler):
    def _go(self, method):
        n = int(self.headers.get("content-length") or 0)
        if n > MAX_BODY:
            return self._send(413, {"error": "too-large"})
        try:
            body = json.loads(self.rfile.read(n) or b"{}") if method == "POST" else {}
        except ValueError:
            return self._send(400, {"error": "bad-json"})
        with LOCK:
            out = handle(method, self.path, body if isinstance(body, dict) else {})
        self._send(*out)

    def _send(self, status, obj):
        b = json.dumps(obj, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        self._go("GET")

    def do_POST(self):
        self._go("POST")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print("verifier binding on :%d %s" % (port, info()), flush=True)
    http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
