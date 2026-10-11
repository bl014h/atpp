#!/usr/bin/env python3
"""ToolHive → Agent Trust Fabric: signed receipts for MCP tool calls.

ToolHive brokers every MCP tool call through an HTTP proxy and writes a NIST-shaped audit
event per call — but those events go to stdout or a file, unsigned, with no network sink
(pkg/audit/config.go). So a ToolHive operator can prove things to their own security team and
to nobody else. This sidecar closes that gap without patching ToolHive: it turns each tool
call into an Ed25519-signed, externally verifiable Agent Trust Fabric action record, and an
out-of-scope call revokes the agent's identity and flips its public badge.

Two modes, both requiring no change to ToolHive itself:

  tail    read the audit JSON log (append-only, one event per line) and post each tool call
          --audit-log /var/log/toolhive/audit.jsonl

  serve   run as a ToolHive *validating webhook* (RFC THV-0017): ToolHive POSTs the parsed
          request, HMAC-SHA256 signed as "<timestamp>.<payload>" in X-ToolHive-Signature.
          Answers "allow" by default — this observes, it does not gate. Configure it with
          failure_policy: ignore so a slow receipt can never break traffic.
          --serve 8099 --hmac-secret-file /etc/toolhive/webhook.key

          Preview, opt-in: --gate <namespace>/<server> [--gate-image ref@sha256:...] [--gate-strict]
          denies every call to this workload while `atpp gate` says no (claim missing, expired or
          invalid, listing swap, missing version, foreign build provenance, unscanned image digest).
          The verdict is re-checked every --gate-every seconds; one that cannot be checked denies.
          Needs atpp.py (github.com/bl014h/atpp) importable and `pip install cryptography`. Use
          failure_policy: fail with --gate, or a sidecar outage silently turns the gate off.

Both modes need an ATF agent key (POST /api/trust-signal/agents issues one, shown once):
  ATF_SPIFFE_ID=spiffe://tenant-acme.redthread.ai/agent/toolhive  ATF_KEY=atfk_...

A note on field extraction: ToolHive's audit event and webhook payload schemas are versioned
and evolving, and the tool name does not sit at one documented path in both. Rather than
guess one and fail silently, the extractors below try the plausible paths and count what they
could not map; `--print-unmapped` shows those events so an operator can add their own path
with --tool-path. Nothing is invented: an event whose tool cannot be identified is skipped
and reported, never posted under a made-up name.
"""
import argparse
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools", "atpp"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))   # the public repo layout

DEFAULT_APP = "https://app.redthreadsec.com"
WEBHOOK_MAX_SKEW = 300          # seconds; a replayed webhook older than this is refused
POST_TIMEOUT = 5                # keep the hot path short — the webhook is synchronous

# Candidate paths for the tool name, most specific first. Dotted, "*" walks a list.
TOOL_PATHS = (
    "data.tool_name", "data.tool", "data.request.params.name", "data.params.name",
    "target.name", "target.tool", "request.params.name", "params.name", "tool",
)
# Only tool *invocations* become receipts. A discovery grant is not evidence that a tool ran,
# which is the distinction ToolHive issue #4048 exists to make — so listings never post.
INVOCATION_TYPES = ("mcp_tool_call", "tool_call", "tools/call", "mcp_request")
DISCOVERY_TYPES = ("mcp_initialize", "tools/list", "mcp_tools_list", "resources/list", "prompts/list")


def dig(doc, path):
    """Resolve a dotted path; '*' walks every element of a list and returns the first hit."""
    cur = doc
    for part in path.split("."):
        if part == "*":
            if not isinstance(cur, list):
                return None
            for item in cur:
                got = item
                if got is not None:
                    return got
            return None
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur if isinstance(cur, (str, int, float)) else None


def tool_of(event, extra_paths=()):
    for p in tuple(extra_paths) + TOOL_PATHS:
        v = dig(event, p)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def is_invocation(event):
    """True for a tool call, False for discovery, None when the event type says neither."""
    t = str(event.get("type") or event.get("method") or "").lower()
    if any(k in t for k in DISCOVERY_TYPES):
        return False
    if any(k in t for k in INVOCATION_TYPES):
        return True
    return None


def subject_of(event):
    """The principal ToolHive authenticated, for the scope label. Best-effort, never fatal."""
    for p in ("subjects.user", "subjects.subject", "subjects.client_id", "data.principal",
              "principal.sub", "principal"):
        v = dig(event, p)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def delegation_of(event):
    """ToolHive carries an RFC 8693 delegation chain on token-exchange paths. Shape varies, so
    accept a list of strings or of dicts with a subject-ish key, and drop anything else."""
    chain = event.get("delegation") or dig_raw(event, "data.delegation")
    out = []
    for hop in (chain if isinstance(chain, list) else [chain] if chain else []):
        if isinstance(hop, str):
            out.append(hop)
        elif isinstance(hop, dict):
            for k in ("subject", "sub", "actor", "client_id", "principal"):
                if isinstance(hop.get(k), str):
                    out.append(hop[k])
                    break
    return out[:10]


def dig_raw(doc, path):
    """dig() but keeps containers, for fields that are lists or objects."""
    cur = doc
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


def verify_webhook(secret: bytes, body: bytes, signature: str, timestamp: str, now=None) -> bool:
    """ToolHive signs HMAC-SHA256 over '<timestamp>.<payload>' (pkg/webhook/signing.go)."""
    if not signature or not timestamp:
        return False
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    if abs((now or time.time()) - ts) > WEBHOOK_MAX_SKEW:
        return False
    want = hmac.new(secret, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    got = signature.split("=", 1)[1] if "=" in signature else signature
    return hmac.compare_digest(want, got)


class Poster:
    """Posts one signed action per tool call. Failures are counted, never raised at the caller —
    a receipt service must not be able to take an operator's gateway down."""

    def __init__(self, app, spiffe_id, key, scope=None, dry_run=False):
        self.app, self.spiffe_id, self.key = app.rstrip("/"), spiffe_id, key
        self.scope, self.dry_run = scope, dry_run
        self.stats = {"posted": 0, "revoked": 0, "skipped_discovery": 0, "unmapped": 0, "errors": 0}
        self.last_skip = None          # "discovery" | "unmapped" — why the last event made no receipt

    def send(self, tool, scope, caller=None, delegation=None):
        if self.dry_run:
            self.stats["posted"] += 1
            return {"ok": True, "dry_run": True, "tool": tool, "scope": scope, "caller": caller}
        doc = {"spiffe_id": self.spiffe_id, "tool": tool, "scope": scope}
        if caller:
            doc["caller"] = caller
        if delegation:
            doc["delegation"] = delegation
        body = json.dumps(doc).encode()
        req = urllib.request.Request(
            f"{self.app}/api/trust-signal/actions", data=body, method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.key}"})
        try:
            with urllib.request.urlopen(req, timeout=POST_TIMEOUT) as r:
                out = json.load(r)
        except urllib.error.HTTPError as e:
            self.stats["errors"] += 1
            return {"ok": False, "status": e.code, "error": e.read(200).decode("utf-8", "replace")}
        except Exception as e:                                  # network, DNS, timeout
            self.stats["errors"] += 1
            return {"ok": False, "error": str(e)}
        self.stats["posted"] += 1
        if out.get("in_scope") is False:
            self.stats["revoked"] += 1
        return out

    def handle(self, event, extra_paths=(), default_scope=None):
        """Map one ToolHive event to an action. Returns None when it is not a tool call."""
        self.last_skip = None
        if is_invocation(event) is False:
            self.stats["skipped_discovery"] += 1
            self.last_skip = "discovery"
            return None
        tool = tool_of(event, extra_paths)
        if not tool:
            self.stats["unmapped"] += 1
            self.last_skip = "unmapped"
            return None
        # Register the agent with the tool names it may call: in a gateway the tool name is the
        # capability, so the tool is the scope. --scope pins one label instead (e.g. "read:*").
        scope = self.scope or default_scope or tool
        return self.send(tool, scope, subject_of(event), delegation_of(event))


def run_tail(args, poster):
    """Follow the audit log. ToolHive appends one JSON object per line; rotation is handled by
    reopening when the inode changes."""
    path = args.audit_log
    pos, inode = 0, None
    if not args.from_start and os.path.exists(path):
        pos = os.path.getsize(path)
    while True:
        try:
            st = os.stat(path)
        except FileNotFoundError:
            time.sleep(args.poll)
            continue
        if inode is not None and st.st_ino != inode:      # rotated
            pos = 0
        inode = st.st_ino
        if st.st_size < pos:                              # truncated
            pos = 0
        if st.st_size > pos:
            with open(path, "r", errors="replace") as fh:
                fh.seek(pos)
                for line in fh:
                    if not line.endswith("\n"):           # partial write; pick it up next pass
                        break
                    pos += len(line.encode("utf-8", "replace"))
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        poster.stats["unmapped"] += 1
                        if args.print_unmapped:
                            print(f"unmapped (not json): {line[:200]}", file=sys.stderr, flush=True)
                        continue
                    out = poster.handle(event, args.tool_path, args.scope)
                    if out is None and args.print_unmapped and poster.last_skip == "unmapped":
                        print(f"unmapped: {line[:400]}", file=sys.stderr, flush=True)
                    elif out and out.get("in_scope") is False:
                        print(f"REVOKED on out-of-scope tool call: {json.dumps(out)[:300]}",
                              file=sys.stderr, flush=True)
        if args.once:
            return
        time.sleep(args.poll)


class Gate:
    """The launch verdict for one workload, cached and refreshed. None means no gate (observe only)."""

    def __init__(self, name, image=None, strict=False, every=600, decide=None, policy=None):
        self.name, self.image, self.strict, self.every, self.policy = name, image, strict, every, policy
        self.decide = decide or self._atpp
        self.at, self.allowed, self.reasons = 0.0, False, ["not checked yet"]

    def _atpp(self):
        import atpp                       # imported late: observe-only users never need cryptography
        pol = atpp.load_policy(self.policy) if self.policy else None    # re-read: edits apply on the next check
        return atpp.gate(self.name, image=self.image, strict=self.strict, policy=pol)

    def verdict(self):
        if time.time() - self.at >= self.every:
            try:
                self.allowed, self.reasons = self.decide()
            except Exception as e:        # a gate that cannot decide denies
                self.allowed, self.reasons = False, [f"gate could not check: {e.__class__.__name__}"]
            self.at = time.time()
        return self.allowed, self.reasons


def make_handler(args, poster, secret, gate=None):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _reply(self, code, doc):
            body = json.dumps(doc).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/healthz":
                return self._reply(200, {"ok": True, "stats": poster.stats})
            self._reply(404, {"error": "not found"})

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            if secret and not verify_webhook(secret, body,
                                             self.headers.get("X-ToolHive-Signature", ""),
                                             self.headers.get("X-ToolHive-Timestamp", "")):
                # Refusing an unauthenticated caller is not the same as gating traffic:
                # ToolHive's own request is signed, so a bad signature is not ToolHive.
                return self._reply(401, {"error": "bad signature"})
            try:
                event = json.loads(body or b"{}")
            except json.JSONDecodeError:
                poster.stats["unmapped"] += 1
                return self._reply(200, {"allowed": True, "reason": "unparsable payload, observing only"})
            out = poster.handle(event, args.tool_path, args.scope)
            if out is None and args.print_unmapped and poster.last_skip == "unmapped":
                print(f"unmapped: {body[:400]!r}", file=sys.stderr, flush=True)
            if gate is not None:          # opt-in preview: deny the workload while its claim says no
                ok, reasons = gate.verdict()
                if not ok:
                    poster.stats["denied"] = poster.stats.get("denied", 0) + 1
                    return self._reply(200, {"allowed": False, "reason": "ATPP gate: " + "; ".join(reasons)[:500],
                                             "receipt": bool(out)})
            # Without --gate this always allows: a witness, not a policy engine, and ToolHive's Cedar
            # authz stays the only thing that denies a call.
            self._reply(200, {"allowed": True, "receipt": bool(out)})

        def log_message(self, *a):                        # quiet; stats live on /healthz
            pass

    return Handler


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("mode", choices=["tail", "serve"])
    ap.add_argument("--audit-log", help="tail mode: ToolHive's audit JSON log")
    ap.add_argument("--serve", type=int, default=8099, help="serve mode: port")
    ap.add_argument("--hmac-secret-file", help="serve mode: ToolHive's webhook signing secret")
    ap.add_argument("--app", default=os.environ.get("ATF_APP", DEFAULT_APP))
    ap.add_argument("--spiffe-id", default=os.environ.get("ATF_SPIFFE_ID"))
    ap.add_argument("--key", default=os.environ.get("ATF_KEY"))
    ap.add_argument("--scope", help="scope label to report (default: the authenticated caller)")
    ap.add_argument("--tool-path", action="append", default=[],
                    help="extra dotted path to the tool name, tried before the built-ins")
    ap.add_argument("--print-unmapped", action="store_true", help="log events whose tool could not be identified")
    ap.add_argument("--dry-run", action="store_true", help="map and count, post nothing")
    ap.add_argument("--from-start", action="store_true", help="tail mode: replay the whole log")
    ap.add_argument("--once", action="store_true", help="tail mode: drain what exists and exit")
    ap.add_argument("--poll", type=float, default=1.0)
    ap.add_argument("--gate", metavar="NAMESPACE/SERVER", help="serve mode, preview: deny calls while `atpp gate` denies this server")
    ap.add_argument("--gate-image", help="with --gate: the image this workload runs, ideally ref@sha256:...")
    ap.add_argument("--gate-strict", action="store_true", help="with --gate: also deny any failed check or an unpinned image")
    ap.add_argument("--gate-every", type=int, default=600, help="with --gate: seconds between re-checks")
    ap.add_argument("--gate-policy", help="with --gate: your org policy JSON (allow-list, pinned images); see atpp load_policy")
    a = ap.parse_args(argv)

    if not a.dry_run and not (a.spiffe_id and a.key):
        ap.error("need --spiffe-id and --key (or ATF_SPIFFE_ID / ATF_KEY), or --dry-run")
    poster = Poster(a.app, a.spiffe_id, a.key, a.scope, a.dry_run)

    if a.mode == "tail":
        if not a.audit_log:
            ap.error("tail mode needs --audit-log")
        run_tail(a, poster)
        print(json.dumps(poster.stats))
        return 0

    secret = None
    if a.hmac_secret_file:
        secret = open(a.hmac_secret_file, "rb").read().strip()
    elif os.environ.get("TOOLHIVE_WEBHOOK_SECRET"):
        secret = os.environ["TOOLHIVE_WEBHOOK_SECRET"].encode()
    else:
        print("warning: no HMAC secret — anyone who can reach this port can write receipts",
              file=sys.stderr)
    gate = Gate(a.gate, a.gate_image, a.gate_strict, a.gate_every, policy=a.gate_policy) if a.gate else None
    if gate:
        ok, reasons = gate.verdict()
        print(f"gate {a.gate}: {'ALLOW' if ok else 'DENY'} — {'; '.join(reasons)}", file=sys.stderr, flush=True)
    srv = HTTPServer(("0.0.0.0", a.serve), make_handler(a, poster, secret, gate))
    print(f"listening on :{a.serve} (validating webhook, {'gating ' + a.gate if gate else 'always allows'}; /healthz for stats)",
          file=sys.stderr, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    print(json.dumps(poster.stats))
    return 0


if __name__ == "__main__":
    sys.exit(main())
