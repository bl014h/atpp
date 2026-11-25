"""The enforcing side of a protected operation: authorise, then re-check just before the operation takes effect,
and run it only if that check still allows the request (IETF 127 scenario P2, "before-effect"; draft-le-agent-passport
"Exposure After Revocation").

The verifier decides; this connects its decision to the operation and records whether the operation ran. Each step
writes one log line in the scenario format (docs/hackathon/ietf127, `ietf127-wimse-scenario/1`), so a run can be
compared with other implementations.

Run `python3 app/protected_op.py` for a self-check."""


class ProtectedOperation:
    """`verifier`: an atpp_verify.Verifier. `operation(req)` performs the effect and returns its result. `log(line)`
    receives one dict per step. `outside`: optional, a decision from another verifier that must also allow just before
    the effect, as `outside(req, txn_id)` returning {"decision": "allow"|"deny", "reason": str, "session_id": str}
    (for example MintID's fresh-proof check at its sandbox verifier); its line carries the session id beside the
    transaction id, which is what binds that decision to this request. `revoked_at`: when the revocation under test was recorded at the issuer, if any, so
    lines carry `t_since_revocation_ms`."""

    def __init__(self, verifier, operation, log, scenario="P2", case="", impl="redthread", hop="E", domain="B",
                 outside=None, clock="utc", evidence=None, release=None, release_needs_chain=True):
        self.v, self.operation, self.log, self.outside = verifier, operation, log, outside
        self.release, self.release_needs_chain = release, release_needs_chain
        self.base = {"scenario": scenario, "case": case, "impl": impl, "hop": hop, "domain": domain, "clock": clock}
        if evidence:
            self.base["evidence"] = evidence
        self.revoked_at = None
        self.seq = 0

    def _emit(self, line):
        self.seq += 1
        line["seq"] = self.seq
        self.log(line)

    def _line(self, check, r, effect, txn_id, **extra):
        now = self.v.now()
        line = dict(self.base, txn_id=txn_id, check=check, actor="rp-verifier", decision=r["decision"],
                    reason=",".join(r["reasons"]) or "ok", effect=effect, ts=now, bound_s=r["exposure"], **extra)
        if r.get("exposure_by_event"):
            line["bound_by_event"] = r["exposure_by_event"]
        if self.revoked_at is not None:
            line["t_since_revocation_ms"] = int(round((now - self.revoked_at) * 1000))
        self._emit(line)

    def _outsides(self):
        """The outside verifiers in order, as (name, decide). `outside` is one callable or a list of callables or of
        (name, callable) pairs; each decides the same request, freshly, and every one must allow."""
        if not self.outside:
            return []
        items = self.outside if isinstance(self.outside, (list, tuple)) else [self.outside]
        return [x if isinstance(x, tuple) else ("outside-%d" % (i + 1) if len(items) > 1 else "outside", x)
                for i, x in enumerate(items)]

    def _outside_line(self, name, o, txn_id):
        allowed = o.get("decision") == "allow"
        # Who decided: the outside verifier, the holder (refused before presenting, so the verifier decided
        # nothing) or our own adapter (failed closed). A holder refusal carries the challenge id, never a session
        # id, so it cannot be read as the outside verifier's decision.
        actor = o.get("actor") or "outside-verifier"
        ids = ({"challenge_id": o.get("challenge_id")} if actor != "outside-verifier"
               else {"session_id": o.get("session_id")})
        line = dict(self.base, txn_id=txn_id, check="outside", actor=actor,
                    decision="allow" if allowed else "deny", reason=o.get("reason") or "ok", ts=self.v.now(),
                    **ids, **({"utc": o["utc"]} if o.get("utc") else {}),
                    **({"evidence": o["evidence"]} if o.get("evidence") else {}),
                    **{k: o[k] for k in ("status_reason", "attributed_by", "stated_bounds") if k in o},
                    effect="pending" if allowed else "none")
        if name != "outside":
            line["outside_name"] = name
        self._emit(line)
        return allowed

    def _release_line(self, txn_id, decision, reason, rel, effect):
        self._emit(dict(self.base, txn_id=txn_id, check="release", actor="rp-verifier", decision=decision,
                        reason=reason, effect=effect, ts=self.v.now(), token_released=bool(rel.get("released")),
                        bound_s=rel.get("token_lifetime_s"),
                        **{k: rel[k] for k in ("provider", "scopes_requested") if k in rel}))

    def run(self, req, value, transport, txn_id, before_effect=None, after_release=None, **kw):
        """The before-effect sequence, stopping at the first deny, one record per step:

            AUTHORIZE -> [window] -> RECHECK (every status and controller fetched now) -> OUTSIDE[1..n] (each must
            allow) -> RELEASE (bearer-only hops) -> EFFECT

        `before_effect()` is where a test changes the world between authorisation and the re-check. `release`, set on
        the operation, hands a bearer credential to a hop that accepts nothing else (scenario P8): it runs only after
        every check allowed, and returns {"released": bool, "token_lifetime_s", "provider", "scopes_requested"}; from
        then on the provider's token lifetime bounds the exposure, not the status list. `after_release()` is where a
        test revokes after the token has left; the effect then still runs (nothing here can recall a bearer token) and
        its line says `token-released`. Returns {"effect": "ran"|"none", "result", "authorize", "before_effect",
        "outside", "release"}."""
        res = {"effect": "none", "result": None, "authorize": None, "before_effect": None, "outside": [], "release": None}
        a = res["authorize"] = self.v.verify(req, value, transport, **kw)
        if a["decision"] != "allow":
            self._line("authorize", a, "none", txn_id)
            return res
        self._line("authorize", a, "pending", txn_id)
        if before_effect:
            before_effect()
        b = res["before_effect"] = self.v.verify(req, value, transport, revalidate=True, **kw)
        if b["decision"] != "allow":
            self._line("before-effect", b, "none", txn_id)
            return res
        for name, decide in self._outsides():                 # each outside verifier's fresh decision, same request
            o = decide(req, txn_id)
            res["outside"].append(dict(o, name=name))
            if not self._outside_line(name, o, txn_id):
                return res
        released_at = None
        if self.release:
            if self.release_needs_chain and not b.get("chain"):
                rel = res["release"] = {"released": False}
                self._release_line(txn_id, "deny", "no-delegation", rel, "none")
                return res
            try:
                rel = res["release"] = dict(self.release(req, b) or {})
            except Exception as ex:                            # fail closed: no credential leaves on an error
                rel = res["release"] = {"released": False, "reason": "release-failed:" + type(ex).__name__}
            if not rel.get("released"):
                self._release_line(txn_id, "deny", rel.get("reason") or "release-refused", rel, "none")
                return res
            self._release_line(txn_id, "allow", "ok", rel, "pending")
            released_at = self.v.now()
            if after_release:
                after_release()
        res["result"] = self.operation(req)
        res["effect"] = "ran"
        if released_at is not None and self.revoked_at is not None and self.revoked_at >= released_at:
            # Revoked after the token left: recorded, but the effect could not be stopped here.
            line_r = dict(b, reasons=["token-released"], exposure=res["release"].get("token_lifetime_s"))
            self._line("before-effect", line_r, "ran", txn_id, token_released=True)
        elif released_at is not None:
            self._line("before-effect", b, "ran", txn_id, token_released=True)
        else:
            self._line("before-effect", b, "ran", txn_id)
        return res


def demo():
    class V:                                     # a verifier that allows once, then sees the revocation
        calls = []

        def now(self):
            return 100.0

        def verify(self, req, value, transport, revalidate=False, **kw):
            self.calls.append(revalidate)
            ok = not revalidate
            return {"decision": "allow" if ok else "deny", "reasons": [] if ok else ["revoked"], "exposure": 120}
    ran, lines = [], []
    op = ProtectedOperation(V(), lambda req: ran.append(req), lines.append, case="before-effect")
    op.revoked_at = 99.5
    r = op.run({}, "high", {}, "t1")
    assert r["effect"] == "none" and ran == [] and V.calls == [False, True]
    assert [x["check"] for x in lines] == ["authorize", "before-effect"] and lines[1]["reason"] == "revoked"
    assert lines[1]["t_since_revocation_ms"] == 500
    assert [x["seq"] for x in lines] == [1, 2] and {x["actor"] for x in lines} == {"rp-verifier"}

    class Ok(V):
        def verify(self, req, value, transport, revalidate=False, **kw):
            return {"decision": "allow", "reasons": [], "exposure": 120}
    out = []                                         # a holder refusal is logged as the holder's, with a challenge id
    holder = lambda req, txn: {"decision": "deny", "reason": "credential_revoked", "actor": "holder", "challenge_id": "c1"}
    r = ProtectedOperation(Ok(), lambda req: ran.append(req), out.append, outside=holder).run({}, "high", {}, "t2")
    assert r["effect"] == "none" and out[-1]["actor"] == "holder" and out[-1]["challenge_id"] == "c1"
    assert "session_id" not in out[-1] and out[-1]["check"] == "outside"
    print("protected_op self-check ok")


if __name__ == "__main__":
    demo()
