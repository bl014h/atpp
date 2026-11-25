"""Relying-party verifier for the agent passport (draft-le-agent-passport-01, Verification): composes the
primitives in passport.py and httpsig.py with the decisions in rp_policy.py (R38-R42).

`fetch(kind, url)` is injected and returns the parsed document or None on any failure; kinds are "issuer"
(metadata with inline `keys` {kid: jwk}), "controller" (the /.well-known/agent-controller document) and
"status" (a compact status-list JWS). `now()` is injected. `rules` defaults to rp_policy so the simulation in
tests/atpp_sim.py can swap in other strategies behind the same interface.

verify() never raises: an unexpected error is a deny with reason "internal-error" (fail closed)."""
import time
from urllib.parse import urlsplit, urlunsplit

import delegation as dlg
import httpsig
import passport as pp
import rp_policy as rp
import sdcard

SKEW = 60
NONCE_CAP = 100_000


def _record(entry, index):
    return {"revoked": index in entry["revoked"], "fetched_at": entry["fetched_at"], "ttl": entry["ttl"]}


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


class Verifier:
    def __init__(self, fetch, now=time.time, policy=None, rules=rp):
        self.fetch, self.now, self.rules = fetch, now, rules
        self.policy = dict({"grace": 0, "max_status_ttl": 60, "require_status": True, "pinned": (), "issuers": None,
                            "accept_unattested": False, "revalidate_issuer_high": True, "ignorable_build": (),
                             "require_card": False, "rp_id": None,
                            "authorization_servers": (), "outside_bounds": {},
                            # dlg_approval at the root: None (record only), "asserted" or "verified" required;
                            # approval_expect(req) -> {"action_digest", "display_digest"} when this RP holds the action
                            "min_approval": None, "approval_expect": None,
                            # dlg_principal at the root: {"issuers": {ev_iss: {"assurance": [..], "bound_s": B}},
                            # "max_age": M, "children": False, "require": False}
                            "principal": {},
                            # authorities this RP declares as its own (draft -01 Intermediaries), e.g. its public host
                            # and the host a front end of its own rewrites to; local configuration only
                            "authorities": ()}, **(policy or {}))
        self.issuers, self.controllers, self.lists, self.nonces = {}, {}, {}, {}
        self.cards = {}                       # JWK thumbprint of the card's `cnf` key -> a verified Agent SD-Card
        self.limit_counts = {}                # (receipt iss, jti) -> calls and spend accepted under it (dlg_limits)
        self.fetches = 0
        self._fresh = False                   # set by verify(revalidate=True): status and controller are fetched now

    # --- Agent SD-Card (draft-le-agent-passport-01, "Use with Agent SD-Card") ---------------------------------
    def accept_card(self, presentation, issuer_jwk, **kw):
        """Remember an Agent SD-Card this RP has VERIFIED at discovery (issuer signature against a key the RP
        trusts, and, unless `require_kb=False`, the presenter's Key Binding JWT). Keyed by the card's holder key:
        a later request whose passport shares that key and names the card can then be bound to it. Raises
        ValueError (from sdcard.verify) for a card that does not verify, or `card-key-type` when the card's key
        is not an OKP key a passport could share."""
        claims = sdcard.verify(presentation, issuer_jwk=issuer_jwk, now=self.now(), **kw)
        jwk = (claims.get("cnf") or {}).get("jwk") or {}
        if jwk.get("kty") != "OKP":
            raise ValueError("card-key-type")
        self.cards[pp.thumbprint(jwk)] = {"presentation": presentation, "claims": claims}
        return claims

    def _card_note(self, c):
        """None when the passport names no card; else whether it is bound to a card this RP verified. A failed
        binding is not a deny by itself: the RP then treats the passport alone and MUST NOT use anything it
        learned from the card (policy `require_card` turns it into a deny)."""
        if "agent_card" not in c:
            return None
        e = self.cards.get(pp.thumbprint(c["cnf"]["jwk"]))
        if e is None:
            return {"bound": False, "reason": "no-verified-card"}
        try:
            sdcard.bind_passport(c, e["claims"], e["presentation"])
        except ValueError as x:
            return {"bound": False, "reason": str(x)}
        pinned = {str(t.get("id")).rsplit("/", 1)[-1]: t.get("attestation")
                  for t in (c["agent_build"].get("tools") or []) if isinstance(t, dict)}
        off = [t.get("name") for t in e["claims"].get("tools") or []
               if isinstance(t, dict) and t.get("name") in pinned and pinned[t["name"]] != sdcard.tool_digest(t)]
        return {"bound": True, "tools_differ_from_build": off}

    # --- cached documents ---------------------------------------------------------------------------------
    def _get(self, kind, url, value, force=False):
        """The document for `url`, or None. Fetches when the rules say so; a failed fetch never falls back to a
        copy the rules would not use (R39: a high-value operation revalidates or fails)."""
        now = self.now()
        cache = self.issuers if kind == "issuer" else self.controllers
        e = cache.get(url)
        if kind == "issuer":
            act = self.rules.issuer_metadata_action(e and e["fetched_at"], now, value, self.policy["revalidate_issuer_high"])
        else:
            act = self.rules.cache_action(e, now, value)
        if act == "use" and not force:
            return e
        self.fetches += 1
        try:
            doc = self.fetch(kind, url)
        except Exception:
            doc = None
        if not isinstance(doc, dict):
            return None
        cache[url] = {"doc": doc, "fetched_at": now}
        return cache[url]

    def _status(self, ref, issuer_key, value, record):
        """('good'|'revoked', reason) for one status reference. An undeterminable status is `status-stale` when this RP
        held a copy of the list that is past its ttl, `status-unavailable` when it held none: both deny (R38), and the
        log keeps them apart from a confirmed revocation."""
        if not isinstance(ref, dict) or not isinstance(ref.get("url"), str) or not _int(ref.get("index")) or ref["index"] < 0 \
                or not ref["url"].startswith("https://"):
            return "revoked", "status-malformed"
        now, url = self.now(), ref["url"]
        entry = self.lists.get(url)
        fresh = None
        if self._fresh or entry is None or not 0 <= now - entry["fetched_at"] <= entry["ttl"]:
            if self._fetch_list(url, entry, issuer_key, now):
                entry = self.lists[url]
                fresh = _record(entry, ref["index"])
            elif self._fresh:                      # a fresh check that cannot be made is not passed on a cached copy
                return "revoked", "status-stale" if entry else "status-unavailable"
        s = self.rules.status_state(fresh, entry and _record(entry, ref["index"]), now, value, self.policy["grace"])
        if s["relaxed"]:
            record.append("status-grace")
        if s["reason"] == "status-unavailable" and entry is not None:
            return s["state"], "status-stale"
        return s["state"], s["reason"]

    def _fetch_list(self, url, entry, issuer_key, now):
        """Fetch and validate a status list. Stores it and returns True, or returns None on any failure. A list
        from the future, older than the ttl we trust, or signed by another key is a failure, and revocations seen
        are kept: replaying an old signed list must not un-revoke anything."""
        self.fetches += 1
        try:
            tok = self.fetch("status", url)
            _, c, si, sig = pp.jws_parse(tok, pp.STATUS_TYP)
            ok = pp.jws_check(si, sig, issuer_key)
        except Exception:
            return None
        iat, ttl, rev = c.get("iat"), c.get("ttl"), c.get("revoked")
        if (not ok or not _int(iat) or not _int(ttl) or ttl <= 0 or not isinstance(rev, list)
                or not all(_int(i) for i in rev)):
            return None
        ttl = min(ttl, self.policy["max_status_ttl"])           # cap first: freshness is judged on what we trust
        if iat > now + SKEW or now - iat > ttl + SKEW:      # skew tolerance both ways, as the draft allows
            return None
        seen = set(rev) | (entry["revoked"] if entry else set())
        self.lists[url] = {"iat": iat, "fetched_at": min(max(iat, 0), now), "ttl": ttl, "revoked": seen}
        return True

    # --- the request --------------------------------------------------------------------------------------
    def verify(self, req, value=rp.HIGH, transport=None, tool=None, spend=None, revalidate=False, tool_digest=None):
        """`req`: see httpsig, plus optional "body" (bytes) for request matching. `transport`: {"scheme",
        "tls_version", "intermediary", "target_uri_from"} as the RP's TLS terminator reports it. `tool`:
        the tool the request invokes, if the RP's protocol has one (MCP `tools/call`); `tool_digest`: the Digest Object of that
        tool's definition as the RP serves it now (sdcard.tool_digest), compared with the digest the acting agent's
        passport pins for it in `agent_build.tools[].attestation`. `spend`: {"currency",
        "amount"} the request spends, for `max_spend`. Returns {"decision", "reasons", "record", "exposure",
        "passport", "card", "chain"}; "chain" is {"sub", "receipts"} when an Agent-Delegation chain was accepted,
        and the caller then authorises the request as `sub` (grants are a ceiling, never access the principal lacks).

        `revalidate=True` re-checks a request this verifier has already allowed, just before its operation takes
        effect (app/protected_op.py): every status list and controller document is fetched now, a failed fetch
        denies, and the nonce and limits are not counted again. Never use it on a request that was not allowed."""
        self._fresh = revalidate
        try:
            return self._verify(req, value, transport or {}, tool, spend, revalidate, tool_digest)
        except Exception as ex:                                # fail closed, and say so
            return {"decision": "deny", "reasons": ["internal-error:" + type(ex).__name__], "record": [],
                    "exposure": None, "exposure_by_event": None, "passport": None, "card": None, "chain": None}
        finally:
            self._fresh = False

    def _verify(self, req, value, transport, tool=None, spend=None, revalidate=False, tool_digest=None):
        why, record, now, pol = [], [], self.now(), self.policy

        card = chain = None
        note = {}                             # what the chain's root says beyond its grants: approval, principal

        def out(passport=None, exposure=None, events=None):
            ch = None
            if chain and not why:
                ch = {"sub": chain[0]["sub"], "receipts": [r["jti"] for r in chain]}
                ch.update((k, note[k]) for k in ("approval", "principal") if note.get(k))
            return {"decision": "deny" if why else "allow", "reasons": why, "record": record,
                    "exposure": None if why else exposure, "exposure_by_event": None if why else events,
                    "passport": None if why else passport,
                    "card": None if why else card, "chain": ch}

        try:
            h, c, si, sig = _parse(_first(req["headers"].get("agent-passport")))
            holder = pp.key_of(c["cnf"]["jwk"])
            exp = c["exp"]
        except (ValueError, KeyError, TypeError):
            why.append("passport-malformed")
            return out()

        # signature of the request first: cheap, and nothing is fetched for a request that cannot be signed
        sig_why, covered, params = httpsig.verify(req, holder, now, SKEW)
        if sig_why == ["signature-invalid"] and pol["authorities"]:
            alt = self._as_declared_authority(req, holder, now)
            if alt:
                req, (sig_why, covered, params) = alt
        why += sig_why
        if params.get("keyid") != pp.thumbprint(c["cnf"]["jwk"]):
            why.append("keyid-mismatch")
        if c["sub"] != pp.THUMB_URI + pp.thumbprint(c["cnf"]["jwk"]):
            why.append("sub-mismatch")
        if why:
            return out()

        t = self.rules.check_transport({"scheme": transport.get("scheme"), "tls_version": transport.get("tls_version"),
                                        "covered": covered, "intermediary": transport.get("intermediary"),
                                        "target_uri_from": transport.get("target_uri_from", "request")})
        why += t["reasons"]
        if self._check_passport(h, c, si, sig, value, record, why) is None:
            return out()
        ref = c.get("status")

        card = self._card_note(c)
        if tool is not None and tool_digest is not None:      # a tool the passport pins must still be the one served
            pinned = {str(t.get("id")).rsplit("/", 1)[-1]: t.get("attestation")
                      for t in (c["agent_build"].get("tools") or []) if isinstance(t, dict)}
            if tool in pinned and pinned[tool] != tool_digest:
                why.append("tool-digest-mismatch")
        if pol["require_card"] and not (card and card["bound"]):
            why.append("card-not-bound" if card else "no-card")
        if not why and "agent-delegation" in req["headers"]:
            if "agent-delegation" not in covered:
                why.append("covered-components-missing:agent-delegation")
            else:
                cw, chain = self._chain(req, c, value, record, tool, spend, note)
                why += cw
        key = (params["keyid"], params["nonce"])
        if not why and not revalidate:
            self._purge(now)
            if key in self.nonces:
                why.append("replay")
            elif len(self.nonces) >= NONCE_CAP:
                why.append("nonce-cache-full")
            else:
                self.nonces[key] = params["expires"] + SKEW
                if chain:
                    dlg.limit_commit(chain, self.limit_counts, spend)
        return out(c, self._exposure(exp, now, ref, value),
                   self._exposure_events(exp, now, ref, value, note.get("principal_bound_args")))

    def _check_passport(self, h, c, si, sig, value, record, why):
        """Passport validation after parsing (the draft's "Validation", steps 2-8): issuer key and signature, time,
        controller authorisation, status, build. Appends reasons to `why`, which may already hold the caller's (they
        stop it before anything is fetched). Returns the issuer's key, or None when it stopped early."""
        pol, now = self.policy, self.now()
        iss, ctrl, build, iat, exp = c["iss"], c["agent_controller"], c["agent_build"], c["iat"], c["exp"]
        if pol["issuers"] is not None and iss not in pol["issuers"]:
            why.append("issuer-not-trusted")
        if set(build) - pp.BUILD_MEMBERS - set(pol["ignorable_build"]):
            why.append("unknown-build-member")
        if iat > now + SKEW or now >= exp or not self.rules.lifetime_ok(iat, exp):
            why.append("passport-time")
        if why:
            return None

        im = self._get("issuer", iss, value)
        keys = im and im["doc"].get("keys")
        if not im or im["doc"].get("issuer") != iss or not isinstance(keys, dict) or h["kid"] not in keys:
            why.append("issuer-unavailable")
            return None
        try:
            issuer_key = pp.key_of(keys[h["kid"]])
        except (ValueError, TypeError):
            why.append("issuer-key-malformed")
            return None
        if not pp.jws_check(si, sig, issuer_key):
            why.append("passport-signature")
            return None

        cd = self._get("controller", ctrl, value, force=self._fresh)
        if not cd:
            why.append("controller-unavailable")
        elif not self.rules.controller_authorises(cd["doc"], ctrl, iss):
            why.append("controller-not-authorised")

        ref = c.get("status")
        if ref is None:
            if pol["require_status"] and value == rp.HIGH:
                why.append("no-status")
        else:
            st, reason = self._status(ref, issuer_key, value, record)
            if st != "good":
                why.append(_status_why(reason))

        b = self.rules.build_assurance(pp.build_digest(build), set(pol["pinned"]), im["doc"].get("policy"), value,
                                       pol["accept_unattested"])
        why += b["reasons"]
        record += b["record"]
        return issuer_key

    # --- Agent-Delegation (draft-le-agent-passport-01, "Chain Validation") ---------------------------------
    def _chain(self, req, leaf, value, record, tool, spend, note=None):
        """(reasons, receipt claims root to leaf). `leaf` is the acting agent's passport, already validated. `note`
        receives what the root carries beyond its grants: "approval" ("verified" | "asserted"), "principal"
        ({"ev_iss", "assurance"}) and "principal_bound_args" for the exposure term."""
        note = {} if note is None else note
        pol = self.policy
        try:
            toks = _members(req["headers"]["agent-delegation"])
            parsed = [_parse_receipt(t) for t in toks]
            others = {}
            for t in _members(req["headers"]["agent-passport"])[1:]:
                p = _parse(t)
                others[p[1]["sub"]] = p
        except (ValueError, KeyError, TypeError):
            return ["delegation-malformed"], None
        if not toks or len(toks) > dlg.MAX_CHAIN:
            return ["chain-length"], None
        receipts = [c for _, c, _, _ in parsed]
        why = sorted({w for c in receipts for w in dlg.receipt_problems(c)} |
                     {k[4:] + "-in-child" for c in receipts[1:] for k in dlg.ROOT_ONLY if k in c})
        if why:
            return why, None

        rh, root, rsi, rsig = parsed[0]
        if "dlg_parent" in root:
            return ["root-has-parent"], None
        if root["iss"] not in pol["authorization_servers"]:
            return ["root-issuer-not-trusted"], None
        im = self._get("issuer", root["iss"], value)
        keys = im and im["doc"].get("keys")
        if not im or im["doc"].get("issuer") != root["iss"] or not isinstance(keys, dict) or rh["kid"] not in keys:
            return ["root-issuer-unavailable"], None
        as_key = pp.key_of(keys[rh["kid"]])
        if not pp.jws_check(rsi, rsig, as_key):
            return ["receipt-signature"], None
        why += self._receipt_checks(root, as_key, value, record)
        why += self._approval(root, im["doc"], req, record, note)
        why += self._principal(root, len(receipts), note)

        by_key = {pp.thumbprint(leaf["cnf"]["jwk"]): leaf}
        prev_tok, prev = toks[0], root
        for tok, (h, c, si, sig) in zip(toks[1:], parsed[1:]):
            if c.get("dlg_parent") != dlg.digest(prev_tok):
                why.append("receipt-parent")
            if c["sub"] != root["sub"]:
                why.append("receipt-sub")
            p = others.get(c["iss"]) or ((None, leaf, None, None) if c["iss"] == leaf["sub"] else None)
            if p is None:
                why.append("delegator-passport-missing")
                break
            ph, pc, psi, psig = p
            if pc is not leaf:
                if pc["sub"] != pp.THUMB_URI + pp.thumbprint(pc["cnf"]["jwk"]):
                    why.append("sub-mismatch")
                    break
                pw = []
                delegator_key = self._check_passport(ph, pc, psi, psig, value, record, pw)
                why += pw
                if delegator_key is None:
                    break
            else:
                delegator_key = None                       # the acting agent's passport, validated by the caller
            by_key[pp.thumbprint(pc["cnf"]["jwk"])] = pc
            if pp.thumbprint(pc["cnf"]["jwk"]) != prev["cnf"]["jkt"]:
                why.append("delegator-key-mismatch")
            if not pp.jws_check(si, sig, pp.key_of(pc["cnf"]["jwk"])):
                why.append("receipt-signature")
                break
            why += dlg.attenuation(c, prev)
            # ponytail: a child receipt's status list is checked against its delegator's passport issuer key; the
            # draft does not say who signs it. No key (acting agent self-delegating) means it cannot be determined.
            why += self._receipt_checks(c, delegator_key, value, record)
            prev_tok, prev = tok, c
        if why:
            return sorted(set(why)), None

        if prev["cnf"]["jkt"] != pp.thumbprint(leaf["cnf"]["jwk"]):
            why.append("leaf-key-mismatch")
        for r in receipts:
            d = by_key.get(r["cnf"]["jkt"])
            if "dlg_build" in r and (d is None or pp.build_digest(d["agent_build"]) != r["dlg_build"]):
                why.append("dlg-build-mismatch")
        if not dlg.match(prev["dlg_grants"], req["method"], req["target_uri"], len(req.get("body") or b""), tool):
            why.append("request-not-granted")
        if not why and not self._fresh:                # a revalidation was counted when it was allowed
            why += dlg.limit_check(receipts, pol["rp_id"], self.limit_counts, spend)
        return sorted(set(why)), receipts

    def _approval(self, root, as_meta, req, record, note):
        """`dlg_approval` on the root (design 4.3.1). With `authenticator_sig` it is checked against the key the root's
        authorisation server vouches for (`authenticator_keys` in its metadata, by `kid`) and recorded
        `approval-verified`: that authenticator approved that action shown as that display. Without it, it is only the
        authorisation server's statement, recorded `approval-asserted`. Whether the display matches the action is
        checked here only when this RP holds the action (`approval_expect`); otherwise by the verifier `checked_by`
        names."""
        pol, a = self.policy, root.get("dlg_approval")
        if a is None:
            return ["approval-missing"] if pol["min_approval"] else []
        why = []
        if a["at"] > self.now() + SKEW:
            why.append("approval-time")
        if "authenticator_sig" in a:
            meta = as_meta if isinstance(as_meta, dict) else {}
            jwk = (meta.get("authenticator_keys") or {}).get(a["kid"])
            if jwk is None:
                why.append("approval-key-unknown")
            elif "webauthn" in a:                           # a WebAuthn assertion: type, challenge, origin, rpIdHash, UP
                bad, uv = dlg.webauthn_problem(a, jwk, meta.get("authenticator_rp_id"), meta.get("authenticator_origins"))
                if bad:
                    why.append(bad)
                else:
                    note["approval"] = "verified"
                    if uv:
                        record.append("approval-uv")
            else:
                try:
                    ok = pp.jws_check(dlg.approval_message(a), pp.unb64u(a["authenticator_sig"]), pp.key_of(jwk))
                except (ValueError, TypeError):
                    ok = False
                if ok:
                    note["approval"] = "verified"
                else:
                    why.append("approval-signature")
        else:
            note["approval"] = "asserted"
            if pol["min_approval"] == "verified":
                why.append("approval-not-verified")
        if note.get("approval"):
            record.append("approval-" + note["approval"])
        want = pol["approval_expect"] and pol["approval_expect"](req)
        if want:
            why += [k.split("_")[0] + "-mismatch" for k in ("action_digest", "display_digest")
                    if want.get(k) is not None and want[k] != a[k]]
        return why

    def _principal(self, root, n_receipts, note):
        """`dlg_principal` on the root (draft -01 Principal Evidence, Marc Molas): ev_iss and assurance against local
        policy, ev_time against the maximum principal-evidence age M; a child under such a root only where the
        profile allows it (deny when it says nothing). Never read as identifying the principal."""
        pol, p = self.policy["principal"] or {}, root.get("dlg_principal")
        if p is None:
            return ["principal-missing"] if pol.get("require") else []
        why, now = [], self.now()
        rule = (pol.get("issuers") or {}).get(p["ev_iss"])
        if rule is None:
            why.append("principal-issuer-not-trusted")
        elif p["assurance"] not in rule.get("assurance", ()):
            why.append("principal-assurance")
        if p["ev_time"] > now + SKEW:
            why.append("principal-time")
        if pol.get("max_age") is not None and now - p["ev_time"] > pol["max_age"]:
            why.append("principal-evidence-age")
        if n_receipts > 1 and not pol.get("children"):
            why.append("principal-no-children")
        note["principal"] = {"ev_iss": p["ev_iss"], "assurance": p["assurance"]}
        # ponytail: R and T (the authorisation server's re-check interval and status ttl) are not known to the RP;
        # add them per authorisation server in policy if one publishes them.
        note["principal_bound_args"] = {"B": (rule or {}).get("bound_s"), "L": root["exp"] - root["iat"],
                                        "M": pol.get("max_age")}
        return why

    def _receipt_checks(self, c, status_key, value, record):
        why, now = [], self.now()
        if c["iat"] > now + SKEW or now >= c["exp"]:
            why.append("receipt-time")
        if c.get("aud") is not None and self.policy["rp_id"] not in c["aud"]:
            why.append("receipt-aud")
        if "status" in c:
            st, reason = self._status(c["status"], status_key, value, record) if status_key else ("revoked", "status-unavailable")
            if st != "good":
                why.append(_status_why(reason))
        return why

    def _as_declared_authority(self, req, holder, now):
        """(request as the client addressed it, httpsig result) when the request reached this RP under one of the
        authorities it declares as its own and the signature verifies under another of them: a front end of the RP's
        own rewrote the host. None otherwise. The set is the RP's configuration, never taken from the request, and
        `@authority` stays covered."""
        own = [str(a).lower() for a in self.policy["authorities"]]
        got = str(req.get("authority") or "").lower()
        if got not in own:
            return None
        u = urlsplit(req["target_uri"])
        for a in own:
            if a == got:
                continue
            r2 = dict(req, authority=a, target_uri=urlunsplit((u.scheme, a, u.path, u.query, u.fragment)))
            res = httpsig.verify(r2, holder, now, SKEW)
            if not res[0]:
                return r2, res
        return None

    def _purge(self, now):
        for k in [k for k, t in self.nonces.items() if t < now]:
            del self.nonces[k]

    def _exposure_events(self, exp, now, ref, value, principal=None):
        """The bound for each kind of revocation event, kept apart (rp_policy.exposure_by_event), with the bounds
        the outside verifiers state (policy `outside_bounds`) and, when the root carries `dlg_principal`, the
        principal-standing term measured from the evidence issuer's event. `exposure` stays the largest of our own
        three."""
        p = self.policy
        ttl = p["max_status_ttl"] + SKEW if ref else 0
        fn = getattr(self.rules, "exposure_by_event", rp.exposure_by_event)
        kw = {"principal": principal} if principal else {}
        return fn(exp, now, ttl, p["grace"], value, p["revalidate_issuer_high"], outside=p["outside_bounds"] or None, **kw)

    def _exposure(self, exp, now, ref, value):
        """Worst-case seconds this acceptance can outlast a revocation event, over the three mechanisms."""
        r, p = self.rules, self.policy
        ttl = p["max_status_ttl"] + SKEW if ref else 0
        rev = p["revalidate_issuer_high"]
        return max(r.exposure_bound(exp, now, "status", ttl, p["grace"], value, rev),
                   r.exposure_bound(exp, now, "controller", value=value),
                   r.exposure_bound(exp, now, "issuer_key", value=value, revalidate_issuer_high=rev))



def _status_why(reason):
    """The deny reason for an undeterminable or revoked status: the three stay distinguishable in the log."""
    return reason if reason in ("status-unavailable", "status-stale") else "revoked"


def _parse(token):
    """(header, claims, signing_input, signature) of a passport whose required claims have the right types."""
    h, c, si, sig = pp.jws_parse(token, pp.PASSPORT_TYP)
    pp.key_of(c["cnf"]["jwk"])
    if (not all(isinstance(c[k], str) for k in ("iss", "agent_controller", "sub", "jti"))
            or not isinstance(c["agent_build"], dict) or not _int(c["iat"]) or not _int(c["exp"])):
        raise ValueError("claims")
    return h, c, si, sig


def _parse_receipt(token):
    h, c, si, sig = pp.jws_parse(token, dlg.DLG_TYP)
    if (not all(isinstance(c.get(k), str) for k in ("iss", "sub", "jti")) or not _int(c.get("iat"))
            or not _int(c.get("exp")) or not isinstance(c.get("cnf"), dict) or not isinstance(c["cnf"].get("jkt"), str)):
        raise ValueError("receipt claims")
    return h, c, si, sig


def _members(header):
    """Every String member of a Structured Field List of JWS values; parameters are ignored."""
    if not isinstance(header, str):
        raise ValueError("header")
    out = []
    for m in header.split(","):
        m = m.split(";")[0].strip()
        if len(m) < 2 or m[0] != '"' or m[-1] != '"':
            raise ValueError("header")
        out.append(m[1:-1])
    return out


def _first(header):
    """First member of the Agent-Passport list: a single quoted string, optionally with more after a comma."""
    if not isinstance(header, str):
        raise ValueError("header")
    m = header.strip().split(",")[0].strip()
    if len(m) < 2 or m[0] != '"' or m[-1] != '"':
        raise ValueError("header")
    return m[1:-1]
