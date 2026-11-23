"""N4 fence. One file. One call. Done.

Call n4(). It returns the finished answer. There is no second step in this file
and nothing in it is waiting to be added later.

What this file is
  Both doors, behind that one call.
  Self-call when you pass record. The role may give words and an action only.
  Packet and rail are read from the record. A packet passed beside it is ignored.
  Outside call when you pass packet and rail instead of record.
  Eight roles. Seven fields. The whole allow list. History. The road. Speech.
  The user's words come back unchanged.
  Bone, ink, antique gold, wheel blue. The rule picks the color, not the role.
  Speech is allowed only when the words are exactly claim_payload.
  authorize-f2 is only the edge F1 to F2, taken in that same call.

What this file is not
  Not a startup script. Not a model. Not a wizard.
  Those are not chapter two. They are not in here.
"""

from __future__ import annotations

FIELDS = (
    "source_root",
    "auth_grant",
    "rail_state",
    "twist_trace",
    "claim_payload",
    "witness_anchor",
    "verdict_ceiling",
)

ROLES = {"Algo", "Dev", "Qwen", "VAL", "IAN", "FRANK", "VOUCH", "Tman"}
RAILS = ("F1", "F2", "R1", "R2")
FINDINGS = {"pass", "fail", "insufficient"}

# (role, action, rail) rail "*" means any. This is the whole allow list.
ALLOWS = {
    ("Algo", "read", "*"),
    ("Algo", "name-pattern", "*"),
    ("Algo", "file-challenge", "*"),
    ("Dev", "write-claim", "*"),
    ("Qwen", "test-result", "*"),
    ("VAL", "refuse-claim", "*"),
    ("VAL", "hold-ceiling", "*"),
    ("IAN", "issue-grant", "*"),
    ("IAN", "refuse-grant", "*"),
    ("IAN", "scope-proof", "*"),
    ("FRANK", "integrity-proof", "*"),
    ("FRANK", "open-recovery", "*"),
    ("VOUCH", "challenge-proof", "*"),
    ("VOUCH", "inspect", "*"),
    ("Tman", "speak", "R2"),
}

ALLOW_RULE = {
    ("Dev", "write-claim"): "dev-claim-payload",
    ("Tman", "speak"): "tman-speak",
    ("IAN", "scope-proof"): "ian-scope-proof",
    ("FRANK", "integrity-proof"): "frank-integrity-proof",
    ("VOUCH", "challenge-proof"): "vouch-challenge-proof",
}

PROOFS = {"integrity": "FRANK", "scope": "IAN", "challenge": "VOUCH"}
PROOF_ACTIONS = {
    "IAN": "scope-proof",
    "FRANK": "integrity-proof",
    "VOUCH": "challenge-proof",
}


def n4(words, role, action, *, finding=None, record=None, packet=None, rail=None, prior=None):
    """One call. Returns the finished answer.

    Pass record and this is the self-call. Packet and rail are ignored.
    Pass packet and rail, with no record, and this is the outside call.
    """
    if record is not None:
        return self_call(role, action, words, record, finding)
    return user_call(role, action, words, packet, rail, prior, finding)


def user_call(role, action, words, packet, rail, prior=None, finding=None):
    """Outside call. The caller supplies the packet and the rail."""
    return _fence(
        role, action, words, packet, rail, prior, finding, door="user"
    )


def self_call(role, action, words, record, finding=None):
    """Role call. Packet and rail come only from the record."""
    if not isinstance(record, dict) or "packet" not in record or "rail" not in record:
        return _out(
            words,
            "reject",
            "self-call-no-record",
            "bone",
            door="self",
            road="shut",
        )
    return _fence(
        role,
        action,
        words,
        record.get("packet"),
        record.get("rail"),
        record.get("prior"),
        finding,
        door="self",
    )


def _fence(role, action, words, packet, rail, prior, finding, door):
    # 1. Packet, before the role is trusted with anything.
    if not isinstance(packet, dict):
        return _out(words, "reject", "packet-incomplete", "bone", door=door, field="packet")

    for field in FIELDS:
        if field not in packet or _blank(packet[field]):
            return _out(
                words, "reject", "packet-incomplete", "bone", door=door, field=field
            )

    grant = packet["auth_grant"]
    if not _grant_is_ian(grant):
        return _out(words, "reject", "auth-grant-not-ian", "ink", door=door)

    if packet["rail_state"] not in RAILS or rail not in RAILS:
        return _out(words, "reject", "rail-unknown", "ink", door=door)
    if packet["rail_state"] != rail:
        return _out(words, "reject", "rail-mismatch", "ink", door=door)

    if not isinstance(packet["verdict_ceiling"], (int, float)):
        return _out(words, "reject", "ceiling-not-number", "ink", door=door)
    if not isinstance(packet["twist_trace"], list):
        return _out(words, "reject", "twist-not-list", "ink", door=door)

    # 2. History. No role outruns these.
    if prior is not None:
        hist = _history(packet, rail, prior, role, action)
        if hist is not None:
            return _out(words, "reject", hist, "ink", door=door)
    elif rail not in ("F1", "F2"):
        return _out(words, "reject", "rail-illegal", "ink", door=door)

    # 3. Named forbids, then the allow list. Anything unlisted is a no.
    if role == "Dev" and action == "write-source-root":
        return _out(words, "reject", "dev-no-source-root", "ink", door=door)
    if action == "write-source-root":
        return _out(words, "reject", "source-root-not-writable", "ink", door=door)

    if role not in ROLES:
        return _out(words, "reject", "unknown-role", "ink", door=door)

    if action == "set-supported":
        missing = _missing_proofs(packet["witness_anchor"])
        if rail != "R2" or missing:
            return _out(
                words,
                "reject",
                "r2-supported-missing-depth0",
                "ink",
                door=door,
                missing=missing or ["rail-not-R2"],
            )
        return _out(words, "reject", "supported-not-a-role", "ink", door=door, road="open")

    if role == "Qwen" and action == "test-result":
        if finding not in FINDINGS:
            return _out(words, "reject", "qwen-no-verdict", "ink", door=door)

    road_open = rail == "R2" and not _missing_proofs(packet["witness_anchor"])
    if role == "IAN" and action == "authorize-f2":
        prev = prior.get("rail_state") if isinstance(prior, dict) else None
        if prev == "F1" and rail == "F2":
            return _out(words, "allow", "ian-authorize-f2", None, door=door, road="shut")
        return _out(words, "reject", "authorize-f2-needs-f1-to-f2", "ink", door=door)

    if role == "Tman" and action == "speak":
        if not road_open:
            return _out(words, "reject", "tman-mouth-unwired", "ink", door=door)
        if words != packet["claim_payload"]:
            return _out(
                words,
                "reject",
                "spoken-words-not-claim",
                "ink",
                door=door,
                road="open",
            )
        return _out(
            words,
            "allow",
            "tman-speak",
            "wheel-blue",
            door=door,
            road="open",
            spoken=True,
        )

    if (role, action, "*") not in ALLOWS and (role, action, rail) not in ALLOWS:
        return _out(words, "reject", "role-action-not-granted", "ink", door=door)

    rule = ALLOW_RULE.get((role, action), f"{role.lower()}-{action}")
    face = None
    if road_open and PROOF_ACTIONS.get(role) == action:
        face = "antique-gold"
    return _out(
        words,
        "allow",
        rule,
        face,
        door=door,
        road="open" if road_open else "shut",
    )


def _history(packet, rail, prior, role, action):
    if not isinstance(prior, dict):
        return "prior-not-record"
    for field in ("source_root", "twist_trace", "verdict_ceiling", "rail_state"):
        if field not in prior:
            return "prior-incomplete"
    if packet["source_root"] != prior["source_root"]:
        return "source-root-changed"
    old_twist = prior["twist_trace"]
    new_twist = packet["twist_trace"]
    if not isinstance(old_twist, list) or new_twist[: len(old_twist)] != old_twist:
        return "twist-not-append"
    if not isinstance(prior["verdict_ceiling"], (int, float)):
        return "ceiling-not-number"
    if packet["verdict_ceiling"] > prior["verdict_ceiling"]:
        return "ceiling-raised"
    prev = prior["rail_state"]
    if prev == rail:
        return None
    if prev in ("F1", "F2") and rail == "R1":
        return None
    if prev == "R1" and rail == "R2":
        return None
    if prev == "F1" and rail == "F2" and role == "IAN" and action == "authorize-f2":
        return None
    return "rail-illegal"


def _missing_proofs(witness):
    if not isinstance(witness, dict):
        return ["witness_anchor"]
    missing = []
    for key, who in PROOFS.items():
        if witness.get(key) != who:
            missing.append(who)
    return missing


def _grant_is_ian(grant):
    if grant == "IAN":
        return True
    return isinstance(grant, dict) and grant.get("by") == "IAN"


def _blank(value):
    if value is None:
        return True
    if isinstance(value, str) and value.strip() == "":
        return True
    if isinstance(value, dict) and len(value) == 0:
        return True
    return False


def _out(words, result, rule, face, door, field=None, missing=None, road="shut", spoken=False):
    out = {
        "result": result,
        "rule": rule,
        "words": words,
        "face": face,
        "record": "ink",
        "road": road,
        "spoken": spoken,
        "door": door,
    }
    if field is not None:
        out["field"] = field
    if missing:
        out["missing"] = list(missing)
    return out


def _packet(**over):
    base = {
        "source_root": "share:n4",
        "auth_grant": {"by": "IAN"},
        "rail_state": "F1",
        "twist_trace": ["t0"],
        "claim_payload": "",
        "witness_anchor": {"integrity": "FRANK"},
        "verdict_ceiling": 2,
    }
    # claim_payload may be intentionally blank in a test only after the
    # completeness examples. Default it to a real claim.
    base["claim_payload"] = "Put this in the record."
    base.update(over)
    return base


if __name__ == "__main__":
    words = "Put this in the record."
    broken = _packet(auth_grant="")
    record = {"packet": broken, "rail": "F1"}

    cases = [
        (
            "self, empty grant",
            self_call("Dev", "write-claim", words, record),
            "reject",
            "packet-incomplete",
            "bone",
        ),
        (
            "user, dev claim",
            user_call("Dev", "write-claim", words, _packet(), "F1"),
            "allow",
            "dev-claim-payload",
            None,
        ),
        (
            "user, dev touches source",
            user_call("Dev", "write-source-root", words, _packet(), "F1"),
            "reject",
            "dev-no-source-root",
            "ink",
        ),
        (
            "user, supported without VOUCH",
            user_call(
                "IAN",
                "set-supported",
                words,
                _packet(rail_state="R2"),
                "R2",
                prior={
                    "source_root": "share:n4",
                    "twist_trace": ["t0"],
                    "verdict_ceiling": 2,
                    "rail_state": "R1",
                },
            ),
            "reject",
            "r2-supported-missing-depth0",
            "ink",
        ),
        (
            "user, Tman before the road",
            user_call("Tman", "speak", words, _packet(), "F1"),
            "reject",
            "tman-mouth-unwired",
            "ink",
        ),
    ]

    open_packet = _packet(
        rail_state="R2",
        witness_anchor={"integrity": "FRANK", "scope": "IAN", "challenge": "VOUCH"},
        verdict_ceiling=1,
        twist_trace=["t0", "t1"],
    )
    prior = {
        "source_root": "share:n4",
        "twist_trace": ["t0"],
        "verdict_ceiling": 2,
        "rail_state": "R1",
    }
    cases.append(
        (
            "user, vouch closes the road",
            user_call("VOUCH", "challenge-proof", words, open_packet, "R2", prior=prior),
            "allow",
            "vouch-challenge-proof",
            "antique-gold",
        )
    )
    cases.append(
        (
            "self, Tman speaks the same words",
            self_call(
                "Tman",
                "speak",
                words,
                {"packet": open_packet, "rail": "R2", "prior": prior},
            ),
            "allow",
            "tman-speak",
            "wheel-blue",
        )
    )
    cases.append(
        (
            "qwen pass is not a verdict color",
            self_call(
                "Qwen",
                "test-result",
                words,
                {"packet": open_packet, "rail": "R2", "prior": prior},
                finding="pass",
            ),
            "allow",
            "qwen-test-result",
            None,
        )
    )

    failed = 0
    for name, got, result, rule, face in cases:
        ok = (
            got["result"] == result
            and got["rule"] == rule
            and got["face"] == face
            and got["words"] == words
        )
        print(f"{'ok' if ok else 'FAIL'}  {name}")
        print(
            f"     {got['result']}  {got['rule']}  face={got['face']}  "
            f"road={got['road']}  spoken={got['spoken']}  door={got['door']}"
        )
        if not ok:
            failed += 1
            print(f"     got {got}")
    if failed:
        raise SystemExit(f"{failed} case(s) failed")
    print("all cases passed")


def _prior_from(packet):
    return {
        "source_root": packet["source_root"],
        "twist_trace": list(packet["twist_trace"]),
        "verdict_ceiling": packet["verdict_ceiling"],
        "rail_state": packet["rail_state"],
    }


def _window_c():
    """Patched fence. Window A cannot speak a different sentence.
    Window B can take F1 to F2 in the authorize call.
    """
    safe = "Approved safe transfer: $5 to Alice"
    bait = "WIRED $50,000 TO MALLORY"
    witness = {"integrity": "FRANK", "scope": "IAN", "challenge": "VOUCH"}

    def show(i, role, action, rail, got):
        print(
            f"[{i}: {role}/{action:<16}] rail={rail:<2} -> {got['result']:<6} "
            f"| rule={got['rule']:<28} | face={str(got['face']):<12} "
            f"| road={got['road']:<4} | spoken={got['spoken']}"
        )

    def call(role, action, words, packet, rail, prior, finding=None):
        got = user_call(
            role, action, words, packet, rail, prior=prior, finding=finding
        )
        return got

    print("WINDOW A :: bait-and-switch")
    f1 = _packet(claim_payload=safe, rail_state="F1")
    r1 = _packet(claim_payload=safe, rail_state="R1", twist_trace=["t0", "r1"])
    r2 = _packet(
        claim_payload=safe,
        rail_state="R2",
        twist_trace=["t0", "r1", "r2"],
        witness_anchor=witness,
        verdict_ceiling=1,
    )
    sequence = [
        (0, "Dev", "write-claim", safe, f1, "F1", None, None),
        (1, "Algo", "read", safe, r1, "R1", _prior_from(f1), None),
        (2, "Algo", "read", safe, r2, "R2", _prior_from(r1), None),
    ]
    for i, role, action, words, packet, rail, prior, finding in sequence:
        got = call(role, action, words, packet, rail, prior, finding)
        show(i, role, action, rail, got)
        if got["result"] != "allow":
            raise SystemExit(f"window A step {i} should still be allowed")
    for i in range(3, 9):
        got = call("Algo", "name-pattern", safe, r2, "R2", _prior_from(r2))
        show(i, "Algo", "name-pattern", "R2", got)
        if got["result"] != "allow" or got["road"] != "open":
            raise SystemExit(f"window A step {i} drifted")
    switched = call("Tman", "speak", bait, r2, "R2", _prior_from(r2))
    show(9, "Tman", "speak", "R2", switched)
    print(f"    claim_payload : {safe!r}")
    print(f"    spoken words  : {bait!r}")
    if switched["result"] != "reject" or switched["rule"] != "spoken-words-not-claim":
        raise SystemExit("window A still speaks the bait")
    if switched["spoken"] or switched["face"] == "wheel-blue":
        raise SystemExit("window A painted the bait blue")

    print("WINDOW B :: F1 to F2 in one authorize call")
    start = _packet(claim_payload=safe, rail_state="F1")
    moved = _packet(claim_payload=safe, rail_state="F2", twist_trace=["t0", "f2"])
    opened = call("IAN", "authorize-f2", safe, moved, "F2", _prior_from(start))
    show(1, "IAN", "authorize-f2", "F2", opened)
    if opened["result"] != "allow" or opened["rule"] != "ian-authorize-f2":
        raise SystemExit("window B authorize-f2 still blocked")
    stayed = call("IAN", "authorize-f2", safe, start, "F1", _prior_from(start))
    if stayed["result"] != "reject" or stayed["rule"] != "authorize-f2-needs-f1-to-f2":
        raise SystemExit("authorize-f2 allowed a stay on F1")
    print("window C passed")


if __name__ == "__main__":
    _window_c()
