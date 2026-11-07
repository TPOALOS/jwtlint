#!/usr/bin/env python3
"""jwtlint - inspect a JSON Web Token and point out weaknesses.

Decodes the header and payload OFFLINE and WITHOUT verifying the signature
(anyone can read a JWT; it is encoded, not encrypted). It never contacts a server
and never tries to guess keys. Use it to review tokens your own services issue.
Standard library only. Exit code 0 = no findings, 1 = findings, 2 = not a JWT.
"""
import argparse
import base64
import datetime
import json
import re
import sys
import time

__version__ = "1.0.0"

SENSITIVE = re.compile(r"(?i)(pass(word|wd)?|secret|ssn|credit|card|cvv|iban|private|api[_-]?key)")
PII = re.compile(r"(?i)^(email|phone|phone_number|address|birthdate|name|given_name|family_name)$")
SEV = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
DAY = 86400


class JwtError(ValueError):
    pass


def b64url_decode(seg):
    try:
        return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
    except (ValueError, TypeError) as exc:
        raise JwtError("invalid base64url segment") from exc


def decode(token):
    """Return (header, payload, signature_segment, segment_count). Does not verify."""
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) == 5:
        try:
            return json.loads(b64url_decode(parts[0])), None, parts[4], 5
        except ValueError as exc:
            raise JwtError("invalid JWE header") from exc
    if len(parts) != 3:
        raise JwtError("expected 3 dot-separated segments (JWS), got %d" % len(parts))
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except (ValueError, UnicodeDecodeError) as exc:
        raise JwtError("header or payload is not valid JSON") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JwtError("header and payload must be JSON objects")
    return header, payload, parts[2], 3


def fmt_time(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def audit(token, now=None):
    """Return list of (severity, rule, message, fix)."""
    now = time.time() if now is None else now
    header, payload, sig, count = decode(token)
    out = []
    add = lambda sev, rule, msg, fix="": out.append((sev, rule, msg, fix))
    alg = header.get("alg")
    if alg is None:
        add("HIGH", "missing-alg", "header has no alg", "reject tokens without an explicit allowed algorithm")
    elif str(alg).lower() == "none":
        add("HIGH", "alg-none", "alg is 'none': the token is unsigned", "never accept alg none; pin the algorithm server-side")
    elif count == 3 and not sig:
        add("HIGH", "empty-signature", "signature segment is empty", "reject unsigned tokens")
    elif str(alg).upper() in ("HS256", "HS384", "HS512"):
        add("INFO", "symmetric-alg", "%s uses a shared secret; make sure it is long and random" % alg,
            "prefer asymmetric signing (RS256/ES256/EdDSA) when many services verify tokens")
    for h in ("jku", "jwk", "x5u", "x5c"):
        if h in header:
            add("MEDIUM", "key-in-header", "header carries %r; servers that trust it can be tricked into using attacker keys" % h,
                "ignore key material in headers and use a fixed, server-side key set")
    kid = header.get("kid")
    if isinstance(kid, str) and re.search(r"[./\\'\";|`$]|\.\.", kid):
        add("HIGH", "suspicious-kid", "kid contains path or injection characters", "treat kid as an opaque lookup key only")
    if payload is None:
        add("INFO", "encrypted", "JWE: payload is encrypted and cannot be inspected")
        return sorted(out, key=lambda f: SEV[f[0]])
    exp, iat, nbf = payload.get("exp"), payload.get("iat"), payload.get("nbf")
    if exp is None:
        add("MEDIUM", "no-expiry", "no exp claim: the token never expires", "set a short exp")
    elif isinstance(exp, (int, float)):
        if exp < now:
            add("INFO", "expired", "expired at %s" % fmt_time(exp))
        base = iat if isinstance(iat, (int, float)) else None
        lifetime = exp - (base if base is not None else now)
        if base is not None and lifetime > 30 * DAY:
            add("MEDIUM", "long-lived", "lifetime is %.0f days" % (lifetime / DAY), "use short-lived access tokens plus refresh tokens")
        elif base is not None and lifetime > DAY:
            add("LOW", "long-lived", "lifetime is %.1f days" % (lifetime / DAY), "prefer minutes to hours for access tokens")
    else:
        add("MEDIUM", "bad-exp", "exp is not a number")
    if isinstance(nbf, (int, float)) and nbf > now:
        add("INFO", "not-yet-valid", "not valid before %s" % fmt_time(nbf))
    for claim in ("iss", "aud"):
        if claim not in payload:
            add("LOW", "no-" + claim, "no %s claim" % claim, "validate %s on every request" % claim)
    for key in payload:
        if SENSITIVE.search(str(key)):
            add("HIGH", "sensitive-claim", "claim %r looks sensitive; payloads are readable by anyone holding the token" % key,
                "never put secrets in a JWT; use an opaque reference or JWE")
        elif PII.match(str(key)):
            add("LOW", "pii-claim", "claim %r exposes personal data to token holders" % key, "keep personal data out of tokens")
    return sorted(out, key=lambda f: SEV[f[0]])


def main(argv=None):
    ap = argparse.ArgumentParser(description="Inspect a JWT offline (no signature verification).")
    ap.add_argument("token", nargs="?", default="-", help="the token, or - to read stdin")
    ap.add_argument("--show", action="store_true", help="also print decoded header and payload")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    token = sys.stdin.read() if args.token == "-" else args.token
    try:
        findings = audit(token)
        if args.show:
            header, payload, _, _ = decode(token)
            print("header :", json.dumps(header, sort_keys=True))
            print("payload:", json.dumps(payload, sort_keys=True) if payload is not None else "(encrypted)")
    except JwtError as exc:
        print("jwtlint: %s" % exc, file=sys.stderr)
        return 2
    real = 0
    for sev, rule, msg, fix in findings:
        print("%-6s %-16s %s%s" % (sev, rule, msg, "\n         fix: " + fix if fix else ""))
        real += sev != "INFO"
    print("jwtlint: %d finding(s) (signature NOT verified)" % real, file=sys.stderr)
    return 1 if real else 0


if __name__ == "__main__":
    sys.exit(main())
