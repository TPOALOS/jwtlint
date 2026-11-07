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

__version__ = "1.1.0"

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
    for name, value in (("exp", exp), ("iat", iat), ("nbf", nbf)):
        if isinstance(value, (int, float)) and value > 100_000_000_000:
            add("MEDIUM", "timestamp-in-milliseconds",
                "%s=%s looks like milliseconds; JWT times are seconds, so this token may be valid for millennia" % (name, value),
                "issue NumericDate values in seconds since the epoch")
    if isinstance(exp, (int, float)) and isinstance(iat, (int, float)) and exp <= iat:
        add("MEDIUM", "exp-before-iat", "exp is not after iat: the token was already expired when issued",
            "check the issuer's clock and lifetime arithmetic")
    if isinstance(nbf, (int, float)) and isinstance(exp, (int, float)) and nbf >= exp:
        add("MEDIUM", "nbf-after-exp", "nbf is not before exp: the token is never valid", "check the issuer's claims")
    if isinstance(iat, (int, float)) and iat > now + 300:
        add("LOW", "iat-in-future", "iat is in the future (clock skew or forged token)", "verify clocks; allow only small leeway")
    if isinstance(alg, str) and alg != alg.upper() and alg.lower() != "none" and alg.lower().startswith(("hs", "rs", "es", "ps")):
        add("LOW", "alg-case", "alg %r is not in the canonical upper-case form" % alg,
            "use the exact RFC 7518 name; lenient parsers are a source of algorithm confusion")
    aud = payload.get("aud")
    if aud == "*" or (isinstance(aud, list) and "*" in aud):
        add("MEDIUM", "wildcard-aud", "aud is a wildcard, so any service may accept this token", "name the intended audience")
    iss = payload.get("iss")
    if isinstance(iss, str) and iss.lower().startswith("http://"):
        add("LOW", "insecure-iss", "iss is a plain http URL", "use an https issuer")
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


def read_tokens(args):
    """Tokens from positional arguments, --file and stdin (one per line)."""
    tokens = []
    for t in args.tokens:
        if t == "-":
            tokens += [l.strip() for l in sys.stdin if l.strip()]
        else:
            tokens.append(t)
    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as fh:
            tokens += [l.strip() for l in fh if l.strip() and not l.lstrip().startswith("#")]
    if not tokens and not args.file:
        tokens = [l.strip() for l in sys.stdin if l.strip()]
    return tokens


def main(argv=None):
    ap = argparse.ArgumentParser(description="Inspect JWTs offline (no signature verification).")
    ap.add_argument("tokens", nargs="*", help="token(s); - or nothing reads stdin, one token per line")
    ap.add_argument("-f", "--file", help="file with one token per line (# comments ok)")
    ap.add_argument("--show", action="store_true", help="also print decoded header and payload")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--now", type=float, help="evaluate expiry against this Unix time instead of the clock")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    try:
        tokens = read_tokens(args)
    except OSError as exc:
        print("jwtlint: %s" % exc, file=sys.stderr)
        return 2
    if not tokens:
        print("jwtlint: no token given", file=sys.stderr)
        return 2
    results, worst = [], 0
    for n, token in enumerate(tokens, 1):
        entry = {"index": n, "valid": True, "findings": [], "signature_verified": False}
        try:
            findings = audit(token, args.now)
            header, payload, _, count = decode(token)
        except JwtError as exc:
            entry.update(valid=False, error=str(exc))
            results.append(entry)
            worst = 2
            continue
        entry["format"] = "JWE" if count == 5 else "JWS"
        entry["findings"] = [{"severity": sv, "rule": r, "message": m, "fix": f} for sv, r, m, f in findings]
        if args.show:
            entry["header"], entry["payload"] = header, payload
        results.append(entry)
        if any(f[0] != "INFO" for f in findings) and worst == 0:
            worst = 1
    if args.json:
        print(json.dumps(results if len(results) > 1 or args.file else results[0], indent=2, sort_keys=True))
    else:
        many = len(results) > 1
        for entry in results:
            if many:
                print("== token %d" % entry["index"])
            if not entry["valid"]:
                print("jwtlint: %s" % entry["error"], file=sys.stderr)
                continue
            if args.show:
                print("header :", json.dumps(entry["header"], sort_keys=True))
                print("payload:", json.dumps(entry["payload"], sort_keys=True) if entry["payload"] is not None else "(encrypted)")
            for f in entry["findings"]:
                print("%-6s %-16s %s%s" % (f["severity"], f["rule"], f["message"], "\n         fix: " + f["fix"] if f["fix"] else ""))
            real = sum(1 for f in entry["findings"] if f["severity"] != "INFO")
            print("jwtlint: %d finding(s) (signature NOT verified)" % real, file=sys.stderr)
    return worst

if __name__ == "__main__":
    sys.exit(main())
