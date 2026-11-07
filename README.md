# jwtlint

Inspect a JSON Web Token and point out weaknesses in how it was issued.
Works **offline** with one file and the standard library only.

> A JWT is *encoded*, not encrypted: anyone who has the token can read it.
> jwtlint decodes the header and payload **without verifying the signature**, never
> contacts a server and never tries to guess keys. Use it to review tokens that your
> own services issue.

## Usage

```bash
python3 jwtlint.py "$TOKEN"
echo "$TOKEN" | python3 jwtlint.py -
python3 jwtlint.py "$TOKEN" --show        # also print decoded header and payload
python3 jwtlint.py "$TOKEN" --json        # machine-readable
python3 jwtlint.py -f tokens.txt          # one token per line, # comments ok (stdin works too)
python3 jwtlint.py "$TOKEN" --now 1700000000   # judge expiry as of another moment
# or: pip install git+https://github.com/TPOALOS/jwtlint && jwtlint "$TOKEN"
```

With several tokens the exit code is the worst result (`2` if any input is not a JWT, else `1` if any has findings).
Tokens are never echoed back in the output.

A leading `Bearer ` is accepted. Example output for a weak token:

```
HIGH   alg-none         alg is 'none': the token is unsigned
         fix: never accept alg none; pin the algorithm server-side
MEDIUM no-expiry        no exp claim: the token never expires
         fix: set a short exp
LOW    no-aud           no aud claim
         fix: validate aud on every request
```

## Checks

| Rule | Severity | Meaning |
|------|----------|---------|
| `alg-none`, `missing-alg`, `empty-signature` | HIGH | unsigned or algorithm-less tokens |
| `suspicious-kid` | HIGH | `kid` with path or injection characters |
| `sensitive-claim` | HIGH | claims like `password`, `secret`, `ssn`, `card` |
| `key-in-header` | MEDIUM | `jku`, `jwk`, `x5u`, `x5c` headers (key-injection vector) |
| `no-expiry`, `bad-exp`, `long-lived` | MEDIUM / LOW | missing, malformed, or very long lifetimes (over 30 days MEDIUM, over 1 day LOW) |
| `timestamp-in-milliseconds`, `exp-before-iat`, `nbf-after-exp` | MEDIUM | broken time claims (a millisecond `exp` makes a token valid for millennia) |
| `wildcard-aud` | MEDIUM | `aud` is `*` |
| `iat-in-future`, `alg-case`, `insecure-iss` | LOW | clock skew or forgery, non-canonical `alg` spelling, `http://` issuer |
| `no-iss`, `no-aud`, `pii-claim` | LOW | missing issuer/audience, personal data in the payload |
| `symmetric-alg`, `expired`, `not-yet-valid`, `encrypted` | INFO | context only, does not affect the exit code |

Exit codes: `0` no findings, `1` findings, `2` input is not a JWT.

## Limits

It cannot tell whether a signature is valid or whether your server validates tokens
correctly; it only reviews what is visible in the token. Encrypted tokens (JWE) are
recognised but their payload cannot be inspected.

## Tests

Tests build their own throwaway tokens at runtime:

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS
