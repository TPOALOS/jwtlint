# Changelog

## 1.1.0

- New checks: timestamps in milliseconds, exp before iat, nbf after exp, iat in the future, wildcard aud, non-canonical alg, http issuer
- Several tokens at once (arguments, `--file`, stdin lines); exit code is the worst result
- `--json` output and `--now` to judge expiry at another moment
- Installable with pip (`jwtlint` command), CI on Linux and macOS

## 1.0.0

Initial release.
