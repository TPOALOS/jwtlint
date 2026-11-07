import base64
import json
import unittest

import jwtlint as jl

NOW = 1_900_000_000


def seg(obj):
    raw = json.dumps(obj).encode() if not isinstance(obj, bytes) else obj
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def make(header=None, payload=None, sig="c2ln"):
    h = {"alg": "RS256", "typ": "JWT"} if header is None else header
    p = {"iss": "i", "aud": "a", "exp": NOW + 600, "iat": NOW} if payload is None else payload
    return "%s.%s.%s" % (seg(h), seg(p), sig)


def rules(token, now=NOW):
    return {(f[0], f[1]) for f in jl.audit(token, now)}


class DecodeTests(unittest.TestCase):
    def test_decode_roundtrip(self):
        h, p, sig, n = jl.decode(make())
        self.assertEqual(h["alg"], "RS256")
        self.assertEqual(p["iss"], "i")
        self.assertEqual(n, 3)

    def test_bearer_prefix(self):
        self.assertEqual(jl.decode("Bearer " + make())[0]["alg"], "RS256")

    def test_invalid(self):
        for bad in ("abc", "a.b", "a.b.c", "!!!.???.xxx", seg([1]) + "." + seg({}) + ".x"):
            with self.assertRaises(jl.JwtError, msg=bad):
                jl.decode(bad)

    def test_jwe_five_segments(self):
        tok = "%s.a.b.c.d" % seg({"alg": "RSA-OAEP", "enc": "A256GCM"})
        self.assertIn(("INFO", "encrypted"), rules(tok))


class AuditTests(unittest.TestCase):
    def test_clean_token(self):
        self.assertEqual(jl.audit(make(), NOW), [])

    def test_alg_none_and_missing_alg(self):
        self.assertIn(("HIGH", "alg-none"), rules(make({"alg": "none"})))
        self.assertIn(("HIGH", "alg-none"), rules(make({"alg": "None"}, sig="")))
        self.assertIn(("HIGH", "missing-alg"), rules(make({"typ": "JWT"})))

    def test_empty_signature(self):
        self.assertIn(("HIGH", "empty-signature"), rules(make(sig="")))

    def test_hs_is_info_only(self):
        r = rules(make({"alg": "HS256"}))
        self.assertIn(("INFO", "symmetric-alg"), r)
        self.assertFalse([x for x in r if x[0] != "INFO"])

    def test_key_headers_and_kid(self):
        self.assertIn(("MEDIUM", "key-in-header"), rules(make({"alg": "RS256", "jku": "https://x.example/k"})))
        self.assertIn(("HIGH", "suspicious-kid"), rules(make({"alg": "RS256", "kid": "../../etc/passwd"})))
        self.assertNotIn(("HIGH", "suspicious-kid"), rules(make({"alg": "RS256", "kid": "key-2024-01"})))

    def test_expiry_rules(self):
        self.assertIn(("MEDIUM", "no-expiry"), rules(make(payload={"iss": "i", "aud": "a"})))
        self.assertIn(("INFO", "expired"), rules(make(payload={"iss": "i", "aud": "a", "exp": NOW - 5})))
        self.assertIn(("MEDIUM", "long-lived"), rules(make(payload={"iss": "i", "aud": "a", "iat": NOW, "exp": NOW + 90 * 86400})))
        self.assertIn(("LOW", "long-lived"), rules(make(payload={"iss": "i", "aud": "a", "iat": NOW, "exp": NOW + 3 * 86400})))
        self.assertIn(("MEDIUM", "bad-exp"), rules(make(payload={"iss": "i", "aud": "a", "exp": "tomorrow"})))

    def test_iss_aud(self):
        r = rules(make(payload={"exp": NOW + 60}))
        self.assertIn(("LOW", "no-iss"), r)
        self.assertIn(("LOW", "no-aud"), r)

    def test_sensitive_and_pii_claims(self):
        r = rules(make(payload={"iss": "i", "aud": "a", "exp": NOW + 60, "password": "x", "email": "a@example.com"}))
        self.assertIn(("HIGH", "sensitive-claim"), r)
        self.assertIn(("LOW", "pii-claim"), r)

    def test_not_yet_valid(self):
        self.assertIn(("INFO", "not-yet-valid"),
                      rules(make(payload={"iss": "i", "aud": "a", "exp": NOW + 600, "nbf": NOW + 60})))


class CliTests(unittest.TestCase):
    def test_exit_codes(self):
        self.assertEqual(jl.main(["not-a-jwt"]), 2)
        self.assertEqual(jl.main([make({"alg": "none"})]), 1)

    def test_show_does_not_crash(self):
        jl.main(["--show", make({"alg": "none"})])


if __name__ == "__main__":
    unittest.main()
