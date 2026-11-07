import base64
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

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


class NewCheckTests(unittest.TestCase):
    def test_milliseconds(self):
        r = rules(make(payload={"iss": "i", "aud": "a", "exp": (NOW + 600) * 1000, "iat": NOW}))
        self.assertIn(("MEDIUM", "timestamp-in-milliseconds"), r)

    def test_seconds_are_fine(self):
        self.assertNotIn("timestamp-in-milliseconds", {r for _, r in rules(make())})

    def test_exp_before_iat(self):
        self.assertIn(("MEDIUM", "exp-before-iat"), rules(make(payload={"iss": "i", "aud": "a", "exp": NOW - 5, "iat": NOW})))

    def test_nbf_after_exp(self):
        p = {"iss": "i", "aud": "a", "exp": NOW + 10, "iat": NOW, "nbf": NOW + 20}
        self.assertIn(("MEDIUM", "nbf-after-exp"), rules(make(payload=p)))

    def test_iat_in_future_with_leeway(self):
        p = {"iss": "i", "aud": "a", "exp": NOW + 9999, "iat": NOW + 3600}
        self.assertIn(("LOW", "iat-in-future"), rules(make(payload=p)))
        p["iat"] = NOW + 60
        self.assertNotIn("iat-in-future", {r for _, r in rules(make(payload=p))})

    def test_alg_case(self):
        self.assertIn(("LOW", "alg-case"), rules(make(header={"alg": "rs256"})))
        self.assertNotIn("alg-case", {r for _, r in rules(make(header={"alg": "RS256"}))})

    def test_wildcard_audience(self):
        for aud in ("*", ["a", "*"]):
            p = {"iss": "i", "aud": aud, "exp": NOW + 60, "iat": NOW}
            self.assertIn(("MEDIUM", "wildcard-aud"), rules(make(payload=p)))

    def test_insecure_issuer(self):
        p = {"iss": "http://auth.example.com", "aud": "a", "exp": NOW + 60, "iat": NOW}
        self.assertIn(("LOW", "insecure-iss"), rules(make(payload=p)))
        p["iss"] = "https://auth.example.com"
        self.assertNotIn("insecure-iss", {r for _, r in rules(make(payload=p))})

    def test_clean_token_still_clean(self):
        self.assertEqual(jl.audit(make(), NOW), [])


def run_main(*argv, stdin=""):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), mock.patch("sys.stdin", io.StringIO(stdin)):
        code = jl.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class NewCliTests(unittest.TestCase):
    GOOD = make()
    WEAK = make(header={"alg": "none"}, payload={"sub": "x"})

    def test_single_token_text_output_unchanged(self):
        code, out, err = run_main(self.WEAK, "--now", str(NOW))
        self.assertEqual(code, 1)
        self.assertIn("alg-none", out)
        self.assertNotIn("== token", out)
        self.assertIn("signature NOT verified", err)

    def test_json_single(self):
        code, out, _ = run_main(self.WEAK, "--json", "--now", str(NOW))
        data = json.loads(out)
        self.assertEqual((code, data["valid"], data["format"], data["signature_verified"]), (1, True, "JWS", False))
        self.assertIn("alg-none", {f["rule"] for f in data["findings"]})
        self.assertNotIn("payload", data)

    def test_json_show_includes_claims(self):
        _, out, _ = run_main(self.GOOD, "--json", "--show", "--now", str(NOW))
        self.assertEqual(json.loads(out)["payload"]["iss"], "i")

    def test_several_tokens_and_worst_exit_code(self):
        code, out, _ = run_main(self.GOOD, self.WEAK, "--json", "--now", str(NOW))
        data = json.loads(out)
        self.assertEqual((code, len(data)), (1, 2))
        self.assertEqual(data[0]["findings"], [])

    def test_invalid_token_is_exit_2_and_reported(self):
        code, out, _ = run_main(self.GOOD, "garbage", "--json", "--now", str(NOW))
        self.assertEqual(code, 2)
        data = json.loads(out)
        self.assertFalse(data[1]["valid"])
        self.assertIn("expected 3", data[1]["error"])

    def test_stdin_lines(self):
        code, out, _ = run_main("-", "--json", "--now", str(NOW), stdin=self.GOOD + "\n\n" + self.WEAK + "\n")
        self.assertEqual((code, len(json.loads(out))), (1, 2))

    def test_no_args_reads_stdin(self):
        self.assertEqual(run_main("--now", str(NOW), stdin=self.GOOD)[0], 0)

    def test_empty_input(self):
        self.assertEqual(run_main(stdin="")[0], 2)

    def test_file_with_comments(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "tokens.txt")
            with open(p, "w") as fh:
                fh.write("# issued by staging\n%s\n\n%s\n" % (self.GOOD, self.WEAK))
            code, out, _ = run_main("-f", p, "--json", "--now", str(NOW))
        self.assertEqual((code, len(json.loads(out))), (1, 2))

    def test_missing_file(self):
        self.assertEqual(run_main("-f", "/nonexistent/tokens.txt")[0], 2)

    def test_tokens_are_never_echoed_in_output(self):
        _, out, err = run_main(self.WEAK, self.GOOD, "--now", str(NOW))
        for tok in (self.WEAK, self.GOOD):
            self.assertNotIn(tok, out + err)

    def test_now_changes_expiry_result(self):
        code, out, _ = run_main(self.GOOD, "--now", str(NOW + 10_000), "--json")
        self.assertIn("expired", {f["rule"] for f in json.loads(out)["findings"]})


if __name__ == "__main__":
    unittest.main()
