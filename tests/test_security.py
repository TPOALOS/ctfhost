import unittest
from unittest import mock

from ctfhost import security


class PasswordTests(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(security, "SCRYPT_N", 2 ** 8)
        p.start()
        self.addCleanup(p.stop)

    def test_roundtrip(self):
        h = security.hash_password("correct horse")
        self.assertTrue(h.startswith("scrypt$"))
        self.assertTrue(security.verify_password("correct horse", h))
        self.assertFalse(security.verify_password("wrong horse", h))

    def test_salted(self):
        self.assertNotEqual(security.hash_password("same"), security.hash_password("same"))

    def test_no_plaintext_in_hash(self):
        self.assertNotIn("correct horse", security.hash_password("correct horse"))

    def test_malformed_hashes_fail_safely(self):
        for bad in ("", "scrypt$1$2", "md5$1$8$1$aa$bb", "scrypt$x$8$1$aa$bb", "scrypt$256$8$1$zz$zz", None):
            self.assertFalse(security.verify_password("x", bad), bad)

    def test_dummy_verify_is_false(self):
        self.assertFalse(security.dummy_verify("anything"))

    def test_parameters_come_from_stored_hash(self):
        h = security.hash_password("pw-12345678")
        with mock.patch.object(security, "SCRYPT_N", 2 ** 9):
            self.assertTrue(security.verify_password("pw-12345678", h))


class ValidationTests(unittest.TestCase):
    def test_usernames(self):
        for ok in ("abc", "Player_1", "a-b-c", "x" * 24):
            self.assertTrue(security.valid_username(ok), ok)
        for bad in ("ab", "x" * 25, "has space", "<script>", "a;b", "ünï", "", None):
            self.assertFalse(security.valid_username(bad), bad)

    def test_passwords(self):
        self.assertTrue(security.valid_password("12345678"))
        self.assertFalse(security.valid_password("1234567"))
        self.assertFalse(security.valid_password("x" * 129))
        self.assertFalse(security.valid_password(None))


class FlagTests(unittest.TestCase):
    def test_hash_and_check(self):
        digest = security.hash_flag("flag{abc}")
        self.assertEqual(len(digest), 64)
        self.assertTrue(security.check_flag("flag{abc}", digest))
        self.assertTrue(security.check_flag("  flag{abc}\n", digest))
        self.assertFalse(security.check_flag("flag{ABC}", digest))
        self.assertFalse(security.check_flag("flag{abc", digest))

    def test_known_sha256(self):
        self.assertEqual(security.hash_flag("abc"),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_tokens_are_unique_and_long(self):
        tokens = {security.new_token() for _ in range(50)}
        self.assertEqual(len(tokens), 50)
        self.assertTrue(all(len(t) >= 40 for t in tokens))


class RateLimiterTests(unittest.TestCase):
    def test_limit_and_window(self):
        now = [0.0]
        rl = security.RateLimiter(3, 60, clock=lambda: now[0])
        self.assertTrue(all(rl.allow("k") for _ in range(3)))
        self.assertFalse(rl.allow("k"))
        self.assertTrue(rl.allow("other"))
        self.assertGreater(rl.retry_after("k"), 0)
        now[0] = 61
        self.assertTrue(rl.allow("k"))

    def test_rejected_attempts_do_not_extend_window(self):
        now = [0.0]
        rl = security.RateLimiter(1, 10, clock=lambda: now[0])
        self.assertTrue(rl.allow("k"))
        now[0] = 5
        self.assertFalse(rl.allow("k"))
        now[0] = 10.5
        self.assertTrue(rl.allow("k"))


if __name__ == "__main__":
    unittest.main()
