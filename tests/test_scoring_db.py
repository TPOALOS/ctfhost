import os
import tempfile
import unittest
from unittest import mock

from ctfhost import db, scoring, security


def challenge(cid, points=100, minimum=None, decay=0, flag=None, **extra):
    c = {"id": cid, "title": cid.title(), "category": "misc", "description": "d", "points": points,
         "flag": flag or "flag{%s}" % cid}
    if minimum is not None:
        c["min_points"] = minimum
    c["decay"] = decay
    c.update(extra)
    return c


class ChallengeValueTests(unittest.TestCase):
    def test_no_decay(self):
        self.assertEqual(scoring.challenge_value(500, 100, 0, 50), 500)

    def test_zero_solves_is_initial(self):
        self.assertEqual(scoring.challenge_value(500, 100, 50, 0), 500)

    def test_monotonic_and_clamped(self):
        vals = [scoring.challenge_value(500, 100, 50, n) for n in range(0, 80)]
        self.assertEqual(vals, sorted(vals, reverse=True))
        self.assertEqual(vals[50], 100)
        self.assertEqual(vals[79], 100)

    def test_known_value(self):
        self.assertEqual(scoring.challenge_value(500, 100, 50, 10), 484)


class DbTestCase(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(security, "SCRYPT_N", 2 ** 8)
        p.start()
        self.addCleanup(p.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "t.db")
        db.init_db(self.path)
        self.conn = db.connect(self.path)
        self.addCleanup(self.conn.close)

    def user(self, name):
        return db.create_user(self.conn, name, "x", 1000)


class SettingsAndUserTests(DbTestCase):
    def test_defaults_and_set(self):
        s = db.get_settings(self.conn)
        self.assertEqual((s["name"], s["start"], s["end"], s["registration"], s["first_blood_pct"]), ("CTF", 0, 0, True, 10))
        db.set_setting(self.conn, "registration", "closed")
        self.assertFalse(db.get_settings(self.conn)["registration"])
        with self.assertRaises(KeyError):
            db.set_setting(self.conn, "nope", 1)

    def test_state(self):
        s = {"start": 100, "end": 200}
        self.assertEqual(db.ctf_state(s, 50), "pending")
        self.assertEqual(db.ctf_state(s, 150), "running")
        self.assertEqual(db.ctf_state(s, 200), "ended")
        self.assertEqual(db.ctf_state({"start": 0, "end": 0}, 5), "running")

    def test_usernames_unique_case_insensitive(self):
        self.assertIsNotNone(self.user("Alice"))
        self.assertIsNone(self.user("alice"))
        self.assertEqual(db.get_user_by_name(self.conn, "ALICE")["username"], "Alice")

    def test_sessions_expire_and_flash(self):
        db.create_session(self.conn, "tok", "csrf", 1000)
        self.assertIsNotNone(db.get_session(self.conn, "tok", 1000 + 10))
        self.assertIsNone(db.get_session(self.conn, "tok", 1000 + db.SESSION_TTL + 1))
        db.set_flash(self.conn, "tok", "hello")
        self.assertEqual(db.pop_flash(self.conn, "tok"), "hello")
        self.assertIsNone(db.pop_flash(self.conn, "tok"))
        self.assertIsNone(db.get_session(self.conn, None, 1000))

    def test_ban_kills_sessions(self):
        uid = self.user("bob")
        db.create_session(self.conn, "tok", "csrf", 1000, uid)
        self.assertTrue(db.set_banned(self.conn, "bob", True))
        self.assertIsNone(db.get_session(self.conn, "tok", 1001))
        self.assertFalse(db.set_banned(self.conn, "ghost", True))


class ChallengeLoadingTests(DbTestCase):
    def test_load_and_flag_hashing(self):
        self.assertEqual(db.load_challenges(self.conn, [challenge("one", flag="flag{x}")]), 1)
        row = db.get_challenge(self.conn, "one")
        self.assertEqual(row["flag_sha256"], security.hash_flag("flag{x}"))
        self.assertNotIn("flag{x}", " ".join(str(v) for v in tuple(row)))

    def test_flag_sha256_accepted(self):
        digest = security.hash_flag("flag{y}")
        c = challenge("two")
        del c["flag"]
        c["flag_sha256"] = digest.upper()
        db.load_challenges(self.conn, [c])
        self.assertEqual(db.get_challenge(self.conn, "two")["flag_sha256"], digest)

    def test_validation_errors(self):
        bad_inputs = [
            [], {}, [1], [challenge("Bad Id")], [challenge("x", points=0)], [challenge("x", points=10, minimum=50)],
            [challenge("x", decay=-1)], [{"id": "x", "title": "t", "category": "c", "points": 5}],
            [challenge("x", flag_sha256="abc")], [challenge("dup"), challenge("dup")],
            [dict(challenge("x"), title="")], [dict(challenge("x"), points=True)], [dict(challenge("x"), flag="  ")],
            [dict(challenge("x"), description="d" * 5001)],
        ]
        for items in bad_inputs:
            with self.assertRaises(db.ChallengeError, msg=str(items)[:60]):
                db.load_challenges(self.conn, items)

    def test_upsert_keeps_solves(self):
        db.load_challenges(self.conn, [challenge("one", points=100)])
        uid = self.user("amy")
        self.assertTrue(db.record_solve(self.conn, uid, "one", 1100))
        db.load_challenges(self.conn, [challenge("one", points=300, title="Renamed")])
        self.assertEqual(db.get_challenge(self.conn, "one")["points"], 300)
        self.assertEqual(db.solved_ids(self.conn, uid), {"one"})

    def test_duplicate_solve_is_not_recorded(self):
        db.load_challenges(self.conn, [challenge("one")])
        uid = self.user("amy")
        self.assertTrue(db.record_solve(self.conn, uid, "one", 1100))
        self.assertFalse(db.record_solve(self.conn, uid, "one", 1200))

    def test_hidden_challenges_are_not_listed(self):
        db.load_challenges(self.conn, [challenge("a"), challenge("b", hidden=True)])
        self.assertEqual([c["id"] for c in db.list_challenges(self.conn)], ["a"])
        self.assertEqual(len(db.list_challenges(self.conn, include_hidden=True)), 2)


class ScoreboardTests(DbTestCase):
    def setUp(self):
        super().setUp()
        db.load_challenges(self.conn, [challenge("a", points=500, minimum=100, decay=50),
                                       challenge("b", points=100)])
        self.s = db.get_settings(self.conn)

    def board(self, now=10 ** 6, public=True):
        return scoring.scoreboard(self.conn, self.s, now, public)

    def test_empty(self):
        self.assertEqual(self.board(), [])

    def test_scores_first_blood_and_tiebreak(self):
        amy, bob = self.user("amy"), self.user("bob")
        db.record_solve(self.conn, amy, "b", 1000)   # first blood on b: 100 + 10
        db.record_solve(self.conn, bob, "b", 1010)
        rows = self.board()
        self.assertEqual([(r["username"], r["score"], r["rank"]) for r in rows], [("amy", 110, 1), ("bob", 100, 2)])
        db.record_solve(self.conn, bob, "a", 1020)   # bob catches up on score
        rows = self.board()
        self.assertEqual(rows[0]["username"], "bob")
        self.assertGreater(rows[0]["score"], rows[1]["score"])

    def test_equal_score_earlier_last_solve_wins(self):
        amy, bob = self.user("amy"), self.user("bob")
        self.s["first_blood_pct"] = 0
        db.record_solve(self.conn, bob, "b", 1000)
        db.record_solve(self.conn, amy, "b", 1005)
        self.assertEqual([r["username"] for r in self.board()], ["bob", "amy"])

    def test_dynamic_values_shrink_for_everyone(self):
        users = [self.user("u%d" % i) for i in range(10)]
        db.record_solve(self.conn, users[0], "a", 1000)
        before = self.board()[0]["score"]
        for i, u in enumerate(users[1:], 1):
            db.record_solve(self.conn, u, "a", 1000 + i)
        values, _ = scoring.compute(self.conn, self.s, 10 ** 6)
        self.assertEqual(values["a"], (scoring.challenge_value(500, 100, 50, 10), 10))
        self.assertLess(self.board()[-1]["score"], before)

    def test_banned_users_excluded(self):
        amy, bob = self.user("amy"), self.user("bob")
        db.record_solve(self.conn, amy, "b", 1000)
        db.record_solve(self.conn, bob, "b", 1001)
        db.set_banned(self.conn, "amy", True)
        rows = self.board()
        self.assertEqual([r["username"] for r in rows], ["bob"])
        self.assertEqual(rows[0]["score"], 110)  # bob is now the first (unbanned) solver

    def test_freeze_hides_late_solves_from_public_only(self):
        amy = self.user("amy")
        self.s["freeze"] = 2000
        db.record_solve(self.conn, amy, "b", 1500)
        db.record_solve(self.conn, amy, "a", 2500)
        public_after = self.board(now=3000, public=True)
        self.assertEqual(public_after[0]["solved"], 1)
        self.assertEqual(self.board(now=3000, public=False)[0]["solved"], 2)
        self.assertEqual(self.board(now=1900, public=True)[0]["solved"], 2)

    def test_limit(self):
        for i in range(5):
            db.record_solve(self.conn, self.user("p%d" % i), "b", 1000 + i)
        self.assertEqual(len(scoring.scoreboard(self.conn, self.s, 10 ** 6, True, limit=3)), 3)


if __name__ == "__main__":
    unittest.main()
