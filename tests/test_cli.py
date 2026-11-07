import io
import json
import os
import tempfile
import unittest
from unittest import mock

from ctfhost import cli, db, security


def run(*argv):
    out = io.StringIO()
    with mock.patch("sys.stderr", io.StringIO()) as err:
        code = cli.main(list(argv), out=out)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(security, "SCRYPT_N", 2 ** 8)
        p.start()
        self.addCleanup(p.stop)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.db = os.path.join(self.dir, "t.db")

    def write_challenges(self, items):
        path = os.path.join(self.dir, "c.json")
        with open(path, "w") as fh:
            json.dump(items, fh)
        return path

    def test_parse_time(self):
        self.assertEqual(cli.parse_time("2030-01-01T00:00"), 1893456000)
        self.assertEqual(cli.parse_time("2030-01-01T02:00+02:00"), 1893456000)
        self.assertEqual(cli.parse_time("2030-01-01T00:00Z"), 1893456000)
        self.assertEqual(cli.parse_time("none"), 0)
        with self.assertRaises(Exception):
            cli.parse_time("yesterday-ish")

    def test_init_set_and_settings(self):
        code, out, _ = run("init", "--db", self.db, "--name", "My CTF", "--start", "2030-01-01T00:00",
                           "--first-blood-pct", "20")
        self.assertEqual(code, 0)
        conn = db.connect(self.db)
        s = db.get_settings(conn)
        self.assertEqual((s["name"], s["start"], s["first_blood_pct"]), ("My CTF", 1893456000, 20))
        self.assertEqual(run("set", "--db", self.db, "--registration", "closed", "--start", "none")[0], 0)
        s = db.get_settings(conn)
        self.assertFalse(s["registration"])
        self.assertEqual(s["start"], 0)
        conn.close()

    def test_bad_percent_is_rejected(self):
        self.assertEqual(run("init", "--db", self.db, "--first-blood-pct", "150")[0], 2)

    def test_load_and_errors(self):
        run("init", "--db", self.db)
        good = self.write_challenges([{"id": "a", "title": "A", "category": "c", "points": 10, "flag": "flag{x}"}])
        code, out, _ = run("load", "--db", self.db, good)
        self.assertEqual((code, "loaded 1" in out), (0, True))
        bad = self.write_challenges([{"id": "A B"}])
        code, _, err = run("load", "--db", self.db, bad)
        self.assertEqual(code, 2)
        self.assertIn("invalid id", err)
        self.assertEqual(run("load", "--db", self.db, os.path.join(self.dir, "missing.json"))[0], 2)
        broken = os.path.join(self.dir, "broken.json")
        with open(broken, "w") as fh:
            fh.write("{not json")
        self.assertEqual(run("load", "--db", self.db, broken)[0], 2)

    def test_example_file_loads(self):
        run("init", "--db", self.db)
        example = os.path.join(os.path.dirname(__file__), "..", "examples", "challenges.example.json")
        code, out, _ = run("load", "--db", self.db, example)
        self.assertEqual(code, 0, out)

    def test_scoreboard_formats_and_ban(self):
        run("init", "--db", self.db)
        run("load", "--db", self.db, self.write_challenges(
            [{"id": "a", "title": "A", "category": "c", "points": 100, "flag": "flag{x}"}]))
        conn = db.connect(self.db)
        uid = db.create_user(conn, "amy", "x", 1000)
        db.record_solve(conn, uid, "a", 1500)
        conn.close()
        code, out, _ = run("scoreboard", "--db", self.db)
        self.assertIn("amy", out)
        data = json.loads(run("scoreboard", "--db", self.db, "--format", "json")[1])
        self.assertEqual((data[0]["player"], data[0]["score"]), ("amy", 110))
        csv_out = run("scoreboard", "--db", self.db, "--format", "csv")[1]
        self.assertTrue(csv_out.startswith("rank,player,solved,score,last_solve"))
        self.assertEqual(run("ban", "--db", self.db, "amy")[0], 0)
        self.assertNotIn("amy", run("scoreboard", "--db", self.db)[1].split("\n", 1)[1])
        self.assertEqual(run("unban", "--db", self.db, "amy")[0], 0)
        self.assertEqual(run("ban", "--db", self.db, "ghost")[0], 1)

    def test_reset_requires_confirmation(self):
        run("init", "--db", self.db)
        conn = db.connect(self.db)
        db.load_challenges(conn, [{"id": "a", "title": "A", "category": "c", "points": 10, "flag": "flag{x}"}])
        uid = db.create_user(conn, "amy", "x", 1000)
        db.record_solve(conn, uid, "a", 1500)
        self.assertEqual(run("reset-solves", "--db", self.db)[0], 1)
        self.assertEqual(db.solved_ids(conn, uid), {"a"})
        self.assertEqual(run("reset-solves", "--db", self.db, "--yes")[0], 0)
        self.assertEqual(db.solved_ids(conn, uid), set())
        conn.close()

    def test_hash_flag(self):
        code, out, _ = run("hash-flag", "abc")
        self.assertEqual(out.strip(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        with mock.patch("sys.stdin", io.StringIO("abc\n")):
            self.assertEqual(run("hash-flag")[1].strip(), out.strip())


if __name__ == "__main__":
    unittest.main()
