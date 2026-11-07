import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from unittest import mock
from wsgiref.simple_server import make_server

from ctfhost import db, security
from ctfhost.cli import QuietHandler, ThreadingServer
from ctfhost.web import App

from .helpers import Client

CHALLENGES = [
    {"id": "warmup", "title": "Warm-up", "category": "misc", "description": "line one\nline two", "points": 100,
     "flag": "flag{test_warmup}"},
    {"id": "decay", "title": "Decaying", "category": "crypto", "description": "d", "points": 500, "min_points": 100,
     "decay": 5, "flag": "flag{test_decay}"},
    {"id": "secret", "title": "Hidden one", "category": "misc", "description": "d", "points": 50,
     "flag": "flag{test_hidden}", "hidden": True},
    {"id": "xss", "title": "<script>alert(1)</script>", "category": "<b>cat</b>",
     "description": "<img src=x onerror=alert(1)>", "points": 10, "flag": "flag{test_xss}"},
]
PW = "pw-for-tests-123"


class WebCase(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(security, "SCRYPT_N", 2 ** 8)
        p.start()
        self.addCleanup(p.stop)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = os.path.join(tmp.name, "t.db")
        db.init_db(self.path)
        conn = db.connect(self.path)
        db.load_challenges(conn, CHALLENGES)
        conn.close()
        self.now = 1_900_000_000
        self.app = App(self.path, clock=lambda: self.now)

    def set_setting(self, key, value):
        conn = db.connect(self.path)
        db.set_setting(conn, key, value)
        conn.close()

    def client(self, **kw):
        return Client(self.app, **kw)

    def player(self, name="amy", **kw):
        c = self.client(**kw)
        r = c.register(name)
        self.assertEqual((r.status, r.location), (303, "/challenges"), "registration failed for %r" % name)
        return c


class SecurityHeaderTests(WebCase):
    def test_headers_on_every_response(self):
        c = self.client()
        for path in ("/", "/login", "/scoreboard", "/nope", "/static/style.css", "/healthz"):
            r = c.get(path)
            self.assertEqual(r.header("X-Content-Type-Options"), "nosniff", path)
            self.assertEqual(r.header("X-Frame-Options"), "DENY", path)
            self.assertIn("default-src 'none'", r.header("Content-Security-Policy"), path)
            self.assertNotIn("script-src", r.header("Content-Security-Policy"))
            self.assertEqual(r.header("Referrer-Policy"), "no-referrer", path)
            self.assertEqual(r.header("Server"), "ctfhost")

    def test_no_store_for_pages_but_css_cached(self):
        c = self.client()
        self.assertEqual(c.get("/login").header("Cache-Control"), "no-store")
        self.assertIn("max-age", c.get("/static/style.css").header("Cache-Control"))

    def test_cookie_flags(self):
        r = self.client().get("/login")
        cookie = r.header("Set-Cookie")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertNotIn("Secure", cookie)
        secure = App(self.path, secure_cookies=True, clock=lambda: self.now)
        self.assertIn("Secure", Client(secure).get("/login").header("Set-Cookie"))

    def test_no_inline_script_or_event_handlers_in_pages(self):
        c = self.player()
        for path in ("/", "/challenges", "/challenges/warmup", "/scoreboard"):
            text = c.get(path).text.lower()
            self.assertNotIn("<script", text, path)
            self.assertNotIn(" onclick=", text, path)


class AuthTests(WebCase):
    def test_register_login_logout_flow(self):
        c = self.client()
        r = c.register("amy")
        self.assertEqual((r.status, r.location), (303, "/challenges"))
        self.assertIn("Warm-up", c.get("/challenges").text)
        self.assertEqual(c.post("/logout").status, 303)
        self.assertEqual(c.get("/challenges").location, "/login")
        self.assertEqual(c.login("amy").location, "/challenges")

    def test_session_rotates_on_login(self):
        c = self.client()
        c.get("/login")
        before = c.cookies["ctfhost_session"]
        c.register("amy")
        after = c.cookies["ctfhost_session"]
        self.assertNotEqual(before, after)
        stale = self.client()
        stale.cookies["ctfhost_session"] = before
        self.assertEqual(stale.get("/challenges").location, "/login")

    def test_csrf_enforced(self):
        c = self.client()
        c.get("/login")
        self.assertEqual(c.post("/login", {"username": "a", "password": "b"}, csrf=False).status, 403)
        self.assertEqual(c.post("/login", {"username": "a", "password": "b"}, csrf="wrong").status, 403)
        self.assertEqual(c.post("/register", {"username": "abc", "password": PW}, csrf=False).status, 403)

    def test_csrf_token_is_per_session(self):
        a, b = self.client(), self.client()
        token_a = a.csrf()
        b.get("/login")
        self.assertEqual(b.post("/login", {"username": "x", "password": "y"}, csrf=token_a).status, 403)

    def test_cross_origin_post_blocked(self):
        c = self.client()
        r = c.post("/login", {"username": "a", "password": "b"}, headers={"Origin": "http://evil.example"})
        self.assertEqual(r.status, 403)
        ok = c.post("/login", {"username": "a", "password": "b"}, headers={"Origin": "http://127.0.0.1:8000"})
        self.assertEqual(ok.status, 303)

    def test_validation_and_duplicates(self):
        c = self.client()
        c.register("ab")
        self.assertIn("Username must be", c.flash("/register"))
        c.register("good_name", "short")
        self.assertIn("Password must be", c.flash("/register"))
        self.player("Amy")
        d = self.client(ip="198.51.100.8")
        d.register("amy")
        self.assertIn("taken", d.flash("/register"))

    def test_login_errors_are_generic(self):
        self.player("amy")
        c = self.client()
        c.login("amy", "wrong-password-1")
        wrong_pw = c.flash("/login")
        c.login("nobody", "wrong-password-1")
        unknown = c.flash("/login")
        self.assertEqual(wrong_pw, unknown)
        self.assertIn("Invalid username or password", unknown)

    def test_login_rate_limit(self):
        c = self.client()
        c.get("/login")
        for _ in range(12):
            c.login("amy", "wrong-password-1")
        self.assertIn("Too many attempts", c.flash("/login"))

    def test_registration_closed(self):
        self.set_setting("registration", "closed")
        c = self.client()
        self.assertIn("closed", c.get("/register").text)
        c.register("amy")
        self.assertIn("closed", c.flash("/register"))

    def test_banned_user_cannot_login_or_keep_session(self):
        c = self.player("amy")
        conn = db.connect(self.path)
        db.set_banned(conn, "amy", True)
        conn.close()
        self.assertEqual(c.get("/challenges").location, "/login")
        d = self.client()
        d.login("amy", PW)
        self.assertIn("Invalid username or password", d.flash("/login"))

    def test_logged_in_users_skip_login_page(self):
        c = self.player("amy")
        self.assertEqual(c.get("/login").location, "/challenges")


class ChallengeTests(WebCase):
    def test_login_required(self):
        c = self.client()
        self.assertEqual(c.get("/challenges").location, "/login")
        self.assertEqual(c.get("/challenges/warmup").location, "/login")
        self.assertEqual(c.post("/challenges/warmup/submit", {"flag": "x"}).location, "/login")

    def test_hidden_and_missing_challenges_404(self):
        c = self.player()
        self.assertEqual(c.get("/challenges/secret").status, 404)
        self.assertEqual(c.get("/challenges/nope").status, 404)
        self.assertEqual(c.post("/challenges/secret/submit", {"flag": "flag{test_hidden}"}).status, 404)
        self.assertNotIn("Hidden one", c.get("/challenges").text)

    def test_submit_wrong_then_right(self):
        c = self.player()
        c.post("/challenges/warmup/submit", {"flag": "flag{nope}"})
        self.assertIn("Incorrect", c.flash("/challenges/warmup"))
        c.post("/challenges/warmup/submit", {"flag": "  flag{test_warmup} "})
        self.assertIn("Correct! +100", c.flash("/challenges/warmup"))
        self.assertIn("You solved this challenge", c.get("/challenges/warmup").text)
        c.post("/challenges/warmup/submit", {"flag": "flag{test_warmup}"})
        self.assertIn("already solved", c.flash("/challenges/warmup"))

    def test_flag_case_and_length_checks(self):
        c = self.player()
        c.post("/challenges/warmup/submit", {"flag": "FLAG{TEST_WARMUP}"})
        self.assertIn("Incorrect", c.flash("/challenges/warmup"))
        c.post("/challenges/warmup/submit", {"flag": "x" * 300})
        self.assertIn("Enter a flag", c.flash("/challenges/warmup"))
        c.post("/challenges/warmup/submit", {"flag": "   "})
        self.assertIn("Enter a flag", c.flash("/challenges/warmup"))

    def test_submission_rate_limit(self):
        c = self.player()
        for i in range(12):
            c.post("/challenges/warmup/submit", {"flag": "flag{guess%d}" % i})
        self.assertIn("Slow down", c.flash("/challenges/warmup"))

    def test_scoreboard_and_dynamic_points(self):
        players = [self.player("player%d" % i, ip="198.51.100.%d" % (10 + i)) for i in range(5)]
        for i, p in enumerate(players):
            self.now += 10
            p.post("/challenges/decay/submit", {"flag": "flag{test_decay}"})
        board = self.client().get("/api/scoreboard")
        import json
        data = json.loads(board.text)
        scores = [s["score"] for s in data["standings"]]
        self.assertEqual(len(scores), 5)
        self.assertEqual(data["standings"][0]["player"], "player0")  # first blood
        self.assertEqual(scores[1], 100)  # decay=5, five solves -> minimum value
        self.assertEqual(scores[0], 110)
        self.assertIn("100 pts &middot; 5 solves", players[0].get("/challenges").text)

    def test_user_text_is_escaped(self):
        c = self.player()
        for path in ("/challenges", "/challenges/xss"):
            text = c.get(path).text
            self.assertNotIn("<script>alert(1)</script>", text, path)
            self.assertNotIn("<img src=x", text, path)
            self.assertIn("&lt;script&gt;", text, path)

    def test_description_newlines_and_scoreboard_self_highlight(self):
        c = self.player("amy")
        self.assertIn("line one<br>line two", c.get("/challenges/warmup").text)
        c.post("/challenges/warmup/submit", {"flag": "flag{test_warmup}"})
        self.assertIn('class="me"', c.get("/scoreboard").text)


class CtfStateTests(WebCase):
    def test_pending(self):
        self.set_setting("start", self.now + 3600)
        c = self.player()
        self.assertIn("starts", c.get("/challenges").text)
        self.assertEqual(c.get("/challenges/warmup").status, 404)
        self.assertEqual(c.post("/challenges/warmup/submit", {"flag": "flag{test_warmup}"}).status, 404)

    def test_ended(self):
        c = self.player()
        self.set_setting("end", self.now - 1)
        self.assertIn("ended", c.get("/").text)
        c.post("/challenges/warmup/submit", {"flag": "flag{test_warmup}"})
        self.assertIn("closed", c.flash("/challenges/warmup"))
        self.assertIn("submissions are closed", c.get("/challenges/warmup").text)

    def test_freeze(self):
        c = self.player("amy")
        c.post("/challenges/warmup/submit", {"flag": "flag{test_warmup}"})
        self.set_setting("freeze", self.now + 100)
        self.now += 200
        c.post("/challenges/decay/submit", {"flag": "flag{test_decay}"})
        import json
        pub = json.loads(self.client().get("/api/scoreboard").text)
        self.assertTrue(pub["frozen"])
        self.assertEqual(pub["standings"][0]["solved"], 1)


class HttpHardeningTests(WebCase):
    def test_body_size_and_content_type(self):
        c = self.client()
        c.get("/login")
        self.assertEqual(c.request("POST", "/login", raw_body=b"a=b", content_length=10 ** 6).status, 413)
        self.assertEqual(c.request("POST", "/login", raw_body=b"{}", content_type="application/json").status, 415)
        self.assertEqual(c.request("POST", "/login", raw_body=b"x", content_length=-5).status, 413)

    def test_unknown_routes_and_methods(self):
        c = self.client()
        self.assertEqual(c.get("/nope").status, 404)
        self.assertEqual(c.get("/challenges/../etc/passwd").status, 404)
        self.assertEqual(c.request("PUT", "/").status, 405)
        self.assertEqual(c.request("DELETE", "/login").status, 405)
        self.assertEqual(c.request("POST", "/scoreboard", {"csrf": c.csrf()}).status, 405)

    def test_head_has_no_body(self):
        r = self.client().request("HEAD", "/")
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body, b"")

    def test_internal_errors_hide_details(self):
        with mock.patch("ctfhost.web.db.get_settings", side_effect=RuntimeError("secret-internal-detail")), \
                mock.patch("sys.stderr"):
            r = self.client().get("/")
        self.assertEqual(r.status, 500)
        self.assertNotIn("secret-internal-detail", r.text)

    def test_sql_injection_attempts_are_inert(self):
        c = self.client()
        c.login("' OR 1=1 --", "x")
        self.assertIn("Invalid username or password", c.flash("/login"))
        self.assertEqual(self.client().get("/challenges/x'%20OR%201=1").status, 404)

    def test_healthz(self):
        self.assertEqual(self.client().get("/healthz").text, "ok")

    def test_client_ip_and_proxy_header(self):
        app = App(self.path, trusted_proxy=True, clock=lambda: self.now)
        env = {"REMOTE_ADDR": "10.0.0.1", "HTTP_X_FORWARDED_FOR": "203.0.113.9, 198.51.100.4"}
        self.assertEqual(app.client_ip(env), "198.51.100.4")
        self.assertEqual(self.app.client_ip(env), "10.0.0.1")


class LiveServerTests(WebCase):
    def test_real_http_roundtrip(self):
        quiet = mock.patch.object(QuietHandler, "log_message")
        quiet.start()
        self.addCleanup(quiet.stop)
        server = make_server("127.0.0.1", 0, App(self.path), server_class=ThreadingServer, handler_class=QuietHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = "http://127.0.0.1:%d" % server.server_address[1]
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))
        with opener.open(base + "/healthz", timeout=5) as r:
            self.assertEqual(r.read(), b"ok")
            self.assertEqual(r.headers["Server"], "ctfhost")
            self.assertIn("default-src 'none'", r.headers["Content-Security-Policy"])
        with opener.open(base + "/login", timeout=5) as r:
            import re
            token = re.search(r'name="csrf" value="([^"]+)"', r.read().decode()).group(1)
        data = urllib.parse.urlencode({"username": "livebob", "password": PW, "csrf": token}).encode()
        with opener.open(base + "/register", data, timeout=5) as r:  # follows the 303 to /challenges
            self.assertEqual(r.status, 200)
            self.assertIn("Warm-up", r.read().decode())


if __name__ == "__main__":
    unittest.main()
