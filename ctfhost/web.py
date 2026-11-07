"""WSGI application: registration, login, challenges, flag submission, scoreboard."""
import hmac
import html
import json
import re
import sqlite3
import sys
import time
import urllib.parse
from http.cookies import SimpleCookie

from . import __version__, db, scoring, security

COOKIE = "ctfhost_session"
MAX_BODY = 16 * 1024
CSP = ("default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; "
       "frame-ancestors 'none'; base-uri 'none'")

CSS = """
:root{--bg:#0f1318;--fg:#e6e9ee;--muted:#8b95a3;--card:#171c24;--line:#2a313c;--accent:#4cc38a;--bad:#e5696a}
*{box-sizing:border-box}body{margin:0;font:16px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg)}
header{display:flex;gap:16px;align-items:center;flex-wrap:wrap;padding:12px 20px;border-bottom:1px solid var(--line);background:var(--card)}
header a{color:var(--fg);text-decoration:none}header .brand{font-weight:700;margin-right:auto}
header form{display:inline;margin:0}main{max-width:900px;margin:0 auto;padding:20px 16px}
h1,h2{line-height:1.2}a{color:var(--accent)}table{width:100%;border-collapse:collapse}
th,td{padding:8px;border-bottom:1px solid var(--line);text-align:left}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px;margin:10px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:10px}
.solved{border-color:var(--accent)}.muted{color:var(--muted)}.flash{padding:10px 14px;border-radius:8px;margin-bottom:14px;background:#1d2b25;border:1px solid var(--accent)}
.flash.bad{background:#2d1b1c;border-color:var(--bad)}
input[type=text],input[type=password]{width:100%;max-width:420px;padding:9px;margin:4px 0 12px;border-radius:6px;border:1px solid var(--line);background:var(--bg);color:var(--fg)}
button{padding:9px 16px;border-radius:6px;border:0;background:var(--accent);color:#04120b;font-weight:600;cursor:pointer}
button.link{background:none;color:var(--fg);padding:0;font-weight:400}.me td{background:#1d2b25}
pre{white-space:pre-wrap;word-break:break-word}
"""


def esc(value):
    return html.escape(str(value), quote=True)


def fmt_time(ts):
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts)) if ts else "-"


class Response:
    def __init__(self, status=200, body=b"", content_type="text/html; charset=utf-8", headers=None, cache=False):
        self.status = status
        self.body = body.encode("utf-8") if isinstance(body, str) else body
        self.content_type = content_type
        self.headers = list(headers or [])
        self.cache = cache

    def send(self, start_response, head_only=False):
        phrase = {200: "OK", 303: "See Other", 400: "Bad Request", 403: "Forbidden", 404: "Not Found",
                  405: "Method Not Allowed", 413: "Payload Too Large", 415: "Unsupported Media Type",
                  429: "Too Many Requests", 500: "Internal Server Error"}.get(self.status, "OK")
        headers = [("Content-Type", self.content_type), ("Content-Length", str(len(self.body))),
                   ("Server", "ctfhost"), ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"),
                   ("Referrer-Policy", "no-referrer"), ("Content-Security-Policy", CSP),
                   ("Cross-Origin-Opener-Policy", "same-origin"), ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
                   ("Cache-Control", "public, max-age=300" if self.cache else "no-store")] + self.headers
        start_response("%d %s" % (self.status, phrase), headers)
        return [b""] if head_only else [self.body]


def redirect(location, cookies=()):
    return Response(303, b"", headers=[("Location", location)] + [("Set-Cookie", c) for c in cookies])


class Request:
    def __init__(self, method, path, form, ip, session, user):
        self.method, self.path, self.form, self.ip, self.session, self.user = method, path, form, ip, session, user


class App:
    def __init__(self, db_path, secure_cookies=False, trusted_proxy=False, clock=time.time):
        self.db_path = db_path
        self.secure_cookies = secure_cookies
        self.trusted_proxy = trusted_proxy
        self.clock = clock
        self.limiters = {"login_ip": security.RateLimiter(10, 60), "login_user": security.RateLimiter(5, 60),
                         "register": security.RateLimiter(5, 600), "submit": security.RateLimiter(10, 60)}
        self.routes = [
            ("GET", re.compile(r"^/$"), self.index),
            ("GET", re.compile(r"^/healthz$"), self.healthz),
            ("GET", re.compile(r"^/static/style\.css$"), self.style),
            ("GET", re.compile(r"^/scoreboard$"), self.scoreboard_page),
            ("GET", re.compile(r"^/api/scoreboard$"), self.scoreboard_api),
            ("GET", re.compile(r"^/(login|register)$"), self.auth_form),
            ("POST", re.compile(r"^/login$"), self.login),
            ("POST", re.compile(r"^/register$"), self.register),
            ("POST", re.compile(r"^/logout$"), self.logout),
            ("GET", re.compile(r"^/challenges$"), self.challenges),
            ("GET", re.compile(r"^/challenges/([a-z0-9][a-z0-9_-]{0,39})$"), self.challenge),
            ("POST", re.compile(r"^/challenges/([a-z0-9][a-z0-9_-]{0,39})/submit$"), self.submit),
        ]

    # ---- WSGI entry --------------------------------------------------
    def __call__(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET")
        try:
            conn = db.connect(self.db_path)
        except sqlite3.Error:
            return Response(500, "Database unavailable", "text/plain; charset=utf-8").send(start_response)
        try:
            resp = self.handle(conn, environ)
        except Exception as exc:  # never leak internals to the client
            print("ctfhost: internal error: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
            resp = Response(500, "Internal server error", "text/plain; charset=utf-8")
        finally:
            conn.close()
        return resp.send(start_response, head_only=(method == "HEAD"))

    def client_ip(self, environ):
        if self.trusted_proxy:
            fwd = environ.get("HTTP_X_FORWARDED_FOR", "")
            if fwd:
                return fwd.split(",")[-1].strip()
        return environ.get("REMOTE_ADDR", "?")

    def cookie_header(self, token, max_age=db.SESSION_TTL):
        parts = ["%s=%s" % (COOKIE, token), "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=%d" % max_age]
        if self.secure_cookies:
            parts.append("Secure")
        return "; ".join(parts)

    def handle(self, conn, environ):
        method = environ.get("REQUEST_METHOD", "GET")
        if method == "HEAD":
            method = "GET"
        path = environ.get("PATH_INFO", "/") or "/"
        if method not in ("GET", "POST"):
            return Response(405, "Method not allowed", "text/plain; charset=utf-8", [("Allow", "GET, HEAD, POST")])
        now = self.clock()
        cookies = SimpleCookie(environ.get("HTTP_COOKIE", ""))
        token = cookies[COOKIE].value if COOKIE in cookies else None
        session, new_cookie = db.get_session(conn, token, now), None
        user = None
        if session is not None and session["user_id"] is not None:
            user = db.get_user(conn, session["user_id"])
            if user is None or user["banned"]:
                db.delete_session(conn, session["token"])
                session, user = None, None
        if session is None:
            token = security.new_token()
            db.create_session(conn, token, security.new_token(), now)
            session = db.get_session(conn, token, now)
            new_cookie = self.cookie_header(token)

        form = {}
        if method == "POST":
            err = self.read_form(environ)
            if isinstance(err, Response):
                return self.with_cookie(err, new_cookie)
            form = err
            if not self.same_origin(environ):
                return self.with_cookie(Response(403, "Cross-origin request blocked", "text/plain; charset=utf-8"), new_cookie)
            if not hmac.compare_digest(form.get("csrf", ""), session["csrf"]):
                return self.with_cookie(Response(403, "Invalid or missing CSRF token", "text/plain; charset=utf-8"), new_cookie)

        req = Request(method, path, form, self.client_ip(environ), session, user)
        allowed = False
        for m, rx, handler in self.routes:
            match = rx.match(path)
            if match:
                allowed = True
                if m == method:
                    resp = handler(conn, req, now, *match.groups())
                    return self.with_cookie(resp, new_cookie)
        status = 405 if allowed else 404
        return self.with_cookie(Response(status, "Method not allowed" if allowed else "Not found",
                                         "text/plain; charset=utf-8"), new_cookie)

    @staticmethod
    def with_cookie(resp, cookie):
        if cookie:
            resp.headers.append(("Set-Cookie", cookie))
        return resp

    @staticmethod
    def same_origin(environ):
        origin = environ.get("HTTP_ORIGIN")
        if not origin:
            return True
        host = environ.get("HTTP_HOST", "")
        return urllib.parse.urlsplit(origin).netloc == host

    @staticmethod
    def read_form(environ):
        ctype = environ.get("CONTENT_TYPE", "").split(";")[0].strip().lower()
        if ctype != "application/x-www-form-urlencoded":
            return Response(415, "Unsupported content type", "text/plain; charset=utf-8")
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            return Response(400, "Bad Content-Length", "text/plain; charset=utf-8")
        if length < 0 or length > MAX_BODY:
            return Response(413, "Request body too large", "text/plain; charset=utf-8")
        raw = environ["wsgi.input"].read(length).decode("utf-8", errors="replace")
        parsed = urllib.parse.parse_qs(raw, keep_blank_values=True, max_num_fields=20)
        return {k: v[0] for k, v in parsed.items()}

    # ---- rendering ---------------------------------------------------
    def page(self, conn, req, title, body, status=200, name=None):
        settings = db.get_settings(conn)
        flash = db.pop_flash(conn, req.session["token"])
        nav = ['<a class="brand" href="/">%s</a>' % esc(settings["name"]),
               '<a href="/challenges">Challenges</a>', '<a href="/scoreboard">Scoreboard</a>']
        if req.user:
            nav.append('<span class="muted">%s</span>' % esc(req.user["username"]))
            nav.append('<form method="post" action="/logout"><input type="hidden" name="csrf" value="%s">'
                       '<button class="link" type="submit">Log out</button></form>' % esc(req.session["csrf"]))
        else:
            nav += ['<a href="/login">Log in</a>', '<a href="/register">Register</a>']
        flash_html = ""
        if flash:
            kind = "bad" if flash.startswith("!") else ""
            flash_html = '<div class="flash %s" role="status">%s</div>' % (kind, esc(flash.lstrip("!")))
        doc = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
               '<meta name="viewport" content="width=device-width,initial-scale=1"><title>%s - %s</title>'
               '<link rel="stylesheet" href="/static/style.css"></head><body><header>%s</header>'
               '<main>%s%s</main></body></html>') % (esc(title), esc(settings["name"]), "".join(nav), flash_html, body)
        return Response(status, doc)

    def flash_redirect(self, conn, req, message, location, cookies=()):
        db.set_flash(conn, req.session["token"], message)
        return redirect(location, cookies)

    def csrf_field(self, req):
        return '<input type="hidden" name="csrf" value="%s">' % esc(req.session["csrf"])

    # ---- simple pages ------------------------------------------------
    def healthz(self, conn, req, now):
        return Response(200, "ok", "text/plain; charset=utf-8")

    def style(self, conn, req, now):
        return Response(200, CSS, "text/css; charset=utf-8", cache=True)

    def index(self, conn, req, now):
        s = db.get_settings(conn)
        state = db.ctf_state(s, now)
        label = {"pending": "starts " + fmt_time(s["start"]), "running": "is running" + (" until " + fmt_time(s["end"]) if s["end"] else ""),
                 "ended": "ended " + fmt_time(s["end"])}[state]
        body = "<h1>%s</h1><p class=\"muted\">This CTF %s.</p>" % (esc(s["name"]), esc(label))
        body += '<p><a href="/challenges">Challenges</a> &middot; <a href="/scoreboard">Scoreboard</a></p>'
        return self.page(conn, req, "Home", body)

    # ---- auth ---------------------------------------------------------
    def auth_form(self, conn, req, now, which):
        if req.user:
            return redirect("/challenges")
        if which == "register" and not db.get_settings(conn)["registration"]:
            return self.page(conn, req, "Register", "<h1>Registration is closed</h1>")
        extra = "" if which == "login" else '<p class="muted">3-24 characters: letters, digits, _ or -. Password: 8-128 characters.</p>'
        body = ('<h1>%s</h1>%s<form method="post" action="/%s">%s<label>Username<br>'
                '<input type="text" name="username" autocomplete="username" maxlength="24" required></label><br>'
                '<label>Password<br><input type="password" name="password" autocomplete="%s" maxlength="128" required></label><br>'
                '<button type="submit">%s</button></form>') % (
            which.title(), extra, which, self.csrf_field(req),
            "current-password" if which == "login" else "new-password", which.title())
        return self.page(conn, req, which.title(), body)

    def start_user_session(self, conn, req, now, user_id):
        """Rotate the session on login to prevent session fixation."""
        db.delete_session(conn, req.session["token"])
        token = security.new_token()
        db.create_session(conn, token, security.new_token(), now, user_id)
        return token

    def login(self, conn, req, now):
        username = req.form.get("username", "")[:64]
        password = req.form.get("password", "")[:security.MAX_PASSWORD + 1]
        if not (self.limiters["login_ip"].allow(req.ip) and self.limiters["login_user"].allow(username.lower())):
            return self.flash_redirect(conn, req, "!Too many attempts. Wait a minute and try again.", "/login")
        user = db.get_user_by_name(conn, username)
        ok = security.verify_password(password, user["pw_hash"]) if user else security.dummy_verify(password)
        if not ok or user["banned"]:
            return self.flash_redirect(conn, req, "!Invalid username or password.", "/login")
        token = self.start_user_session(conn, req, now, user["id"])
        db.set_flash(conn, token, "Logged in.")
        return redirect("/challenges", [self.cookie_header(token)])

    def register(self, conn, req, now):
        if not db.get_settings(conn)["registration"]:
            return self.flash_redirect(conn, req, "!Registration is closed.", "/register")
        if not self.limiters["register"].allow(req.ip):
            return self.flash_redirect(conn, req, "!Too many registrations from your address.", "/register")
        username, password = req.form.get("username", ""), req.form.get("password", "")
        if not security.valid_username(username):
            return self.flash_redirect(conn, req, "!Username must be 3-24 characters: letters, digits, _ or -.", "/register")
        if not security.valid_password(password):
            return self.flash_redirect(conn, req, "!Password must be 8-128 characters.", "/register")
        user_id = db.create_user(conn, username, security.hash_password(password), now)
        if user_id is None:
            return self.flash_redirect(conn, req, "!That username is taken.", "/register")
        token = self.start_user_session(conn, req, now, user_id)
        db.set_flash(conn, token, "Welcome! Your account is ready.")
        return redirect("/challenges", [self.cookie_header(token)])

    def logout(self, conn, req, now):
        db.delete_session(conn, req.session["token"])
        token = security.new_token()
        db.create_session(conn, token, security.new_token(), now)
        return redirect("/", [self.cookie_header(token)])

    # ---- challenges ---------------------------------------------------
    def need_login(self, req):
        return None if req.user else redirect("/login")

    def challenges(self, conn, req, now):
        gate = self.need_login(req)
        if gate:
            return gate
        s = db.get_settings(conn)
        if db.ctf_state(s, now) == "pending":
            return self.page(conn, req, "Challenges", "<h1>Challenges</h1><p>The CTF starts %s.</p>" % esc(fmt_time(s["start"])))
        values, _ = scoring.compute(conn, s, now, public=False)
        mine = db.solved_ids(conn, req.user["id"])
        by_cat = {}
        for ch in db.list_challenges(conn):
            by_cat.setdefault(ch["category"], []).append(ch)
        body = "<h1>Challenges</h1>"
        for cat, items in sorted(by_cat.items()):
            body += "<h2>%s</h2><div class=\"grid\">" % esc(cat)
            for ch in items:
                val, n = values.get(ch["id"], (ch["points"], 0))
                done = ch["id"] in mine
                body += ('<div class="card %s"><a href="/challenges/%s">%s</a><br><span class="muted">%d pts &middot; %d solve%s%s</span></div>'
                         % ("solved" if done else "", esc(ch["id"]), esc(ch["title"]), val, n, "" if n == 1 else "s",
                            " &middot; solved" if done else ""))
            body += "</div>"
        if not by_cat:
            body += "<p class=\"muted\">No challenges yet.</p>"
        return self.page(conn, req, "Challenges", body)

    def visible_challenge(self, conn, cid):
        ch = db.get_challenge(conn, cid)
        return None if ch is None or ch["hidden"] else ch

    def challenge(self, conn, req, now, cid):
        gate = self.need_login(req)
        if gate:
            return gate
        s = db.get_settings(conn)
        ch = self.visible_challenge(conn, cid)
        if ch is None or db.ctf_state(s, now) == "pending":
            return self.page(conn, req, "Not found", "<h1>Not found</h1>", status=404)
        values, _ = scoring.compute(conn, s, now, public=False)
        val, n = values.get(cid, (ch["points"], 0))
        done = cid in db.solved_ids(conn, req.user["id"])
        desc = esc(ch["description"]).replace("\n", "<br>")
        body = '<h1>%s</h1><p class="muted">%s &middot; %d pts &middot; %d solve%s</p><div class="card">%s</div>' % (
            esc(ch["title"]), esc(ch["category"]), val, n, "" if n == 1 else "s", desc or "<em>No description.</em>")
        if done:
            body += '<p class="flash">You solved this challenge.</p>'
        elif db.ctf_state(s, now) == "ended":
            body += "<p class=\"muted\">The CTF has ended; submissions are closed.</p>"
        else:
            body += ('<form method="post" action="/challenges/%s/submit">%s<label>Flag<br>'
                     '<input type="text" name="flag" maxlength="%d" autocomplete="off" required></label><br>'
                     '<button type="submit">Submit</button></form>') % (esc(cid), self.csrf_field(req), security.MAX_FLAG_LENGTH)
        body += '<p><a href="/challenges">&larr; All challenges</a></p>'
        return self.page(conn, req, ch["title"], body)

    def submit(self, conn, req, now, cid):
        gate = self.need_login(req)
        if gate:
            return gate
        back = "/challenges/" + cid
        s = db.get_settings(conn)
        ch = self.visible_challenge(conn, cid)
        state = db.ctf_state(s, now)
        if ch is None or state == "pending":
            return self.page(conn, req, "Not found", "<h1>Not found</h1>", status=404)
        if state == "ended":
            return self.flash_redirect(conn, req, "!The CTF has ended; submissions are closed.", back)
        if not self.limiters["submit"].allow(req.user["id"]):
            return self.flash_redirect(conn, req, "!Slow down: too many submissions. Try again in a minute.", back)
        flag = req.form.get("flag", "")
        if not flag.strip() or len(flag) > security.MAX_FLAG_LENGTH:
            return self.flash_redirect(conn, req, "!Enter a flag (up to %d characters)." % security.MAX_FLAG_LENGTH, back)
        if cid in db.solved_ids(conn, req.user["id"]):
            return self.flash_redirect(conn, req, "You already solved this challenge.", back)
        if not security.check_flag(flag, ch["flag_sha256"]):
            db.record_wrong(conn, req.user["id"], cid)
            return self.flash_redirect(conn, req, "!Incorrect flag.", back)
        if not db.record_solve(conn, req.user["id"], cid, now):
            return self.flash_redirect(conn, req, "You already solved this challenge.", back)
        values, _ = scoring.compute(conn, s, now, public=False)
        return self.flash_redirect(conn, req, "Correct! +%d points." % values[cid][0], back)

    # ---- scoreboard ---------------------------------------------------
    def scoreboard_rows(self, conn, now, limit=100):
        s = db.get_settings(conn)
        return s, scoring.scoreboard(conn, s, now, public=True, limit=limit)

    def scoreboard_page(self, conn, req, now):
        s, rows = self.scoreboard_rows(conn, now)
        frozen = s["freeze"] and now >= s["freeze"]
        body = "<h1>Scoreboard</h1>" + ('<p class="muted">The scoreboard is frozen.</p>' if frozen else "")
        body += "<table><tr><th>#</th><th>Player</th><th>Solved</th><th>Score</th></tr>"
        me = req.user["username"] if req.user else None
        for r in rows:
            body += '<tr class="%s"><td>%d</td><td>%s</td><td>%d</td><td>%d</td></tr>' % (
                "me" if r["username"] == me else "", r["rank"], esc(r["username"]), r["solved"], r["score"])
        body += "</table>" + ("" if rows else '<p class="muted">No solves yet.</p>')
        return self.page(conn, req, "Scoreboard", body)

    def scoreboard_api(self, conn, req, now):
        s, rows = self.scoreboard_rows(conn, now)
        data = {"ctf": s["name"], "frozen": bool(s["freeze"] and now >= s["freeze"]),
                "standings": [{"rank": r["rank"], "player": r["username"], "solved": r["solved"],
                               "score": r["score"], "last_solve": r["last"]} for r in rows]}
        return Response(200, json.dumps(data), "application/json; charset=utf-8")
