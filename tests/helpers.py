"""Test helpers: drive the WSGI app directly, no sockets needed."""
import io
import re
import urllib.parse
from http.cookies import SimpleCookie


PW = "pw-for-tests-123"


class Resp:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    def header(self, name):
        vals = [v for k, v in self.headers if k.lower() == name.lower()]
        return vals[0] if vals else None

    @property
    def location(self):
        return self.header("Location")

    @property
    def text(self):
        return self.body.decode("utf-8")


class Client:
    def __init__(self, app, ip="198.51.100.7", host="127.0.0.1:8000"):
        self.app, self.ip, self.host, self.cookies = app, ip, host, {}

    def request(self, method, path, form=None, headers=None, raw_body=None, content_type=None, content_length=None):
        body = raw_body if raw_body is not None else urllib.parse.urlencode(form or {}).encode()
        environ = {"REQUEST_METHOD": method, "PATH_INFO": path, "SERVER_NAME": "127.0.0.1", "SERVER_PORT": "8000",
                   "wsgi.input": io.BytesIO(body), "HTTP_HOST": self.host, "REMOTE_ADDR": self.ip,
                   "CONTENT_LENGTH": str(content_length if content_length is not None else len(body)) if method == "POST" else "",
                   "CONTENT_TYPE": (content_type or "application/x-www-form-urlencoded") if method == "POST" else ""}
        if self.cookies:
            environ["HTTP_COOKIE"] = "; ".join("%s=%s" % kv for kv in self.cookies.items())
        for k, v in (headers or {}).items():
            environ["HTTP_" + k.upper().replace("-", "_")] = v
        captured = {}

        def start_response(status, hdrs):
            captured["status"], captured["headers"] = int(status.split()[0]), hdrs

        out = b"".join(self.app(environ, start_response))
        for k, v in captured["headers"]:
            if k.lower() == "set-cookie":
                c = SimpleCookie(v)
                for name, morsel in c.items():
                    self.cookies[name] = morsel.value
        return Resp(captured["status"], captured["headers"], out)

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def csrf(self):
        page = self.get("/login").text if "csrf" not in getattr(self, "_page", "") else self._page
        m = re.search(r'name="csrf" value="([^"]+)"', page)
        if not m:  # logged-in users are redirected away from /login; use the home page's logout form
            m = re.search(r'name="csrf" value="([^"]+)"', self.get("/scoreboard").text)
        return m.group(1)

    def post(self, path, form=None, csrf=True, **kw):
        form = dict(form or {})
        if csrf is True:
            form["csrf"] = self.csrf()
        elif csrf:
            form["csrf"] = csrf
        return self.request("POST", path, form, **kw)

    def register(self, name, password=PW):
        return self.post("/register", {"username": name, "password": password})

    def login(self, name, password=PW):
        return self.post("/login", {"username": name, "password": password})

    def flash(self, path="/challenges"):
        m = re.search(r'<div class="flash[^"]*" role="status">(.*?)</div>', self.get(path).text, re.S)
        return m.group(1) if m else None
