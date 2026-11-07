# ctfhost

A small, **dependency-free** platform for hosting your own Capture The Flag (CTF)
event: challenges, flag submission, dynamic scoring, first-blood bonus and a live
scoreboard. Pure Python standard library (`http`/`wsgiref`, `sqlite3`, `hashlib.scrypt`):
no pip install, no Docker, no JavaScript. Built for school and club CTFs, workshops and
practice events where a full CTFd deployment is overkill.

It is an **organizer tool**: it contains no exploits and no challenge solutions. The
example challenges use obviously fake flags.

## Features

- Registration and login with **scrypt**-hashed passwords, server-side sessions, CSRF protection
- Challenges from a JSON file (categories, descriptions, hidden challenges, live reload)
- **Dynamic scoring** (points fall as more players solve) and a **first-blood bonus**
- Public scoreboard (HTML and JSON API), tie-break by earliest last solve
- Event window (start/end), **scoreboard freeze**, closing registration
- Per-user and per-IP **rate limiting** on logins, registrations and flag submissions
- Organizer CLI: load challenges, ban players, export the scoreboard (table/JSON/CSV)
- Flags are stored only as SHA-256 digests, so a leaked database does not reveal them
- 77 automated tests, including live HTTP and security regression tests

## Quick start

Written for Python 3.8+ (tested on Python 3.14). Run from the repository root:

```bash
python3 -m ctfhost init --db ctf.db --name "My CTF" \
    --start 2030-05-01T18:00 --end 2030-05-03T18:00        # times are UTC unless you add an offset
cp examples/challenges.example.json challenges.json         # then edit it with your own challenges
python3 -m ctfhost load --db ctf.db challenges.json
python3 -m ctfhost serve --db ctf.db                        # http://127.0.0.1:8000
```

Players register on the site. You manage the event from the command line:

```bash
python3 -m ctfhost scoreboard --db ctf.db --format csv > results.csv
python3 -m ctfhost set --db ctf.db --freeze 2030-05-03T16:00     # freeze the public scoreboard
python3 -m ctfhost set --db ctf.db --registration closed
python3 -m ctfhost ban --db ctf.db some_player                   # removes their score; `unban` restores it
python3 -m ctfhost reset-solves --db ctf.db --yes                # wipe solves after a test run
```

Re-running `load` updates existing challenges (by `id`) and keeps all solves.

## Challenge file

A JSON list. Example:

```json
[
  {
    "id": "base-camp",
    "title": "Base camp",
    "category": "crypto",
    "description": "Decode this: ...",
    "points": 300,
    "min_points": 100,
    "decay": 25,
    "flag": "flag{...}"
  }
]
```

| Field | Meaning |
|-------|---------|
| `id` | lowercase letters, digits, `-`, `_` (max 40); stable identifier used in URLs |
| `title`, `category`, `description` | shown to players as **plain text** (never rendered as HTML) |
| `points` | starting value (1-10000) |
| `min_points` | lowest value the challenge decays to (default: `points`) |
| `decay` | number of solves after which the challenge reaches `min_points` (0 = fixed points) |
| `flag` **or** `flag_sha256` | the flag, or its SHA-256 digest (`python3 -m ctfhost hash-flag`) so the file can be shared |
| `hidden` | `true` keeps the challenge out of the site until you set it to `false` and re-load |

Challenge files that contain plaintext `flag` values are secrets: keep them out of public
repositories (`challenges.json` is in `.gitignore`). Use long random flags; a SHA-256 digest
of a guessable flag can be brute-forced.

## Scoring

```
value = max(min_points, ceil(((min_points - points) / decay^2) * solves^2 + points))
```

Every solver of a challenge gets its **current** value, so earlier solvers' points drop as
more players solve it (the CTFd-style parabolic curve). The first solver additionally gets a
bonus of `first_blood_pct` percent (default 10, set with `--first-blood-pct`). Ranking: highest
score first, then earliest last solve. Banned players are excluded from all counts.

## Security design

| Area | What ctfhost does |
|------|-------------------|
| Passwords | `hashlib.scrypt` (N=2^14, r=8, p=1), 16-byte random salt, constant-time compare; unknown users cost the same time as known ones |
| Sessions | 256-bit random tokens stored server-side, `HttpOnly` + `SameSite=Lax` (+ `Secure` with `--secure-cookies`), 12 h expiry, **rotated on login** (no session fixation) |
| CSRF | per-session token on every POST, constant-time compare, plus `Origin` check |
| XSS | all dynamic output is HTML-escaped; descriptions are plain text; the site serves **no JavaScript** and sends `Content-Security-Policy: default-src 'none'; style-src 'self'; ...` |
| SQL | parameterised queries only |
| Brute force | limiters: logins 10/min per IP and 5/min per username, registrations 5 per 10 min per IP, flag submissions 10/min per user |
| Input limits | request body max 16 KB, flag max 256 characters, strict username/password rules |
| Information leaks | generic login errors, no stack traces (500 pages are generic), `Server: ctfhost` only, hidden challenges return 404 |
| Flags | stored as SHA-256 digests; wrong guesses are counted, never stored |
| Admin | **CLI only**: there is no web admin interface to attack |
| Other headers | `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` for pages |

The tests cover these properties (CSRF failures, fixation, escaping, rate limits, headers, body limits,
SQL-injection strings, banned sessions, state windows).

## Running a real event

1. Run behind a reverse proxy that terminates **HTTPS** (nginx, Caddy, ...) and start with
   `--secure-cookies`. If the proxy sets `X-Forwarded-For`, add `--trusted-proxy` so rate limits use the real client address
   (only do this behind your own proxy; the last entry is used).
2. Bind to `127.0.0.1` (default) and let the proxy forward to it. The server warns when you bind elsewhere.
3. Back up the `.db` file (SQLite, WAL mode) and keep challenge files private.
4. Test the whole flow with a few accounts, then `reset-solves --yes` before the event starts.

## Limitations

- One process with SQLite: comfortable for hundreds of players, not for huge public events.
- Rate limiters live in memory and reset when the server restarts.
- No teams, writeups, file attachments, hints or e-mail: players are individual accounts, and attachments
  can be shared as links in the description.
- No password reset: a player who forgets a password registers a new name (or you handle it out of band).
- Security is only as good as your deployment: use HTTPS and keep the host patched.

## Project layout

```
ctfhost/security.py   password/flag hashing, tokens, rate limiter
ctfhost/db.py         SQLite schema and queries, challenge validation
ctfhost/scoring.py    dynamic scoring and the scoreboard
ctfhost/web.py        WSGI app: routes, sessions, CSRF, pages
ctfhost/cli.py        organizer commands and the server launcher
tests/                unit, web (WSGI-level) and live-HTTP tests
examples/             example challenge file with fake flags
```

## Tests

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS
