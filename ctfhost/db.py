"""SQLite storage. All queries are parameterised."""
import re
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    pw_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    banned INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    flash TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    points INTEGER NOT NULL,
    min_points INTEGER NOT NULL,
    decay INTEGER NOT NULL,
    flag_sha256 TEXT NOT NULL,
    hidden INTEGER NOT NULL DEFAULT 0,
    position INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS solves (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge_id TEXT NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    solved_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, challenge_id));
CREATE TABLE IF NOT EXISTS attempts (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge_id TEXT NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    wrong INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, challenge_id));
"""

DEFAULTS = {"name": "CTF", "start": "0", "end": "0", "freeze": "0",
            "registration": "open", "first_blood_pct": "10"}
SESSION_TTL = 12 * 3600
CHALLENGE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ChallengeError(ValueError):
    pass


def connect(path):
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if path != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(path, **settings):
    conn = connect(path)
    with conn:
        conn.executescript(SCHEMA)
        for k, v in DEFAULTS.items():
            conn.execute("INSERT OR IGNORE INTO settings VALUES (?, ?)", (k, v))
    for k, v in settings.items():
        set_setting(conn, k, v)
    conn.close()


def set_setting(conn, key, value):
    if key not in DEFAULTS:
        raise KeyError("unknown setting %r" % key)
    with conn:
        conn.execute("INSERT INTO settings VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                     (key, str(value)))


def get_settings(conn):
    raw = dict(DEFAULTS)
    raw.update({r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM settings")})
    return {"name": raw["name"], "start": int(raw["start"]), "end": int(raw["end"]),
            "freeze": int(raw["freeze"]), "registration": raw["registration"] == "open",
            "first_blood_pct": max(0, min(100, int(raw["first_blood_pct"])))}


def ctf_state(settings, now):
    if settings["start"] and now < settings["start"]:
        return "pending"
    if settings["end"] and now >= settings["end"]:
        return "ended"
    return "running"


# ---- users and sessions -------------------------------------------------

def create_user(conn, username, pw_hash, now):
    """Return the new user id, or None when the name is taken (case-insensitive)."""
    try:
        with conn:
            cur = conn.execute("INSERT INTO users (username, pw_hash, created_at) VALUES (?, ?, ?)",
                               (username, pw_hash, int(now)))
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None


def get_user_by_name(conn, username):
    return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_user(conn, user_id):
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def set_banned(conn, username, banned):
    with conn:
        cur = conn.execute("UPDATE users SET banned = ? WHERE username = ?", (1 if banned else 0, username))
        if banned:
            conn.execute("DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ?)", (username,))
    return cur.rowcount > 0


def create_session(conn, token, csrf, now, user_id=None):
    with conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (int(now),))
        conn.execute("INSERT INTO sessions (token, user_id, csrf, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                     (token, user_id, csrf, int(now), int(now) + SESSION_TTL))


def get_session(conn, token, now):
    if not token:
        return None
    return conn.execute("SELECT * FROM sessions WHERE token = ? AND expires_at >= ?", (token, int(now))).fetchone()


def delete_session(conn, token):
    with conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


def set_flash(conn, token, message):
    with conn:
        conn.execute("UPDATE sessions SET flash = ? WHERE token = ?", (message, token))


def pop_flash(conn, token):
    row = conn.execute("SELECT flash FROM sessions WHERE token = ?", (token,)).fetchone()
    if row and row["flash"]:
        set_flash(conn, token, None)
        return row["flash"]
    return None


# ---- challenges and solves ----------------------------------------------

def validate_challenge(c, position=0):
    """Validate one challenge dict from a JSON file and return a normalised copy."""
    if not isinstance(c, dict):
        raise ChallengeError("each challenge must be an object")
    cid = c.get("id")
    if not isinstance(cid, str) or not CHALLENGE_ID_RE.match(cid):
        raise ChallengeError("invalid id %r (use lowercase letters, digits, '-' or '_', max 40)" % (cid,))

    def text(key, limit, required=True):
        v = c.get(key, "")
        if not isinstance(v, str) or (required and not v.strip()) or len(v) > limit:
            raise ChallengeError("%s: invalid %s (text up to %d characters)" % (cid, key, limit))
        return v

    def integer(key, lo, hi, default=None):
        v = c.get(key, default)
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            raise ChallengeError("%s: %s must be an integer between %d and %d" % (cid, key, lo, hi))
        return v

    points = integer("points", 1, 10000)
    out = {"id": cid, "title": text("title", 100), "category": text("category", 30),
           "description": text("description", 5000, required=False), "points": points,
           "min_points": integer("min_points", 1, points, default=points),
           "decay": integer("decay", 0, 100000, default=0), "hidden": 1 if c.get("hidden") else 0,
           "position": position}
    if "flag_sha256" in c:
        digest = str(c["flag_sha256"]).lower()
        if not HEX64.match(digest):
            raise ChallengeError("%s: flag_sha256 must be 64 hex characters" % cid)
    elif "flag" in c:
        from . import security
        flag = c["flag"]
        if not isinstance(flag, str) or not flag.strip():
            raise ChallengeError("%s: flag must be a non-empty string" % cid)
        digest = security.hash_flag(flag)
    else:
        raise ChallengeError("%s: provide `flag` or `flag_sha256`" % cid)
    out["flag_sha256"] = digest
    return out


def load_challenges(conn, items):
    """Insert or update challenges; existing solves are kept. Returns the count."""
    if not isinstance(items, list) or not items:
        raise ChallengeError("expected a non-empty JSON list of challenges")
    clean = [validate_challenge(c, i) for i, c in enumerate(items)]
    ids = [c["id"] for c in clean]
    if len(set(ids)) != len(ids):
        raise ChallengeError("duplicate challenge ids in file")
    with conn:
        for c in clean:
            conn.execute(
                "INSERT INTO challenges (id, title, category, description, points, min_points, decay, flag_sha256, hidden, position) "
                "VALUES (:id, :title, :category, :description, :points, :min_points, :decay, :flag_sha256, :hidden, :position) "
                "ON CONFLICT(id) DO UPDATE SET title=excluded.title, category=excluded.category, "
                "description=excluded.description, points=excluded.points, min_points=excluded.min_points, "
                "decay=excluded.decay, flag_sha256=excluded.flag_sha256, hidden=excluded.hidden, position=excluded.position", c)
    return len(clean)


def list_challenges(conn, include_hidden=False):
    sql = "SELECT * FROM challenges" + ("" if include_hidden else " WHERE hidden = 0") + " ORDER BY category, position, id"
    return conn.execute(sql).fetchall()


def get_challenge(conn, cid):
    return conn.execute("SELECT * FROM challenges WHERE id = ?", (cid,)).fetchone()


def record_solve(conn, user_id, cid, now):
    """Return True when this is a new solve (the primary key makes it race-safe)."""
    with conn:
        cur = conn.execute("INSERT OR IGNORE INTO solves (user_id, challenge_id, solved_at) VALUES (?, ?, ?)",
                           (user_id, cid, int(now)))
    return cur.rowcount == 1


def record_wrong(conn, user_id, cid):
    with conn:
        conn.execute("INSERT INTO attempts (user_id, challenge_id, wrong) VALUES (?, ?, 1) "
                     "ON CONFLICT(user_id, challenge_id) DO UPDATE SET wrong = wrong + 1", (user_id, cid))


def solved_ids(conn, user_id):
    return {r["challenge_id"] for r in conn.execute("SELECT challenge_id FROM solves WHERE user_id = ?", (user_id,))}


def reset_solves(conn):
    with conn:
        conn.execute("DELETE FROM solves")
        conn.execute("DELETE FROM attempts")


def now():
    return int(time.time())
