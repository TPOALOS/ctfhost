"""Dynamic scoring, first-blood bonus and the scoreboard."""
import math


def challenge_value(initial, minimum, decay, solves):
    """CTFd-style parabolic decay: points fall from `initial` towards `minimum` as solves grow.

    decay is the number of solves after which the challenge reaches its minimum.
    """
    if decay <= 0 or solves <= 0:
        return initial
    value = ((minimum - initial) / (decay ** 2)) * (solves ** 2) + initial
    return max(minimum, math.ceil(value))


def compute(conn, settings, now, public=True):
    """Return (values, scores).

    values: {challenge_id: (current_value, solve_count)}
    scores: {user_id: {"username", "score", "solved", "last"}}
    When `public` and the scoreboard is frozen, solves after the freeze time are ignored.
    """
    freeze = settings.get("freeze", 0)
    cutoff = freeze if (public and freeze and now >= freeze) else None
    sql = ("SELECT s.user_id, u.username, s.challenge_id, s.solved_at, s.rowid AS rid "
           "FROM solves s JOIN users u ON u.id = s.user_id WHERE u.banned = 0")
    params = []
    if cutoff is not None:
        sql += " AND s.solved_at <= ?"
        params.append(cutoff)
    rows = conn.execute(sql + " ORDER BY s.solved_at, s.rowid", params).fetchall()
    challenges = {r["id"]: r for r in conn.execute("SELECT * FROM challenges")}

    counts, first = {}, {}
    for r in rows:
        counts[r["challenge_id"]] = counts.get(r["challenge_id"], 0) + 1
        first.setdefault(r["challenge_id"], r["user_id"])
    values = {}
    for cid, ch in challenges.items():
        n = counts.get(cid, 0)
        values[cid] = (challenge_value(ch["points"], ch["min_points"], ch["decay"], n), n)

    pct = settings.get("first_blood_pct", 0)
    scores = {}
    for r in rows:
        cid = r["challenge_id"]
        if cid not in values:
            continue
        value = values[cid][0]
        gain = value + (value * pct // 100 if first[cid] == r["user_id"] else 0)
        entry = scores.setdefault(r["user_id"], {"username": r["username"], "score": 0, "solved": 0, "last": 0})
        entry["score"] += gain
        entry["solved"] += 1
        entry["last"] = max(entry["last"], r["solved_at"])
    return values, scores


def scoreboard(conn, settings, now, public=True, limit=None):
    """Ranked list: highest score first, earliest last solve wins ties."""
    _, scores = compute(conn, settings, now, public)
    ordered = sorted(scores.values(), key=lambda e: (-e["score"], e["last"], e["username"].lower()))
    for i, e in enumerate(ordered, 1):
        e["rank"] = i
    return ordered[:limit] if limit else ordered
