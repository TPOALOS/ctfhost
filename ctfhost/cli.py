"""Command line interface: init, load, set, scoreboard, ban, hash-flag, reset-solves, serve."""
import argparse
import csv
import datetime
import io
import json
import sys
import time
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from . import __version__, db, scoring, security
from .web import App

LOOPBACK = ("127.0.0.1", "::1", "localhost")


def parse_time(text):
    """ISO date/time (UTC unless an offset is given) -> epoch seconds. 'none' -> 0."""
    if text.strip().lower() in ("none", "0", ""):
        return 0
    try:
        dt = datetime.datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("invalid time %r (use e.g. 2030-05-01T18:00 or 2030-05-01T18:00+02:00)" % text) from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return int(dt.timestamp())


class QuietHandler(WSGIRequestHandler):
    server_version = "ctfhost"
    sys_version = ""

    def log_message(self, fmt, *args):  # keep request lines (paths only) out of the console noise
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


class ThreadingServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


def build_parser():
    ap = argparse.ArgumentParser(prog="ctfhost", description="Host your own CTF: challenges, flags, scoreboard.")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_db(p):
        p.add_argument("--db", default="ctf.db", help="SQLite database file (default: ctf.db)")

    def add_settings(p):
        p.add_argument("--name", help="CTF name")
        p.add_argument("--start", type=parse_time, help="start time, e.g. 2030-05-01T18:00 (UTC); 'none' clears")
        p.add_argument("--end", type=parse_time, help="end time; 'none' clears")
        p.add_argument("--freeze", type=parse_time, help="freeze the public scoreboard at this time; 'none' clears")
        p.add_argument("--registration", choices=("open", "closed"))
        p.add_argument("--first-blood-pct", type=int, help="bonus for the first solver, percent of the challenge value (0-100)")

    p = sub.add_parser("init", help="create a database")
    add_db(p)
    add_settings(p)
    p = sub.add_parser("set", help="change CTF settings")
    add_db(p)
    add_settings(p)
    p = sub.add_parser("load", help="load or update challenges from a JSON file")
    add_db(p)
    p.add_argument("file")
    p = sub.add_parser("scoreboard", help="print the full (unfrozen) scoreboard")
    add_db(p)
    p.add_argument("--format", choices=("table", "json", "csv"), default="table")
    for name, helptext in (("ban", "ban a player (removes their score and sessions)"), ("unban", "lift a ban")):
        p = sub.add_parser(name, help=helptext)
        add_db(p)
        p.add_argument("username")
    p = sub.add_parser("reset-solves", help="delete all solves and attempts (keeps users and challenges)")
    add_db(p)
    p.add_argument("--yes", action="store_true", help="confirm")
    p = sub.add_parser("hash-flag", help="print the SHA-256 digest of a flag (reads stdin when no argument is given)")
    p.add_argument("flag", nargs="?")
    p = sub.add_parser("serve", help="run the web server")
    add_db(p)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--secure-cookies", action="store_true", help="mark cookies Secure (use behind HTTPS)")
    p.add_argument("--trusted-proxy", action="store_true",
                   help="use the last X-Forwarded-For entry as client IP (only behind your own reverse proxy)")
    return ap


def collect_settings(args):
    out = {}
    for key in ("name", "start", "end", "freeze", "registration"):
        if getattr(args, key, None) is not None:
            out[key] = getattr(args, key)
    pct = getattr(args, "first_blood_pct", None)
    if pct is not None:
        if not 0 <= pct <= 100:
            raise ValueError("--first-blood-pct must be between 0 and 100")
        out["first_blood_pct"] = pct
    return out


def print_scoreboard(rows, fmt, out):
    if fmt == "json":
        json.dump([{"rank": r["rank"], "player": r["username"], "solved": r["solved"], "score": r["score"],
                    "last_solve": r["last"]} for r in rows], out, indent=2)
        out.write("\n")
    elif fmt == "csv":
        w = csv.writer(out)
        w.writerow(["rank", "player", "solved", "score", "last_solve"])
        for r in rows:
            w.writerow([r["rank"], r["username"], r["solved"], r["score"], r["last"]])
    else:
        out.write("%-5s %-24s %-7s %s\n" % ("rank", "player", "solved", "score"))
        for r in rows:
            out.write("%-5d %-24s %-7d %d\n" % (r["rank"], r["username"], r["solved"], r["score"]))


def main(argv=None, out=None):
    out = out or sys.stdout
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "hash-flag":
            flag = args.flag if args.flag is not None else sys.stdin.readline()
            out.write(security.hash_flag(flag) + "\n")
            return 0
        if args.cmd == "init":
            db.init_db(args.db, **collect_settings(args))
            out.write("ctfhost: database ready: %s\n" % args.db)
            return 0
        conn = db.connect(args.db)
        try:
            if args.cmd == "set":
                for k, v in collect_settings(args).items():
                    db.set_setting(conn, k, v)
                out.write("ctfhost: settings updated\n")
            elif args.cmd == "load":
                with open(args.file, encoding="utf-8") as fh:
                    n = db.load_challenges(conn, json.load(fh))
                out.write("ctfhost: loaded %d challenge(s)\n" % n)
            elif args.cmd == "scoreboard":
                rows = scoring.scoreboard(conn, db.get_settings(conn), time.time(), public=False)
                print_scoreboard(rows, args.format, out)
            elif args.cmd in ("ban", "unban"):
                if not db.set_banned(conn, args.username, args.cmd == "ban"):
                    out.write("ctfhost: no such user: %s\n" % args.username)
                    return 1
                out.write("ctfhost: %s %s\n" % (args.cmd, args.username))
            elif args.cmd == "reset-solves":
                if not args.yes:
                    out.write("ctfhost: this deletes all solves; re-run with --yes to confirm\n")
                    return 1
                db.reset_solves(conn)
                out.write("ctfhost: solves cleared\n")
            elif args.cmd == "serve":
                conn.close()
                return serve(args, out)
        finally:
            conn.close()
        return 0
    except (OSError, ValueError, KeyError, db.ChallengeError, json.JSONDecodeError) as exc:
        sys.stderr.write("ctfhost: error: %s\n" % exc)
        return 2
    except Exception as exc:  # sqlite3.Error and friends
        sys.stderr.write("ctfhost: error: %s\n" % exc)
        return 2


def serve(args, out):
    db.init_db(args.db)  # make sure the schema exists; never overwrites data
    app = App(args.db, secure_cookies=args.secure_cookies, trusted_proxy=args.trusted_proxy)
    if args.host not in LOOPBACK:
        sys.stderr.write("ctfhost: warning: listening on %s without TLS. Put a reverse proxy with HTTPS in front "
                         "and use --secure-cookies.\n" % args.host)
    server = make_server(args.host, args.port, app, server_class=ThreadingServer, handler_class=QuietHandler)
    out.write("ctfhost %s serving %s on http://%s:%d (Ctrl+C to stop)\n" % (__version__, args.db, args.host, args.port))
    out.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        out.write("\nctfhost: stopped\n")
    finally:
        server.server_close()
    return 0
