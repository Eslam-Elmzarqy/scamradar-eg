"""Tail Cowrie's JSON log and store the interesting events in SQLite.

Reads only new lines (the byte offset is persisted), ignores half-written
lines, flags private/loopback sources as local=1 so lab tests never pollute
real statistics, and extracts URLs from attacker commands (wget, curl, ...).
"""
import ipaddress
import json
import os
import re
import time

import db

LOG = os.environ.get(
    "COWRIE_LOG", "/home/cowrie/my-honeypot/var/log/cowrie/cowrie.json")
URL_RE = re.compile(r"https?://[^\s;|&'\"<>]+", re.IGNORECASE)

KEEP = {
    "cowrie.session.connect",
    "cowrie.login.success",
    "cowrie.login.failed",
    "cowrie.command.input",
    "cowrie.session.file_download",
    "cowrie.session.file_upload",
}


def init():
    con = db.connect()
    con.execute("""CREATE TABLE IF NOT EXISTS hp_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, session TEXT, src_ip TEXT, local INTEGER,
        eventid TEXT, username TEXT, password TEXT,
        command TEXT, url TEXT, sha256 TEXT,
        UNIQUE(ts, session, eventid))""")
    con.execute("CREATE INDEX IF NOT EXISTS idx_hp_ip ON hp_events(src_ip)")
    con.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)")
    con.commit()
    con.close()


def get_offset() -> int:
    con = db.connect()
    row = con.execute("SELECT v FROM meta WHERE k='cowrie_offset'").fetchone()
    con.close()
    return int(row[0]) if row else 0


def set_offset(n: int):
    con = db.connect()
    con.execute("INSERT OR REPLACE INTO meta VALUES ('cowrie_offset', ?)", (str(n),))
    con.commit()
    con.close()


def is_local(ip: str) -> int:
    try:
        a = ipaddress.ip_address(ip)
        return int(a.is_private or a.is_loopback)
    except ValueError:
        return 0


def parse(line: str):
    """Turn one JSON log line into a DB row, or None if we don't care about it."""
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        return None
    ev = e.get("eventid", "")
    if ev not in KEEP:
        return None

    ip = e.get("src_ip", "")
    cmd = e.get("input") if ev == "cowrie.command.input" else None
    url = e.get("url")
    if not url and cmd:
        m = URL_RE.search(cmd)
        url = m.group(0) if m else None

    return (
        e.get("timestamp", ""), e.get("session", ""), ip, is_local(ip), ev,
        e.get("username"), e.get("password"), cmd, url, e.get("shasum"),
    )


def run():
    init()
    offset = get_offset()
    print(f"[collector] reading {LOG} from offset {offset}")

    while True:
        try:
            size = os.path.getsize(LOG)
        except FileNotFoundError:
            print("[collector] log file not found, waiting...")
            time.sleep(5)
            continue

        if size < offset:  # file was rotated or replaced
            offset = 0

        if size > offset:
            with open(LOG, "rb") as f:
                f.seek(offset)
                data = f.read()
            last_nl = data.rfind(b"\n")
            if last_nl != -1:  # only consume complete lines
                chunk = data[: last_nl + 1]
                rows = []
                for line in chunk.decode("utf-8", "replace").splitlines():
                    r = parse(line)
                    if r:
                        rows.append(r)

                if rows:
                    con = db.connect()
                    with con:
                        con.executemany(
                            "INSERT OR IGNORE INTO hp_events "
                            "(ts,session,src_ip,local,eventid,username,password,"
                            "command,url,sha256) VALUES (?,?,?,?,?,?,?,?,?,?)", rows)
                    con.close()
                    for r in rows:
                        detail = (r[7] or (f"{r[5]}/{r[6]}" if r[5] else "")
                                  or r[8] or "")
                        print(f"[+] {r[2]:<15} {r[4].replace('cowrie.', ''):<22} "
                              f"{detail[:60]}")

                offset += len(chunk)
                set_offset(offset)

        time.sleep(1)


if __name__ == "__main__":
    run()
