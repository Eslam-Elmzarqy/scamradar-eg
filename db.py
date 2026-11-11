"""SQLite storage for ScamRadar EG.

Stores only what the project needs: scan scores, cached URL verdicts,
threat-feed entries and honeypot events. It never stores message text
or Telegram user identities.
"""
import json
import os
import sqlite3
import time

DB_PATH = os.environ.get("SCAMRADAR_DB", "scamradar.db")


def connect():
    """Open a new connection. One connection per operation keeps it thread-safe."""
    return sqlite3.connect(DB_PATH, timeout=30)


def init():
    con = connect()
    con.execute("""CREATE TABLE IF NOT EXISTS url_cache (
        url TEXT PRIMARY KEY,
        score INTEGER,
        reasons TEXT,
        checked_at INTEGER)""")
    con.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER,
        score INTEGER,
        url_count INTEGER)""")
    con.commit()
    con.close()


def get_cached(url, max_age=86400):
    """Return (score, reasons) if the cached verdict is newer than max_age, else None."""
    con = connect()
    row = con.execute(
        "SELECT score, reasons, checked_at FROM url_cache WHERE url=?", (url,)
    ).fetchone()
    con.close()
    if row and time.time() - row[2] < max_age:
        return row[0], json.loads(row[1])
    return None


def save_cache(url, score, reasons):
    con = connect()
    con.execute(
        "INSERT OR REPLACE INTO url_cache VALUES (?,?,?,?)",
        (url, score, json.dumps(reasons, ensure_ascii=False), int(time.time())),
    )
    con.commit()
    con.close()


def log_scan(score, url_count):
    """Record one scan (timestamp, score, number of URLs). Nothing else."""
    con = connect()
    con.execute(
        "INSERT INTO scans (ts, score, url_count) VALUES (?,?,?)",
        (int(time.time()), score, url_count),
    )
    con.commit()
    con.close()


def get_stats():
    con = connect()
    total = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    high = con.execute("SELECT COUNT(*) FROM scans WHERE score>=60").fetchone()[0]
    mid = con.execute(
        "SELECT COUNT(*) FROM scans WHERE score>=30 AND score<60").fetchone()[0]
    low = con.execute("SELECT COUNT(*) FROM scans WHERE score<30").fetchone()[0]
    cached = con.execute("SELECT COUNT(*) FROM url_cache").fetchone()[0]
    con.close()
    return {"total": total, "high": high, "mid": mid, "low": low, "cached": cached}
