"""OpenPhish community feed: download, store locally, match locally.

The feed is downloaded once every 12 hours and stored in SQLite, so the
URLs users submit are never sent to a third party.
Note: the OpenPhish community feed is for non-commercial use only.
"""
import re
import threading
import time

import requests
import tldextract

import db

FEED_URL = "https://openphish.com/feed.txt"
UPDATE_EVERY = 12 * 3600  # seconds

# Shared hosting / shortener platforms. A feed entry on one of these domains
# says nothing about the rest of the domain, so we never match on them.
SHARED_HOSTS = {
    "google.com", "googleapis.com", "github.io", "githubusercontent.com",
    "blogspot.com", "weebly.com", "wixsite.com", "wordpress.com",
    "firebaseapp.com", "web.app", "netlify.app", "vercel.app",
    "pages.dev", "workers.dev", "herokuapp.com", "000webhostapp.com",
    "godaddysites.com", "square.site", "carrd.co", "notion.site",
    "bit.ly", "tinyurl.com", "cutt.ly", "t.me", "facebook.com",
}


def normalize(url: str) -> str:
    """Lowercase, drop scheme, fragment and trailing slash for comparison."""
    u = url.strip().lower().split("#")[0]
    u = re.sub(r"^https?://", "", u)
    return u.rstrip("/")


def registered_domain(normalized: str) -> str:
    ext = tldextract.extract("http://" + normalized)
    if not ext.domain or not ext.suffix:
        return ""
    return f"{ext.domain}.{ext.suffix}"


def init():
    con = db.connect()
    con.execute("""CREATE TABLE IF NOT EXISTS phish_feed (
        url TEXT PRIMARY KEY,
        reg_domain TEXT)""")
    con.execute(
        "CREATE INDEX IF NOT EXISTS idx_phish_domain ON phish_feed(reg_domain)")
    con.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)")
    con.commit()
    con.close()


def _last_update() -> int:
    con = db.connect()
    row = con.execute("SELECT v FROM meta WHERE k='feed_updated'").fetchone()
    con.close()
    return int(row[0]) if row else 0


def update_feed() -> int:
    """Download the feed and replace the stored copy. Returns the entry count."""
    r = requests.get(
        FEED_URL, timeout=60,
        headers={"User-Agent": "ScamRadar-EG/1.0 (educational project)"})
    r.raise_for_status()

    rows = []
    for line in r.text.splitlines():
        line = line.strip()
        if not line.lower().startswith("http"):
            continue
        n = normalize(line)
        rows.append((n, registered_domain(n)))

    if not rows:
        raise RuntimeError("Feed came back empty; keeping the previous copy")

    con = db.connect()
    with con:
        con.execute("DELETE FROM phish_feed")
        con.executemany("INSERT OR IGNORE INTO phish_feed VALUES (?,?)", rows)
        con.execute("INSERT OR REPLACE INTO meta VALUES ('feed_updated', ?)",
                    (str(int(time.time())),))
    con.close()
    return len(rows)


def _loop():
    while True:
        try:
            if time.time() - _last_update() >= UPDATE_EVERY:
                n = update_feed()
                print(f"[feeds] OpenPhish updated: {n} URLs")
        except Exception as e:
            print(f"[feeds] update failed: {e}")
        time.sleep(1800)  # re-check every 30 minutes


def start_background_updater():
    init()
    threading.Thread(target=_loop, daemon=True).start()


def check(url: str):
    """Return 'exact' (URL is in the feed), 'host' (domain is in the feed), or None."""
    try:
        n = normalize(url)
        con = db.connect()
        try:
            if con.execute("SELECT 1 FROM phish_feed WHERE url=?", (n,)).fetchone():
                return "exact"
            reg = registered_domain(n)
            if reg and reg not in SHARED_HOSTS:
                if con.execute(
                        "SELECT 1 FROM phish_feed WHERE reg_domain=? LIMIT 1",
                        (reg,)).fetchone():
                    return "host"
        finally:
            con.close()
    except Exception:
        pass
    return None
