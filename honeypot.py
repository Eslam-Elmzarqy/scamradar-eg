"""Query honeypot data: has this URL, server or IP been seen attacking us?

Events from private/loopback sources (lab tests) are ignored unless
HP_INCLUDE_LOCAL=1 is set, so tests never pollute real threat intel.
"""
import os

import db
import feeds

# Shared platforms: one bad file there says nothing about the whole domain.
EXTRA_SHARED = {
    "pastebin.com", "transfer.sh", "discord.com", "discordapp.com",
    "dropbox.com", "mega.nz", "anonfiles.com", "gofile.io",
    "raw.githubusercontent.com", "gitlab.com", "bitbucket.org",
}

INCLUDE_LOCAL = os.environ.get("HP_INCLUDE_LOCAL") == "1"


def _local_clause() -> str:
    return "" if INCLUDE_LOCAL else " AND local=0"


def _host(normalized: str) -> str:
    return normalized.split("/")[0].split(":")[0]


def _urls():
    con = db.connect()
    try:
        return con.execute(
            "SELECT url, src_ip, ts FROM hp_events WHERE url IS NOT NULL"
            + _local_clause()
        ).fetchall()
    except Exception:  # table not created yet
        return []
    finally:
        con.close()


def _ip_seen(ip: str) -> int:
    con = db.connect()
    try:
        row = con.execute(
            "SELECT COUNT(*) FROM hp_events WHERE src_ip=?" + _local_clause(),
            (ip,),
        ).fetchone()
        return row[0] if row else 0
    except Exception:
        return 0
    finally:
        con.close()


def check(url: str):
    """Return a dict with kind = 'exact' | 'ip' | 'host', or None."""
    n = feeds.normalize(url)
    host = _host(n)
    reg = feeds.registered_domain(n)
    rows = _urls()

    # 1) The exact URL was attempted against the honeypot
    exact = [r for r in rows if feeds.normalize(r[0]) == n]
    if exact:
        return {
            "kind": "exact",
            "count": len(exact),
            "attackers": len({r[1] for r in exact}),
            "first": min(r[2] for r in exact),
        }

    # 2) The URL points at an IP that itself attacked the honeypot
    if host and _ip_seen(host):
        return {"kind": "ip", "count": _ip_seen(host)}

    # 3) Same server that attackers tried to download from
    shared = feeds.SHARED_HOSTS | EXTRA_SHARED
    if host and host not in shared and (not reg or reg not in shared):
        same = []
        for r in rows:
            rn = feeds.normalize(r[0])
            if _host(rn) == host or (reg and feeds.registered_domain(rn) == reg):
                same.append(r)
        if same:
            return {"kind": "host", "count": len(same)}

    return None
