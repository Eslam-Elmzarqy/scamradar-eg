from flask import Flask, render_template_string, request

import db

app = Flask(__name__)


def q(sql, args=()):
    """Run a query and return all rows (empty list on error)."""
    con = db.connect()
    try:
        return con.execute(sql, args).fetchall()
    except Exception:
        return []
    finally:
        con.close()


def one(sql, args=()):
    """Run a query and return a single value (0 if missing)."""
    rows = q(sql, args)
    return rows[0][0] if rows and rows[0][0] is not None else 0


def bars(rows):
    """Turn (name, count) rows into (name, count, percent-of-max) tuples."""
    if not rows:
        return []
    mx = max(r[1] for r in rows) or 1
    return [(str(r[0]), r[1], int(r[1] * 100 / mx)) for r in rows]


@app.after_request
def security_headers(resp):
    # Attacker-controlled strings are shown on this page, so block all scripts.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; "
        "base-uri 'none'; form-action 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


PAGE = """<!doctype html>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>ScamRadar EG</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1c1f23;--mut:#6b7280;--bar:#2563eb;--bd:#e5e7eb}
@media (prefers-color-scheme: dark){:root{--bg:#0f1115;--card:#171a21;--fg:#e6e8eb;--mut:#9aa3af;--bar:#60a5fa;--bd:#2a2f3a}}
body{margin:0;padding:20px;background:var(--bg);color:var(--fg);font-family:system-ui,Segoe UI,Tahoma,sans-serif}
h1{margin:0 0 4px;font-size:22px}
.sub{color:var(--mut);margin-bottom:16px;font-size:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px}
.num{font-size:26px;font-weight:600}
.lbl{color:var(--mut);font-size:13px}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px}
h2{font-size:15px;margin:0 0 10px}
.row{display:flex;align-items:center;gap:8px;margin:6px 0;font-size:13px}
.name{flex:0 0 45%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:ui-monospace,Consolas,monospace}
.track{flex:1;background:var(--bd);border-radius:4px;height:8px}
.fill{background:var(--bar);height:8px;border-radius:4px}
.cnt{flex:0 0 36px;text-align:right;color:var(--mut)}
.empty{color:var(--mut);font-size:13px}
.banner{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:10px 14px;margin-bottom:16px;font-size:13px}
a{color:var(--bar)}
</style>
</head>
<body>
{% macro show(rows) %}
  {% if rows %}
    {% for name, c, pct in rows %}
    <div class="row">
      <div class="name" title="{{ name }}">{{ name }}</div>
      <div class="track"><div class="fill" style="width:{{ pct }}%"></div></div>
      <div class="cnt">{{ c }}</div>
    </div>
    {% endfor %}
  {% else %}
    <div class="empty">No data yet</div>
  {% endif %}
{% endmacro %}

<h1>🛡️ ScamRadar EG</h1>
<div class="sub">Honeypot and scan dashboard (auto-refreshes every 30 seconds)</div>

<div class="banner">
  {% if inc %}
    ⚠️ <b>Test mode:</b> local events (your own tests) are included. <a href="/">Back to normal view</a>
  {% else %}
    Normal view: local events are ignored. For testing, open <a href="/?local=1">test mode</a>.
  {% endif %}
</div>

<div class="grid">
  <div class="card"><div class="num">{{ events }}</div><div class="lbl">Honeypot events</div></div>
  <div class="card"><div class="num">{{ ips }}</div><div class="lbl">Unique IPs</div></div>
  <div class="card"><div class="num">{{ sessions }}</div><div class="lbl">Sessions</div></div>
  <div class="card"><div class="num">{{ logins }}</div><div class="lbl">Login attempts</div></div>
  <div class="card"><div class="num">{{ scans.total }}</div><div class="lbl">Bot scans</div></div>
  <div class="card"><div class="num">{{ feed }}</div><div class="lbl">OpenPhish URLs</div></div>
</div>

<div class="cols">
  <div class="card"><h2>Top attacking IPs</h2>{{ show(top_ips) }}</div>
  <div class="card"><h2>Top passwords tried</h2>{{ show(top_pass) }}</div>
  <div class="card"><h2>Top usernames tried</h2>{{ show(top_user) }}</div>
  <div class="card"><h2>Top commands executed</h2>{{ show(top_cmd) }}</div>
  <div class="card"><h2>Bot scan verdicts</h2>{{ show(verdicts) }}</div>
  <div class="card">
    <h2>Latest download attempts</h2>
    {% if urls %}
      {% for url, ip, ts in urls %}
      <div class="row">
        <div class="name" title="{{ url }}" style="flex:1">{{ url }}</div>
        <div class="cnt" style="flex:0 0 auto">{{ ip }}</div>
      </div>
      {% endfor %}
    {% else %}
      <div class="empty">No data yet</div>
    {% endif %}
  </div>
</div>
</body>
</html>"""


@app.route("/")
def index():
    inc = request.args.get("local") == "1"
    w = "1=1" if inc else "local=0"

    scans = db.get_stats()
    verdicts = bars([
        ("High risk", scans["high"]),
        ("Suspicious", scans["mid"]),
        ("No indicators", scans["low"]),
    ]) if scans["total"] else []

    return render_template_string(
        PAGE,
        inc=inc,
        scans=scans,
        events=one(f"SELECT COUNT(*) FROM hp_events WHERE {w}"),
        ips=one(f"SELECT COUNT(DISTINCT src_ip) FROM hp_events WHERE {w}"),
        sessions=one(f"SELECT COUNT(DISTINCT session) FROM hp_events WHERE {w}"),
        logins=one(f"SELECT COUNT(*) FROM hp_events WHERE {w} AND eventid LIKE 'cowrie.login.%'"),
        feed=one("SELECT COUNT(*) FROM phish_feed"),
        top_ips=bars(q(f"SELECT src_ip, COUNT(*) c FROM hp_events WHERE {w} "
                       "GROUP BY src_ip ORDER BY c DESC LIMIT 10")),
        top_pass=bars(q(f"SELECT password, COUNT(*) c FROM hp_events WHERE {w} "
                        "AND password IS NOT NULL AND password!='' "
                        "GROUP BY password ORDER BY c DESC LIMIT 10")),
        top_user=bars(q(f"SELECT username, COUNT(*) c FROM hp_events WHERE {w} "
                        "AND username IS NOT NULL AND username!='' "
                        "GROUP BY username ORDER BY c DESC LIMIT 10")),
        top_cmd=bars(q(f"SELECT command, COUNT(*) c FROM hp_events WHERE {w} "
                       "AND command IS NOT NULL AND command!='' "
                       "GROUP BY command ORDER BY c DESC LIMIT 10")),
        urls=q(f"SELECT url, src_ip, ts FROM hp_events WHERE {w} "
               "AND url IS NOT NULL ORDER BY id DESC LIMIT 10"),
        verdicts=verdicts,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
