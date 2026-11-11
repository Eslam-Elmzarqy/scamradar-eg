"""Threat-intelligence lookups: URLhaus, OpenPhish (via feeds) and our honeypot.

Two stages on purpose:
  analyze_with_intel()  slow, cacheable checks (URLhaus, OpenPhish, heuristics)
  apply_honeypot()      fast local check, runs on EVERY request, even for cached
                        results, because honeypot data changes all the time.
"""
import os

import requests

import feeds
import honeypot

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"

# User-facing messages (Egyptian Arabic: the bot's audience is Egyptian users).
# Other modules match on these constants, never on raw text.
MSG_URLHAUS = "🚨 اللينك ده مؤكد إنه خبيث في قاعدة URLhaus العالمية"
MSG_PHISH = "🚨 اللينك ده مؤكد إنه phishing في قاعدة OpenPhish"
MSG_HP_EXACT = "🚨 اللينك ده مؤكد إنه خبيث: اتسجّل في الـHoneypot بتاعنا"
MSG_PHISH_HOST = "🚨 الدومين ده ظهر قبل كده في لينكات phishing مؤكدة (OpenPhish)"
MSG_HP_HOST = "🚨 السيرفر ده اتحاول التحميل منه في الـHoneypot بتاعنا"
MSG_HP_IP = "🚨 العنوان ده هو نفسه IP مهاجم هاجم الـHoneypot بتاعنا"
MSG_URLHAUS_DOWN = "ℹ️ مقدرتش أتواصل مع URLhaus، اعتمدت على باقي الفحوصات"
MSG_NOT_VISITED = "🛡️ ماتم زيارة اللينك: الحكم من مصدر Threat Intel"
MSG_NOT_VISITED_OWN = "🛡️ ماتم زيارة اللينك: الحكم من Threat Intel خاص بينا"

CONFIRMED = (MSG_URLHAUS, MSG_PHISH, MSG_HP_EXACT)


def check_urlhaus(url: str):
    """Return a dict if URLhaus lists the URL, None if not listed, 'error' on failure."""
    key = os.environ.get("URLHAUS_KEY")
    if not key:
        return "error"
    try:
        r = requests.post(
            URLHAUS_API,
            data={"url": url},
            headers={"Auth-Key": key},
            timeout=30,
        )
        data = r.json()
    except Exception:
        return "error"

    if data.get("query_status") == "ok":
        return data
    if data.get("query_status") == "no_results":
        return None
    return "error"


def local_verdict(url: str):
    """Exact honeypot match. Cheap, so it runs before the cache."""
    hp = honeypot.check(url)
    if hp and hp["kind"] == "exact":
        return 100, [
            MSG_HP_EXACT,
            f"مهاجمين حاولوا يحمّلوه: {hp['attackers']} IP مختلف ({hp['count']} مرة)",
            MSG_NOT_VISITED_OWN,
        ]
    return None


def analyze_with_intel(url: str, fallback_analyzer):
    """Run URLhaus, OpenPhish and the local heuristics.

    Returns (score, reasons, cacheable). Results are not cacheable when URLhaus
    could not be reached, so a network hiccup is never remembered for 24 hours.
    Honeypot data is added later by apply_honeypot().
    """
    # 1) URLhaus: confirmed malware distribution
    hit = check_urlhaus(url)
    if isinstance(hit, dict):
        reasons = [
            MSG_URLHAUS,
            f"حالته: {hit.get('url_status', 'غير معروف')}",
            f"نوع التهديد: {hit.get('threat', 'غير معروف')}",
        ]
        tags = hit.get("tags")
        if tags:
            reasons.append("تصنيفات: " + "، ".join(tags[:5]))
        reasons.append(MSG_NOT_VISITED)
        return 100, reasons, True

    # 2) OpenPhish: confirmed phishing (matched locally, nothing is sent out)
    phish = feeds.check(url)
    if phish == "exact":
        return 100, [MSG_PHISH, MSG_NOT_VISITED], True

    # 3) Our own heuristics
    score, reasons = fallback_analyzer(url)

    if phish == "host":
        score = min(100, score + 35)
        reasons.append(MSG_PHISH_HOST)

    if hit == "error":
        reasons.append(MSG_URLHAUS_DOWN)
    return score, reasons, hit != "error"


def apply_honeypot(url: str, score: int, reasons: list):
    """Add honeypot evidence and the final 'not found in ...' note."""
    if any(m in r for r in reasons for m in CONFIRMED):
        return score, reasons

    reasons = list(reasons)
    hp = honeypot.check(url)
    if hp and hp["kind"] == "host":
        score = min(100, score + 40)
        reasons.append(MSG_HP_HOST)
    elif hp and hp["kind"] == "ip":
        score = min(100, score + 40)
        reasons.append(MSG_HP_IP)

    checked = []
    if not any(MSG_URLHAUS_DOWN in r for r in reasons):
        checked.append("URLhaus")
    if not any(MSG_PHISH_HOST in r for r in reasons):
        checked.append("OpenPhish")
    if hp is None:
        checked.append("الـHoneypot")
    if checked:
        reasons.append(
            "ℹ️ مش موجود في " + " و".join(checked) + " (ده مش معناه إنه سليم)")
    return score, reasons
