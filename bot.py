"""ScamRadar EG: a Telegram bot that scores suspicious links and messages.

Per message: refang -> extract URLs -> honeypot exact match -> cache ->
URLhaus -> OpenPhish -> local heuristics -> honeypot server/IP match -> verdict.
Replies are in Egyptian Arabic on purpose: that is the target audience.
"""
import asyncio
import ipaddress
import os
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
import tldextract
import whois
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

import db
import feeds
import intel

BOT_TOKEN = os.environ["BOT_TOKEN"]
UA = {"User-Agent": "Mozilla/5.0"}
CACHE_NOTE = "💾 (نتيجة محفوظة من فحص سابق)"

# ---------------------------------------------------------------- word lists

# Brands commonly impersonated in Egyptian scams
BRANDS = ["vodafone", "etisalat", "orange", "instapay", "fawry",
          "aramex", "bosta", "cib", "nbe", "banquemisr", "egyptpost"]

# Urgency / threat / prize wording (Arabic and English)
URGENCY = ["عاجل", "فورا", "فوراً", "خلال 24", "سيتم إيقاف", "تم إيقاف",
           "ربحت", "مبروك", "جائزة", "استرداد", "تحديث بياناتك",
           "اضغط هنا", "الرابط التالي", "رقم سري", "كود التفعيل",
           "urgent", "suspended", "verify", "winner", "click here"]

SUSPICIOUS_TLDS = {"xyz", "top", "click", "icu", "tk", "ml", "ga", "cf",
                   "gq", "buzz", "live"}

SHORTENERS = {"bit.ly", "tinyurl.com", "cutt.ly", "t.co", "goo.gl", "is.gd",
              "rb.gy", "ow.ly", "shorturl.at", "tiny.cc", "t.ly"}

IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
SCHEME_RE = re.compile(r"https?://[^\s]+", re.IGNORECASE)
BARE_RE = re.compile(
    r"(?<![@\w.\-/])"
    r"((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}|(?:\d{1,3}\.){3}\d{1,3})"
    r"(?::\d{2,5})?(?:/[^\s]*)?",
    re.IGNORECASE,
)
ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")
TRAIL = ".,;:!?)]}>»\"'،؟"

# ---------------------------------------------------------------- text cleanup


def refang(text: str) -> str:
    """Undo the obfuscation scammers use to dodge filters (hxxp, [.], etc.)."""
    t = ZERO_WIDTH.sub("", text)
    t = t.replace("\\/", "/")
    t = re.sub(r"hxxp(s?)", r"http\1", t, flags=re.IGNORECASE)
    t = t.replace("[://]", "://").replace("[:]", ":").replace("(:)", ":")
    t = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}", ".", t,
               flags=re.IGNORECASE)
    return t


def extract_urls(text, entities=()):
    """Find URLs written with a scheme, without one, or hidden behind link text."""
    found = []

    # 1) Links hidden behind a word (e.g. "click here" with an embedded URL)
    for e in entities:
        if getattr(e, "type", "") == "text_link" and getattr(e, "url", None):
            found.append(e.url.strip())

    # 2) URLs with http/https
    for m in SCHEME_RE.findall(text):
        found.append(m.rstrip(TRAIL))
    rest = SCHEME_RE.sub(" ", text)

    # 3) URLs without a scheme (www.site.com, site.com/login, bare IPs)
    for m in BARE_RE.finditer(rest):
        cand = m.group(0).rstrip(TRAIL)
        host = re.split(r"[/:]", cand)[0]
        if IP_RE.fullmatch(host) or tldextract.extract(host).suffix:
            found.append("http://" + cand)

    seen, out = set(), []
    for u in found:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out

# ---------------------------------------------------------------- network checks


def domain_age_days(domain: str):
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - created).days
    except Exception:
        return None


def host_status(host: str) -> str:
    """SSRF guard: 'ok' (safe to visit), 'internal' (private address), 'dns' (unresolvable).

    Known limitation: DNS can change between this check and the request
    (DNS rebinding). Pinning the resolved IP would close that gap.
    """
    if not host:
        return "dns"
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
                return "internal"
        return "ok"
    except Exception:
        return "dns"


def check_ssl(host: str, port: int = 443) -> bool:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def follow_redirects(url: str, max_hops: int = 5):
    """Follow redirects by hand, checking every hop. Never downloads the body."""
    hist, cur = [], url
    try:
        for hop in range(max_hops + 1):
            host = urlparse(cur).hostname or ""
            st = host_status(host)
            if st == "internal":
                return hist, cur, "internal"
            if st == "dns":
                return hist, cur, ("dns" if hop == 0 else "ok")
            r = requests.get(cur, timeout=8, allow_redirects=False,
                             headers=UA, stream=True)
            code = r.status_code
            loc = r.headers.get("Location")
            r.close()
            if code in (301, 302, 303, 307, 308) and loc:
                cur = urljoin(cur, loc)
                hist.append(cur)
            else:
                return hist, cur, "ok"
        return hist, cur, "ok"
    except Exception:
        return hist, None, "error"


def _registered(host: str) -> str:
    e = tldextract.extract(host)
    return f"{e.domain}.{e.suffix}" if e.suffix else host

# ---------------------------------------------------------------- analysis


def analyze_url(url: str):
    """Heuristic score (0-100) and reasons for a single URL."""
    score, reasons = 0, []
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return 20, ["⚠️ شكل اللينك غير طبيعي (بورت أو عنوان غلط)"]
    if not host:
        return 0, []

    is_ip = bool(IP_RE.fullmatch(host))
    ext = tldextract.extract(host)
    registered = host if is_ip else _registered(host)

    # 1) Raw IP address instead of a domain name
    if is_ip:
        score += 25
        reasons.append("🚨 اللينك بيستخدم عنوان IP مباشر بدل اسم دومين")

    # 2) Domain age (WHOIS)
    if not is_ip:
        age = domain_age_days(registered)
        if age is None:
            score += 15
            reasons.append("⚠️ مقدرتش أعرف عمر الدومين (مش مسجّل أو مخفي)")
        elif age < 30:
            score += 35
            reasons.append(f"🚨 الدومين عمره {age} يوم بس (جديد جداً)")
        elif age < 180:
            score += 15
            reasons.append(f"⚠️ الدومين عمره {age} يوم (حديث نسبياً)")

    # 3) Brand impersonation (short brand names must match a whole token)
    if not is_ip:
        low = host.lower()
        tokens = re.split(r"[^a-z0-9]+", low)
        for b in BRANDS:
            hit = (b in tokens) if len(b) <= 4 else (b in low)
            if hit and b != ext.domain.lower():
                score += 35
                reasons.append(
                    f"🚨 اللينك فيه اسم '{b}' بس الدومين الحقيقي مش بتاعهم ({registered})")
                break

    # 4) Suspicious TLD
    if ext.suffix and ext.suffix.split(".")[-1] in SUSPICIOUS_TLDS:
        score += 15
        reasons.append(f"⚠️ امتداد الدومين (.{ext.suffix}) كتير بيستخدم في النصب")

    # 5) Unusual port
    if port and port not in (80, 443):
        score += 15
        reasons.append(f"⚠️ اللينك بيستخدم بورت غير عادي ({port})")

    # 6) Punycode (look-alike characters)
    if "xn--" in host:
        score += 25
        reasons.append("🚨 الدومين فيه حروف مموّهة (Punycode) بتشبه حروف تانية")

    # 7) URL shortener
    if registered in SHORTENERS:
        score += 15
        reasons.append("⚠️ لينك مختصر بيخفي الوجهة الحقيقية")

    # 8) Odd-looking domain
    if not is_ip and (host.count("-") >= 3 or sum(c.isdigit() for c in host) >= 5):
        score += 10
        reasons.append("⚠️ شكل الدومين غريب (شرطات/أرقام كتير)")

    # 9) No HTTPS
    if parsed.scheme != "https":
        score += 10
        reasons.append("⚠️ اللينك مش HTTPS")

    # 10) Live checks (only after the SSRF guard passes)
    net = host_status(host)
    if net == "internal":
        score += 30
        reasons.append("🚨 اللينك بيشاور على عنوان داخلي/خاص، ماتم زيارته")
    elif net == "dns":
        reasons.append("ℹ️ الدومين مش بيتحل دلوقتي (ممكن يكون اتقفل أو مش شغال)")
    else:
        if parsed.scheme == "https" and not check_ssl(host, port or 443):
            score += 15
            reasons.append("⚠️ شهادة SSL فيها مشكلة")

        hist, final, st = follow_redirects(url)
        if st == "internal":
            score += 30
            reasons.append("🚨 اللينك بيحوّل لعنوان داخلي/خاص، ماتم زيارته")
        elif st == "error":
            reasons.append("ℹ️ اللينك ماردش في الوقت المحدد")
        else:
            if len(hist) >= 3:
                score += 15
                reasons.append(f"⚠️ اللينك بيحوّلك {len(hist)} مرات قبل ما يوصل")
            if final:
                final_host = urlparse(final).hostname or ""
                final_reg = _registered(final_host)
                if final_host and final_reg != registered:
                    score += 10
                    reasons.append(f"⚠️ بيوديك لدومين تاني: {final_reg}")

    return min(score, 100), reasons


def analyze_text(text: str):
    """Score the message wording itself (pressure, prizes, OTP requests)."""
    score, reasons = 0, []
    hits = [w for w in URGENCY if w.lower() in text.lower()]
    if hits:
        score += min(10 * len(hits), 30)
        reasons.append("🚨 الرسالة فيها أسلوب ضغط/استعجال: " + "، ".join(hits[:4]))
    if re.search(r"\b\d{4,6}\b", text) and any(
            k in text for k in ["كود", "رقم سري", "OTP", "otp"]):
        score += 20
        reasons.append("🚨 بتطلب كود أو رقم سري، ومفيش جهة محترمة بتطلب ده")
    return score, reasons


def detect_kind(reasons):
    """Classify a confirmed hit so the headline can say malware or phishing."""
    if any(m in r for r in reasons for m in (intel.MSG_URLHAUS, intel.MSG_HP_EXACT)):
        return "malware"
    if any(intel.MSG_PHISH in r for r in reasons):
        return "phishing"
    return None


def verdict(score: int, kind=None) -> str:
    if kind == "malware":
        return "🔴 رابط مالوير مؤكد: ماتفتحوش ولا تحمّل منه حاجة"
    if kind == "phishing":
        return "🔴 رابط phishing مؤكد: ماتفتحوش وماتدخلش أي بيانات"
    if score >= 60:
        return "🔴 خطر عالي: غالباً نصب، ماتفتحوش"
    if score >= 30:
        return "🟡 مشبوه: خد حذرك وتأكد من المصدر الرسمي"
    return ("⚪ مالقيتش مؤشرات واضحة، لكن ده مش ضمان إنه آمن. "
            "اتأكد من المصدر قبل ما تدخل أي بيانات")


def analyze_url_cached(url: str):
    """Score a URL. Slow checks are cached for 24h; honeypot data never is."""
    local = intel.local_verdict(url)
    if local:
        return local

    cached = db.get_cached(url)
    from_cache = cached is not None
    if from_cache:
        score, reasons = cached
    else:
        score, reasons, cacheable = intel.analyze_with_intel(url, analyze_url)
        if cacheable:
            db.save_cache(url, score, reasons)

    score, reasons = intel.apply_honeypot(url, score, reasons)
    if from_cache:
        reasons = reasons + [CACHE_NOTE]
    return score, reasons

# ---------------------------------------------------------------- Telegram


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "أهلاً بيك في ScamRadar EG 🛡️\n\n"
        "ابعتلي أي رسالة أو لينك مشكوك فيه (SMS، واتساب، إيميل) "
        "وأنا هفحصه وأقولك لو فيه علامات نصب، وليه.\n\n"
        "الأوامر:\n/stats إحصائيات البوت\n\n"
        "ملحوظة: البوت مابيخزّنش نص رسايلك."
    )


async def handle(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.message
    text = refang(msg.text or "")
    urls = extract_urls(text, msg.entities or [])

    text_score, reasons = analyze_text(text)
    url_score = 0

    for u in urls[:3]:
        s, r = await asyncio.to_thread(analyze_url_cached, u)
        url_score = max(url_score, s)
        reasons += [f"[{u[:40]}] {x}" for x in r]

    if len(urls) > 3:
        reasons.append(f"ℹ️ الرسالة فيها {len(urls)} لينكات، فحصت أول 3 بس")

    total = max(text_score, url_score)
    if text_score >= 30 and url_score >= 30:
        total = min(100, total + 10)

    if not reasons:
        reasons = ["ℹ️ مفيش لينك في الرسالة ومفيش علامات خداع واضحة في النص. "
                   "ده مش ضمان إنها سليمة"]

    kind = detect_kind(reasons)
    db.log_scan(total, len(urls))  # only score and URL count are stored
    reply = f"{verdict(total, kind)}\nدرجة الخطورة: {total}/100\n\n" + "\n".join(reasons)
    await msg.reply_text(reply[:4000])


async def stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = db.get_stats()
    await update.message.reply_text(
        "📊 إحصائيات ScamRadar\n\n"
        f"إجمالي الفحوصات: {s['total']}\n"
        f"🔴 خطر عالي: {s['high']}\n"
        f"🟡 مشبوه: {s['mid']}\n"
        f"⚪ مفيش مؤشرات: {s['low']}\n"
        f"💾 روابط في الكاش: {s['cached']}"
    )


def main():
    db.init()
    feeds.start_background_updater()
    # Generous timeouts: the connection can be slow (300ms+ latency)
    app = (
        ApplicationBuilder()
        .token(BOT_TOKEN)
        .connect_timeout(30)
        .read_timeout(30)
        .write_timeout(30)
        .pool_timeout(30)
        .get_updates_connect_timeout(30)
        .get_updates_read_timeout(30)
        .get_updates_write_timeout(30)
        .get_updates_pool_timeout(30)
        .build()
    )
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("stats", stats))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle))
    print("Bot is running...")
    app.run_polling()


if __name__ == "__main__":
    main()
