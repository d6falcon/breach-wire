#!/usr/bin/env python3
"""Breach Wire: a one-line-per-incident cyber-attack feed written to breach-wire.md.

Each line reads like a message:

    DATE | STATUS | TTP | COMPANY (country, sector) | Stolen: what | via sources

STATUS
    CONFIRMED  the victim, a regulator or a filing acknowledges the incident
    REPORTED   credible press reports it; the victim has not (yet) confirmed
    CLAIMED    a leak site, dark-web forum or Telegram post claims it; unverified

Sources live in sources.json (tiers: leak, darkweb, telegram, press, news, filing). Leak sites are read
through clearnet trackers, so this script never touches .onion infrastructure.

Every run merges into state/wire.tsv (deduplicated by company + lane, so a claim and a later confirmation
appear as two messages) and regenerates breach-wire.md from it. Only data categories and volumes are
written; raw leaked values are never copied. TTPs are keyword-derived ATT&CK hints, not attribution.

Standard library only. Python 3.11+.

    python3 scripts/breach_wire.py
    python3 scripts/breach_wire.py --days 7 --no-claims
"""
from __future__ import annotations

import argparse
import csv
import email.utils
import hashlib
import html
import json
import re
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CFG_FILE = ROOT / "sources.json"
STATE_DIR = ROOT / "state"
STORE_FILE = STATE_DIR / "wire.tsv"
LOG_FILE = STATE_DIR / "run.log"
OUT_FILE = ROOT / "breach-wire.md"

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) breach-wire/1.0"
FIELDS = ["Id", "Date", "Status", "Ttp", "Company", "Context", "Stolen", "Sources", "Links", "Headline", "Tier", "FirstSeen"]
UTC = timezone.utc
I = re.IGNORECASE

# ---------------------------------------------------------------- helpers


def get_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=40) as r:
        return r.read().decode("utf-8", errors="replace")


def from_html(s: str | None) -> str:
    if not s:
        return ""
    s = re.sub(r"<br\s*/?>", " ", s, flags=I)
    s = re.sub(r"<[^>]+>", " ", s)
    s = html.unescape(s)
    s = re.sub(r"[\t\r\n]+", " ", s)
    return re.sub(r"\s{2,}", " ", s).strip()


def xml_text(el: ET.Element | None) -> str:
    return "" if el is None else "".join(el.itertext())


def to_utc(s: str | None) -> datetime | None:
    if not s:
        return None
    s = str(s).strip()
    d = None
    try:
        d = email.utils.parsedate_to_datetime(s)
    except (TypeError, ValueError, IndexError):
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    if d is None:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=UTC)
    return d.astimezone(UTC)


def get_id(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:12]


def norm_name(n: str) -> str:
    x = re.sub(r"\(.*?\)", " ", n.lower())
    x = re.sub(r"^(www\.)", "", x)
    x = re.sub(r"\.(com|net|org|edu|gov|io|co|co\.uk|org\.uk|ac\.uk|de|fr|it|es|nl|be|ch|at|pl|com\.br|com\.mx"
               r"|com\.au|ca|au|in|jp|cn|tw|kr|ar|cl|co\.za)$", "", x)
    x = re.sub(r"\b(inc|incorporated|ltd|limited|llc|llp|plc|gmbh|corp|corporation|company|co|s\.?a\.?|s\.?p\.?a"
               r"|b\.?v|n\.?v|ag|group|holdings?|the)\b\.?", " ", x)
    return re.sub(r"[^a-z0-9]", "", x)


def clean_name(n: str | None) -> str:
    n = re.sub(r"['’]s$", "", from_html(n), flags=I)
    n = re.sub(r"\s{2,}", " ", n)
    return n.strip(" -:,.|\"'")


STOP = re.compile(
    r"^(name upcoming|upcoming|unknown|redacted|n/?a|hackers?|ransomware|data|cyberattack|cyber attack|police|report"
    r"|new|a|an|the|us|uk|eu|government|threat actors?|cybercriminals|researchers|experts|this|how|why|what|major"
    r"|millions?|thousands|suspected|reported|alleged|popular|massive|fbi|cisa|ncsc|europol|interpol|doj|nsa|police"
    r"|russia|china|iran|north korea)$", I)


def bad_name(n: str | None) -> bool:
    if not n or len(n) < 2 or len(n) > 80:
        return True
    if re.search(r"\*|\?{2,}", n):  # masked victims
        return True
    return bool(STOP.search(n) or re.search(r"\b(actors?|hackers|nexus|gang)$", n, I))


# ---------------------------------------------------------------- classifiers
# (pattern, label, allowed on leak/darkweb claims)
TTP_RULES = [
    (r"ransomware|encrypt(ed|ion)? (files|systems|servers)|locker", "Ransomware [T1486]", True),
    (r"vish|voice phish|phone call|help ?desk|social[- ]engineer", "Vishing/help-desk social engineering [T1566.004]", False),
    (r"\bmfa (fatigue|bomb)|push (bombing|fatigue)", "MFA fatigue [T1621]", False),
    (r"phish", "Phishing [T1566]", False),
    (r"credential stuffing|password spray", "Credential stuffing [T1110.004]", False),
    (r"zero-?day|0-?day|exploit|vulnerab|\bflaw\b|CVE-\d{4}", "Exploited public-facing app [T1190]", True),
    (r"oauth|access token|salesforce|saas|snowflake|okta|cloud (tenant|instance)", "SaaS/token abuse [T1528]", False),
    (r"stolen credentials|compromised (credentials|account)|valid account|infostealer|leaked (credentials|passwords)",
     "Valid accounts [T1078]", False),
    (r"supply[- ]chain|third[- ]party|vendor|supplier|service provider|contractor",
     "Third-party/trusted relationship [T1199]", False),
    (r"misconfigur|unsecured|exposed (database|server|bucket|elasticsearch)|publicly accessible|open (s3|bucket|database)",
     "Exposed cloud data [T1530]", False),
    (r"\bddos\b|denial[- ]of[- ]service", "DDoS [T1498]", True),
    (r"defac", "Defacement [T1491.002]", True),
    (r"wiper|wiped|destroy(ed)? data", "Data destruction [T1485]", True),
    (r"crypto(currency)? (heist|theft)|drained|stole \$|\$[\d.,]+\s?(m|million|bn|billion) (stolen|in crypto)",
     "Financial theft [T1657]", False),
]
STOLEN_RULES = [
    (r"customer|client|member|user (data|accounts|records)|subscriber|shopper", "customer data"),
    (r"personal (data|information)|\bpii\b|identity|names?,? (address|email|phone|date of birth)"
     r"|contact (data|details|information)|date of birth|\bdob\b", "personal data (PII)"),
    (r"employee|staff|\bhr\b|human resources|payroll|payslip|personnel", "employee/HR data"),
    (r"patient|medical|health|\bphi\b|clinical", "health data"),
    (r"passport|national id|social security|\bssns?\b|driver.?s licen|citizen", "government IDs"),
    (r"bank|iban|financ|invoice|billing|accounting|bookkeeping|payment|credit card|card data|tax", "financial data"),
    (r"password|credential|login|hash", "credentials"),
    (r"source code|repositor|github|gitlab", "source code"),
    (r"mailbox|email (archive|correspondence|spool)|internal email", "mailboxes"),
    (r"contract|legal|\bnda\b|confidential (documents|files)|internal documents", "contracts/internal docs"),
    (r"student|enrol", "student records"),
    (r"wallet|crypto|funds", "funds/crypto"),
    (r"database|\bsql\b|backup", "databases/backups"),
]


def get_ttp(text: str, tier: str, group: str = "") -> str:
    claim = tier in ("leak", "darkweb")
    hits: list[str] = []
    for pat, label, leak_ok in TTP_RULES:
        if (not claim or leak_ok) and len(hits) < 2 and re.search(pat, text or "", I):
            hits.append(label)
    if not hits:
        hits.append({"leak": "Exfiltration + extortion [T1657]",
                     "darkweb": "Data theft, offered for sale/leak"}.get(tier, "not disclosed"))
    t = " + ".join(hits)
    return f"{t} - {group}" if group else t


def get_stolen(text: str, size: str = "") -> str:
    text = text or ""
    cats = [label for pat, label in STOLEN_RULES if re.search(pat, text, I)][:4]
    vol: list[str] = []
    if size:
        vol.append(size)
    m = re.search(r"(\d[\d.,]*)\s?(TB|TiB|GB|GiB)\b", text, I)
    if m and not size:
        vol.append(f"{m.group(1)} {m.group(2).upper()}")
    m = re.search(r"(\d[\d.,]*\s?(million|billion|m\b|k\b|thousand)?)\s+(records|rows|customers|users|individuals"
                  r"|people|patients|accounts|employees|members|students|citizens)", text, I)
    if m:
        vol.append(f"{m.group(1).strip()} {m.group(3).lower()}")
    if not cats and not vol:
        return "not disclosed"
    if not cats:
        cats = ["data"]
    return ", ".join(cats) + (f" ({', '.join(vol)})" if vol else "")


CONFIRM_RE = re.compile(
    r"\b(confirm(s|ed)?|disclos(es|ed)|notif(y|ies|ying|ied)|acknowledg|admits|8-K|sec filing|regulatory filing"
    r"|says it (was|has been|is) (hit|investigating|responding)|is investigating"
    r"|investigating (a |an |the )?(breach|cyber|incident|attack|data|security|ransomware|hack)"
    r"|detected (unauthori|suspicious)|warns (customers|users)|statement)\b", I)
CLAIM_RE = re.compile(r"\b(claim(s|ed)?|alleged(ly)?|purported(ly)?)\b", I)


def news_status(text: str, tier: str) -> str:
    if tier == "filing":
        return "CONFIRMED"
    if tier in ("leak", "darkweb"):
        return "CLAIMED"
    if CONFIRM_RE.search(text):
        return "CONFIRMED"
    if CLAIM_RE.search(text):
        return "CLAIMED"
    return "REPORTED"


INCLUDE_RE = re.compile(
    r"\b(breach(ed|es)?|hack(ed|ers? (hit|breach|steal|stole|target|claim))|cyber-?attack|ransomware (attack|gang|group)"
    r"|data (leak|theft|exposure|stolen)|stolen (data|records|information|files|credentials|funds|crypto|customer"
    r"|personal|patient)|(data|records|information|files|funds) (were |was )?stolen|stole|compromised|extort"
    r"|intrusion|unauthori[sz]ed access|leak(ed|s)?|exfiltrat|ddos|defaced|cyber ?incident|security incident)\b", I)
EXCLUDE_RE = re.compile(
    r"\b(arrest(ed)?|sentenced|charged|extradit|pleads?|guilty|indicted|convicted|jailed|prison|webinar|podcast"
    r"|how to|tips|funding|raises|acquires|acquisition|launches|patch(es|ed)?|update now|fixes|proof-of-concept|poc"
    r"|survey|study|week in review|roundup|sponsored|top \d+|best|explained|opinion|analysis:|interview"
    r"|malware analysis|new malware|botnet|campaign targets|apt\d*|nation-state|denies|blames|attributes)\b", I)

_W = r"[\w&'’.\-]"
_NAME = rf"(?P<c>[A-Z0-9]{_W}*(?:\s+(?:[A-Z0-9&]{_W}*|of|and|de|du|la|for)){{0,5}}?)"
_NAME2 = rf"(?P<c>[A-Z0-9]{_W}*(?:\s+(?:[A-Z0-9&]{_W}*|of|and|de|for)){{0,5}}?)"
CO_PATTERNS = [
    re.compile(
        rf"^{_NAME}\s+(?i:confirms|confirmed|discloses|says|suffers|hit by|hacked|reports|notifies|notifying"
        r"|is investigating|investigating|investigates|warns|falls victim|data breach|data leak|data exposure"
        r"|cyberattack|cyber-attack|cyber attack|cyber incident|ransomware attack|security incident|breach|was hacked"
        r"|struck by|targeted by|attacked|probes|shuts|takes systems offline|server outage|outage|systems down"
        r"|withholds|links)\b"),
    re.compile(
        rf"(?i:attack|cyberattack|cyber-attack|breach|hack|intrusion|incident|leak)\s+(?i:on|at|of|hits?|targeting"
        rf"|affecting|impacting)\s+{_NAME2}(?=\s+(?i:exposes|leaks|impacts|affects|hits|disrupts|compromises|may"
        r"|could|leaves|led|forces|sees|puts|knocks|takes|causes)\b|[,:;]|\s+-\s|$)"),
    re.compile(
        rf"\b(?i:hackers?|ransomware (?:gang|group)|threat actors?|cybercriminals|extortionists)\s+(?i:hit|hits|breach"
        rf"|breached|target|targets|targeted|steal from|stole from|attack|attacked|claims? (?:attack|breach) on|claim"
        rf"|claims|compromise[sd]?)\s+{_NAME2}(?=[,:;]|\s+(?i:and|in|to|data|systems|network|customers|employees"
        r"|with|after|over)\b|\s+-\s|$)"),
]


def get_company(title: str) -> str | None:
    t = re.sub(r"\s+[-|]\s+(Reuters|AP News|The Associated Press|AP|BBC News|The Guardian)$", "", title, flags=I)
    t = re.sub(r"^[A-Z]{2}:\s+", "", t, flags=I)
    t = re.sub(r"^[^\w]+", "", t).strip()
    for pat in CO_PATTERNS:
        m = pat.search(t)
        if m:
            c = clean_name(m.group("c"))
            c = re.sub(r"^(US|UK|EU|Japanese|German|French|British|American|Australian|Canadian|Indian|Dutch|Italian"
                       r"|Spanish|Korean|Chinese)\s+(?=\S+\s+\S)", "", c, flags=I)
            c = re.sub(r"^.*?\b(Giant|Firm|Maker|Provider|Retailer|Operator|Chain|Insurer|Startup|Platform|Company)\s+"
                       r"(?=[A-Z0-9])", "", c, flags=I)
            if not bad_name(c):
                return c
    return None


# ---------------------------------------------------------------- collectors


class Collector:
    def __init__(self, since: datetime, now: datetime):
        self.since, self.now = since, now
        self.items: list[dict] = []

    def add(self, date, status, ttp, company, context, stolen, source, link, headline, tier):
        if not date or date < self.since:
            return
        self.items.append({
            "Date": date.strftime("%Y-%m-%d"), "Status": status, "Ttp": ttp, "Company": company,
            "Context": context or "", "Stolen": stolen, "Sources": source, "Links": link or "",
            "Headline": (headline or "").replace("\t", " "), "Tier": tier,
        })

    # dark web: ransomware leak-site trackers
    def ransomwarelive(self, s):
        for v in json.loads(get_text(s["url"])):
            victim = str(v.get("victim") or "")
            recs = re.search(r"\s+-\s+([\d.,]+\s*(million\s+)?records)\s*$", victim, I)
            name = clean_name(re.sub(r"\s+-\s+[\d.,]+\s*(million\s+)?records\s*$", "", victim, flags=I))
            if bad_name(name):
                continue
            d = to_utc(v.get("discovered")) or to_utc(v.get("attackdate"))
            ctx = [x for x in (v.get("country"),) if x]
            if v.get("activity") and v.get("activity") != "Not Found":
                ctx.append(v["activity"])
            txt = f"{v.get('description') or ''} {recs.group(1) if recs else ''}"
            size = "" if v.get("data_size") in (None, "") else str(v["data_size"])
            self.add(d, "CLAIMED", get_ttp(txt, "leak", v.get("group") or ""), name, ", ".join(ctx),
                     get_stolen(txt, size), s["name"], v.get("url"), name, "leak")

    def ransomlook(self, s):
        for v in json.loads(get_text(s["url"])):
            name = clean_name(re.sub(r"\s*\(.*$", "", v.get("post_title") or ""))
            if bad_name(name):
                continue
            txt = v.get("description") or ""
            m = re.search(r"size:\s*([\d.,]+\s?[KMGT]i?B)", txt, I)
            group = v.get("group_name") or ""
            link = "https://www.ransomlook.io/group/" + urllib.parse.quote(group, safe="")
            self.add(to_utc(v.get("discovered")), "CLAIMED", get_ttp(txt, "leak", group), name, "",
                     get_stolen(txt, m.group(1) if m else ""), s["name"], link, name, "leak")

    # dark web: forum monitor
    def dwi(self, s):
        root = ET.fromstring(get_text(s["url"]))
        for it in root.iter("item"):
            title = from_html(xml_text(it.find("title")))
            m = re.search(r"^(?P<c>.+?)\s+(?:Database Sale|Data Sale|Data Leak|Database Leak|Breach|Access Sale|Leak"
                          r"|Data Breach)\s+Claim", title)
            if not m:
                continue
            name = clean_name(m.group("c"))
            if bad_name(name):
                continue
            self.add(to_utc(xml_text(it.find("pubDate"))), "CLAIMED", get_ttp(title, "darkweb"), name, "",
                     get_stolen(title), s["name"], xml_text(it.find("link")), title, "darkweb")

    # Telegram public channel previews
    @staticmethod
    def tg_messages(s) -> list[dict]:
        out = []
        for b in get_text(s["url"]).split("tgme_widget_message_wrap")[1:]:
            tm = re.search(r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', b, re.S)
            dm = re.search(r'<time datetime="([^"]+)"', b)
            pm = re.search(r'data-post="([^"]+)"', b)
            if tm and dm:
                raw = tm.group(1)
                out.append({"text": from_html(raw), "title": from_html(re.split(r"<br\s*/?>", raw, flags=I)[0]),
                            "date": to_utc(dm.group(1)),
                            "link": f"https://t.me/{pm.group(1)}" if pm else s["url"]})
        return out

    def tg_ransomfeed(self, s):
        # "ID: n  <warn> date  <ninja> GROUP  <target> Victim, Country  <link> url"
        pat = re.compile("\U0001F977\\s*(?P<g>.+?)\\s*\U0001F3AF\\s*(?P<v>.+?)\\s*\U0001F517")
        for msg in self.tg_messages(s):
            m = pat.search(msg["text"])
            if not m:
                continue
            v = re.sub(r"\s+AND\s+", " & ", m.group("v"), flags=I)
            ctry = ""
            cm = re.search(r"^(?P<n>.+),\s*(?P<c>[^,]{2,30})$", v)
            if cm:
                v, ctry = cm.group("n"), cm.group("c")
            name = clean_name(v)
            if bad_name(name):
                continue
            self.add(msg["date"], "CLAIMED", get_ttp("", "leak", m.group("g").strip()), name, ctry, "not disclosed",
                     s["name"], msg["link"], name, "leak")

    def news_item(self, s, title, desc, date, link):
        title, desc = from_html(title), from_html(desc)
        if not INCLUDE_RE.search(title) or EXCLUDE_RE.search(title):
            return
        text = f"{title}. {desc}"
        co = get_company(title) or "?"
        self.add(date, news_status(text, s["tier"]), get_ttp(text, s["tier"]), co, "", get_stolen(text),
                 s["name"], link, title, s["tier"])

    def tg_news(self, s):
        for msg in self.tg_messages(s):
            self.news_item(s, msg["title"], msg["text"], msg["date"], msg["link"])

    def rss(self, s):
        root = ET.fromstring(get_text(s["url"]))
        if root.tag == "rss":
            for it in root.iter("item"):
                self.news_item(s, xml_text(it.find("title")), xml_text(it.find("description")),
                               to_utc(xml_text(it.find("pubDate"))), xml_text(it.find("link")))
        elif root.tag.endswith("feed"):
            ns = {"a": root.tag[1:].split("}")[0]} if root.tag.startswith("{") else {"a": ""}
            q = (lambda t: f"a:{t}") if ns["a"] else (lambda t: t)
            for e in root.findall(q("entry"), ns):
                href = ""
                for ln in e.findall(q("link"), ns):
                    if ln.get("rel") in (None, "", "alternate"):
                        href = ln.get("href", "")
                        break
                d = to_utc(xml_text(e.find(q("published"), ns))) or to_utc(xml_text(e.find(q("updated"), ns)))
                self.news_item(s, xml_text(e.find(q("title"), ns)), xml_text(e.find(q("summary"), ns)), d, href)

    # regulator: SEC 8-K Item 1.05
    def sec(self, s):
        q = (f"{s['url']}?q=%22Item%201.05%22&forms=8-K,8-K/A&dateRange=custom"
             f"&startdt={(self.since - timedelta(days=1)):%Y-%m-%d}&enddt={self.now:%Y-%m-%d}")
        for h in json.loads(get_text(q)).get("hits", {}).get("hits", []):
            src = h.get("_source", {})
            name = clean_name(re.sub(r"\s*\(.*$", "", (src.get("display_names") or [""])[0]))
            if bad_name(name):
                continue
            cik = int((src.get("ciks") or ["0"])[0])
            file = h.get("_id", ":").split(":", 1)[1]
            link = f"https://www.sec.gov/Archives/edgar/data/{cik}/{src.get('adsh', '').replace('-', '')}/{file}"
            ctx = "US-" + src["biz_states"][0] if src.get("biz_states") else "US"
            self.add(to_utc(src.get("file_date")), "CONFIRMED", "not disclosed (see 8-K)", name, ctx,
                     "not disclosed (see 8-K)", s["name"], link, f"{name} 8-K Item 1.05", "filing")


READERS = {"ransomwarelive": "ransomwarelive", "ransomlook": "ransomlook", "dwi": "dwi",
           "tg-ransomfeed": "tg_ransomfeed", "tg-news": "tg_news", "rss": "rss", "sec": "sec"}

# ---------------------------------------------------------------- merge


def split_stolen(s: str) -> tuple[list[str], list[str]]:
    if not s or s.startswith("not disclosed"):
        return [], []
    m = re.match(r"^(?P<c>.*?)(?:\s\((?P<v>.*)\))?$", s)
    cats = [c for c in re.split(r",\s*", m.group("c")) if c and c != "data"]
    vols = [v for v in re.split(r"(?<=[A-Za-z]),\s", m.group("v"))] if m.group("v") is not None else []
    return cats, [v for v in vols if v]


def unique(xs):
    return list(OrderedDict.fromkeys(xs))


def merge_stolen(a: str, b: str) -> str:
    if not b or b.startswith("not disclosed"):
        return a
    if not a or a.startswith("not disclosed"):
        return b
    (ca, va), (cb, vb) = split_stolen(a), split_stolen(b)
    c = unique(ca + cb)[:5] or ["data"]
    v = unique(va + vb)[:3]
    return ", ".join(c) + (f" ({', '.join(v)})" if v else "")


def fmt_md(s: str) -> str:
    return re.sub(r"([\\`*_\[\]<>])", r"\\\1", (s or "").replace("|", "/"))


# ---------------------------------------------------------------- main


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--days", type=int, default=3, help="look-back window per run (default 3)")
    ap.add_argument("--keep-days", type=int, default=14, help="days shown in breach-wire.md (default 14)")
    ap.add_argument("--no-claims", action="store_true", help="leave CLAIMED items out of breach-wire.md")
    args = ap.parse_args()

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    log: list[str] = []

    def write_log(m: str):
        log.append(f"{datetime.now(UTC):%Y-%m-%d %H:%M:%S}Z {m}")

    col = Collector(now - timedelta(days=args.days), now)
    cfg = json.loads(CFG_FILE.read_text(encoding="utf-8-sig"))
    for s in (x for x in cfg["sources"] if x.get("enabled")):
        before = len(col.items)
        try:
            reader = READERS.get(s["type"])
            if not reader:
                raise ValueError(f"unknown source type '{s['type']}'")
            getattr(col, reader)(s)
            write_log(f"ok   {s['name']:<26} +{len(col.items) - before}")
        except Exception as e:  # one broken source must not stop the feed
            write_log(f"FAIL {s['name']:<26} {type(e).__name__}: {e}")

    store: dict[str, dict] = {}
    if STORE_FILE.exists():
        with STORE_FILE.open(encoding="utf-8-sig", newline="") as f:
            for r in csv.DictReader(f, delimiter="\t"):
                store[r["Id"]] = {k: r.get(k) or "" for k in FIELDS}

    # news items without a parsed company: match against known victim names (store + this run)
    known: dict[str, str] = {}
    for r in list(store.values()) + col.items:
        if r["Company"] and r["Company"] != "?":
            n = norm_name(r["Company"])
            if len(n) >= 5 and n not in known:
                known[n] = r["Company"]
    for it in (x for x in col.items if x["Company"] == "?"):
        h = " " + re.sub(r"[^a-z0-9]+", " ", it["Headline"].lower()) + " "
        for name in known.values():
            words = re.sub(r"[^a-z0-9]+", " ", name.lower()).strip()
            if len(words) >= 5 and f" {words} " in h:
                it["Company"] = name
                break

    added = 0
    for it in col.items:
        key = norm_name(it["Company"]) if it["Company"] != "?" else "h:" + norm_name(it["Headline"])
        if not key:
            continue
        lane = "CLAIMED" if it["Status"] == "CLAIMED" else "NEWS"
        rid = get_id(f"{key}|{lane}")
        e = store.get(rid)
        if e:
            srcs, lnks = e["Sources"].split("; "), e["Links"].split(" ")
            if it["Sources"].lower() not in (x.lower() for x in srcs):
                e["Sources"] = "; ".join(srcs + [it["Sources"]])
                e["Links"] = " ".join(lnks + [it["Links"]])
            if it["Status"] == "CONFIRMED" and e["Status"] == "REPORTED":
                e["Status"] = "CONFIRMED"
            e["Stolen"] = merge_stolen(e["Stolen"], it["Stolen"])
            if e["Ttp"].startswith("not disclosed") and not it["Ttp"].startswith("not disclosed"):
                e["Ttp"] = it["Ttp"]
            if e["Ttp"].startswith("Exfiltration + extortion") and it["Ttp"].startswith("Ransomware"):
                e["Ttp"] = it["Ttp"]
            if not e["Context"] and it["Context"]:
                e["Context"] = it["Context"]
            if it["Date"] < e["Date"]:
                e["Date"] = it["Date"]
        else:
            store[rid] = {"Id": rid, **it, "FirstSeen": f"{now:%Y-%m-%d %H:%M:%S}Z"}
            added += 1

    cut = f"{now - timedelta(days=60):%Y-%m-%d}"
    rows = sorted((r for r in store.values() if r["Date"] >= cut),
                  key=lambda r: (r["Date"], r["Status"], r["Company"].casefold()), reverse=True)
    with STORE_FILE.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, delimiter="\t", quoting=csv.QUOTE_ALL, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)

    # ------------------------------------------------------------ render markdown
    rank = {"CONFIRMED": 0, "REPORTED": 1, "CLAIMED": 2}
    show_cut = f"{now - timedelta(days=args.keep_days):%Y-%m-%d}"
    show = [r for r in rows if r["Date"] >= show_cut and not (args.no_claims and r["Status"] == "CLAIMED")]
    cnt = {k: sum(1 for r in show if r["Status"] == k) for k in rank}

    out = [
        "# Breach Wire", "",
        "One line per incident: **date | status | TTP | company | what was stolen | sources**.", "",
        f"Last run **{now:%Y-%m-%d %H:%M} UTC** - last {args.keep_days} days - {cnt['CONFIRMED']} confirmed, "
        f"{cnt['REPORTED']} reported, {cnt['CLAIMED']} claimed", "",
        "| Status | Meaning |", "|---|---|",
        "| **CONFIRMED** | Victim, regulator or filing (e.g. SEC 8-K Item 1.05) acknowledges the incident |",
        "| **REPORTED** | Credible press reports it; the victim has not confirmed yet |",
        "| CLAIMED | Ransomware leak site, dark-web forum or Telegram claim. Unverified; groups exaggerate and re-post |",
        "",
        'TTPs are MITRE ATT&CK Enterprise IDs inferred from headline and claim text: triage hints, not attribution. '
        '"What was stolen" lists data categories and volumes only; no leaked values are copied here. '
        '`?` = company not parsed from the headline; follow the source.',
        "",
    ]
    for day in sorted({r["Date"] for r in show}, reverse=True):
        group = [r for r in show if r["Date"] == day]
        out += [f"## {day}", ""]
        last = None
        for r in sorted(group, key=lambda r: (rank.get(r["Status"], 3), r["Company"].casefold(),
                                              r["Headline"].casefold())):
            if r["Status"] == "CLAIMED" and last != "CLAIMED":
                n = sum(1 for x in group if x["Status"] == "CLAIMED")
                out += ["", f"<details><summary>Claimed on leak sites / dark web / Telegram ({n})</summary>", ""]
            last = r["Status"]
            st = "CLAIMED" if r["Status"] == "CLAIMED" else f"**{r['Status']}**"
            co = f'? "{fmt_md(r["Headline"])}"' if r["Company"] == "?" else f"**{fmt_md(r['Company'])}**"
            if r["Context"]:
                co += f" ({fmt_md(r['Context'])})"
            names, links = r["Sources"].split("; "), r["Links"].split(" ")
            via = []
            for k, nm in enumerate(names):
                u = links[k] if k < len(links) else ""
                via.append(f"[{nm}]({u})" if re.match(r"^https?://", u) and ".onion" not in u else nm)
            out.append(f"- {r['Date']} | {st} | {fmt_md(r['Ttp'])} | {co} | Stolen: {fmt_md(r['Stolen'])} | "
                       f"via {', '.join(via)}")
        if last == "CLAIMED":
            out += ["", "</details>"]
        out.append("")
    OUT_FILE.write_text("\n".join(out) + "\n", encoding="utf-8")

    write_log(f"done: {len(col.items)} collected, {added} new, {len(rows)} in store, {len(show)} shown")
    old = LOG_FILE.read_text(encoding="utf-8-sig").splitlines()[-400:] if LOG_FILE.exists() else []
    LOG_FILE.write_text("\n".join(old + log) + "\n", encoding="utf-8")
    print("\n".join(log))
    return 0


if __name__ == "__main__":
    sys.exit(main())
