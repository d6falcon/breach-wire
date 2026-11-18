#!/usr/bin/env python3
"""vuln-wire: one line per notable vulnerability from the last 30 days, written to vuln-wire.md.

    DATE | STATUS | CVE | NAME (nickname: vendor product, type) | TTP [ATT&CK] | Fix | via sources

STATUS
    EXPLOITED   in CISA KEV, or a source reports exploitation in the wild
    ZERO-DAY    disclosed before a patch existed (ZDI "0Day", or reported as a zero-day)
    CRITICAL / HIGH   severity from the advisory (GitHub Advisory critical, vendor severity or CVSS)

Sources live in vuln-sources.json: CISA KEV, GitHub Advisory Database (critical), research blogs (Wiz,
watchTowr, Rapid7, Unit 42, Tenable), vendor PSIRTs (Cisco, Fortinet, Palo Alto), ZDI zero-days and the
security press. Enriched with FIRST EPSS scores and, when the product is unknown, the CVE record.

Observations are kept in state/vuln-wire.json for 30 days (press feeds only carry a few days) and merged by
CVE or nickname on every run. TTPs are inferred from the vulnerability type: triage hints, not attribution.

Standard library only. Python 3.11+.

    python3 scripts/vuln_wire.py
    python3 scripts/vuln_wire.py --days 14
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from breach_wire import UA, fmt_md, from_html, get_text, to_utc, xml_text  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CFG_FILE = ROOT / "vuln-sources.json"
STATE_FILE = ROOT / "state" / "vuln-wire.json"
LOG_FILE = ROOT / "state" / "run.log"
OUT_FILE = ROOT / "vuln-wire.md"
UTC = timezone.utc
I = re.IGNORECASE

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", I)
NICK_RE = re.compile(r"\b([A-Z][A-Za-z]*\d*(?:Shell|Bleed|Hammer|Jack|Doom|Pwn|Storm|Spill|Bomb|Ghost)|"
                     r"[A-Z][a-z]+\d[A-Z][a-z]+)\b")
DUBBED_RE = re.compile(r"\b(?:dubbed|codenamed|nicknamed|named|called)\s+[\"'“‘]?([A-Z][\w-]{2,30})")
NICK_STOP = {"powershell", "webshell", "shell", "secureshell", "reverseshell", "openshell", "bashshell", "cloudshell"}
EXPLOITED_RE = re.compile(r"actively exploited|exploited in the wild|under (active )?exploitation|in-the-wild exploitation"
                          r"|exploitation (has been )?(detected|observed)|exploited as a zero-day|zero-day attacks?", I)
ZERODAY_RE = re.compile(r"\(0day\)|\bzero[- ]day\b|\b0[- ]?day\b", I)

# vulnerability type: first match wins
TYPES = [
    (r"deserial", "deserialisation"),
    (r"command injection|os command", "command injection"),
    (r"code injection|template injection|\bssti\b|expression language injection", "code injection"),
    (r"sql injection|\bsqli\b", "SQL injection"),
    (r"path traversal|directory traversal|\.\./|link following", "path traversal"),
    (r"\bssrf\b|server-side request forgery", "SSRF"),
    (r"auth(entication)? bypass|authori[sz]ation bypass|missing authentication|improper authentication"
     r"|unauthenticated access", "auth bypass"),
    (r"privilege escalation|elevation of privilege|\beop\b", "privilege escalation"),
    (r"remote code execution|\brce\b|arbitrary code|code execution", "RCE"),
    (r"use[- ]after[- ]free|buffer overflow|out-of-bounds|heap overflow|memory corruption|integer (overflow|underflow)"
     r"|type confusion", "memory corruption"),
    (r"cross[- ]site scripting|\bxss\b", "XSS"),
    (r"denial[- ]of[- ]service|\bdos\b", "DoS"),
    (r"security feature bypass|mark of the web|smartscreen", "security feature bypass"),
    (r"information disclosure|sensitive information|memory leak|\bleak", "info disclosure"),
    (r"spoofing", "spoofing"),
]
CLIENT_RE = re.compile(r"browser|chrome|chromium|firefox|safari|webkit|microsoft office|\bword\b|excel|outlook|acrobat"
                       r"|reader|user (opens|visits)|malicious (file|document|link)|crafted (file|document)|7-zip|winrar", I)


def get_ttp(vtype: str, text: str) -> str:
    if vtype == "privilege escalation":
        return "Exploitation for privilege escalation [T1068]"
    if vtype == "DoS":
        return "Application or system exploitation (DoS) [T1499.004]"
    if vtype == "security feature bypass":
        return "Exploitation for stealth [T1211]"
    if vtype == "spoofing" and re.search(r"ntlm", text, I):
        return "Forced authentication [T1187]"
    if vtype in ("RCE", "memory corruption", "code injection", "XSS") and CLIENT_RE.search(text):
        return "Exploitation for client execution [T1203]"
    if re.search(r"\badjacent\b|lateral movement|\bsmb\b|internal network", text, I):
        return "Exploitation of remote services [T1210]"
    return "Exploit public-facing application [T1190]"


def default_fix(vtype: str, ttp: str, text: str) -> str:
    """Mitigation step when the sources give no fixed version."""
    if vtype == "spoofing" and re.search(r"ntlm", text, I):
        return "apply vendor patch; block outbound SMB/NTLM and enforce SMB signing"
    if vtype == "auth bypass":
        return "apply vendor patch; restrict the management interface to trusted networks, then rotate sessions and credentials"
    if "T1203" in ttp:
        return "update the client; block untrusted files and links until patched"
    if "T1068" in ttp:
        return "apply vendor patch; limit local logon and watch for privilege escalation"
    if "T1211" in ttp:
        return "apply vendor patch; keep compensating controls (MotW, SmartScreen, EDR) enforced"
    if "T1499" in ttp:
        return "apply vendor patch; rate-limit or filter the service at the edge"
    return "apply vendor patch; until then remove internet exposure (allow-list or VPN) and check for compromise"


def find_nick(text: str) -> str:
    for m in list(NICK_RE.finditer(text)) + list(DUBBED_RE.finditer(text)):
        n = m.group(1)
        if n.lower() not in NICK_STOP and not CVE_RE.match(n):
            return n
    return ""


def find_fix(text: str) -> list[str]:
    out = []
    for m in re.finditer(r"(?:fixed in|upgrade to|update to|patched in|upgrading to|updated to|resolved in)\s+"
                         r"(?:version\s+|v)?(\d+(?:\.\d+){1,3}[\w.-]*)", text, I):
        v = m.group(1).rstrip(".-")
        if v not in out:
            out.append(v)
    return out[:3]


def severity(text: str) -> str:
    m = re.search(r"severity:\s*(critical|high|medium|low)", text, I)
    if m:
        return m.group(1).upper()
    m = re.search(r"CVSS(?:v\d(?:\.\d)?)?(?:\s*(?:base\s*)?score)?\s*[:of]*\s*(\d{1,2}\.\d)", text, I)
    if m:
        s = float(m.group(1))
        return "CRITICAL" if s >= 9 else "HIGH" if s >= 7 else "MEDIUM"
    return "CRITICAL" if re.search(r"\bcritical\b", text, I) else ""


def join_vendor(vendor: str, product: str) -> str:
    """'Apache Software Foundation' + 'Apache Axis' -> 'Apache Axis'; 'Perforce' + 'Puppet' -> 'Perforce Puppet'."""
    vendor = "" if vendor.strip().lower() in ("", "n/a") else vendor.strip()
    product = "" if product.strip().lower() in ("", "n/a") else product.strip()
    if not vendor or not product:
        return vendor or product
    return product if product.lower().startswith(vendor.split()[0].lower()) else f"{vendor} {product}"


def short_title(title: str) -> str:
    t = re.sub(r"^ZDI-\d+-\d+:\s*(\(0Day\)\s*)?", "", title, flags=I)
    t = re.sub(r"^(CVE-\d{4}-\d+[\s:,/]*)+", "", t, flags=I)
    t = re.sub(r"\s+Vulnerabilit(y|ies)\b.*$", "", t, flags=I).strip(" :-")
    return t[:90]


def http_json(url: str, token: str = "") -> tuple[object, str]:
    """GET JSON; also return the rel="next" link (GitHub pagination)."""
    h = {"User-Agent": UA, "Accept": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=40) as r:
        nxt = re.search(r'<([^>]+)>;\s*rel="next"', r.headers.get("Link", "") or "")
        return json.loads(r.read().decode("utf-8")), (nxt.group(1) if nxt else "")


# ---------------------------------------------------------------- collectors


def obs(src, date, title, text, link, *, cves=None, nick="", product="", fix="", sev="", zeroday=False,
        exploited=False, kev=None, extra_link=""):
    blob = f"{title} {text}"
    return {
        "src": src, "date": date, "title": title, "text": text[:800], "link": link or "",
        "cves": cves if cves is not None else list(dict.fromkeys(c.upper() for c in CVE_RE.findall(blob))),
        "nick": nick or find_nick(blob), "product": product, "fix": fix, "sev": sev or severity(blob),
        "zeroday": zeroday or bool(ZERODAY_RE.search(title)), "exploited": exploited or bool(EXPLOITED_RE.search(blob)),
        "kev": kev, "extra_link": extra_link,
    }


def read_kev(s, since):
    out = []
    for v in json.loads(get_text(s["url"]))["vulnerabilities"]:
        if v.get("dateAdded", "") < since:
            continue
        product = join_vendor(v.get("vendorProject", ""), v.get("product", ""))
        cve = v["cveID"].upper()
        adv = re.search(r"https?://\S+", v.get("notes", "") or "")
        out.append(obs(s["name"], v["dateAdded"], v.get("vulnerabilityName", ""), v.get("shortDescription", ""),
                       f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}",
                       cves=[cve], product=product, exploited=True,
                       kev={"due": v.get("dueDate", ""), "ransomware": v.get("knownRansomwareCampaignUse") == "Known"},
                       extra_link=adv.group(0).rstrip(";,") if adv else ""))
    return out


def read_ghsa(s, since):
    out, token = [], os.environ.get("GITHUB_TOKEN", "")
    url = (f"{s['url']}?type=reviewed&severity=critical&per_page=100&sort=published&direction=desc"
           f"&published={urllib.parse.quote('>=' + since)}")
    for _ in range(5):
        data, url = http_json(url, token)
        for a in data:
            pkgs = [v for v in a.get("vulnerabilities") or [] if v.get("package")]
            product = ", ".join(dict.fromkeys(f"{p['package']['ecosystem']}/{p['package']['name']}" for p in pkgs[:2]))
            fixes = [f"upgrade {p['package']['name']} to {p['first_patched_version']}" for p in pkgs[:2]
                     if p.get("first_patched_version")]
            fix = "; ".join(dict.fromkeys(fixes)) or "no patched version yet"
            cwes = " ".join(c.get("name", "") for c in a.get("cwes") or [])
            cves = [a["cve_id"].upper()] if a.get("cve_id") else [a["ghsa_id"]]
            out.append(obs(s["name"], (a.get("published_at") or "")[:10], a.get("summary", ""),
                           f"{a.get('description', '')} {cwes}", a.get("html_url", ""),
                           cves=cves, product=product, fix=fix, sev="CRITICAL"))
        if not url:
            break
    return out


def read_rss(s, since):
    root = ET.fromstring(get_text(s["url"]))
    entries = []
    if root.tag == "rss" or root.find("channel") is not None:
        for it in root.iter("item"):
            entries.append((xml_text(it.find("title")), xml_text(it.find("description")),
                            xml_text(it.find("pubDate")), xml_text(it.find("link"))))
    else:  # Atom
        ns = {"a": root.tag[1:].split("}")[0]} if root.tag.startswith("{") else None
        q = (lambda t: f"a:{t}") if ns else (lambda t: t)
        for e in root.findall(q("entry"), ns):
            ln = next((x.get("href", "") for x in e.findall(q("link"), ns) if x.get("rel") in (None, "alternate")), "")
            d = xml_text(e.find(q("published"), ns)) or xml_text(e.find(q("updated"), ns))
            entries.append((xml_text(e.find(q("title"), ns)), xml_text(e.find(q("summary"), ns)), d, ln))
    out, flt = [], s.get("filter", "cve")
    for title, desc, date, link in entries:
        d = to_utc(date)
        if not d or f"{d:%Y-%m-%d}" < since:
            continue
        title, desc = from_html(title), from_html(desc)
        t_cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(title)))
        d_cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(desc)))
        # title CVEs identify the item; body CVEs often list older, related bugs, so only the first two count
        o = obs(s["name"], f"{d:%Y-%m-%d}", title, desc, link, cves=t_cves or d_cves[:2])
        t_nick = find_nick(title)
        o["nick"] = t_nick  # body text often name-drops older bugs ("like Log4Shell"); trust the title only
        if flt == "zdi0day":
            cvss = re.search(r"CVSS rating of (\d+(?:\.\d)?)", desc, I)
            if "(0day)" not in title.lower() or not cvss or float(cvss.group(1)) < 9.0:
                continue
            m = re.match(r"(ZDI-\d+-\d+):\s*\(0Day\)\s*(.*)", title, I)
            if not o["cves"] and m:
                o["cves"] = [m.group(1)]
            o["zeroday"] = True
            o["fix"] = "no patch at disclosure: restrict access, apply vendor guidance"
        elif flt == "severity":
            if o["sev"] not in ("CRITICAL", "HIGH") and not (o["exploited"] or o["nick"] or o["zeroday"]):
                continue
        elif not (t_cves or t_nick or o["zeroday"] or (o["exploited"] and o["cves"])):
            continue
        if not o["cves"] and not o["nick"]:
            continue
        pm = re.match(r"CVE-\d{4}-\d+\s+([^:]{2,40}):", title)  # Palo Alto: "CVE-x PAN-OS: ..."
        if pm and s["name"] == "Palo Alto":
            o["product"] = "Palo Alto " + pm.group(1).strip()
        o["fix"] = o["fix"] or ("upgrade to " + " / ".join(find_fix(desc)) if find_fix(desc) else "")
        out.append(o)
    return out


READERS = {"kev": read_kev, "ghsa": read_ghsa, "rss": read_rss}

# ---------------------------------------------------------------- merge


def build_entries(observations: list[dict]) -> list[dict]:
    entries: list[dict] = []
    index: dict[str, int] = {}

    def keys(o):
        ks = [c.upper() for c in o["cves"]]
        if o["nick"]:
            ks.append("nick:" + o["nick"].lower())
        return ks or ["link:" + (o["link"] or o["title"])]

    for o in sorted(observations, key=lambda x: (x["src"] != "CISA KEV", x["src"] != "GitHub Advisory", x["date"])):
        ks = keys(o)
        hits = sorted({index[k] for k in ks if k in index})
        if hits:
            tgt = hits[0]
            for h in hits[1:]:  # an observation that bridges two entries merges them
                entries[tgt]["obs"] += entries[h]["obs"]
                entries[h]["obs"] = []
                for k, v in list(index.items()):
                    if v == h:
                        index[k] = tgt
        else:
            tgt = len(entries)
            entries.append({"obs": []})
        entries[tgt]["obs"].append(o)
        for k in ks:
            index[k] = tgt
    return [e for e in entries if e["obs"]]


def summarise(e: dict, cve_cache: dict, epss: dict) -> dict:
    ob = e["obs"]
    cves = list(dict.fromkeys(c for o in ob for c in o["cves"]))
    nick = next((o["nick"] for o in ob if o["nick"]), "")
    product = next((o["product"] for o in ob if o["product"] and o["src"] in ("CISA KEV", "GitHub Advisory")), "") \
        or next((o["product"] for o in ob if o["product"]), "")
    info = next((cve_cache[c] for c in cves if c in cve_cache), {})
    product = product or info.get("product", "")
    text = " ".join(f"{o['title']} {o['text']}" for o in ob) + " " + info.get("title", "")
    vtype = next((label for pat, label in TYPES if re.search(pat, text, I)), "")
    kev = next((o["kev"] for o in ob if o.get("kev")), None)
    exploited = any(o["exploited"] for o in ob)
    zeroday = any(o["zeroday"] for o in ob)
    sevs = [o["sev"] for o in ob if o["sev"]]
    sev = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if s in sevs), "")

    fix = next((o["fix"] for o in ob if o["src"] == "GitHub Advisory" and o["fix"]), "") \
        or next((o["fix"] for o in ob if o["fix"] and not o["fix"].startswith("no patch")), "")
    if not fix:
        vers = list(dict.fromkeys(v for o in ob for v in find_fix(o["text"])))[:3]
        fix = ("upgrade to " + " / ".join(vers)) if vers else ""
    ttp = get_ttp(vtype, text)
    if not fix:
        fix = next((o["fix"] for o in ob if o["fix"]), "") or default_fix(vtype, ttp, text)
    if kev and kev.get("due"):
        fix += f"; CISA KEV due {kev['due']}"

    scores = [epss[c] for c in cves if c in epss]
    if product:
        name = ", ".join(x for x in (product, vtype) if x)
    else:
        name = short_title(ob[0]["title"]) or vtype
    via, seen = [], set()
    for o in ob:
        if o["src"] not in seen:
            seen.add(o["src"])
            via.append((o["src"], o["link"]))
        if o.get("extra_link") and "Vendor advisory" not in seen:
            seen.add("Vendor advisory")
            via.append(("Vendor advisory", o["extra_link"]))
    return {
        "date": min(o["date"] for o in ob), "cves": cves, "nick": nick, "name": name, "vtype": vtype,
        "exploited": exploited, "zeroday": zeroday, "sev": sev, "kev": kev, "epss": max(scores) if scores else None,
        "ttp": ttp, "fix": fix, "via": via,
    }


# ---------------------------------------------------------------- main


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--days", type=int, default=30, help="window kept and shown (default 30)")
    args = ap.parse_args()

    now = datetime.now(UTC)
    since = f"{now - timedelta(days=args.days):%Y-%m-%d}"
    cfg = json.loads(CFG_FILE.read_text(encoding="utf-8-sig"))
    state = json.loads(STATE_FILE.read_text(encoding="utf-8")) if STATE_FILE.exists() else {}
    log: list[str] = []

    def write_log(m: str):
        log.append(f"{datetime.now(UTC):%Y-%m-%d %H:%M:%S}Z vuln {m}")

    # observations: keep stored ones in the window, replace with this run's version where the same item reappears
    def okey(o):
        return f"{o['src']}|{o['link'] or o['title']}|{','.join(o['cves'])}"

    store = {okey(o): o for o in state.get("observations", []) if o.get("date", "") >= since}
    fresh = 0
    for s in (x for x in cfg["sources"] if x.get("enabled")):
        try:
            got = READERS[s["type"]](s, since)
            for o in got:
                fresh += okey(o) not in store
                store[okey(o)] = o
            write_log(f"ok   {s['name']:<18} +{len(got)}")
        except Exception as e:  # one broken source must not stop the feed
            write_log(f"FAIL {s['name']:<18} {type(e).__name__}: {e}")
    observations = list(store.values())

    entries = build_entries(observations)

    # enrich: CVE record for entries with no product, then EPSS for every CVE
    cache = state.get("cve_cache", {})
    fetched = 0
    for e in entries:
        if any(o["product"] for o in e["obs"]):
            continue
        cve = next((c for o in e["obs"] for c in o["cves"] if c.startswith("CVE-")), "")
        if not cve or cve in cache or fetched >= 40:
            continue
        try:
            rec = json.loads(get_text(cfg["enrich"]["cve"] + cve))
            cna = rec.get("containers", {}).get("cna", {})
            aff = (cna.get("affected") or [{}])[0]
            cache[cve] = {"product": join_vendor(aff.get("vendor", ""), aff.get("product", "")),
                          "title": cna.get("title", "") or (cna.get("descriptions") or [{}])[0].get("value", "")[:300]}
        except Exception:
            cache[cve] = {}
        fetched += 1

    all_cves = sorted({c for e in entries for o in e["obs"] for c in o["cves"] if c.startswith("CVE-")})
    epss: dict[str, float] = {}
    for i in range(0, len(all_cves), 80):
        try:
            data = json.loads(get_text(f"{cfg['enrich']['epss']}?cve={','.join(all_cves[i:i + 80])}"))
            epss.update({d["cve"].upper(): float(d["epss"]) for d in data.get("data", [])})
        except Exception as e:
            write_log(f"FAIL EPSS              {type(e).__name__}: {e}")
            break

    rows = [summarise(e, cache, epss) for e in entries]
    rows = [r for r in rows if r["date"] >= since]
    live = {c for r in rows for c in r["cves"]}
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps({"observations": sorted(observations, key=lambda o: (o["date"], okey(o))),
                                      "cve_cache": {k: v for k, v in sorted(cache.items()) if k in live}},
                                     ensure_ascii=False, indent=0) + "\n", encoding="utf-8")

    # ------------------------------------------------------------ render
    def line(r):
        if r["exploited"]:
            st = "**EXPLOITED**"
        elif r["zeroday"]:
            st = "**ZERO-DAY**"
        else:
            st = r["sev"] or "NEW"
        tags = []
        if r["exploited"] and r["zeroday"]:
            tags.append("zero-day")
        if r["kev"]:
            tags.append("KEV" + (", ransomware" if r["kev"].get("ransomware") else ""))
        if r["epss"] is not None:
            p = r["epss"] * 100
            tags.append(f"EPSS {p:.0f}%" if p >= 0.95 else f"EPSS {p:.1f}%")
        if tags:
            st += " (" + ", ".join(tags) + ")"
        ids = ", ".join(r["cves"][:2]) + (f" (+{len(r['cves']) - 2})" if len(r["cves"]) > 2 else "") or "no CVE yet"
        name = (f"**{fmt_md(r['nick'])}**: " if r["nick"] else "") + fmt_md(r["name"])
        via = ", ".join(f"[{fmt_md(n)}]({u})" if u.startswith("http") else fmt_md(n) for n, u in r["via"])
        return f"- {r['date']} | {st} | {ids} | {name} | {fmt_md(r['ttp'])} | Fix: {fmt_md(r['fix'])} | via {via}"

    hot = [r for r in rows if r["exploited"] or r["zeroday"]]
    rest = [r for r in rows if not (r["exploited"] or r["zeroday"]) and r["sev"] in ("CRITICAL", "HIGH")]
    order = lambda r: (r["date"], r["epss"] or 0)  # noqa: E731
    out = [
        "# Vuln Wire", "",
        "One line per vulnerability: **date | status | CVE | name | TTP | fix | sources**. "
        f"Last {args.days} days.", "",
        f"Last run **{now:%Y-%m-%d %H:%M} UTC** - {len(hot)} exploited or zero-day, {len(rest)} critical or high", "",
        "| Status | Meaning |", "|---|---|",
        "| **EXPLOITED** | In CISA KEV, or a source reports exploitation in the wild |",
        "| **ZERO-DAY** | Disclosed before a patch existed |",
        "| CRITICAL / HIGH | Severity from the advisory; not known to be exploited yet |", "",
        "EPSS is FIRST.org's probability of exploitation in the next 30 days. TTPs are MITRE ATT&CK Enterprise IDs "
        "inferred from the vulnerability type: triage hints, not attribution. Nicknames (e.g. Java4Shell) come from "
        "the sources. Fix versions are taken from the advisories; check the linked source before patching.", "",
        f"## Exploited or zero-day ({len(hot)})", "",
        *[line(r) for r in sorted(hot, key=order, reverse=True)], "",
        f"## Critical and high, not known exploited ({len(rest)})", "",
        "<details><summary>Show</summary>", "",
        *[line(r) for r in sorted(rest, key=order, reverse=True)], "", "</details>", "",
    ]
    OUT_FILE.write_text("\n".join(out), encoding="utf-8")

    write_log(f"done: {fresh} new observations, {len(observations)} kept, {len(hot)} exploited/zero-day, "
              f"{len(rest)} critical/high")
    old = LOG_FILE.read_text(encoding="utf-8-sig").splitlines()[-400:] if LOG_FILE.exists() else []
    LOG_FILE.write_text("\n".join(old + log) + "\n", encoding="utf-8")
    print("\n".join(log))
    return 0


if __name__ == "__main__":
    sys.exit(main())
