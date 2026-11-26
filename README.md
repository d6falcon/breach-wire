<p align="center"><img src="assets/breach-wire-banner.svg" alt="Breach Wire" width="100%"></p>

# Breach-Wire

**One line per cyber attack, every 4 hours.** Breach Wire watches ransomware leak sites, dark-web forums, Telegram, the security press, mainstream news and SEC filings. It writes what it finds to [breach-wire.md](breach-wire.md) as short messages:

```
DATE | STATUS | TTP [ATT&CK] | COMPANY (country, sector) | Stolen: what (volume) | via sources
2026-11-16 | CONFIRMED | Third-party/trusted relationship [T1199] | Infoblox | Stolen: customer data, employee/HR data | via Security Affairs, The Register, TechCrunch
2026-11-17 | CLAIMED | Exfiltration + extortion [T1657] - Vortex | Apellis Pharmaceuticals (US, Healthcare) | Stolen: data (307.64 GB) | via ransomware.live, RansomLook
```

A second, separate feed, **Vuln Wire**, writes the last 30 days of notable vulnerabilities to [vuln-wire.md](vuln-wire.md):

```
DATE | STATUS | CVE | NAME (nickname: product, type) | TTP [ATT&CK] | Fix | via sources
2026-11-17 | EXPLOITED (EPSS 0.7%) | CVE-2026-114938 | Java4Shell: Oracle Java SE, RCE | Exploit public-facing application [T1190] | Fix: apply vendor patch; until then remove internet exposure | via Wiz, Rapid7, Tenable
2026-11-18 | CRITICAL | CVE-2026-130001 | rubygems/mustache, code injection | Exploit public-facing application [T1190] | Fix: upgrade mustache to 1.1.3 | via GitHub Advisory
```

Sources ([vuln-sources.json](vuln-sources.json)): CISA KEV, GitHub Advisory Database (critical), Wiz, watchTowr, Rapid7, Unit 42, Tenable, Cisco, Fortinet and Palo Alto PSIRTs, ZDI zero-days (CVSS 9+), and the security press, scored with FIRST EPSS. Exploited and zero-day bugs come first; critical and high ones follow.

## What's new

- **Vuln Wire:** exploited, zero-day and critical vulnerabilities with nicknames (Java4Shell, Node2Shell...), ATT&CK TTP and fix, in its own file.
- **Runs on GitHub Actions** every 4 hours, both feeds together. No laptop needed.
- **Stays inside the free tier:** about 180–360 Actions minutes a month, against 2,000 free.
- **19 sources**, all confirmed working from GitHub's runners.
- **Pure Python**, standard library only: nothing to install.

## Status

| | |
|---|---|
| **CONFIRMED** | The victim, a regulator or an SEC 8-K Item 1.05 filing acknowledges it |
| **REPORTED** | Credible press reports it; the victim hasn't confirmed yet (upgraded once they do) |
| CLAIMED | A leak site, dark-web forum or Telegram post claims it. Unverified |

## Sources

[sources.json](sources.json) lists them all. Disable one with `"enabled": false`.

- **Dark web:** ransomware.live, RansomLook (leak-site trackers), Dark Web Informer (forum claims)
- **Telegram:** RansomFeedNews, cyber_security_channel
- **Security press:** BleepingComputer, The Hacker News, The Record, SecurityWeek, DataBreaches.net, Security Affairs, Dark Reading, The Register, TechCrunch
- **News:** Reuters, AP, The Guardian, BBC
- **Filings:** SEC 8-K Item 1.05

## Schedule

The [workflow](.github/workflows/breach-wire.yml) runs both feeds every 4 hours from **00:30 UTC**. To run it now, go to **Actions → breach-wire → Run workflow**.

GitHub's own cron is best effort: it ran this workflow only 2–3 times a day, often hours late. So an external scheduler starts it on time and GitHub's cron stays as a fallback.

| Setting | Value |
|---|---|
| Token | GitHub fine-grained token: **Only select repositories → breach-wire**, permission **Actions: Read and write**. Nothing else |
| Scheduler | Any free HTTP cron, e.g. [cron-job.org](https://cron-job.org): every 4 hours at :30, timezone UTC, notify on failure |
| Request | `POST https://api.github.com/repos/d6falcon/breach-wire/actions/workflows/breach-wire.yml/dispatches` |
| Headers | `Authorization: Bearer <token>` · `Accept: application/vnd.github+json` · `X-GitHub-Api-Version: 2022-11-28` |
| Body | `{"ref":"main"}` |
| Success | HTTP `204`. The run appears in Actions as *Manually run by d6falcon* |

Test it from a shell before saving the job:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X POST \
  -H "Authorization: Bearer $BREACH_WIRE_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/d6falcon/breach-wire/actions/workflows/breach-wire.yml/dispatches \
  -d '{"ref":"main"}'
```

The token has no access to the code. It can only start, re-run, cancel and read this repo's workflow runs. Give it an expiry and renew it before it lapses, or the scheduler starts failing (it emails you).

To run it locally (Python 3.11+, standard library only):

```bash
python3 scripts/breach_wire.py --days 7 --no-claims
python3 scripts/vuln_wire.py --days 30
```

## Caveats

- **The TTP and "stolen" columns are keyword-derived.** Use them for triage, not attribution.
- **Only data types and volumes are recorded.** Leaked values are never copied into the feed.
- **Leak-site claims are noisy.** Groups re-post old victims and inflate volumes.
- **`?` means no company could be parsed** from the headline; follow the source link.

## Licence

Code is [MIT](LICENSE) © 2026 d6falcon. The feed summarises third-party reporting; each linked source keeps its own terms.
