# breach-wire

A messaging-style OSINT feed of cyber attacks. One line per incident, written to [breach-wire.md](breach-wire.md):

```
DATE | STATUS | TTP [ATT&CK] | COMPANY (country, sector) | Stolen: what (volume) | via sources
2026-11-16 | CONFIRMED | Third-party/trusted relationship [T1199] | Infoblox | Stolen: customer data, employee/HR data | via Security Affairs, The Register, TechCrunch
2026-11-17 | CLAIMED | Exfiltration + extortion [T1657] - Vortex | Apellis Pharmaceuticals (US, Healthcare) | Stolen: data (307.64 GB) | via ransomware.live, RansomLook
```

## Status

| Status | Meaning |
|---|---|
| CONFIRMED | The victim, a regulator or a filing (SEC 8-K Item 1.05) acknowledges it |
| REPORTED | Credible press reports it; the victim has not confirmed yet. Upgraded in place once confirmed |
| CLAIMED | A ransomware leak site, dark-web forum or Telegram post claims it. Unverified, and kept as its own line so you can see claim → confirmation |

## Sources

Edit [sources.json](sources.json) to add or disable a source.

| Tier | Sources |
|---|---|
| Dark web: leak sites | ransomware.live, RansomLook (clearnet trackers of ransomware leak sites; no `.onion` access needed) |
| Dark web: forums | Dark Web Informer (breach and data-sale claims) |
| Telegram | RansomFeedNews, cyber_security_channel (public channel previews, `t.me/s/...`) |
| Security press | BleepingComputer, The Hacker News, The Record, SecurityWeek, DataBreaches.net, Security Affairs, Dark Reading, The Register, TechCrunch |
| Mainstream news | Reuters, AP (via Google News), The Guardian, BBC |
| Regulator | SEC EDGAR 8-K Item 1.05 (material cybersecurity incidents) |

Telegram channels are researcher and aggregator channels only. Criminal channels are not scraped directly; their claims reach the feed through the leak-site trackers.

## Run it

```bash
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Get-BreachWire.ps1
```

Options: `-Days 7` (look-back), `-KeepDays 30` (days shown), `-NoClaims` (confirmed and reported only).

## Schedule

GitHub Actions ([.github/workflows/breach-wire.yml](.github/workflows/breach-wire.yml)) runs the feed three times a day, at a different time each day (UTC):

| Run | Possible start times |
|---|---|
| Morning | 06:00, 06:30, 07:00, 07:30 |
| Afternoon | 13:00, 13:30, 14:00, 14:30 |
| Evening | 20:00, 20:30, 21:00, 21:30 |

One start time per window is picked from the date, so it varies day to day; the others exit immediately. GitHub can delay scheduled runs by a few minutes. Each run refreshes the feed and commits `breach-wire.md` and `state/wire.tsv` as d6falcon. Run it on demand from **Actions → breach-wire → Run workflow**. Usage is roughly 400 Actions minutes a month.

**Local fallback:** `scripts/Register-BreachWireSchedule.ps1` registers the same schedule as a Windows scheduled task that refreshes, commits and pushes (`scripts/Invoke-BreachWireRun.ps1`). Don't run both: they would push over each other.

## Caveats

- **TTP and "what was stolen" are keyword-derived** from headlines and claim text. Treat them as triage hints, not attribution. ATT&CK IDs are Enterprise v20.1.
- **Only data categories and volumes are written.** Leaked values (IBANs, emails, passwords, file links) are never copied into the feed.
- **`?` means the company could not be parsed** from the headline; the headline is shown and the source is linked.
- **Leak-site claims are noisy.** Groups re-post old victims, inflate volumes and sometimes name the wrong entity.
- State lives in `state/wire.tsv` (60 days). Per-source results are in each Actions run log (locally, `state/run.log`).
