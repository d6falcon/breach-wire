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

`scripts/Register-BreachWireSchedule.ps1` registers a Windows scheduled task, `BreachWire`, that runs three times a day at different times each day:

| Run | Window |
|---|---|
| Morning | 06:00-08:00 |
| Afternoon | 13:00-15:00 |
| Evening | 20:00-22:00 |

Each run starts at a random time inside its window. Missed runs catch up when the machine wakes up.

Each scheduled run goes through `scripts/Invoke-BreachWireRun.ps1`, which refreshes the feed, commits `breach-wire.md` and `state/wire.tsv`, and pushes to `origin`. It never prompts for credentials: a failed push stays committed locally and goes out on the next run. Use `-NoPush` to commit without pushing. Change it with `-Times 07:30,12:00,18:45 -JitterHours 1`, or remove it with `-Remove`.

## Caveats

- **TTP and "what was stolen" are keyword-derived** from headlines and claim text. Treat them as triage hints, not attribution. ATT&CK IDs are Enterprise v20.1.
- **Only data categories and volumes are written.** Leaked values (IBANs, emails, passwords, file links) are never copied into the feed.
- **`?` means the company could not be parsed** from the headline; the headline is shown and the source is linked.
- **Leak-site claims are noisy.** Groups re-post old victims, inflate volumes and sometimes name the wrong entity.
- State lives in `state/wire.tsv` (60 days) and `state/run.log`.
