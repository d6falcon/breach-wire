<#
.SYNOPSIS
  Breach Wire: a one-line-per-incident cyber-attack feed written to breach-wire.md.

.DESCRIPTION
  Each line reads like a message:

    DATE | STATUS | TTP | COMPANY (country, sector) | Stolen: what | via sources

  STATUS
    CONFIRMED  the victim, a regulator or a filing acknowledges the incident
    REPORTED   credible press reports it; the victim has not (yet) confirmed
    CLAIMED    a leak site, dark-web forum or Telegram post claims it; unverified

  Sources (sources.json):
    leak      ransomware leak-site trackers (ransomware.live, RansomLook) - the dark web, read through
              clearnet mirrors so this script never touches .onion infrastructure
    darkweb   dark-web forum monitors (Dark Web Informer)
    telegram  public channel previews (t.me/s/<channel>), researcher/aggregator channels only
    press     security press (BleepingComputer, The Hacker News, The Record, SecurityWeek ...)
    news      mainstream (Reuters, AP, Guardian, BBC)
    filing    SEC 8-K Item 1.05 (material cybersecurity incident)

  Every run merges into state/wire.tsv (deduplicated by company + status, so a claim and a later
  confirmation appear as two messages) and regenerates breach-wire.md from it.

  Only data CATEGORIES and volumes are written. Raw leaked values (IBANs, emails, passwords, URLs to
  leaked files) are never copied into the feed.

  TTP labels use MITRE ATT&CK Enterprise technique IDs. They are keyword-derived from headlines and
  claim text, so treat them as triage hints, not attribution.

  Runs on Windows PowerShell 5.1 and PowerShell 7+.

.PARAMETER Days
  Look-back window per run. Default 3 (runs overlap; duplicates are merged).

.PARAMETER KeepDays
  Days shown in breach-wire.md. Default 14. state/wire.tsv keeps 60.

.PARAMETER NoClaims
  Leave CLAIMED items out of breach-wire.md (they are still stored).

.EXAMPLE
  ./scripts/Get-BreachWire.ps1
  ./scripts/Get-BreachWire.ps1 -Days 7 -NoClaims
#>
[CmdletBinding()]
param(
  [int]$Days = 3,
  [int]$KeepDays = 14,
  [switch]$NoClaims
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root      = Split-Path -Parent $PSScriptRoot
$cfgFile   = Join-Path $root 'sources.json'
$stateDir  = Join-Path $root 'state'
$storeFile = Join-Path $stateDir 'wire.tsv'
$logFile   = Join-Path $stateDir 'run.log'
$outFile   = Join-Path $root 'breach-wire.md'
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null

$UA      = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) breach-wire/1.0'
$nowUtc  = [DateTimeOffset]::UtcNow
$since   = $nowUtc.AddDays(-$Days)
$log     = New-Object System.Collections.Generic.List[string]
function Write-Log([string]$m) { $line = '{0:u} {1}' -f [DateTime]::UtcNow, $m; $log.Add($line); Write-Verbose $line }

# ---------------------------------------------------------------- helpers
function Get-Text([string]$url) {
  $r = Invoke-WebRequest -UseBasicParsing -Uri $url -UserAgent $UA -TimeoutSec 40
  $ms = $r.RawContentStream; $ms.Position = 0
  (New-Object IO.StreamReader($ms, [Text.Encoding]::UTF8)).ReadToEnd()
}
function ConvertFrom-Html([string]$s) {
  if (-not $s) { return '' }
  $s = $s -replace '(?i)<br\s*/?>', ' ' -replace '<[^>]+>', ' '
  $s = [System.Net.WebUtility]::HtmlDecode($s)
  ($s -replace '[\t\r\n]+', ' ' -replace '\s{2,}', ' ').Trim()
}
function Get-XmlText($node) {
  if ($null -eq $node) { return '' }
  if ($node -is [string]) { return $node }
  if ($node -is [array]) { $node = $node[0] }
  if ($node.InnerText) { return $node.InnerText }
  return [string]$node
}
function ConvertTo-Utc([string]$s) {
  if (-not $s) { return $null }
  $s = $s.Trim() -replace '\s(GMT|UTC|UT|Z)$', ' +00:00' -replace '\s([+-]\d{2})(\d{2})$', ' $1:$2'
  $d = [DateTimeOffset]::MinValue
  if ([DateTimeOffset]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { return $d.ToUniversalTime() }
  return $null
}
function Get-Id([string]$s) {
  $sha = [Security.Cryptography.SHA1]::Create()
  ((($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($s))) | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0, 12)
}
function Get-NormName([string]$n) {
  $x = $n.ToLowerInvariant() -replace '\(.*?\)', ' ' -replace '^(www\.)', ''
  $x = $x -replace '\.(com|net|org|edu|gov|io|co|co\.uk|org\.uk|ac\.uk|de|fr|it|es|nl|be|ch|at|pl|com\.br|com\.mx|com\.au|ca|au|in|jp|cn|tw|kr|ar|cl|co\.za)$', ''
  $x = $x -replace '\b(inc|incorporated|ltd|limited|llc|llp|plc|gmbh|corp|corporation|company|co|s\.?a\.?|s\.?p\.?a|b\.?v|n\.?v|ag|group|holdings?|the)\b\.?', ' '
  ($x -replace '[^a-z0-9]', '')
}
function Get-CleanName([string]$n) {
  $n = (ConvertFrom-Html $n) -replace "(?i)['$RSQ]s$", '' -replace '\s{2,}', ' '
  $n.Trim(' ', '-', ':', ',', '.', '|', '"', "'")
}
function Test-BadName([string]$n) {
  if (-not $n -or $n.Length -lt 2 -or $n.Length -gt 80) { return $true }
  if ($n -match '\*|\?{2,}') { return $true }                          # masked victims
  $stop = '^(?i)(name upcoming|upcoming|unknown|redacted|n/?a|hackers?|ransomware|data|cyberattack|cyber attack|police|report|new|a|an|the|us|uk|eu|government|threat actors?|cybercriminals|researchers|experts|this|how|why|what|major|millions?|thousands|suspected|reported|alleged|popular|massive|fbi|cisa|ncsc|europol|interpol|doj|nsa|police|russia|china|iran|north korea)$'
  return ($n -match $stop -or $n -match '(?i)\b(actors?|hackers|nexus|gang)$')
}

# ---------------------------------------------------------------- classifiers
$TtpRules = @(
  @{ re = '(?i)ransomware|encrypt(ed|ion)? (files|systems|servers)|locker';                       label = 'Ransomware [T1486]'; leak = $true }
  @{ re = '(?i)vish|voice phish|phone call|help ?desk|social[- ]engineer';                         label = 'Vishing/help-desk social engineering [T1566.004]' }
  @{ re = '(?i)\bmfa (fatigue|bomb)|push (bombing|fatigue)';                                       label = 'MFA fatigue [T1621]' }
  @{ re = '(?i)phish';                                                                              label = 'Phishing [T1566]' }
  @{ re = '(?i)credential stuffing|password spray';                                                 label = 'Credential stuffing [T1110.004]' }
  @{ re = '(?i)zero-?day|0-?day|exploit|vulnerab|\bflaw\b|CVE-\d{4}';                              label = 'Exploited public-facing app [T1190]'; leak = $true }
  @{ re = '(?i)oauth|access token|salesforce|saas|snowflake|okta|cloud (tenant|instance)';          label = 'SaaS/token abuse [T1528]' }
  @{ re = '(?i)stolen credentials|compromised (credentials|account)|valid account|infostealer|leaked (credentials|passwords)'; label = 'Valid accounts [T1078]' }
  @{ re = '(?i)supply[- ]chain|third[- ]party|vendor|supplier|service provider|contractor';         label = 'Third-party/trusted relationship [T1199]' }
  @{ re = '(?i)misconfigur|unsecured|exposed (database|server|bucket|elasticsearch)|publicly accessible|open (s3|bucket|database)'; label = 'Exposed cloud data [T1530]' }
  @{ re = '(?i)\bddos\b|denial[- ]of[- ]service';                                                   label = 'DDoS [T1498]'; leak = $true }
  @{ re = '(?i)defac';                                                                              label = 'Defacement [T1491.002]'; leak = $true }
  @{ re = '(?i)wiper|wiped|destroy(ed)? data';                                                      label = 'Data destruction [T1485]'; leak = $true }
  @{ re = '(?i)crypto(currency)? (heist|theft)|drained|stole \$|\$[\d.,]+\s?(m|million|bn|billion) (stolen|in crypto)'; label = 'Financial theft [T1657]' }
)
$StolenRules = @(
  @{ re = '(?i)customer|client|member|user (data|accounts|records)|subscriber|shopper';            label = 'customer data' }
  @{ re = '(?i)personal (data|information)|\bpii\b|identity|names?,? (address|email|phone|date of birth)|contact (data|details|information)|date of birth|\bdob\b'; label = 'personal data (PII)' }
  @{ re = '(?i)employee|staff|\bhr\b|human resources|payroll|payslip|personnel';                    label = 'employee/HR data' }
  @{ re = '(?i)patient|medical|health|\bphi\b|clinical';                                            label = 'health data' }
  @{ re = '(?i)passport|national id|social security|\bssns?\b|driver.?s licen|citizen';             label = 'government IDs' }
  @{ re = '(?i)bank|iban|financ|invoice|billing|accounting|bookkeeping|payment|credit card|card data|tax'; label = 'financial data' }
  @{ re = '(?i)password|credential|login|hash';                                                     label = 'credentials' }
  @{ re = '(?i)source code|repositor|github|gitlab';                                                label = 'source code' }
  @{ re = '(?i)mailbox|email (archive|correspondence|spool)|internal email';                       label = 'mailboxes' }
  @{ re = '(?i)contract|legal|\bnda\b|confidential (documents|files)|internal documents';           label = 'contracts/internal docs' }
  @{ re = '(?i)student|enrol';                                                                      label = 'student records' }
  @{ re = '(?i)wallet|crypto|funds';                                                                label = 'funds/crypto' }
  @{ re = '(?i)database|\bsql\b|backup';                                                            label = 'databases/backups' }
)
function Get-Ttp([string]$text, [string]$tier, [string]$group) {
  $claim = ($tier -in 'leak', 'darkweb')
  $hits = @(); foreach ($r in $TtpRules) { if ((-not $claim -or $r.leak) -and $text -match $r.re -and $hits.Count -lt 2) { $hits += $r.label } }
  if ($hits.Count -eq 0) {
    if ($tier -eq 'leak') { $hits += 'Exfiltration + extortion [T1657]' }
    elseif ($tier -eq 'darkweb') { $hits += 'Data theft, offered for sale/leak' }
    else { $hits += 'not disclosed' }
  }
  $t = $hits -join ' + '
  if ($group) { $t = "$t - $group" }
  return $t
}
function Get-Stolen([string]$text, [string]$size) {
  $cats = @(); foreach ($r in $StolenRules) { if ($text -match $r.re -and $cats.Count -lt 4) { $cats += $r.label } }
  $vol = @()
  if ($size) { $vol += $size }
  $m = [regex]::Match($text, '(?i)(\d[\d.,]*)\s?(TB|TiB|GB|GiB)\b')
  if ($m.Success -and -not $size) { $vol += ($m.Groups[1].Value + ' ' + $m.Groups[2].Value.ToUpper()) }
  $m = [regex]::Match($text, '(?i)(\d[\d.,]*\s?(million|billion|m\b|k\b|thousand)?)\s+(records|rows|customers|users|individuals|people|patients|accounts|employees|members|students|citizens)')
  if ($m.Success) { $vol += ($m.Groups[1].Value.Trim() + ' ' + $m.Groups[3].Value.ToLower()) }
  if ($cats.Count -eq 0 -and $vol.Count -eq 0) { return 'not disclosed' }
  if ($cats.Count -eq 0) { $cats += 'data' }
  return (($cats -join ', ') + $(if ($vol.Count) { ' (' + ($vol -join ', ') + ')' } else { '' }))
}
function Get-NewsStatus([string]$text, [string]$tier) {
  if ($tier -eq 'filing') { return 'CONFIRMED' }
  if ($tier -in 'leak', 'darkweb') { return 'CLAIMED' }
  if ($text -match '(?i)\b(confirm(s|ed)?|disclos(es|ed)|notif(y|ies|ying|ied)|acknowledg|admits|8-K|sec filing|regulatory filing|says it (was|has been|is) (hit|investigating|responding)|is investigating|investigating (a |an |the )?(breach|cyber|incident|attack|data|security|ransomware|hack)|detected (unauthori|suspicious)|warns (customers|users)|statement)\b') { return 'CONFIRMED' }
  if ($text -match '(?i)\b(claim(s|ed)?|alleged(ly)?|purported(ly)?)\b') { return 'CLAIMED' }
  return 'REPORTED'
}

$IncludeRe = '(?i)\b(breach(ed|es)?|hack(ed|ers? (hit|breach|steal|stole|target|claim))|cyber-?attack|ransomware (attack|gang|group)|data (leak|theft|exposure|stolen)|stolen (data|records|information|files|credentials|funds|crypto|customer|personal|patient)|(data|records|information|files|funds) (were |was )?stolen|stole|compromised|extort|intrusion|unauthori[sz]ed access|leak(ed|s)?|exfiltrat|ddos|defaced|cyber ?incident|security incident)\b'
$ExcludeRe = '(?i)\b(arrest(ed)?|sentenced|charged|extradit|pleads?|guilty|indicted|convicted|jailed|prison|webinar|podcast|how to|tips|funding|raises|acquires|acquisition|launches|patch(es|ed)?|update now|fixes|proof-of-concept|poc|survey|study|week in review|roundup|sponsored|top \d+|best|explained|opinion|analysis:|interview|malware analysis|new malware|botnet|campaign targets|apt\d*|nation-state|denies|blames|attributes)\b'

$RSQ = [string][char]0x2019
$CoPat = @(
  "^(?<c>[A-Z0-9][\w&''$RSQ.\-]*(?:\s+(?:[A-Z0-9&][\w&''$RSQ.\-]*|of|and|de|du|la|for)){0,5}?)\s+(?i:confirms|confirmed|discloses|discloses|says|suffers|hit by|hacked|reports|notifies|notifying|is investigating|investigating|investigates|warns|falls victim|data breach|data leak|data exposure|cyberattack|cyber-attack|cyber attack|cyber incident|ransomware attack|security incident|breach|was hacked|struck by|targeted by|attacked|probes|shuts|takes systems offline|server outage|outage|systems down|withholds|links)\b"
  "(?i:attack|cyberattack|cyber-attack|breach|hack|intrusion|incident|leak)\s+(?i:on|at|of|hits?|targeting|affecting|impacting)\s+(?<c>[A-Z0-9][\w&''$RSQ.\-]*(?:\s+(?:[A-Z0-9&][\w&''$RSQ.\-]*|of|and|de|for)){0,5}?)(?=\s+(?i:exposes|leaks|impacts|affects|hits|disrupts|compromises|may|could|leaves|led|forces|sees|puts|knocks|takes|causes)\b|[,:;]|\s+-\s|$)"
  "\b(?i:hackers?|ransomware (?:gang|group)|threat actors?|cybercriminals|extortionists)\s+(?i:hit|hits|breach|breached|target|targets|targeted|steal from|stole from|attack|attacked|claims? (?:attack|breach) on|claim|claims|compromise[sd]?)\s+(?<c>[A-Z0-9][\w&''$RSQ.\-]*(?:\s+(?:[A-Z0-9&][\w&''$RSQ.\-]*|of|and|de|for)){0,5}?)(?=[,:;]|\s+(?i:and|in|to|data|systems|network|customers|employees|with|after|over)\b|\s+-\s|$)"
)
function Get-Company([string]$title) {
  $t = ($title -replace '\s+[-|]\s+(Reuters|AP News|The Associated Press|AP|BBC News|The Guardian)$', '' -replace '^[A-Z]{2}:\s+', '' -replace '^[^\w]+', '').Trim()
  foreach ($p in $CoPat) {
    $m = [regex]::Match($t, $p)
    if ($m.Success) {
      $c = Get-CleanName $m.Groups['c'].Value
      $c = $c -replace '^(?i)(US|UK|EU|Japanese|German|French|British|American|Australian|Canadian|Indian|Dutch|Italian|Spanish|Korean|Chinese)\s+(?=\S+\s+\S)', ''
      $c = $c -replace '^.*?\b(?i:Giant|Firm|Maker|Provider|Retailer|Operator|Chain|Insurer|Startup|Platform|Company)\s+(?=[A-Z0-9])', ''
      if (-not (Test-BadName $c)) { return $c }
    }
  }
  return $null
}

# ---------------------------------------------------------------- collectors
$items = New-Object System.Collections.Generic.List[object]
function Add-Item($date, $status, $ttp, $company, $context, $stolen, $source, $link, $headline, $tier) {
  if (-not $date -or $date -lt $since) { return }
  $items.Add([pscustomobject]@{
      Date = $date.ToString('yyyy-MM-dd'); Status = $status; Ttp = $ttp; Company = $company; Context = $context
      Stolen = $stolen; Sources = $source; Links = $link; Headline = ($headline -replace '\t', ' '); Tier = $tier
    })
}

function Read-RansomwareLive($s) {
  $data = (Get-Text $s.url) | ConvertFrom-Json
  foreach ($v in $data) {
    $recs = [regex]::Match([string]$v.victim, '\s+-\s+([\d.,]+\s*(million\s+)?records)\s*$')
    $name = Get-CleanName ([string]$v.victim -replace '\s+-\s+[\d.,]+\s*(million\s+)?records\s*$', '')
    if (Test-BadName $name) { continue }
    $d = ConvertTo-Utc $v.discovered; if (-not $d) { $d = ConvertTo-Utc $v.attackdate }
    $ctx = @(); if ($v.country) { $ctx += $v.country }; if ($v.activity -and $v.activity -ne 'Not Found') { $ctx += $v.activity }
    $txt = "$($v.description) $(if ($recs.Success) { $recs.Groups[1].Value })"
    Add-Item $d 'CLAIMED' (Get-Ttp $txt 'leak' $v.group) $name ($ctx -join ', ') (Get-Stolen $txt $v.data_size) $s.name $v.url $name 'leak'
  }
}
function Read-RansomLook($s) {
  $data = (Get-Text $s.url) | ConvertFrom-Json
  foreach ($v in $data) {
    $name = Get-CleanName ($v.post_title -replace '\s*\(.*$', '')
    if (Test-BadName $name) { continue }
    $txt = "$($v.description)"
    $size = $null; $m = [regex]::Match($txt, '(?i)size:\s*([\d.,]+\s?[KMGT]i?B)'); if ($m.Success) { $size = $m.Groups[1].Value }
    $link = 'https://www.ransomlook.io/group/' + [uri]::EscapeDataString($v.group_name)
    Add-Item (ConvertTo-Utc $v.discovered) 'CLAIMED' (Get-Ttp $txt 'leak' $v.group_name) $name '' (Get-Stolen $txt $size) $s.name $link $name 'leak'
  }
}
function Read-DarkWebInformer($s) {
  $x = [xml](Get-Text $s.url)
  foreach ($i in $x.rss.channel.item) {
    $title = ConvertFrom-Html (Get-XmlText $i.title)
    $m = [regex]::Match($title, '^(?<c>.+?)\s+(?:Database Sale|Data Sale|Data Leak|Database Leak|Breach|Access Sale|Leak|Data Breach)\s+Claim')
    if (-not $m.Success) { continue }
    $name = Get-CleanName $m.Groups['c'].Value
    if (Test-BadName $name) { continue }
    Add-Item (ConvertTo-Utc (Get-XmlText $i.pubDate)) 'CLAIMED' (Get-Ttp $title 'darkweb' '') $name '' (Get-Stolen $title $null) $s.name (Get-XmlText $i.link) $title 'darkweb'
  }
}
function Get-TgMessages($s) {
  $h = Get-Text $s.url
  $out = @()
  foreach ($b in ($h -split 'tgme_widget_message_wrap') | Select-Object -Skip 1) {
    $tm = [regex]::Match($b, '<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', 'Singleline')
    $dm = [regex]::Match($b, '<time datetime="([^"]+)"')
    $pm = [regex]::Match($b, 'data-post="([^"]+)"')
    if ($tm.Success -and $dm.Success) {
      $out += [pscustomobject]@{ Text = (ConvertFrom-Html $tm.Groups[1].Value); Title = (ConvertFrom-Html (($tm.Groups[1].Value -split '(?i)<br\s*/?>')[0])); Date = (ConvertTo-Utc $dm.Groups[1].Value)
        Link = $(if ($pm.Success) { 'https://t.me/' + $pm.Groups[1].Value } else { $s.url }) }
    }
  }
  return $out
}
function Read-TgRansomFeed($s) {
  # "ID: n  <warn> date  <ninja> GROUP  <target> Victim, Country  <link> url"
  $re = ('{0}\s*(?<g>.+?)\s*{1}\s*(?<v>.+?)\s*{2}' -f [char]::ConvertFromUtf32(0x1F977), [char]::ConvertFromUtf32(0x1F3AF), [char]::ConvertFromUtf32(0x1F517))
  foreach ($msg in (Get-TgMessages $s)) {
    $m = [regex]::Match($msg.Text, $re)
    if (-not $m.Success) { continue }
    $v = $m.Groups['v'].Value -replace '\s+AND\s+', ' & '
    $ctry = ''; $cm = [regex]::Match($v, '^(?<n>.+),\s*(?<c>[^,]{2,30})$'); if ($cm.Success) { $v = $cm.Groups['n'].Value; $ctry = $cm.Groups['c'].Value }
    $name = Get-CleanName $v
    if (Test-BadName $name) { continue }
    $g = $m.Groups['g'].Value.Trim()
    Add-Item $msg.Date 'CLAIMED' (Get-Ttp '' 'leak' $g) $name $ctry 'not disclosed' $s.name $msg.Link $name 'leak'
  }
}
function Add-NewsItem($s, $title, $desc, $date, $link) {
  $title = ConvertFrom-Html $title; $desc = ConvertFrom-Html $desc
  if ($title -notmatch $IncludeRe -or $title -match $ExcludeRe) { return }
  $text = "$title. $desc"
  $co = Get-Company $title
  if (-not $co) { $co = '?' }
  Add-Item $date (Get-NewsStatus $text $s.tier) (Get-Ttp $text $s.tier '') $co '' (Get-Stolen $text $null) $s.name $link $title $s.tier
}
function Read-TgNews($s) {
  foreach ($msg in (Get-TgMessages $s)) {
    Add-NewsItem $s $msg.Title $msg.Text $msg.Date $msg.Link
  }
}
function Read-Rss($s) {
  $x = [xml](Get-Text $s.url)
  if ($x.rss) {
    foreach ($i in $x.rss.channel.item) { Add-NewsItem $s (Get-XmlText $i.title) (Get-XmlText $i.description) (ConvertTo-Utc (Get-XmlText $i.pubDate)) (Get-XmlText $i.link) }
  } elseif ($x.feed) {
    foreach ($e in $x.feed.entry) {
      $l = $e.link | Where-Object { -not $_.rel -or $_.rel -eq 'alternate' } | Select-Object -First 1
      $d = ConvertTo-Utc (Get-XmlText $e.published); if (-not $d) { $d = ConvertTo-Utc (Get-XmlText $e.updated) }
      Add-NewsItem $s (Get-XmlText $e.title) (Get-XmlText $e.summary) $d $l.href
    }
  }
}
function Read-Sec($s) {
  $q = '{0}?q=%22Item%201.05%22&forms=8-K,8-K/A&dateRange=custom&startdt={1:yyyy-MM-dd}&enddt={2:yyyy-MM-dd}' -f $s.url, $since.AddDays(-1), $nowUtc
  $r = (Get-Text $q) | ConvertFrom-Json
  foreach ($h in $r.hits.hits) {
    $src = $h._source
    $name = Get-CleanName (($src.display_names | Select-Object -First 1) -replace '\s*\(.*$', '')
    if (Test-BadName $name) { continue }
    $cik = [int64]($src.ciks | Select-Object -First 1)
    $file = ($h._id -split ':', 2)[1]
    $link = 'https://www.sec.gov/Archives/edgar/data/{0}/{1}/{2}' -f $cik, ($src.adsh -replace '-', ''), $file
    $ctx = @('US'); if ($src.biz_states) { $ctx = @('US-' + ($src.biz_states | Select-Object -First 1)) }
    Add-Item (ConvertTo-Utc $src.file_date) 'CONFIRMED' 'not disclosed (see 8-K)' $name ($ctx -join ', ') 'not disclosed (see 8-K)' $s.name $link "$name 8-K Item 1.05" 'filing'
  }
}

$cfg = Get-Content -Raw -Path $cfgFile | ConvertFrom-Json
foreach ($s in ($cfg.sources | Where-Object { $_.enabled })) {
  $before = $items.Count
  try {
    switch ($s.type) {
      'ransomwarelive' { Read-RansomwareLive $s }
      'ransomlook'     { Read-RansomLook $s }
      'dwi'            { Read-DarkWebInformer $s }
      'tg-ransomfeed'  { Read-TgRansomFeed $s }
      'tg-news'        { Read-TgNews $s }
      'rss'            { Read-Rss $s }
      'sec'            { Read-Sec $s }
      default          { throw "unknown source type '$($s.type)'" }
    }
    Write-Log ("ok   {0,-26} +{1}" -f $s.name, ($items.Count - $before))
  } catch {
    Write-Log ("FAIL {0,-26} {1}" -f $s.name, $_.Exception.Message)
  }
}

# ---------------------------------------------------------------- correlate, merge, store
function Split-Stolen([string]$s) {
  if (-not $s -or $s -like 'not disclosed*') { return @(@(), @()) }
  $m = [regex]::Match($s, '^(?<c>.*?)(?:\s\((?<v>.*)\))?$')
  $c = @($m.Groups['c'].Value -split ',\s*' | Where-Object { $_ -and $_ -ne 'data' })
  $v = @(); if ($m.Groups['v'].Success) { $v = @($m.Groups['v'].Value -split '(?<=[A-Za-z]),\s' | Where-Object { $_ }) }
  return @($c, $v)
}
function Merge-Stolen([string]$a, [string]$b) {
  if (-not $b -or $b -like 'not disclosed*') { return $a }
  if (-not $a -or $a -like 'not disclosed*') { return $b }
  $x = Split-Stolen $a; $y = Split-Stolen $b
  $c = @($x[0] + $y[0] | Select-Object -Unique | Select-Object -First 5); if (-not $c) { $c = @('data') }
  $v = @($x[1] + $y[1] | Select-Object -Unique | Select-Object -First 3)
  return (($c -join ', ') + $(if ($v) { ' (' + ($v -join ', ') + ')' } else { '' }))
}
$store = @{}
if (Test-Path $storeFile) { foreach ($r in (Import-Csv -Path $storeFile -Delimiter "`t" -Encoding UTF8)) { $store[$r.Id] = $r } }

# news items without a parsed company: match against known victim names (claims seen in store or this run)
$known = @{}
foreach ($r in (@($store.Values) + $items.ToArray())) {
  if ($r.Company -and $r.Company -ne '?') { $n = Get-NormName $r.Company; if ($n.Length -ge 5 -and -not $known.ContainsKey($n)) { $known[$n] = $r.Company } }
}
foreach ($i in $items | Where-Object { $_.Company -eq '?' }) {
  $h = ' ' + (($i.Headline.ToLowerInvariant()) -replace '[^a-z0-9]+', ' ') + ' '
  foreach ($k in $known.Keys) {
    $words = ($known[$k].ToLowerInvariant() -replace '[^a-z0-9]+', ' ').Trim()
    if ($words.Length -ge 5 -and $h.Contains(" $words ")) { $i.Company = $known[$k]; break }
  }
}

$added = 0
foreach ($i in $items) {
  $key = if ($i.Company -ne '?') { Get-NormName $i.Company } else { 'h:' + (Get-NormName $i.Headline) }
  if (-not $key) { continue }
  $lane = if ($i.Status -eq 'CLAIMED') { 'CLAIMED' } else { 'NEWS' }
  $id = Get-Id ("$key|$lane")
  if ($store.ContainsKey($id)) {
    $e = $store[$id]
    $srcs = @($e.Sources -split '; ') ; $lnks = @($e.Links -split ' ')
    if ($srcs -notcontains $i.Sources) { $e.Sources = (($srcs + $i.Sources) -join '; '); $e.Links = (($lnks + $i.Links) -join ' ') }
    if ($i.Status -eq 'CONFIRMED' -and $e.Status -eq 'REPORTED') { $e.Status = 'CONFIRMED' }
    $e.Stolen = Merge-Stolen $e.Stolen $i.Stolen
    if ($e.Ttp -like 'not disclosed*' -and $i.Ttp -notlike 'not disclosed*') { $e.Ttp = $i.Ttp }
    if ($e.Ttp -like 'Exfiltration + extortion*' -and $i.Ttp -like 'Ransomware*') { $e.Ttp = $i.Ttp }
    if (-not $e.Context -and $i.Context) { $e.Context = $i.Context }
    if ($i.Date -lt $e.Date) { $e.Date = $i.Date }
  } else {
    $store[$id] = [pscustomobject]@{ Id = $id; Date = $i.Date; Status = $i.Status; Ttp = $i.Ttp; Company = $i.Company; Context = $i.Context
      Stolen = $i.Stolen; Sources = $i.Sources; Links = $i.Links; Headline = $i.Headline; Tier = $i.Tier; FirstSeen = $nowUtc.ToString('u') }
    $added++
  }
}
$cut = $nowUtc.AddDays(-60).ToString('yyyy-MM-dd')
$rows = @($store.Values | Where-Object { $_.Date -ge $cut } | Sort-Object Date, Status, Company -Descending)
$rows | Export-Csv -Path $storeFile -Delimiter "`t" -NoTypeInformation -Encoding UTF8

# ---------------------------------------------------------------- render markdown
function Format-Md([string]$s) { ($s -replace '\|', '/' -replace '([\\`*_\[\]<>])', '\$1') }
$rank = @{ CONFIRMED = 0; REPORTED = 1; CLAIMED = 2 }
$show = @($rows | Where-Object { $_.Date -ge $nowUtc.AddDays(-$KeepDays).ToString('yyyy-MM-dd') })
if ($NoClaims) { $show = @($show | Where-Object { $_.Status -ne 'CLAIMED' }) }
$cnt = @{}; foreach ($k in 'CONFIRMED', 'REPORTED', 'CLAIMED') { $cnt[$k] = @($show | Where-Object { $_.Status -eq $k }).Count }

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('# Breach Wire')
[void]$sb.AppendLine()
[void]$sb.AppendLine('One line per incident: **date | status | TTP | company | what was stolen | sources**.')
[void]$sb.AppendLine()
[void]$sb.AppendLine(('Last run **{0:yyyy-MM-dd HH:mm} UTC** - last {1} days - {2} confirmed, {3} reported, {4} claimed' -f $nowUtc.UtcDateTime, $KeepDays, $cnt.CONFIRMED, $cnt.REPORTED, $cnt.CLAIMED))
[void]$sb.AppendLine()
[void]$sb.AppendLine('| Status | Meaning |')
[void]$sb.AppendLine('|---|---|')
[void]$sb.AppendLine('| **CONFIRMED** | Victim, regulator or filing (e.g. SEC 8-K Item 1.05) acknowledges the incident |')
[void]$sb.AppendLine('| **REPORTED** | Credible press reports it; the victim has not confirmed yet |')
[void]$sb.AppendLine('| CLAIMED | Ransomware leak site, dark-web forum or Telegram claim. Unverified; groups exaggerate and re-post |')
[void]$sb.AppendLine()
[void]$sb.AppendLine('TTPs are MITRE ATT&CK Enterprise IDs inferred from headline and claim text: triage hints, not attribution. "What was stolen" lists data categories and volumes only; no leaked values are copied here. `?` = company not parsed from the headline; follow the source.')
[void]$sb.AppendLine()

foreach ($day in ($show | Group-Object Date | Sort-Object Name -Descending)) {
  [void]$sb.AppendLine("## $($day.Name)")
  [void]$sb.AppendLine()
  $lastStatus = $null
  foreach ($r in ($day.Group | Sort-Object @{ e = { $rank[$_.Status] } }, Company)) {
    if ($r.Status -eq 'CLAIMED' -and $lastStatus -ne 'CLAIMED') {
      [void]$sb.AppendLine(); [void]$sb.AppendLine('<details><summary>Claimed on leak sites / dark web / Telegram (' + @($day.Group | Where-Object { $_.Status -eq 'CLAIMED' }).Count + ')</summary>'); [void]$sb.AppendLine()
    }
    $lastStatus = $r.Status
    $st = if ($r.Status -eq 'CLAIMED') { 'CLAIMED' } else { "**$($r.Status)**" }
    $co = if ($r.Company -eq '?') { '? "' + (Format-Md $r.Headline) + '"' } else { '**' + (Format-Md $r.Company) + '**' }
    if ($r.Context) { $co += ' (' + (Format-Md $r.Context) + ')' }
    $srcN = @($r.Sources -split '; '); $srcL = @($r.Links -split ' ')
    $via = @(); for ($k = 0; $k -lt $srcN.Count; $k++) {
      $u = if ($k -lt $srcL.Count) { $srcL[$k] } else { '' }
      if ($u -match '^https?://' -and $u -notmatch '\.onion') { $via += "[$($srcN[$k])]($u)" } else { $via += $srcN[$k] }
    }
    [void]$sb.AppendLine(('- {0} | {1} | {2} | {3} | Stolen: {4} | via {5}' -f $r.Date, $st, (Format-Md $r.Ttp), $co, (Format-Md $r.Stolen), ($via -join ', ')))
  }
  if ($lastStatus -eq 'CLAIMED') { [void]$sb.AppendLine(); [void]$sb.AppendLine('</details>') }
  [void]$sb.AppendLine()
}
[IO.File]::WriteAllText($outFile, $sb.ToString(), (New-Object Text.UTF8Encoding($false)))

Write-Log ("done: {0} collected, {1} new, {2} in store, {3} shown" -f $items.Count, $added, $rows.Count, $show.Count)
$old = @(); if (Test-Path $logFile) { $old = @(Get-Content $logFile -Tail 400) }
Set-Content -Path $logFile -Value ($old + $log) -Encoding UTF8
$log | ForEach-Object { Write-Host $_ }
