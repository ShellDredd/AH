# Beleronfonte Tool's Pack — VTI Firefox Extension
![JUMP MTF JUMP](https://i.pinimg.com/736x/2c/5f/67/2c5f679a3cda3c77f21ceaa35a79412a.jpg)

Copyright © 2026 ShellDredd
Original concept, architecture and technical direction by ShellDredd.
Software implementation developed with AI-assisted programming tools under the author's direction, review and engineering supervision.
Licensed under GNU GPL-3.0-or-later,

Local-first vulnerability intelligence aggregator for cybersecurity laboratories.
Collects, normalizes, correlates and visualizes threat data from multiple public sources.

**Educational and defensive use only.** This extension does not execute exploits, generate payloads, or automate attacks.

## Features

- **Multi-source aggregation**: NVD, INCIBE-CERT, Tenable (optional), Exploit-DB
- **CVE correlation**: Deduplicates vulnerabilities across sources by CVE-ID
- **Zero-day classification**: Evidence-based indicators with explicit reasoning
- **SOC-style dashboard**: Cyberpunk UI with severity badges, source status, statistics
- **Local storage**: All data in `browser.storage.local` — no external backend
- **Offline mode**: Shows cached data when sources are unavailable
- **Configurable updates**: Manual or scheduled (15m – 24h)
- **Notifications**: Critical CVEs, known exploited, zero-day indicators, new exploits

## Architecture

```
cyber-threat-intel/
├── manifest.json              # Firefox MV3 manifest
├── background/
│   ├── background.js          # Service worker entry
│   ├── sources/               # Data source adapters
│   ├── normalization/         # Common data model
│   ├── correlation/           # CVE correlation & zero-day logic
│   ├── services/              # Update, cache, notifications
│   └── schedulers/            # Alarm-based updates
├── storage/                   # Local storage layer
├── popup/                     # Dashboard UI
├── options/                   # Configuration page
├── utils/                     # Shared utilities
└── tests/                     # Offline test suite
```

### Design Principles

| Principle | Implementation |
|-----------|---------------|
| LOCAL-FIRST | `browser.storage.local`, no backend |
| MODULAR | Isolated source adapters with common interface |
| SECURE | Strict CSP, input validation, no eval/inline scripts |
| EXTENSIBLE | Add sources without modifying core engine |

## Installation

### Firefox (Temporary)

1. Open `about:debugging`
2. Click **This Firefox** → **Load Temporary Add-on**
3. Select `cyber-threat-intel/manifest.json`

### Firefox (Signed / Permanent)

Package with `web-ext` or sign through Mozilla Add-ons.

## Development

### Run Tests (offline, no network)

```bash
cd cyber-threat-intel
node tests/run-tests.mjs
```

Tests cover: NVD/INCIBE/Tenable/ExploitDB parsers, normalization, correlation, zero-day classification, severity display.

### Project Structure

Each source implements the `ThreatSource` interface:

```javascript
class ThreatSource {
  async fetchLatest() {}
  async fetchById(id) {}
  normalize(data) {}
  getSourceName() {}
  getStatus() {}
}
```

## Data Sources

### NVD (NIST)

- **API**: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Data**: CVE ID, descriptions, CVSS v2/v3/v4, CWE, CPE, references, KEV
- **Rate limit**: 5 req/30s (50 with API key)
- **Optional**: NVD API key in settings (increases rate limit)

### INCIBE-CERT

- **Feeds**:
  - Vulnerabilities: `https://www.incibe.es/feed/vulnerabilities`
  - Advisories: `https://www.incibe.es/incibe-cert/alerta-temprana/avisos/feed`
- **Data**: Spanish translations, severity, solutions, CVE links
- **Method**: RSS/Atom parsing (no aggressive scraping)

### Tenable (Optional)

- **API**: Configurable (default: `https://cloud.tenable.com`)
- **Auth**: Access Key + Secret Key (stored locally only)
- **Endpoints**: `/plugins/plugin`, `/workbenches/vulnerabilities`
- **Data**: Plugins, CVE, CVSS, VPR, EPSS, exploit availability
- **Note**: Requires Tenable Vulnerability Management account

### Exploit-DB

- **Source**: `https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv`
- **Data**: EDB-ID, CVE, platform, type, author, description
- **Note**: Reference links only — no exploit execution or payload download

## Permissions

| Permission | Purpose |
|------------|---------|
| `storage` | Local data persistence |
| `alarms` | Scheduled updates |
| `notifications` | Security alerts |
| Host permissions | API endpoints for configured sources only |

No browsing history, tabs, or user navigation data is collected.

## Configuration

Open extension options (⚙ button or `about:addons`):

- Enable/disable sources
- Update interval (manual to 24h)
- Notifications on/off
- Data retention (7–365 days)
- Tenable API credentials
- Optional NVD API key

### Tenable Setup

1. Log in to [cloud.tenable.com](https://cloud.tenable.com)
2. My Account → API Keys → Generate
3. Enter API URL, Access Key, Secret Key in extension settings
4. Enable Tenable source

**Security**: Credentials are stored in `browser.storage.local` on your machine only. They are sent exclusively to your configured Tenable API URL.

## Storage

Data stored locally:

- `vulnerabilities` — Correlated CVE records (indexed by CVE-ID)
- `exploits` — Exploit-DB entries (indexed by EDB-ID)
- `advisories` — Security advisories
- `news` — News and alerts (separate from CVEs)
- `sources` — Source health status
- `settings` — User configuration
- `statistics` — Aggregated counts
- `cache` — HTTP cache metadata (ETag, lastModified)

Retention policy removes data older than configured days (default: 30).

## Threat Correlation

Primary key: **CVE-ID**

```
NVD:       CVE-2026-1234
INCIBE:    CVE-2026-1234  →  Single merged record
Tenable:   CVE-2026-1234     Sources: [NVD, INCIBE, TENABLE, EXPLOIT-DB]
ExploitDB: CVE-2026-1234
```

## Zero-Day Classification

**Never** classifies new CVEs as zero-day automatically.

| Status | Criteria |
|--------|----------|
| NEW | Published < 2 days, no exploitation evidence |
| RECENT | Published < 7 days |
| PUBLIC_EXPLOIT | Public exploit reference found |
| KNOWN_EXPLOITED | KEV/CISA listing or known exploitation |
| POTENTIAL_ZERO_DAY | New + public exploit (inference, not fact) |
| ZERO_DAY_CONFIRMED | Vendor advisory + public exploit on new CVE |

All classifications display supporting evidence and reasons.

## Privacy & Security

- No user browsing data collected or transmitted
- External connections limited to configured intelligence sources
- Strict Content Security Policy (no eval, no inline scripts, no remote scripts)
- All external input validated and sanitized before DOM insertion
- URLs validated (https/http only) before opening in new tabs
- Rate limiting with backoff on HTTP 429

## Testing

```bash
node tests/run-tests.mjs
```

Fixtures in `tests/fixtures/` enable offline testing:
- `nvd.json` — NVD API response sample
- `incibe.json` — INCIBE RSS feed sample
- `tenable.json` — Tenable plugin response
- `exploitdb.json` — Exploit-DB CSV sample

## Troubleshooting

| Issue | Solution |
|-------|----------|
| NVD rate limited | Add NVD API key in settings, increase update interval |
| Tenable offline | Verify credentials and API URL; check account permissions |
| INCIBE feed error | Check network; cached data still displayed |
| Exploit-DB slow | CSV is large (~47k records); first load may take time |
| No data shown | Click refresh (⟳); check source status tab |

## Roadmap

Prepared architecture for future sources:

- CISA KEV (partial via NVD `hasKev`)
- FIRST EPSS
- MITRE ATT&CK mapping
- CERT-EU, MSRC, Cisco PSIRT, Red Hat, Debian, GitHub Advisories, OSV

## License

Educational / laboratory use. Respect source terms of service and rate limits.

## Disclaimer

This tool provides vulnerability intelligence for defensive security research.
It does not facilitate exploitation. Exploit-DB links are references only.
Zero-day indicators are evidence-based inferences, not confirmed attributions.
