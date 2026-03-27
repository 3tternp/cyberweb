# Cyberweb

![Cyberweb](https://img.shields.io/badge/Cyberweb-CTI%20Dashboard-0ea5e9?style=for-the-badge)
![Node](https://img.shields.io/badge/node-%3E%3D16-111827?style=for-the-badge&logo=node.js&logoColor=white)
![Express](https://img.shields.io/badge/express-4.x-111827?style=for-the-badge&logo=express&logoColor=white)

Cyberweb is a lightweight cyber threat intelligence (CTI) dashboard for investigating IPs, domains, public CVEs, and basic dark-web signals using live enrichment sources.

## What You Can Do

- Asset Intelligence: investigate an IP or domain with DNS, RDAP, certificates, web probing, open-port hints, and scoring
- Vulnerabilities: search CVEs by vendor/product, filter by severity and date, export results
- Dark Web Monitor: search Tor index results via Ahmia and check email exposure via Have I Been Pwned (optional API key)

## Run Locally

```bash
npm install
npm start
```

Open http://127.0.0.1:4000

## Configuration

- PORT: defaults to 4000
- HIBP_API_KEY: enables live Have I Been Pwned lookups in the Dark Web Monitor tab

Example (PowerShell):

```powershell
$env:HIBP_API_KEY="your_key_here"
npm start
```

## Usage Tips

### Asset Intelligence

- IP examples: `8.8.8.8`, `1.1.1.1`
- Domain examples: `example.com`, `microsoft.com`

### Vulnerabilities

- Vendor/product examples: `microsoft / windows`, `apache / tomcat`, `linux / kernel`
- For large ecosystems (like linux kernel), narrow the date range to avoid hitting API page limits

### Dark Web Monitor

- Tor Search uses Ahmia (clearnet index) and links to .onion addresses; use Tor Browser to open .onion sites
- Breach Check uses Have I Been Pwned; without HIBP_API_KEY it falls back to a safe informational message

## Data Sources

- ip-api.com: IP geolocation and hosting/proxy signals
- rdap.org: IP and domain registration context
- System DNS: A, AAAA, MX, NS, TXT, CNAME records
- crt.sh: certificate transparency and subdomain discovery
- NVD API: CVE search and metadata
- cve.circl.lu: supplementary CVE browsing/search behavior
- ahmia.fi: Tor index search (clearnet)
- haveibeenpwned.com: breach and paste lookups (requires API key)

## Project Structure

- server.js: Express server and API routes
- public/index.html: single-page UI
- services/assetIntel.js: asset enrichment orchestration
- services/scoring.js: scoring logic
- providers/: upstream enrichment adapters
- lib/: shared cache and HTTP helpers

## Notes

- Public APIs can rate-limit or return partial results for very broad searches.
- This project uses live enrichment and does not persist results in a database.
