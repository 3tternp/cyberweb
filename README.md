# Cyberweb

Cyberweb is a threat intelligence dashboard for investigating IPs, domains, and public CVEs with real-world enrichment data.

## Features

- Asset intelligence for IPs and domains
- Real enrichment from DNS, RDAP, certificate transparency, and live web probing
- Parsed analyst-style dashboards instead of raw JSON
- Vulnerability search with NVD-backed results
- Interactive severity donut chart for CVE filtering
- Detailed CVE side panel with metadata, weaknesses, and references

## Data Sources

- `ip-api.com` for IP geolocation and hosting/proxy signals
- `rdap.org` for IP and domain registration context
- System DNS resolution for `A`, `AAAA`, `MX`, `NS`, `TXT`, and `CNAME`
- `crt.sh` for certificate transparency and subdomain discovery
- NVD API for vulnerability search and CVE metadata
- `cve.circl.lu` for supplementary CVE browsing/search behavior

## Project Structure

- [server.js](/C:/Users/ASUS/Documents/Github/Cyberweb/server.js): Express server and API routes
- [public/index.html](/C:/Users/ASUS/Documents/Github/Cyberweb/public/index.html): Frontend dashboard UI
- [services/assetIntel.js](/C:/Users/ASUS/Documents/Github/Cyberweb/services/assetIntel.js): Asset enrichment orchestration
- [services/scoring.js](/C:/Users/ASUS/Documents/Github/Cyberweb/services/scoring.js): Threat scoring logic
- [providers/](/C:/Users/ASUS/Documents/Github/Cyberweb/providers): Upstream enrichment adapters
- [lib/](/C:/Users/ASUS/Documents/Github/Cyberweb/lib): Shared cache and HTTP helpers

## Run Locally

```bash
npm install
npm start
```

Open [http://127.0.0.1:4000](http://127.0.0.1:4000).

## Current Capabilities

### Asset Search

- IP enrichment with:
  - Geo and provider context
  - RDAP ownership/range details
  - Common port exposure checks
  - Evidence and risk scoring

- Domain enrichment with:
  - Web server and page fingerprinting
  - Connected IP discovery
  - Subdomain discovery
  - RDAP registration details
  - Technology profile and source coverage

### Vulnerabilities

- Vendor and product CVE search
- Date filtering
- Severity filtering
- Interactive severity chart
- Detailed CVE metadata and references
- Newest-first ordering

## Notes

- Some upstream data quality depends on the public APIs used.
- Large NVD result sets may take longer for broad vendor/product searches.
- This project currently uses live public enrichment and does not yet persist results in a database.
