# Changelog

## Unreleased

### Added

- Real IP enrichment using geolocation, RDAP, and active port checks
- Real domain enrichment using DNS, RDAP, certificate transparency, and live web probing
- In-memory caching and shared HTTP helpers
- Parsed asset report view with analyst-style details
- Asset dashboard with risk rings and threat source cards
- Interactive vulnerability severity donut chart
- Vulnerability detail panel with metadata, weaknesses, and references
- `README.md` and `CHANGELOG.md`

### Changed

- Replaced mock asset scoring with source-backed scoring
- Expanded NVD CVE mapping to include CVSS version, vector, severity, exploitability, impact, weaknesses, and references
- Increased NVD result retrieval to page through larger result sets
- Sorted vulnerabilities by newest published date first
- Reworked the frontend from a simple output panel into a more complete intel dashboard

### Fixed

- Fixed `Failed to fetch` issues caused by backend availability during local runs
- Improved domain connected IP discovery with DNS lookup fallbacks
- Filtered noisy certificate transparency entries from subdomain results
