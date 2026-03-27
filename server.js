const express = require("express");
const path = require("path");
const cors = require("cors");
const fetch = require("node-fetch");
const net = require("net");
const { buildAssetResponse } = require("./services/assetIntel");
const { searchAhmia } = require("./providers/ahmia");
const { checkBreach, checkPastes } = require("./providers/hibp");

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

const publicDir = path.join(__dirname, "public");
app.use(express.static(publicDir));

const mockCveByVendorProduct = {
  "microsoft:windows": [
    {
      id: "CVE-2021-34527",
      summary:
        "Remote code execution vulnerability in Windows Print Spooler service (PrintNightmare).",
      cvss: 8.8,
      Published: "2021-07-01T00:00:00Z",
      LastModified: "2021-07-07T00:00:00Z",
    },
    {
      id: "CVE-2020-0601",
      summary:
        "Windows CryptoAPI spoofing vulnerability allowing spoofed code-signing certificates.",
      cvss: 8.1,
      Published: "2020-01-14T00:00:00Z",
      LastModified: "2020-01-30T00:00:00Z",
    },
  ],
  "microsoft:office": [
    {
      id: "CVE-2017-11882",
      summary:
        "Memory corruption vulnerability in Equation Editor allowing remote code execution.",
      cvss: 7.8,
      Published: "2017-11-14T00:00:00Z",
      LastModified: "2019-10-03T00:00:00Z",
    },
    {
      id: "CVE-2010-3333",
      summary:
        "Stack-based buffer overflow in Microsoft Office allowing remote code execution.",
      cvss: 9.3,
      Published: "2010-11-09T00:00:00Z",
      LastModified: "2018-10-09T00:00:00Z",
    },
  ],
  "apache:http_server": [
    {
      id: "CVE-2021-41773",
      summary:
        "Path traversal vulnerability in Apache HTTP Server 2.4.x allowing file disclosure.",
      cvss: 5.5,
      Published: "2021-10-05T00:00:00Z",
      LastModified: "2021-10-08T00:00:00Z",
    },
    {
      id: "CVE-2019-0211",
      summary:
        "Privilege escalation vulnerability in Apache HTTP Server scoreboard handling.",
      cvss: 8.8,
      Published: "2019-04-01T00:00:00Z",
      LastModified: "2019-04-04T00:00:00Z",
    },
  ],
};

function classifyQuery(query) {
  const ipV4Regex =
    /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
  if (ipV4Regex.test(query)) {
    return "ip";
  }
  return "domain";
}

function mockRiskScore() {
  const levels = ["Very Low", "Low", "Moderate", "High", "Critical"];
  const pick = () => levels[Math.floor(Math.random() * levels.length)];
  return {
    inbound: pick(),
    outbound: pick(),
  };
}

function scanCommonPorts(ip) {
  const portsToCheck = [21, 22, 25, 53, 80, 110, 143, 443, 3389];
  const timeoutMs = 1000;

  const checks = portsToCheck.map(
    (port) =>
      new Promise((resolve) => {
        const socket = new net.Socket();
        let resolved = false;

        socket.setTimeout(timeoutMs);

        socket.once("connect", () => {
          resolved = true;
          socket.destroy();
          resolve({ port, open: true });
        });

        const closeOrError = () => {
          if (resolved) return;
          resolved = true;
          socket.destroy();
          resolve({ port, open: false });
        };

        socket.once("timeout", closeOrError);
        socket.once("error", closeOrError);
        socket.once("close", closeOrError);

        try {
          socket.connect(port, ip);
        } catch (_) {
          closeOrError();
        }
      })
  );

  return Promise.all(checks).then((results) =>
    results.filter((r) => r.open).map((r) => r.port)
  );
}

async function buildIpResponse(ip) {
  const score = mockRiskScore();

  try {
    const url = "http://ip-api.com/json/" + encodeURIComponent(ip);
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error("GeoIP request failed");
    }
    const data = await res.json();
    if (data.status !== "success") {
      throw new Error("GeoIP lookup error");
    }

    const openPorts = await scanCommonPorts(ip);

    return {
      type: "ip",
      ip,
      score,
      country: data.country || null,
      country_code: data.countryCode || null,
      region: data.regionName || null,
      city: data.city || null,
      isp: data.isp || null,
      org_name: data.org || null,
      as_no: data.as ? parseInt(String(data.as).replace(/[^0-9]/g, ""), 10) || null : null,
      latitude: data.lat || null,
      longitude: data.lon || null,
      open_ports: openPorts,
      tags: [],
      status: 200,
      source: "ip-api.com",
    };
  } catch (err) {
    return {
      type: "ip",
      ip,
      score,
      country: null,
      country_code: null,
      region: null,
      city: null,
      isp: null,
      org_name: null,
      as_no: null,
      latitude: null,
      longitude: null,
      open_ports: [],
      tags: [],
      status: 200,
      source: "fallback-no-geoip",
    };
  }
}

function buildDomainResponse(domain) {
  const score = mockRiskScore();

  return {
    type: "domain",
    domain,
    score,
    is_phishing_suspected: score.inbound === "High" || score.inbound === "Critical",
    technologies: [],
    connected_ips: [],
    subdomains: [],
    status: 200,
    source: "demo",
  };
}

async function proxyJson(url) {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error("Upstream request failed");
  }
  const data = await res.json();
  return data;
}

async function searchCveCircl(vendor, product) {
  const url =
    "https://cve.circl.lu/api/search/" +
    encodeURIComponent(vendor) +
    "/" +
    encodeURIComponent(product);
  try {
    const data = await proxyJson(url);
    if (Array.isArray(data)) {
      return data;
    }
    return [];
  } catch (err) {
    return [];
  }
}

function mapNvdItem(item) {
  if (!item || !item.cve) return null;
  const c = item.cve;
  const id = c.id || "";
  let summary = "";
  if (Array.isArray(c.descriptions)) {
    for (let i = 0; i < c.descriptions.length; i++) {
      const d = c.descriptions[i];
      if (d && d.lang === "en" && d.value) {
        summary = d.value;
        break;
      }
    }
  }
  const metrics = c.metrics || {};
  let score = null;
  let cvssVersion = null;
  let cvssVector = null;
  let severity = null;
  let attackVector = null;
  let attackComplexity = null;
  const pickMetric = (arr, versionLabel) => {
    if (Array.isArray(arr) && arr.length > 0) {
      const m = arr[0];
      if (m && m.cvssData && typeof m.cvssData.baseScore === "number") {
        return {
          score: m.cvssData.baseScore,
          version: versionLabel,
          vector: m.cvssData.vectorString || null,
          severity:
            m.cvssData.baseSeverity ||
            m.baseSeverity ||
            null,
          attackVector: m.cvssData.attackVector || null,
          attackComplexity: m.cvssData.attackComplexity || null,
          exploitabilityScore:
            typeof m.exploitabilityScore === "number" ? m.exploitabilityScore : null,
          impactScore:
            typeof m.impactScore === "number" ? m.impactScore : null,
        };
      }
    }
    return null;
  };
  const metric =
    pickMetric(metrics.cvssMetricV31, "3.1") ||
    pickMetric(metrics.cvssMetricV30, "3.0") ||
    pickMetric(metrics.cvssMetricV2, "2.0");

  if (metric) {
    score = metric.score;
    cvssVersion = metric.version;
    cvssVector = metric.vector;
    severity = metric.severity;
    attackVector = metric.attackVector;
    attackComplexity = metric.attackComplexity;
  }

  const weaknesses = Array.isArray(c.weaknesses)
    ? c.weaknesses
        .flatMap((item) => Array.isArray(item.description) ? item.description : [])
        .filter((item) => item && item.lang === "en" && item.value)
        .map((item) => item.value)
        .slice(0, 5)
    : [];

  const references = Array.isArray(c.references)
    ? c.references
        .filter((ref) => ref && ref.url)
        .map((ref) => ({
          url: ref.url,
          source: ref.source || null,
          tags: Array.isArray(ref.tags) ? ref.tags : [],
        }))
        .slice(0, 8)
    : [];

  return {
    id,
    summary,
    cvss: score,
    severity: severity || null,
    cvssVersion,
    cvssVector,
    attackVector,
    attackComplexity,
    exploitabilityScore: metric ? metric.exploitabilityScore : null,
    impactScore: metric ? metric.impactScore : null,
    weaknesses,
    references,
    Published: c.published || null,
    LastModified: c.lastModified || null,
  };
}

function getNewestCveDate(item) {
  const raw = item && (item.Published || item.published || item.LastModified || item.last_modified);
  const time = raw ? new Date(raw).getTime() : 0;
  return Number.isFinite(time) ? time : 0;
}

function sortCvesDescending(items) {
  return (items || []).slice().sort((a, b) => {
    const dateDiff = getNewestCveDate(b) - getNewestCveDate(a);
    if (dateDiff !== 0) {
      return dateDiff;
    }

    const aScore = typeof a.cvss === "number" ? a.cvss : -1;
    const bScore = typeof b.cvss === "number" ? b.cvss : -1;
    return bScore - aScore;
  });
}

async function searchCveNvd(vendor, product, fromDate, toDate) {
  try {
    const mapped = [];
    const maxResults = 1000;
    const pageSize = 200;

    for (let startIndex = 0; startIndex < maxResults; startIndex += pageSize) {
      const params = new URLSearchParams({
        keywordSearch: vendor + " " + product,
        resultsPerPage: String(pageSize),
        startIndex: String(startIndex),
      });
      if (fromDate) {
        const d = new Date(fromDate);
        if (!isNaN(d.getTime())) {
          params.set("pubStartDate", d.toISOString());
        }
      }
      if (toDate) {
        const d = new Date(toDate);
        if (!isNaN(d.getTime())) {
          d.setDate(d.getDate() + 1);
          params.set("pubEndDate", d.toISOString());
        }
      }

      const url =
        "https://services.nvd.nist.gov/rest/json/cves/2.0?" + params.toString();
      const res = await fetch(url);
      if (!res.ok) {
        break;
      }

      const data = await res.json();
      const vulns = data && Array.isArray(data.vulnerabilities)
        ? data.vulnerabilities
        : [];

      for (let i = 0; i < vulns.length; i++) {
        const m = mapNvdItem(vulns[i]);
        if (m) mapped.push(m);
      }

      if (vulns.length < pageSize) {
        break;
      }
    }

    return mapped;
  } catch (err) {
    return [];
  }
}

app.get("/api/search", async (req, res) => {
  const { query } = req.query;
  if (!query || typeof query !== "string" || !query.trim()) {
    return res.status(400).json({ error: "Query is required" });
  }

  try {
    const result = await buildAssetResponse(query);
    return res.json(result);
  } catch (err) {
    return res.status(502).json({ error: "Unable to enrich asset", detail: err.message });
  }
});

app.get("/api/cve/last", async (req, res) => {
  try {
    const data = await proxyJson("https://cve.circl.lu/api/last");
    res.json({ source: "cve.circl.lu", items: data });
  } catch (err) {
    res.status(502).json({ error: "Unable to fetch last CVEs" });
  }
});

app.get("/api/cve/id", async (req, res) => {
  const { cve } = req.query;
  if (!cve || typeof cve !== "string") {
    return res.status(400).json({ error: "cve is required" });
  }
  const trimmed = cve.trim();
  try {
    const url = "https://cve.circl.lu/api/cve/" + encodeURIComponent(trimmed);
    const data = await proxyJson(url);
    res.json({ source: "cve.circl.lu", item: data });
  } catch (err) {
    res.status(502).json({ error: "Unable to fetch CVE by id" });
  }
});

app.get("/api/cve/search", async (req, res) => {
  const { vendor, product, from, to } = req.query;
  if (!vendor || !product) {
    return res.status(400).json({ error: "vendor and product are required" });
  }
  const v = String(vendor).trim();
  const p = String(product).trim();
  if (!v || !p) {
    return res.status(400).json({ error: "vendor and product are required" });
  }
  try {
    let source = "cve.circl.lu";
    let result = await searchCveCircl(v, p);

    if (!result || result.length === 0) {
      const nvdResult = await searchCveNvd(v, p, from, to);
      if (nvdResult && nvdResult.length > 0) {
        source = "nvd";
        result = nvdResult;
      }
    }

    if (!result || result.length === 0) {
      const key = v.toLowerCase() + ":" + p.toLowerCase();
      const mock = mockCveByVendorProduct[key];
      if (mock && mock.length > 0) {
        source = "mock";
        result = mock;
      }
    }

    res.json({ source, result: sortCvesDescending(result || []) });
  } catch (err) {
    res.status(502).json({ error: "Unable to search CVEs" });
  }
});

app.get("/api/cve/vendors", async (req, res) => {
  try {
    const data = await proxyJson("https://cve.circl.lu/api/browse");
    const vendors = data && Array.isArray(data.vendor) ? data.vendor : [];
    res.json({ source: "cve.circl.lu", vendors });
  } catch (err) {
    res.status(502).json({ error: "Unable to fetch vendors" });
  }
});

app.get("/api/cve/products", async (req, res) => {
  const { vendor } = req.query;
  if (!vendor || typeof vendor !== "string") {
    return res.status(400).json({ error: "vendor is required" });
  }
  const v = vendor.trim();
  if (!v) {
    return res.status(400).json({ error: "vendor is required" });
  }
  try {
    const url =
      "https://cve.circl.lu/api/browse/" + encodeURIComponent(v);
    const data = await proxyJson(url);
    const products = data && Array.isArray(data.product) ? data.product : [];
    res.json({ source: "cve.circl.lu", vendor: v, products });
  } catch (err) {
    res.status(502).json({ error: "Unable to fetch products" });
  }
});

// ── Dark Web Monitor routes ───────────────────────────────────────────────────

app.get("/api/darkweb/search", async (req, res) => {
  const { q } = req.query;
  if (!q || !String(q).trim()) {
    return res.status(400).json({ error: "Query parameter q is required" });
  }
  try {
    const result = await searchAhmia(String(q).trim());
    return res.json(result);
  } catch (err) {
    return res.status(502).json({ error: "Dark web search failed", detail: err.message });
  }
});

app.get("/api/darkweb/breach", async (req, res) => {
  const { email } = req.query;
  if (!email || !String(email).trim()) {
    return res.status(400).json({ error: "Email parameter is required" });
  }
  const trimmed = String(email).trim();
  try {
    const [breachResult, pastes] = await Promise.all([
      checkBreach(trimmed),
      checkPastes(trimmed),
    ]);
    return res.json({ ...breachResult, pastes: pastes || [] });
  } catch (err) {
    return res.status(502).json({ error: "Breach check failed", detail: err.message });
  }
});

app.get("/api/darkweb/resources", (_req, res) => {
  res.json({
    searchEngines: [
      {
        name: "Ahmia",
        url: "https://ahmia.fi",
        type: "clearnet",
        description: "Clearnet search engine that indexes .onion hidden services on the Tor network.",
      },
      {
        name: "Torch",
        onion: "xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5ayieonly2dfzljkybaad.onion",
        type: "onion",
        description: "One of the oldest and largest Tor search engines with millions of indexed pages.",
      },
      {
        name: "HayStack",
        onion: "haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion",
        type: "onion",
        description: "Large-scale dark web index with over 1.5 billion crawled pages.",
      },
      {
        name: "Tor66",
        onion: "tor66sewebgixwhcqfnp5higgiuw4isdmfuoceqqczfciqnuafonb6ad.onion",
        type: "onion",
        description: "Lightweight Tor search engine and fresh .onion link indexer.",
      },
    ],
    breachTools: [
      {
        name: "HaveIBeenPwned",
        url: "https://haveibeenpwned.com",
        type: "clearnet",
        description: "Check if an email or password has appeared in known public data breaches.",
      },
      {
        name: "DeHashed",
        url: "https://dehashed.com",
        type: "clearnet",
        description: "Search leaked credentials, emails, usernames, IPs across breach databases.",
      },
      {
        name: "LeakOSINT",
        url: "https://leakosint.com",
        type: "clearnet",
        description: "OSINT platform for querying data leaks and breach intelligence sources.",
      },
    ],
    telegramOsint: [
      {
        name: "Telemetry",
        handle: "@telemetrybot",
        url: "https://t.me/telemetrybot",
        type: "telegram",
        description: "Telegram OSINT bot for phone number, username, and Telegram ID lookups.",
      },
      {
        name: "UniversalSearchBot",
        handle: "@UniversalSearchBot",
        url: "https://t.me/UniversalSearchBot",
        type: "telegram",
        description: "Multi-source OSINT search across emails, phones, usernames, and IPs.",
      },
    ],
    directories: [
      {
        name: "Hidden Wiki",
        url: "https://thehiddenwiki.org",
        onion: "zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/wiki/",
        type: "onion",
        description: "Community-maintained directory and wiki of .onion services.",
      },
      {
        name: "Tor.link",
        url: "https://tor.link",
        type: "clearnet",
        description: "Clearnet proxy and curated .onion link directory for Tor services.",
      },
      {
        name: "Onion.live",
        url: "https://onion.live",
        type: "clearnet",
        description: "Real-time uptime monitor and directory of live .onion services.",
      },
    ],
    securityTools: [
      {
        name: "PGP Tool",
        url: "https://pgptool.org",
        type: "clearnet",
        description: "Browser-based PGP encryption and decryption for secure dark web communications.",
      },
      {
        name: "TorCrawl.py",
        url: "https://github.com/MikeMeliz/TorCrawl.py",
        type: "tool",
        description: "Python-based crawler for .onion sites using Tor SOCKS proxy.",
      },
      {
        name: "DeepDarkCTI",
        url: "https://github.com/fastfire/deepdarkCTI",
        type: "tool",
        description: "Curated collection of CTI threat intelligence feeds sourced from dark web forums.",
      },
    ],
  });
});

// ── SPA fallback ──────────────────────────────────────────────────────────────
app.get("*", (req, res) => {
  res.sendFile(path.join(publicDir, "index.html"));
});

app.listen(PORT, () => {
  console.log(`Cyberweb CTI demo running on http://localhost:${PORT}`);
});
