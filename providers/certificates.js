const cache = require("../lib/cache");
const { fetchJson } = require("../lib/http");

const TTL_MS = 1000 * 60 * 60;

function toArray(data) {
  if (Array.isArray(data)) {
    return data;
  }
  return [];
}

function isLikelyHostname(name, domain) {
  if (!name || name.includes("@") || /\s/.test(name)) {
    return false;
  }

  const normalized = name.replace(/^\*\./, "");
  if (!normalized.endsWith(domain)) {
    return false;
  }

  return /^[a-z0-9.-]+$/i.test(normalized);
}

async function lookupCertificates(domain) {
  return cache.remember(`crtsh:${domain}`, TTL_MS, async () => {
    const url =
      "https://crt.sh/?q=" + encodeURIComponent("%." + domain) + "&output=json";

    const raw = await fetchJson(url, {
      headers: {
        Accept: "application/json",
      },
      timeoutMs: 12000,
    });

    const seen = new Set();
    const rows = [];

    for (const item of toArray(raw)) {
      if (!item || !item.name_value) {
        continue;
      }

      const names = String(item.name_value)
        .split("\n")
        .map((value) => value.trim().toLowerCase())
        .filter(Boolean);

      for (const name of names) {
        if (!isLikelyHostname(name, domain) || seen.has(name)) {
          continue;
        }
        seen.add(name);
        rows.push(name);
      }
    }

    return {
      source: "crt.sh",
      subdomains: rows.slice(0, 50),
      count: rows.length,
    };
  });
}

module.exports = {
  lookupCertificates,
};
