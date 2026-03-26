const fetch = require("node-fetch");

function extractTitle(html) {
  const match = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  return match ? match[1].trim() : null;
}

function extractMetaGenerator(html) {
  const match = html.match(
    /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i
  );
  return match ? match[1].trim() : null;
}

function detectTechnologies(html, headers) {
  const findings = [];
  const lowerHtml = String(html || "").toLowerCase();
  const add = (value) => {
    if (value && findings.indexOf(value) === -1) {
      findings.push(value);
    }
  };

  const server = headers.get("server");
  const poweredBy = headers.get("x-powered-by");
  const generator = extractMetaGenerator(html);

  if (server) add(`Web Server: ${server}`);
  if (poweredBy) add(`Framework: ${poweredBy}`);
  if (generator) add(`Generator: ${generator}`);

  if (lowerHtml.includes("wp-content") || lowerHtml.includes("wordpress")) add("CMS: WordPress");
  if (lowerHtml.includes("/cdn-cgi/")) add("Edge: Cloudflare");
  if (lowerHtml.includes("_next/")) add("Framework: Next.js");
  if (lowerHtml.includes("__nuxt")) add("Framework: Nuxt");
  if (lowerHtml.includes("react")) add("Frontend: React");
  if (lowerHtml.includes("vue")) add("Frontend: Vue");
  if (lowerHtml.includes("bootstrap")) add("UI: Bootstrap");
  if (lowerHtml.includes("jquery")) add("Library: jQuery");

  return findings;
}

async function fetchWithTimeout(url, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent": "Cyberweb-Intel/1.0",
      },
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function lookupWebProfile(domain) {
  const candidates = [`https://${domain}`, `http://${domain}`];

  for (const url of candidates) {
    try {
      const response = await fetchWithTimeout(url, 7000);
      const html = await response.text();
      return {
        source: "active-web-probe",
        url,
        status: response.status,
        title: extractTitle(html),
        server: response.headers.get("server") || null,
        poweredBy: response.headers.get("x-powered-by") || null,
        technologies: detectTechnologies(html, response.headers),
      };
    } catch (_) {
      continue;
    }
  }

  return {
    source: "active-web-probe",
    url: null,
    status: null,
    title: null,
    server: null,
    poweredBy: null,
    technologies: [],
  };
}

module.exports = {
  lookupWebProfile,
};
