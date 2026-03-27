const fetch = require("node-fetch");

const AHMIA_URL = "https://ahmia.fi/search/";
const TIMEOUT_MS = 15000;

async function searchAhmia(query) {
  const url = AHMIA_URL + "?q=" + encodeURIComponent(query);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml",
      },
    });
    clearTimeout(timer);

    if (!res.ok) {
      return { results: [], source: "ahmia.fi", error: "HTTP " + res.status };
    }

    const html = await res.text();
    const results = parseResults(html);
    return { results, source: "ahmia.fi", query };
  } catch (err) {
    clearTimeout(timer);
    if (err.name === "AbortError") {
      return { results: [], source: "ahmia.fi", error: "Request timed out" };
    }
    return { results: [], source: "ahmia.fi", error: err.message };
  }
}

function parseResults(html) {
  const results = [];

  // Ahmia wraps each result in <li class="result">...</li>
  const liRe = /<li[^>]+class="result"[^>]*>([\s\S]*?)<\/li>/gi;
  let liMatch;

  while ((liMatch = liRe.exec(html)) !== null && results.length < 12) {
    const block = liMatch[1];

    // Title + redirect URL from <h4><a href="...">Title</a></h4>
    const titleRe = /<h4[^>]*>\s*<a[^>]+href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/i;
    const titleMatch = titleRe.exec(block);
    const redirectHref = titleMatch ? titleMatch[1] : "";
    const title = titleMatch ? stripTags(titleMatch[2]) : "";

    // Onion address from <cite>
    const citeRe = /<cite[^>]*>([\s\S]*?)<\/cite>/i;
    const citeMatch = citeRe.exec(block);
    const onionUrl = citeMatch ? stripTags(citeMatch[1]).trim() : "";

    // Description from <p class="..."> or plain <p>
    const descRe = /<p[^>]*>([\s\S]*?)<\/p>/i;
    const descMatch = descRe.exec(block);
    const description = descMatch ? stripTags(descMatch[1]).trim() : "";

    if (title || onionUrl) {
      results.push({ title, redirectHref, onionUrl, description });
    }
  }

  return results;
}

function stripTags(str) {
  return String(str || "")
    .replace(/<[^>]+>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .trim();
}

module.exports = { searchAhmia };
