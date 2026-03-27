const fetch = require("node-fetch");

const HIBP_BASE = "https://haveibeenpwned.com/api/v3";
const TIMEOUT_MS = 10000;

async function checkBreach(email) {
  const apiKey = process.env.HIBP_API_KEY;

  if (!apiKey) {
    return {
      email,
      noApiKey: true,
      hibpUrl: "https://haveibeenpwned.com/account/" + encodeURIComponent(email),
      message:
        "Set the HIBP_API_KEY environment variable to enable live breach lookups. " +
        "You can get a key at https://haveibeenpwned.com/API/Key",
    };
  }

  const url =
    HIBP_BASE +
    "/breachedaccount/" +
    encodeURIComponent(email) +
    "?truncateResponse=false";

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        "hibp-api-key": apiKey,
        "User-Agent": "CyberwebCTI/1.0",
      },
    });
    clearTimeout(timer);

    if (res.status === 404) {
      return { email, found: false, breaches: [], count: 0 };
    }

    if (res.status === 401) {
      return { email, error: "Invalid HIBP API key." };
    }

    if (res.status === 429) {
      return { email, error: "HIBP rate limit reached. Please wait and retry." };
    }

    if (!res.ok) {
      return { email, error: "HIBP API returned HTTP " + res.status };
    }

    const breaches = await res.json();
    return {
      email,
      found: breaches.length > 0,
      breaches,
      count: breaches.length,
    };
  } catch (err) {
    clearTimeout(timer);
    if (err.name === "AbortError") {
      return { email, error: "Request timed out" };
    }
    return { email, error: err.message };
  }
}

async function checkPastes(email) {
  const apiKey = process.env.HIBP_API_KEY;
  if (!apiKey) return null;

  const url = HIBP_BASE + "/pasteaccount/" + encodeURIComponent(email);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        "hibp-api-key": apiKey,
        "User-Agent": "CyberwebCTI/1.0",
      },
    });
    clearTimeout(timer);

    if (res.status === 404) return [];
    if (!res.ok) return null;

    return await res.json();
  } catch (_) {
    clearTimeout(timer);
    return null;
  }
}

module.exports = { checkBreach, checkPastes };
