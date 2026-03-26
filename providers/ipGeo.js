const cache = require("../lib/cache");
const { fetchJson } = require("../lib/http");

const TTL_MS = 1000 * 60 * 30;

async function lookupIpGeo(ip) {
  return cache.remember(`ip-geo:${ip}`, TTL_MS, async () => {
    const url = "http://ip-api.com/json/" + encodeURIComponent(ip);
    const data = await fetchJson(url);

    if (data.status !== "success") {
      throw new Error("GeoIP lookup failed");
    }

    return {
      source: "ip-api.com",
      country: data.country || null,
      countryCode: data.countryCode || null,
      region: data.regionName || null,
      city: data.city || null,
      isp: data.isp || null,
      org: data.org || null,
      asnRaw: data.as || null,
      latitude: data.lat || null,
      longitude: data.lon || null,
      timezone: data.timezone || null,
      mobile: Boolean(data.mobile),
      proxy: Boolean(data.proxy),
      hosting: Boolean(data.hosting),
    };
  });
}

module.exports = {
  lookupIpGeo,
};
