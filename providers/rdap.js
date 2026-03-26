const cache = require("../lib/cache");
const { fetchJson } = require("../lib/http");

const TTL_MS = 1000 * 60 * 60;

function normalizeEventMap(events) {
  const map = {};
  if (!Array.isArray(events)) {
    return map;
  }

  for (const event of events) {
    if (!event || !event.eventAction || !event.eventDate) {
      continue;
    }
    map[event.eventAction] = event.eventDate;
  }

  return map;
}

async function lookupIpRdap(ip) {
  return cache.remember(`rdap-ip:${ip}`, TTL_MS, async () => {
    const data = await fetchJson("https://rdap.org/ip/" + encodeURIComponent(ip));
    const events = normalizeEventMap(data.events);

    return {
      source: "rdap.org",
      handle: data.handle || null,
      name: data.name || null,
      type: data.type || null,
      country: data.country || null,
      startAddress: data.startAddress || null,
      endAddress: data.endAddress || null,
      parentHandle: data.parentHandle || null,
      created: events.registration || null,
      updated: events.last_changed || null,
    };
  });
}

async function lookupDomainRdap(domain) {
  return cache.remember(`rdap-domain:${domain}`, TTL_MS, async () => {
    const data = await fetchJson("https://rdap.org/domain/" + encodeURIComponent(domain));
    const events = normalizeEventMap(data.events);
    const statuses = Array.isArray(data.status) ? data.status : [];
    const nameservers = Array.isArray(data.nameservers)
      ? data.nameservers
          .map((item) => (item && item.ldhName ? item.ldhName : null))
          .filter(Boolean)
      : [];

    return {
      source: "rdap.org",
      handle: data.handle || null,
      ldhName: data.ldhName || null,
      unicodeName: data.unicodeName || null,
      registrar: data.port43 || null,
      statuses,
      nameservers,
      created: events.registration || null,
      expires: events.expiration || null,
      updated: events.last_changed || null,
    };
  });
}

module.exports = {
  lookupIpRdap,
  lookupDomainRdap,
};
