const dns = require("dns").promises;

async function safeResolve(method, domain) {
  try {
    return await dns[method](domain);
  } catch (_) {
    return [];
  }
}

async function lookupDomainDns(domain) {
  let lookupAll = [];
  try {
    lookupAll = await dns.lookup(domain, { all: true });
  } catch (_) {
    lookupAll = [];
  }

  const [a, aaaa, mx, ns, txt, cname] = await Promise.all([
    safeResolve("resolve4", domain),
    safeResolve("resolve6", domain),
    safeResolve("resolveMx", domain),
    safeResolve("resolveNs", domain),
    safeResolve("resolveTxt", domain),
    safeResolve("resolveCname", domain),
  ]);

  return {
    source: "system-dns",
    a: Array.from(
      new Set(
        a.concat(
          lookupAll
            .filter((item) => item && item.family === 4 && item.address)
            .map((item) => item.address)
        )
      )
    ),
    aaaa: Array.from(
      new Set(
        aaaa.concat(
          lookupAll
            .filter((item) => item && item.family === 6 && item.address)
            .map((item) => item.address)
        )
      )
    ),
    mx: Array.isArray(mx) ? mx.map((item) => item.exchange).filter(Boolean) : [],
    ns,
    txt: Array.isArray(txt) ? txt.map((parts) => parts.join("")).filter(Boolean) : [],
    cname,
  };
}

module.exports = {
  lookupDomainDns,
};
