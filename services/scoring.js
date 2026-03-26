function labelFromScore(score) {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 35) return "Moderate";
  if (score >= 15) return "Low";
  return "Very Low";
}

function extractAsNumber(asnRaw) {
  if (!asnRaw) {
    return null;
  }

  const match = String(asnRaw).match(/AS(\d+)/i) || String(asnRaw).match(/(\d+)/);
  if (!match) {
    return null;
  }

  return Number(match[1]);
}

function buildIpScore(ipGeo, openPorts) {
  let inbound = 5;
  let outbound = 5;
  const evidence = [];
  const tags = [];

  const riskyPorts = new Set([21, 23, 25, 3389]);
  const webPorts = new Set([80, 443, 8080, 8443]);
  const open = Array.isArray(openPorts) ? openPorts : [];

  if (ipGeo && ipGeo.hosting) {
    inbound += 18;
    outbound += 8;
    evidence.push("Hosting provider IP range");
    tags.push("hosting");
  }

  if (ipGeo && ipGeo.proxy) {
    inbound += 20;
    outbound += 12;
    evidence.push("IP geolocation provider flags proxy/VPN behavior");
    tags.push("proxy");
  }

  if (open.some((port) => riskyPorts.has(port))) {
    inbound += 28;
    evidence.push("Sensitive ports exposed to the internet");
    tags.push("sensitive-ports");
  }

  if (open.some((port) => webPorts.has(port))) {
    inbound += 8;
    evidence.push("Public web-facing service detected");
    tags.push("web-service");
  }

  if (open.length >= 4) {
    inbound += 12;
    outbound += 6;
    evidence.push("Multiple exposed ports increase attack surface");
  }

  return {
    score: {
      inbound: labelFromScore(inbound),
      outbound: labelFromScore(outbound),
      inboundNumeric: Math.min(inbound, 100),
      outboundNumeric: Math.min(outbound, 100),
    },
    evidence,
    tags: Array.from(new Set(tags)),
  };
}

function buildDomainScore(domain, dnsData, rdapData, certs) {
  let inbound = 4;
  let outbound = 2;
  const evidence = [];
  const tags = [];

  const hasMx = Array.isArray(dnsData.mx) && dnsData.mx.length > 0;
  const hasSpf = Array.isArray(dnsData.txt) && dnsData.txt.some((entry) => entry.includes("v=spf1"));
  const hasDmarc = Array.isArray(dnsData.txt) && dnsData.txt.some((entry) => entry.includes("v=DMARC1"));
  const createdAt = rdapData && rdapData.created ? new Date(rdapData.created) : null;
  const ageDays = createdAt && !isNaN(createdAt.getTime())
    ? Math.floor((Date.now() - createdAt.getTime()) / (1000 * 60 * 60 * 24))
    : null;
  const certCount = certs && typeof certs.count === "number" ? certs.count : 0;
  const nameservers = []
    .concat(Array.isArray(dnsData.ns) ? dnsData.ns : [])
    .concat(rdapData && Array.isArray(rdapData.nameservers) ? rdapData.nameservers : []);

  if (ageDays !== null && ageDays <= 30) {
    inbound += 30;
    outbound += 10;
    evidence.push("Recently registered domain");
    tags.push("new-domain");
  } else if (ageDays !== null && ageDays <= 180) {
    inbound += 15;
    evidence.push("Relatively new domain");
  }

  if (hasMx && !hasSpf) {
    inbound += 12;
    evidence.push("Mail-enabled domain without SPF");
    tags.push("missing-spf");
  }

  if (hasMx && !hasDmarc) {
    inbound += 8;
    evidence.push("Mail-enabled domain without DMARC");
    tags.push("missing-dmarc");
  }

  if (certCount > 20) {
    outbound += 8;
    evidence.push("Certificate transparency shows many issued subdomains");
    tags.push("broad-surface");
  }

  if (nameservers.length === 0) {
    inbound += 10;
    evidence.push("Nameserver data is incomplete");
  }

  return {
    score: {
      inbound: labelFromScore(inbound),
      outbound: labelFromScore(outbound),
      inboundNumeric: Math.min(inbound, 100),
      outboundNumeric: Math.min(outbound, 100),
    },
    evidence,
    tags: Array.from(new Set(tags)),
    isPhishingSuspected: inbound >= 35,
  };
}

module.exports = {
  extractAsNumber,
  buildIpScore,
  buildDomainScore,
};
