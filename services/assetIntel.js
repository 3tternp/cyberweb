const net = require("net");

const { lookupIpGeo } = require("../providers/ipGeo");
const { lookupIpRdap, lookupDomainRdap } = require("../providers/rdap");
const { lookupDomainDns } = require("../providers/domainDns");
const { lookupCertificates } = require("../providers/certificates");
const { lookupWebProfile } = require("../providers/webProbe");
const { buildIpScore, buildDomainScore, extractAsNumber } = require("./scoring");

function classifyQuery(query) {
  const ipV4Regex =
    /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
  if (ipV4Regex.test(query)) {
    return "ip";
  }
  return "domain";
}

function scanCommonPorts(ip) {
  const portsToCheck = [21, 22, 25, 53, 80, 110, 143, 443, 3389, 8080, 8443];
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

async function safe(provider, fallback) {
  try {
    return await provider();
  } catch (_) {
    return fallback;
  }
}

async function buildIpResponse(ip) {
  const [ipGeo, rdap, openPorts] = await Promise.all([
    safe(() => lookupIpGeo(ip), null),
    safe(() => lookupIpRdap(ip), null),
    scanCommonPorts(ip),
  ]);

  const scoring = buildIpScore(ipGeo, openPorts);
  const sources = [ipGeo && ipGeo.source, rdap && rdap.source, "active-port-scan"].filter(Boolean);

  return {
    type: "ip",
    ip,
    score: scoring.score,
    country: ipGeo ? ipGeo.country : null,
    country_code: ipGeo ? ipGeo.countryCode : null,
    region: ipGeo ? ipGeo.region : null,
    city: ipGeo ? ipGeo.city : null,
    isp: ipGeo ? ipGeo.isp : null,
    org_name: ipGeo ? ipGeo.org : null,
    as_no: ipGeo ? extractAsNumber(ipGeo.asnRaw) : null,
    latitude: ipGeo ? ipGeo.latitude : null,
    longitude: ipGeo ? ipGeo.longitude : null,
    open_ports: openPorts,
    tags: scoring.tags,
    status: 200,
    source: sources.join(", "),
    evidence: scoring.evidence,
    sources,
    rdap,
    geo: ipGeo,
  };
}

async function buildDomainResponse(domain) {
  const [dnsData, rdapData, certs, webProfile] = await Promise.all([
    safe(() => lookupDomainDns(domain), { source: "system-dns", a: [], aaaa: [], mx: [], ns: [], txt: [], cname: [] }),
    safe(() => lookupDomainRdap(domain), null),
    safe(() => lookupCertificates(domain), { source: "crt.sh", subdomains: [], count: 0 }),
    safe(() => lookupWebProfile(domain), { source: "active-web-probe", technologies: [], title: null, server: null, poweredBy: null, status: null, url: null }),
  ]);

  const connectedIps = []
    .concat(Array.isArray(dnsData.a) ? dnsData.a : [])
    .concat(Array.isArray(dnsData.aaaa) ? dnsData.aaaa : []);
  const scoring = buildDomainScore(domain, dnsData, rdapData, certs);
  const technologies = [];
  const addTech = (value) => {
    if (value && technologies.indexOf(value) === -1) {
      technologies.push(value);
    }
  };
  if (webProfile.server) addTech(`Web Server: ${webProfile.server}`);
  if (webProfile.poweredBy) addTech(`Framework: ${webProfile.poweredBy}`);
  if (webProfile.title) addTech(`Site Title: ${webProfile.title}`);
  if (webProfile.url && webProfile.status) addTech(`Live Endpoint: ${webProfile.url} (${webProfile.status})`);
  if (dnsData.mx.length > 0) addTech(`Mail Providers: ${dnsData.mx.slice(0, 3).join(", ")}`);
  if (dnsData.ns.length > 0) addTech(`Nameservers: ${dnsData.ns.slice(0, 2).join(", ")}`);
  if (rdapData && Array.isArray(rdapData.nameservers) && rdapData.nameservers.length > 0) {
    addTech(`RDAP Nameservers: ${rdapData.nameservers.slice(0, 2).join(", ")}`);
  }
  if (dnsData.cname.length > 0) addTech(`CNAME: ${dnsData.cname.slice(0, 2).join(", ")}`);
  if (certs.count > 0) addTech(`TLS Certificates: ${certs.count}`);
  for (const tech of webProfile.technologies || []) {
    addTech(tech);
  }

  const subdomains = Array.from(
    new Set(
      []
        .concat(Array.isArray(certs.subdomains) ? certs.subdomains : [])
        .concat(Array.isArray(dnsData.cname) ? dnsData.cname : [])
        .concat(Array.isArray(dnsData.mx) ? dnsData.mx : [])
        .map((value) => String(value || "").toLowerCase())
        .filter((value) => value && value !== domain && value.endsWith(domain))
    )
  );

  return {
    type: "domain",
    domain,
    score: scoring.score,
    is_phishing_suspected: scoring.isPhishingSuspected,
    technologies,
    connected_ips: Array.from(new Set(connectedIps)).slice(0, 20),
    subdomains: subdomains.slice(0, 20),
    status: 200,
    source: [dnsData.source, rdapData && rdapData.source, certs.source, webProfile.source].filter(Boolean).join(", "),
    tags: scoring.tags,
    evidence: scoring.evidence,
    sources: [dnsData.source, rdapData && rdapData.source, certs.source, webProfile.source].filter(Boolean),
    dns: dnsData,
    rdap: rdapData,
    certificates: certs,
    web: webProfile,
  };
}

async function buildAssetResponse(query) {
  const normalized = String(query || "").trim().toLowerCase();
  const kind = classifyQuery(normalized);

  if (kind === "ip") {
    return buildIpResponse(normalized);
  }

  return buildDomainResponse(normalized);
}

module.exports = {
  buildAssetResponse,
};
