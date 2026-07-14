const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const dns = require("dns").promises;
const tls = require("tls");
const net = require("net");
const path = require("path");
require("dotenv").config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const dataDir = path.resolve(__dirname, "data");
const storePath = path.join(dataDir, "workspace-store.json");

app.use(express.json({ limit: "1mb" }));

function ensureWorkspaceStore() {
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  if (!fs.existsSync(storePath)) {
    fs.writeFileSync(
      storePath,
      JSON.stringify({ cases: [], watchlists: [] }, null, 2),
      "utf8"
    );
  }
}

function readWorkspaceStore() {
  ensureWorkspaceStore();
  try {
    const raw = fs.readFileSync(storePath, "utf8");
    const parsed = JSON.parse(raw || "{}");
    return {
      cases: Array.isArray(parsed.cases) ? parsed.cases : [],
      watchlists: Array.isArray(parsed.watchlists) ? parsed.watchlists : [],
      ctMonitor: parsed.ctMonitor && typeof parsed.ctMonitor === "object" ? parsed.ctMonitor : { domains: [], alerts: [] }
    };
  } catch {
    return { cases: [], watchlists: [], ctMonitor: { domains: [], alerts: [] } };
  }
}

function writeWorkspaceStore(nextStore) {
  ensureWorkspaceStore();
  const ctMonitor = nextStore.ctMonitor && typeof nextStore.ctMonitor === "object" ? nextStore.ctMonitor : { domains: [], alerts: [] };
  fs.writeFileSync(
    storePath,
    JSON.stringify(
      {
        cases: Array.isArray(nextStore.cases) ? nextStore.cases : [],
        watchlists: Array.isArray(nextStore.watchlists) ? nextStore.watchlists : [],
        ctMonitor: {
          domains: Array.isArray(ctMonitor.domains) ? ctMonitor.domains : [],
          alerts: Array.isArray(ctMonitor.alerts) ? ctMonitor.alerts : []
        }
      },
      null,
      2
    ),
    "utf8"
  );
}

function makeId(prefix) {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function normalizeStringArray(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((item) => String(item || "").trim()).filter(Boolean))];
}

function sameStringArray(a = [], b = []) {
  const left = [...new Set((a || []).map((item) => String(item || "").trim().toLowerCase()).filter(Boolean))].sort();
  const right = [...new Set((b || []).map((item) => String(item || "").trim().toLowerCase()).filter(Boolean))].sort();
  return JSON.stringify(left) === JSON.stringify(right);
}

function buildCaseSnapshot(caseItem) {
  return {
    id: caseItem.id,
    title: caseItem.title,
    indicator: caseItem.indicator,
    indicatorType: caseItem.indicatorType,
    verdict: caseItem.verdict,
    tags: caseItem.tags || [],
    status: caseItem.status || "open",
    priority: caseItem.priority || "medium",
    locked: Boolean(caseItem.locked),
    createdAt: caseItem.createdAt,
    updatedAt: caseItem.updatedAt,
    lastObservedAt: caseItem.lastObservedAt || null,
    notesCount: Array.isArray(caseItem.notes) ? caseItem.notes.length : 0,
    commentsCount: Array.isArray(caseItem.comments) ? caseItem.comments.length : 0,
    evidenceCount: Array.isArray(caseItem.evidence) ? caseItem.evidence.length : 0
  };
}

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  next();
});

const rateWindowMs = 60 * 1000;
const rateLimit = 60;
const requestBuckets = new Map();
const threatIntelCache = new Map();
const THREAT_INTEL_TTL_MS = 60 * 60 * 1000;
const UPSTREAM_TIMEOUT_MS = Number(process.env.UPSTREAM_TIMEOUT_MS || 8000);
const WHOIS_TIMEOUT_MS = Number(process.env.WHOIS_TIMEOUT_MS || 7000);
const DETONATOR_SERVICE_URL = String(process.env.DETONATOR_SERVICE_URL || "http://127.0.0.1:8010").trim().replace(/\/+$/, "");

app.use("/api", (req, res, next) => {
  const now = Date.now();
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  const bucket = requestBuckets.get(ip);

  if (!bucket || now - bucket.startedAt > rateWindowMs) {
    requestBuckets.set(ip, { count: 1, startedAt: now });
    return next();
  }

  if (bucket.count >= rateLimit) {
    return res.status(429).json({ error: "Too many requests. Please try again shortly." });
  }

  bucket.count += 1;
  next();
});

function isLikelyDomain(value) {
  return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value);
}

function normalizeDomainInput(value) {
  const input = String(value || "").trim();
  if (!input) return "";

  try {
    const parsed = new URL(/^https?:\/\//i.test(input) ? input : `https://${input}`);
    return parsed.hostname.replace(/^www\./i, "").toLowerCase();
  } catch {
    return input.replace(/^https?:\/\//i, "").split(/[/?#]/)[0].replace(/^www\./i, "").toLowerCase();
  }
}

function parseUserDomainInput(userInput) {
  const raw = String(userInput ?? "").trim();
  if (!raw) {
    return { hostname: "", warnings: ["Empty input"] };
  }

  let candidate = raw;
  // Strip surrounding whitespace and accidental trailing punctuation
  candidate = candidate.replace(/[\s\u0000-\u001F]+$/g, "");

  // If user passed a full URL, use URL parser.
  if (/^https?:\/\//i.test(candidate)) {
    try {
      const parsed = new URL(candidate);
      const host = parsed.hostname || "";
      return {
        hostname: host.replace(/^www\./i, "").toLowerCase(),
        original: raw,
        warnings: []
      };
    } catch {
      // fall through to best-effort parsing
    }
  }

  // Best-effort parsing:
  // - remove protocol if present
  // - cut off path/query/fragment
  // - handle optional :port
  candidate = candidate.replace(/^https?:\/\//i, "");
  candidate = candidate.split(/[/?#]/)[0];
  candidate = candidate.replace(/\.$/g, "");

  // Remove optional port (example.com:443)
  candidate = candidate.replace(/:\d{1,5}$/g, "");

  // Normalize www.
  candidate = candidate.replace(/^www\./i, "").toLowerCase();

  const warnings = [];
  if (!isLikelyDomain(candidate)) {
    // still return candidate so caller can show a consistent error
    warnings.push("Input did not match the expected domain pattern.");
  }

  return { hostname: candidate, original: raw, warnings };
}


function isLikelyIp(value) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) || /^[0-9a-f:]+$/i.test(value);
}

function badRequest(res, message) {
  return res.status(400).json({ error: message });
}

function withTimeout(promise, timeoutMs, fallbackValue) {
  return Promise.race([
    promise,
    new Promise((resolve) => setTimeout(() => resolve(fallbackValue), timeoutMs))
  ]);
}

async function resolveIpv4Fast(domain) {
  const [lookupIps, resolveIps, googleData] = await Promise.all([
    withTimeout(
      dns.lookup(domain, { family: 4, all: true }).then((items) => items.map((item) => item.address)),
      2500,
      []
    ).catch(() => []),
    withTimeout(dns.resolve4(domain), 2500, []).catch(() => []),
    fetchJson(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`, { timeoutMs: 3500 }).catch(() => null)
  ]);
  const googleIps = (googleData?.Answer || [])
    .filter((answer) => Number(answer.type) === 1 || String(answer.type).toUpperCase() === "A")
    .map((answer) => answer.data)
    .filter(Boolean);
  return [...new Set([...lookupIps, ...resolveIps, ...googleIps])];
}

function getRdapEntityByRole(payload, roleName) {
  const entities = payload?.entities || [];
  for (const entity of entities) {
    if ((entity.roles || []).includes(roleName)) return entity;
    for (const nested of entity.entities || []) {
      if ((nested.roles || []).includes(roleName)) return nested;
    }
  }
  return null;
}

function getVcardField(entity, fieldName) {
  const entries = entity?.vcardArray?.[1] || [];
  const match = entries.find((entry) => String(entry?.[0] || "").toLowerCase() === fieldName.toLowerCase());
  return match?.[3] || null;
}

function getVcardAddress(entity) {
  const value = getVcardField(entity, "adr");
  if (!Array.isArray(value)) return null;

  return [
    value[2],
    value[3],
    value[4],
    value[5],
    value[6]
  ].filter(Boolean).join(", ") || null;
}

function buildEntityContact(entity) {
  if (!entity) return null;

  const contact = {
    name: getVcardField(entity, "fn") || null,
    organization: getVcardField(entity, "org") || null,
    email: getVcardField(entity, "email") || null,
    phone: getVcardField(entity, "tel") || null,
    url: getVcardField(entity, "url") || null,
    address: getVcardAddress(entity),
    handle: entity.handle || null,
    roles: Array.isArray(entity.roles) ? entity.roles : []
  };

  return Object.fromEntries(
    Object.entries(contact).filter(([, value]) => Array.isArray(value) ? value.length : Boolean(value))
  );
}

function parseWhoisText(rawText) {
  const fields = {};
  const nameServers = [];
  const statuses = [];

  for (const line of String(rawText || "").split(/\r?\n/)) {
    const match = line.match(/^\s*([^:%#][^:]{1,80}):\s*(.*?)\s*$/);
    if (!match) continue;

    const key = match[1].trim().replace(/\s+/g, " ");
    const normalizedKey = key.toLowerCase();
    const value = match[2].trim();
    if (!value) continue;

    if (normalizedKey === "name server") {
      nameServers.push(value.toUpperCase());
    } else if (normalizedKey === "domain status" || normalizedKey === "status") {
      statuses.push(value);
    }

    if (fields[key]) {
      fields[key] = Array.isArray(fields[key]) ? [...fields[key], value] : [fields[key], value];
    } else {
      fields[key] = value;
    }
  }

  return {
    fields,
    domainName: fields["Domain Name"] || fields.Domain || null,
    registrar: fields.Registrar || fields["Sponsoring Registrar"] || null,
    registrarWhoisServer: fields["Registrar WHOIS Server"] || fields["Whois Server"] || null,
    registrarUrl: fields["Registrar URL"] || fields.URL || null,
    updatedDate: fields["Updated Date"] || fields["Last Updated On"] || null,
    createdDate: fields["Creation Date"] || fields["Created Date"] || fields["Created On"] || null,
    expiresDate: fields["Registry Expiry Date"] || fields["Expiration Date"] || fields["Registrar Registration Expiration Date"] || null,
    nameServers: [...new Set(nameServers)],
    domainStatus: [...new Set(statuses)]
  };
}

function fetchWhoisText(server, query) {
  return new Promise((resolve, reject) => {
    let rawText = "";
    const socket = net.createConnection(43, server);
    const timer = setTimeout(() => {
      socket.destroy();
      const error = new Error(`WHOIS request to ${server} timed out after ${WHOIS_TIMEOUT_MS}ms.`);
      error.status = 504;
      reject(error);
    }, WHOIS_TIMEOUT_MS);

    socket.setEncoding("utf8");
    socket.on("connect", () => {
      socket.write(`${query}\r\n`);
    });
    socket.on("data", (chunk) => {
      rawText += chunk;
    });
    socket.on("end", () => {
      clearTimeout(timer);
      resolve(rawText);
    });
    socket.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

async function fetchRawWhoisWithReferral(domain) {
  const normalizedDomain = normalizeDomainInput(domain);
  const tld = normalizedDomain.split(".").pop()?.toLowerCase();
  const registryServers = {
    com: "whois.verisign-grs.com",
    net: "whois.verisign-grs.com",
    org: "whois.pir.org",
    info: "whois.afilias.net",
    biz: "whois.biz"
  };
  const registryServer = registryServers[tld];
  if (!registryServer) return null;

  const registryText = await fetchWhoisText(registryServer, normalizedDomain);
  const registryParsed = parseWhoisText(registryText);
  const referralServer = registryParsed.registrarWhoisServer;

  if (!referralServer || referralServer.toLowerCase() === registryServer.toLowerCase()) {
    return {
      registryServer,
      registry: registryParsed,
      registryText,
      registrarServer: null,
      registrar: null,
      registrarText: null
    };
  }

  try {
    const registrarText = await fetchWhoisText(referralServer, normalizedDomain);
    return {
      registryServer,
      registry: registryParsed,
      registryText,
      registrarServer: referralServer,
      registrar: parseWhoisText(registrarText),
      registrarText
    };
  } catch (error) {
    return {
      registryServer,
      registry: registryParsed,
      registryText,
      registrarServer: referralServer,
      registrar: null,
      registrarText: null,
      registrarError: error.message
    };
  }
}

function mergeRawWhoisIntoParsed(parsedData, rawWhois) {
  if (!rawWhois) return parsedData;
  const source = rawWhois.registrar || rawWhois.registry || {};
  const merged = { ...parsedData };

  merged.rawWhois = {
    registryServer: rawWhois.registryServer,
    registrarServer: rawWhois.registrarServer,
    registrarError: rawWhois.registrarError || null,
    fields: source.fields || {}
  };

  merged.domainName ||= source.domainName;
  merged.createdDate ||= source.createdDate;
  merged.expiresDate ||= source.expiresDate;
  merged.updatedDate ||= source.updatedDate;

  if ((!merged.nameServers || !merged.nameServers.length) && source.nameServers?.length) {
    merged.nameServers = source.nameServers;
  }
  if ((!merged.domainStatus || !merged.domainStatus.length) && source.domainStatus?.length) {
    merged.domainStatus = source.domainStatus;
  }
  if (source.registrar) {
    merged.registrar = {
      ...(merged.registrar || {}),
      name: merged.registrar?.name || source.registrar,
      url: merged.registrar?.url || source.registrarUrl || null
    };
  }

  return Object.fromEntries(
    Object.entries(merged).filter(([, value]) => Array.isArray(value) ? value.length : value !== null && value !== undefined)
  );
}

function parseAsnFromOrg(orgValue) {
  const text = String(orgValue || "").trim();
  const match = text.match(/^(AS\d+)\s+(.*)$/i);
  if (!match) {
    return { asn: null, name: text || null };
  }
  return {
    asn: match[1].toUpperCase(),
    name: match[2] || null
  };
}

function normalizePortTransport(value) {
  return String(value || "tcp").toLowerCase() === "udp" ? "udp" : "tcp";
}

function serviceNameForPort(port, transport = "tcp") {
  const names = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: transport === "udp" ? "DNS/UDP" : "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker API",
    2376: "Docker TLS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    9200: "Elasticsearch",
    9300: "Elasticsearch Transport",
    11211: "Memcached",
    27017: "MongoDB"
  };
  return names[Number(port)] || "Unknown";
}

function inferTechnologiesFromText(text) {
  const value = String(text || "").toLowerCase();
  const findings = [];
  const add = (name, category, evidence) => findings.push({ name, category, evidence });

  if (/nginx/.test(value)) add("nginx", "Web Server", "service banner/header");
  if (/apache/.test(value)) add("Apache", "Web Server", "service banner/header");
  if (/microsoft-iis|iis\//.test(value)) add("Microsoft IIS", "Web Server", "service banner/header");
  if (/openssh/.test(value)) add("OpenSSH", "Remote Access", "SSH banner");
  if (/wordpress|wp-content|wp-includes/.test(value)) add("WordPress", "CMS", "HTTP fingerprint");
  if (/react|_next|next\.js/.test(value)) add(/_next|next\.js/.test(value) ? "Next.js" : "React", "Frontend", "HTTP asset/header fingerprint");
  if (/php|x-powered-by:\s*php/.test(value)) add("PHP", "Backend Runtime", "header/banner");
  if (/node\.js|express/.test(value)) add("Node.js / Express", "Backend Runtime", "HTTP header/banner");
  if (/django|gunicorn/.test(value)) add("Django / Python", "Backend Runtime", "service banner/header");
  if (/ruby|rails|puma/.test(value)) add("Ruby on Rails", "Backend Framework", "service banner/header");
  if (/asp\.net|x-aspnet-version/.test(value)) add("ASP.NET", "Backend Framework", "HTTP header");
  if (/cloudflare|cf-ray|cf-cache-status/.test(value)) add("Cloudflare", "CDN / WAF", "HTTP header");
  if (/cloudfront/.test(value)) add("Amazon CloudFront", "CDN", "HTTP/Shodan metadata");
  if (/akamai/.test(value)) add("Akamai", "CDN", "HTTP/Shodan metadata");
  if (/fastly/.test(value)) add("Fastly", "CDN", "HTTP/Shodan metadata");
  if (/hsts|strict-transport-security/.test(value)) add("HSTS Enabled", "Security", "Strict-Transport-Security header");
  if (/ubuntu/.test(value)) add("Ubuntu", "Operating System", "banner/product metadata");
  if (/debian/.test(value)) add("Debian", "Operating System", "banner/product metadata");
  if (/windows/.test(value)) add("Windows", "Operating System", "banner/product metadata");

  return findings;
}

function technologiesFromShodanMetadata(item = {}) {
  const findings = [];
  const add = (name, category, evidence) => name && findings.push({ name, category, evidence });
  const product = String(item.product || "").trim();
  const cpes = Array.isArray(item.cpe) ? item.cpe : item.cpe ? [item.cpe] : [];
  const components = item.http?.components && typeof item.http.components === "object" ? item.http.components : {};

  if (product) add(product, /ssh/i.test(product) ? "Remote Access" : "Service Product", "Shodan product metadata");
  for (const cpe of cpes) {
    const parts = String(cpe).split(":");
    const vendor = parts[3];
    const name = parts[4];
    if (name) add(`${vendor ? `${vendor} ` : ""}${name}`.replace(/_/g, " "), "CPE Fingerprint", "Shodan CPE metadata");
  }
  for (const [name, component] of Object.entries(components)) {
    add(name, component?.categories?.[0] || "HTTP Component", "Shodan HTTP component fingerprint");
  }

  return findings;
}

function dedupeTechnologies(items) {
  const seen = new Set();
  return items.filter((item) => {
    const key = `${item.name}|${item.category}`.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function normalizeShodanService(item, host) {
  const port = Number(item.port);
  const transport = normalizePortTransport(item.transport);
  const ssl = item.ssl || {};
  const http = item.http || {};
  const banner = String(item.data || "").trim();
  const product = [item.product, item.version].filter(Boolean).join(" ");
  const service = item.product || item.devicetype || item._shodan?.module || serviceNameForPort(port, transport);
  const textForTech = [
    banner,
    item.product,
    item.version,
    item.os,
    http.server,
    http.title,
    JSON.stringify(http.headers || {}),
    item.hostnames?.join(" "),
    item.domains?.join(" "),
    ssl.cert?.issuer?.CN,
    ssl.cert?.subject?.CN,
    (Array.isArray(item.cpe) ? item.cpe : [item.cpe]).filter(Boolean).join(" "),
    JSON.stringify(http.components || {})
  ].filter(Boolean).join("\n");
  const tlsVersions = ssl.versions || [];
  const vulns = item.vulns && typeof item.vulns === "object" ? Object.keys(item.vulns) : [];

  return {
    ip: host.ip_str || host.ip || item.ip_str || null,
    port,
    transport,
    protocol: String(item.transport || item._shodan?.module || "").toUpperCase() || transport.toUpperCase(),
    service: String(service || serviceNameForPort(port, transport)).toUpperCase(),
    product: product || item.product || null,
    version: item.version || null,
    os: item.os || host.os || null,
    banner: banner.slice(0, 1800),
    module: item._shodan?.module || null,
    tags: item.tags || [],
    cpe: Array.isArray(item.cpe) ? item.cpe : item.cpe ? [item.cpe] : [],
    vulns,
    hostAttribution: {
      org: host.org || null,
      isp: host.isp || null,
      asn: host.asn ? `AS${String(host.asn).replace(/^AS/i, "")}` : null,
      country: host.country_name || host.country_code || null,
      city: host.city || null
    },
    hostnames: item.hostnames || host.hostnames || [],
    domains: item.domains || host.domains || [],
    observedAt: item.timestamp || host.last_update || null,
    tlsEnabled: Boolean(ssl.cert || port === 443 || /https|ssl|tls/i.test(item._shodan?.module || "")),
    tls: ssl.cert ? {
      issuer: ssl.cert.issuer?.CN || ssl.cert.issuer?.O || null,
      subject: ssl.cert.subject?.CN || null,
      expires: ssl.cert.expires || null,
      issued: ssl.cert.issued || null,
      fingerprint: ssl.cert.fingerprint?.sha256 || ssl.cert.fingerprint?.sha1 || null,
      serial: ssl.cert.serial || null,
      versions: tlsVersions,
      cipher: ssl.cipher?.name || null,
      cipherBits: ssl.cipher?.bits || null,
      san: ssl.cert.extensions?.subjectAltName || []
    } : null,
    http: {
      title: http.title || null,
      server: http.server || null,
      headers: http.headers || null,
      faviconHash: http.favicon?.hash || null,
      components: http.components || null
    },
    tlsIssues: tlsVersions.filter((version) => /TLSv1\.0|TLSv1\.1|SSLv2|SSLv3/i.test(version)),
    technologies: dedupeTechnologies([
      ...inferTechnologiesFromText(textForTech),
      ...technologiesFromShodanMetadata(item)
    ])
  };
}

function classifyExposureRisk(services, tlsSummary = {}) {
  const riskyAdminPorts = new Set([22, 23, 445, 3389, 5900, 6379, 9200, 9300, 11211, 27017, 2375, 2376]);
  let score = 0;
  const indicators = [];
  const serviceRisks = [];

  for (const service of services) {
    const risks = [];
    if (riskyAdminPorts.has(Number(service.port))) {
      score += service.port === 23 || service.port === 2375 ? 28 : 16;
      risks.push("Externally exposed administrative or infrastructure service");
      indicators.push(`${service.port}/${service.transport.toUpperCase()} externally exposes ${service.service}`);
    }
    if (/telnet|ftp|rdp|vnc|redis|mongodb|elasticsearch|docker/i.test(`${service.service} ${service.product || ""}`)) {
      score += 12;
      risks.push("Risky public service category");
    }
    if (/openssh_[0-6]\.|apache\/2\.2|php\/5|iis\/6|iis\/7/i.test(`${service.banner} ${service.product || ""}`)) {
      score += 22;
      risks.push("Potentially outdated product or end-of-life banner");
      indicators.push(`Potentially outdated product observed on ${service.port}/${service.transport.toUpperCase()}`);
    }
    if (/TLSv1\.0|TLSv1\.1|SSLv2|SSLv3/i.test(JSON.stringify(service.tls?.versions || []))) {
      score += 18;
      risks.push("Unsupported TLS protocol advertised");
      indicators.push(`Unsupported TLS protocol advertised on ${service.port}/${service.transport.toUpperCase()}`);
    }
    if ((service.vulns || []).length) {
      score += Math.min(28, service.vulns.length * 7);
      risks.push(`${service.vulns.length} Shodan vulnerability reference(s) observed`);
      indicators.push(`${service.port}/${service.transport.toUpperCase()} has Shodan vulnerability references`);
    }
    if (!service.tlsEnabled && /http|smtp|ftp|telnet/i.test(`${service.service} ${service.protocol}`)) {
      score += 5;
      risks.push("Cleartext-capable public service");
    }
    serviceRisks.push({
      ip: service.ip,
      port: service.port,
      transport: service.transport,
      service: service.service,
      severity: risks.some((risk) => /vulnerability|outdated|unsupported|administrative/i.test(risk)) ? "HIGH" : risks.length ? "MEDIUM" : "LOW",
      risks
    });
  }

  if (tlsSummary.status && String(tlsSummary.status).toUpperCase() !== "READY") {
    score += 8;
    indicators.push(`TLS scanner status is ${tlsSummary.status}`);
  }

  score += Math.min(22, Math.max(0, services.length - 3) * 4);
  const capped = Math.min(100, score);
  const severity = capped >= 85 ? "CRITICAL" : capped >= 65 ? "HIGH" : capped >= 35 ? "MEDIUM" : "LOW";
  return { score: capped, severity, indicators: [...new Set(indicators)], serviceRisks };
}

async function fetchShodanHost(ip) {
  const apiKey = String(process.env.SHODAN_API_KEY || "").trim();
  if (!apiKey) return { ip, available: false, reason: "SHODAN_API_KEY is not configured." };
  try {
    return await fetchJson(`https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(apiKey)}`, { timeoutMs: 9000 });
  } catch (error) {
    const cause = error.cause?.code || error.cause?.message || error.payload?.error || error.message;
    return { ip, available: false, reason: `Shodan lookup failed: ${cause}` };
  }
}

async function fetchInfrastructureExposure(domain) {
  const ips = (await resolveIpv4Fast(domain)).slice(0, 8);
  const shodanSettled = await Promise.allSettled(ips.map((ip) => fetchShodanHost(ip)));
  const shodanHosts = shodanSettled.map((result, index) => result.status === "fulfilled"
    ? result.value
    : { ip: ips[index], available: false, reason: result.reason?.payload?.error || result.reason?.message || "Shodan lookup failed." });

  const services = shodanHosts.flatMap((host) => Array.isArray(host.data)
    ? host.data.map((item) => normalizeShodanService(item, host)).filter((item) => Number.isFinite(item.port))
    : []);
  const technologies = dedupeTechnologies(services.flatMap((service) => service.technologies || []));
  const hostWithMeta = shodanHosts.find((host) => host && host.available !== false && (host.org || host.asn || host.isp || host.country_name)) || {};
  const lastObserved = services.map((service) => service.observedAt).filter(Boolean).sort().slice(-1)[0] || null;
  const tlsServices = services.filter((service) => service.tlsEnabled);
  const exposure = classifyExposureRisk(services);
  const protocolDistribution = services.reduce((acc, service) => {
    const key = service.service || serviceNameForPort(service.port, service.transport);
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  const serviceToInfrastructure = services.map((service) => ({
    domain,
    ip: service.ip,
    port: service.port,
    transport: service.transport,
    service: service.service,
    product: service.product,
    organization: service.hostAttribution?.org || hostWithMeta.org || null,
    asn: service.hostAttribution?.asn || (hostWithMeta.asn ? `AS${String(hostWithMeta.asn).replace(/^AS/i, "")}` : null),
    country: service.hostAttribution?.country || hostWithMeta.country_name || hostWithMeta.country_code || null,
    tlsEnabled: service.tlsEnabled,
    risk: exposure.serviceRisks.find((risk) => risk.ip === service.ip && risk.port === service.port && risk.transport === service.transport) || null
  }));
  const timeline = [
    ...services.map((service) => ({
      type: "service_observation",
      label: `${service.service || "Service"} service detected`,
      timestamp: service.observedAt || lastObserved,
      source: "Shodan host scan",
      detail: `${service.port}/${String(service.transport || "tcp").toUpperCase()} on ${service.ip || domain}`
    })),
    ...tlsServices.map((service) => ({
      type: "tls_certificate",
      label: "TLS certificate observed",
      timestamp: service.tls?.issued || service.tls?.expires || service.observedAt,
      source: "Shodan TLS metadata",
      detail: `${service.tls?.issuer || "Unknown issuer"} on ${service.port}/${String(service.transport || "tcp").toUpperCase()}`
    })),
    ...technologies.map((tech) => ({
      type: "technology_fingerprint",
      label: `${tech.name} fingerprint observed`,
      timestamp: lastObserved,
      source: tech.evidence || "Shodan fingerprint correlation",
      detail: tech.category || "Technology"
    }))
  ].filter((event) => event.timestamp || event.detail);

  return {
    domain,
    resolvedIps: ips,
    architecture: [
      "Domain",
      "DNS Resolution",
      "Resolved IP Discovery",
      "Shodan Infrastructure Lookup",
      "Port Enumeration",
      "Banner & TLS Analysis",
      "Technology Fingerprinting",
      "Threat & Exposure Correlation"
    ],
    sourceStatus: {
      shodan: String(process.env.SHODAN_API_KEY || "").trim() ? "configured" : "missing_api_key",
      crtsh: "available via /api/security/ssl",
      technology: "banner/header/favicon/CPE correlation"
    },
    hosts: shodanHosts.map((host) => ({
      ip: host.ip_str || host.ip || null,
      org: host.org || null,
      isp: host.isp || null,
      asn: host.asn ? `AS${String(host.asn).replace(/^AS/i, "")}` : null,
      os: host.os || null,
      hostnames: host.hostnames || [],
      domains: host.domains || [],
      country: host.country_name || host.country_code || null,
      city: host.city || null,
      latitude: host.latitude || null,
      longitude: host.longitude || null,
      lastUpdate: host.last_update || null,
      available: host.available !== false,
      reason: host.reason || null,
      ports: host.ports || []
    })),
    services,
    ports: [...new Set(services.map((service) => service.port))].sort((a, b) => a - b),
    protocols: [...new Set(services.map((service) => service.service).filter(Boolean))],
    tls: {
      enabled: tlsServices.length > 0,
      serviceCount: tlsServices.length,
      certificates: tlsServices.map((service) => ({ ip: service.ip, port: service.port, ...service.tls })).filter((cert) => cert.issuer || cert.subject || cert.fingerprint)
    },
    technology: {
      items: technologies,
      operatingSystems: [...new Set(services.map((service) => service.os).filter(Boolean))],
      sources: ["Shodan metadata", "service banners", "HTTP headers", "favicon hashes", "TLS metadata", "CPE fingerprints"]
    },
    attribution: {
      hostingProvider: hostWithMeta.org || hostWithMeta.isp || null,
      asn: hostWithMeta.asn ? `AS${String(hostWithMeta.asn).replace(/^AS/i, "")}` : null,
      organization: hostWithMeta.org || null,
      country: hostWithMeta.country_name || hostWithMeta.country_code || null,
      city: hostWithMeta.city || null
    },
    exposure: {
      ...exposure,
      classification: services.length ? `${exposure.severity} PUBLIC EXPOSURE` : "UNOBSERVED",
      openPortCount: services.length ? [...new Set(services.map((service) => service.port))].length : 0,
      serviceCount: services.length,
      lastObserved,
      protocolDistribution,
      serviceToInfrastructure,
      unsupportedTlsServices: services.filter((service) => (service.tlsIssues || []).length).map((service) => ({
        ip: service.ip,
        port: service.port,
        issues: service.tlsIssues
      })),
      eolSoftware: exposure.serviceRisks.filter((risk) => (risk.risks || []).some((item) => /outdated|end-of-life/i.test(item))),
      exposedManagement: exposure.serviceRisks.filter((risk) => (risk.risks || []).some((item) => /administrative|infrastructure/i.test(item)))
    },
    timeline,
    integrations: {
      shodan: "https://developer.shodan.io",
      crtsh: "https://crt.sh"
    }
  };
}

async function fetchJson(url, options = {}) {
  const { timeoutMs = UPSTREAM_TIMEOUT_MS, ...fetchOptions } = options;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, { ...fetchOptions, signal: controller.signal });
    const text = await response.text();
    let data;

    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = { raw: text };
    }

    if (!response.ok) {
      const error = new Error(`Upstream request failed with status ${response.status}`);
      error.status = response.status;
      error.payload = data;
      throw error;
    }

    return data;
  } catch (error) {
    if (error.name === "AbortError") {
      const timeoutError = new Error(`Upstream request timed out after ${timeoutMs}ms.`);
      timeoutError.status = 504;
      timeoutError.payload = { url };
      throw timeoutError;
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchText(url, options = {}) {
  const { timeoutMs = UPSTREAM_TIMEOUT_MS, ...fetchOptions } = options;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, { ...fetchOptions, signal: controller.signal });
    const text = await response.text();

    if (!response.ok) {
      const error = new Error(`Upstream request failed with status ${response.status}`);
      error.status = response.status;
      error.payload = text;
      throw error;
    }

    return text;
  } catch (error) {
    if (error.name === "AbortError") {
      const timeoutError = new Error(`Upstream request timed out after ${timeoutMs}ms.`);
      timeoutError.status = 504;
      timeoutError.payload = { url };
      throw timeoutError;
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchRedirectStep(url, method = "HEAD") {
  const response = await fetch(url, { method, redirect: "manual" });
  if ((response.status === 405 || response.status === 501) && method === "HEAD") {
    return fetch(url, { method: "GET", redirect: "manual" });
  }
  return response;
}

async function fetchDomainRdapWithFallback(domain) {
  const normalizedDomain = normalizeDomainInput(domain);
  const attempts = [];
  const tld = normalizedDomain.split(".").pop()?.toLowerCase();
  if (tld === "com" || tld === "net") {
    attempts.push(`https://rdap.verisign.com/${tld}/v1/domain/${encodeURIComponent(normalizedDomain.toUpperCase())}`);
  }
  attempts.push(`https://rdap.org/domain/${encodeURIComponent(normalizedDomain)}`);

  let lastError = null;
  for (const url of attempts) {
    try {
      return await fetchJson(url);
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError || new Error("Failed to fetch RDAP domain data.");
}

function parseWhoisFromRdap(rdapData) {
  if (!rdapData || typeof rdapData !== "object") {
    return {};
  }

  const result = {
    domainName: rdapData.ldhName || rdapData.unicodeName || null,
    handle: rdapData.handle || null,
    objectClassName: rdapData.objectClassName || null,
    source: "RDAP"
  };

  if (Array.isArray(rdapData.events)) {
    result.events = rdapData.events;
    for (const event of rdapData.events) {
      const action = String(event.eventAction || "").toLowerCase();
      if (action === "registration" && event.eventDate) {
        result.createdDate = event.eventDate;
      } else if (action === "expiration" && event.eventDate) {
        result.expiresDate = event.eventDate;
      } else if (action === "last changed" && event.eventDate) {
        result.updatedDate = event.eventDate;
      }
    }
  }

  if (Array.isArray(rdapData.nameservers)) {
    const nameservers = rdapData.nameservers
      .map((ns) => ns.ldhName || ns.unicodeName)
      .filter(Boolean);
    if (nameservers.length > 0) {
      result.nameServers = nameservers;
    }
  }

  // Extract status
  if (Array.isArray(rdapData.status)) {
    result.domainStatus = rdapData.status;
  }

  const registrarEntity = getRdapEntityByRole(rdapData, "registrar");
  if (registrarEntity) {
    const registrarInfo = buildEntityContact(registrarEntity) || {};
    const ianaId = registrarEntity.publicIds?.find((item) => /iana/i.test(item?.type || ""))?.identifier;
    if (ianaId) {
      registrarInfo.ianaId = ianaId;
    }
    result.registrar = registrarInfo;
  }

  const registrantEntity = getRdapEntityByRole(rdapData, "registrant");
  if (registrantEntity) {
    result.registrant = buildEntityContact(registrantEntity);
  }

  const adminEntity = getRdapEntityByRole(rdapData, "administrative");
  if (adminEntity) {
    result.adminContact = buildEntityContact(adminEntity);
  }

  const techEntity = getRdapEntityByRole(rdapData, "technical");
  if (techEntity) {
    result.technicalContact = buildEntityContact(techEntity);
  }

  const abuseEntity = getRdapEntityByRole(rdapData, "abuse");
  if (abuseEntity) {
    result.abuseContact = buildEntityContact(abuseEntity);
  }

  if (rdapData.secureDNS) {
    result.dnssec = rdapData.secureDNS.delegationSigned !== undefined ? rdapData.secureDNS.delegationSigned : null;
  }

  return Object.fromEntries(
    Object.entries(result).filter(([, value]) => Array.isArray(value) ? value.length : value !== null && value !== undefined)
  );
}

function inferMimeTypeFromUrl(url) {
  const pathname = (() => {
    try {
      return new URL(url).pathname.toLowerCase();
    } catch {
      return "";
    }
  })();

  if (pathname.endsWith(".css")) return "text/css (inferred)";
  if (pathname.endsWith(".js")) return "application/javascript (inferred)";
  if (pathname.endsWith(".svg")) return "image/svg+xml (inferred)";
  if (pathname.endsWith(".png")) return "image/png (inferred)";
  if (pathname.endsWith(".jpg") || pathname.endsWith(".jpeg")) return "image/jpeg (inferred)";
  if (pathname.endsWith(".webp")) return "image/webp (inferred)";
  if (pathname.endsWith(".gif")) return "image/gif (inferred)";
  if (pathname.endsWith(".woff2")) return "font/woff2 (inferred)";
  if (pathname.endsWith(".woff")) return "font/woff (inferred)";
  if (pathname.endsWith(".ttf")) return "font/ttf (inferred)";
  if (pathname.endsWith(".json")) return "application/json (inferred)";
  if (pathname.endsWith(".html") || pathname.endsWith(".htm")) return "text/html (inferred)";
  return null;
}

async function resolveHostAddresses(hostname) {
  if (!hostname) {
    return { ipv4: [], ipv6: [], primaryIp: null, source: "dns_resolution" };
  }

  const [ipv4, ipv6] = await Promise.all([
    dns.resolve4(hostname).catch(() => []),
    dns.resolve6(hostname).catch(() => [])
  ]);

  return {
    ipv4,
    ipv6,
    primaryIp: ipv4[0] || ipv6[0] || null,
    source: "dns_resolution"
  };
}

async function fetchHttpTrace(url) {
  const redirectChain = [];
  let currentUrl = url;
  let finalResponse = null;

  for (let step = 0; step < 6; step += 1) {
    const response = await fetchRedirectStep(currentUrl);
    const location = response.headers.get("location");
    redirectChain.push({
      url: currentUrl,
      status: response.status,
      location: location ? new URL(location, currentUrl).toString() : null
    });

    if (location) {
      currentUrl = new URL(location, currentUrl).toString();
      continue;
    }

    finalResponse = response;
    break;
  }

  const headers = finalResponse
    ? {
        server: finalResponse.headers.get("server") || null,
        contentType: finalResponse.headers.get("content-type") || null,
        contentLength: finalResponse.headers.get("content-length") || null,
        contentSecurityPolicy: finalResponse.headers.get("content-security-policy") || null,
        strictTransportSecurity: finalResponse.headers.get("strict-transport-security") || null,
        xFrameOptions: finalResponse.headers.get("x-frame-options") || null,
        xContentTypeOptions: finalResponse.headers.get("x-content-type-options") || null
      }
    : {};

  return {
    finalUrl: currentUrl,
    finalStatus: finalResponse?.status || redirectChain.slice(-1)[0]?.status || null,
    redirectChain,
    headers,
    mimeType: headers.contentType || inferMimeTypeFromUrl(currentUrl),
    source: "http_reconstruction"
  };
}

async function fetchTlsSnapshot(hostname) {
  if (!hostname) return null;

  return new Promise((resolve) => {
    const socket = tls.connect(
      443,
      hostname,
      {
        servername: hostname,
        rejectUnauthorized: false,
        timeout: 5000
      },
      () => {
        const cert = socket.getPeerCertificate(true);
        socket.end();
        resolve({
          issuer: cert?.issuer?.O || cert?.issuer?.CN || null,
          subject: cert?.subject?.CN || null,
          validFrom: cert?.valid_from || null,
          validTo: cert?.valid_to || null,
          source: "tls_inspection"
        });
      }
    );

    socket.on("error", () => resolve(null));
    socket.on("timeout", () => {
      socket.destroy();
      resolve(null);
    });
  });
}

function buildEnrichmentConfidence(enrichment) {
  let score = 0;
  if (enrichment.primaryIp) score += 30;
  if (enrichment.status) score += 20;
  if (enrichment.mimeType) score += 10;
  if (enrichment.headers?.server) score += 10;
  if (Array.isArray(enrichment.redirectChain) && enrichment.redirectChain.length) score += 10;
  if (enrichment.tls?.issuer) score += 10;
  if (enrichment.domain) score += 10;
  const capped = Math.min(100, score);
  return {
    score: capped,
    level: capped >= 85 ? "high" : capped >= 55 ? "medium" : "low"
  };
}

async function enrichUrlscanRequestEntry(entry) {
  const request = entry?.request || {};
  const nestedRequest = request?.request || {};
  const response = entry?.response || {};
  const requestUrl = request?.url || nestedRequest?.url || entry?.url || response?.url;

  if (!requestUrl) {
    return {
      ...entry,
      enrichment: {
        url: null,
        hostname: null,
        ip: null,
        status: null,
        mimeType: null,
        sourceTags: [],
        redirectChain: [],
        headers: {},
        tls: null,
        confidence: { score: 0, level: "low" }
      }
    };
  }

  let hostname = null;
  try {
    hostname = new URL(requestUrl).hostname;
  } catch {
    hostname = null;
  }

  const [dnsData, httpData, tlsData] = await Promise.all([
    resolveHostAddresses(hostname).catch(() => ({ ipv4: [], ipv6: [], primaryIp: null, source: "dns_resolution" })),
    fetchHttpTrace(requestUrl).catch(() => ({
      finalUrl: requestUrl,
      finalStatus: null,
      redirectChain: [],
      headers: {},
      mimeType: inferMimeTypeFromUrl(requestUrl),
      source: "http_reconstruction"
    })),
    fetchTlsSnapshot(hostname).catch(() => null)
  ]);

  const enrichment = {
    url: requestUrl,
    hostname,
    domain: hostname,
    ip: dnsData.primaryIp,
    primaryIp: dnsData.primaryIp,
    ips: dnsData.ipv4,
    ipv6: dnsData.ipv6,
    status: httpData.finalStatus,
    mimeType: httpData.mimeType,
    headers: httpData.headers,
    redirectChain: httpData.redirectChain,
    tls: tlsData,
    sourceTags: ["DNS Resolution", "HTTP Scanner", "TLS Analyzer"].filter(Boolean)
  };

  enrichment.confidence = buildEnrichmentConfidence(enrichment);

  return {
    ...entry,
    enrichment
  };
}

async function fetchUrlscanJson(url, options = {}) {
  const apiKey = String(process.env.URLSCAN_API_KEY || "").trim();
  if (!apiKey) {
    const error = new Error("URLSCAN_API_KEY is not configured on the server.");
    error.status = 500;
    throw error;
  }

  return fetchJson(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "API-Key": apiKey,
      ...(options.headers || {})
    }
  });
}

function extractUrlscanErrorMessage(error) {
  const payload = error?.payload;
  if (!payload) return error?.message || "URLScan request failed.";
  if (typeof payload === "string") return payload;
  return (
    payload.message ||
    payload.description ||
    payload.detail ||
    payload.error ||
    error?.message ||
    "URLScan request failed."
  );
}

function detectThreatIntelType(rawValue) {
  const value = String(rawValue || "").trim();
  if (!value) return "unknown";
  if (/^https?:\/\//i.test(value)) return "url";
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return "ip";
  if (/^[a-f0-9]{32,128}$/i.test(value)) return "hash";
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value)) return "domain";
  return "unknown";
}

function normalizeThreatInput(rawValue) {
  const value = String(rawValue || "").trim();
  const type = detectThreatIntelType(value);
  if (type === "url") {
    try {
      const parsed = new URL(value);
      parsed.hash = "";
      return parsed.toString();
    } catch {
      return value;
    }
  }
  return value.toLowerCase();
}

async function fetchAbuseChJson(url, payload) {
  const apiKey = String(process.env.ABUSECH_API_KEY || "").trim();
  if (!apiKey) {
    const error = new Error("ABUSECH_API_KEY is not configured on the server.");
    error.status = 500;
    throw error;
  }

  return fetchJson(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Auth-Key": apiKey
    },
    body: JSON.stringify(payload)
  });
}

function describeThreatType(rawType) {
  const value = String(rawType || "").toLowerCase();
  if (value.includes("botnet_cc") || value.includes("c2")) return "Command & Control";
  if (value.includes("phishing")) return "Credential Harvesting";
  if (value.includes("payload_delivery")) return "Malware Hosting";
  if (value.includes("malware_download")) return "Malware Distribution";
  if (value.includes("scanner")) return "Scanner";
  return rawType || "Unknown";
}

function isTrustedASN(asnOrg) {
  const value = String(asnOrg || "").toLowerCase();
  return ["google", "cloudflare", "microsoft", "amazon", "akamai"].some((item) => value.includes(item));
}

function classifyEntity(input, asnOrg) {
  const normalized = String(input || "").trim().toLowerCase();
  const org = String(asnOrg || "").toLowerCase();
  if (normalized === "8.8.8.8" || normalized === "1.1.1.1") return "Public DNS Resolver";
  if (org.includes("cloudflare")) return "CDN / Reverse Proxy";
  if (org.includes("google")) return "Web Platform / Cloud Infra";
  if (org.includes("amazon") || org.includes("microsoft") || org.includes("digitalocean") || org.includes("linode")) return "Hosting Server";
  return "Unknown Infrastructure";
}

function getAbusePotential(entityType) {
  const value = String(entityType || "").toLowerCase();
  if (value.includes("dns")) return "DNS amplification / resolver misuse";
  if (value.includes("hosting")) return "Malware hosting or payload delivery";
  if (value.includes("cdn")) return "Phishing or origin shielding through edge delivery";
  return "Low general misuse risk";
}

function severityFromThreatType(rawType) {
  const value = String(rawType || "").toLowerCase();
  if (value.includes("botnet_cc") || value.includes("c2")) return 95;
  if (value.includes("phishing")) return 80;
  if (value.includes("payload_delivery") || value.includes("malware")) return 75;
  if (value.includes("scanner")) return 45;
  return 35;
}

function mapThreatFoxItem(item, sourceLabel) {
  return {
    source: sourceLabel,
    ioc: item.ioc || item.host || null,
    iocType: item.ioc_type || null,
    threatType: item.threat_type || null,
    threatLabel: describeThreatType(item.threat_type),
    malware: item.malware || item.malware_printable || null,
    confidence: Number(item.confidence_level || 0),
    firstSeen: item.first_seen || null,
    lastSeen: item.last_seen || null,
    reference: item.reference || item.urlhaus_reference || null,
    tags: Array.isArray(item.tags) ? item.tags : [],
    reporter: item.reporter || null
  };
}

async function queryThreatFoxIoc(searchTerm) {
  const data = await fetchAbuseChJson("https://threatfox-api.abuse.ch/api/v1/", {
    query: "search_ioc",
    search_term: searchTerm,
    exact_match: false
  });

  return Array.isArray(data?.data) ? data.data.map((item) => mapThreatFoxItem(item, "abuse.ch / ThreatFox")) : [];
}

async function queryThreatFoxHash(searchTerm) {
  const data = await fetchAbuseChJson("https://threatfox-api.abuse.ch/api/v1/", {
    query: "search_hash",
    hash: searchTerm
  });

  return Array.isArray(data?.data) ? data.data.map((item) => mapThreatFoxItem(item, "abuse.ch / ThreatFox")) : [];
}

function vtUrlId(url) {
  return Buffer.from(url).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function queryOptionalExternalFeeds(input, type, normalizedInput) {
  const feeds = [];
  const vtKey = String(process.env.VIRUSTOTAL_API_KEY || "").trim();
  const abuseIpdbKey = String(process.env.ABUSEIPDB_API_KEY || "").trim();
  const otxKey = String(process.env.OTX_API_KEY || process.env.ALIENVAULT_OTX_API_KEY || "").trim();

  if (vtKey && ["ip", "domain", "url", "hash"].includes(type)) {
    const vtPath = type === "ip"
      ? `ip_addresses/${encodeURIComponent(normalizedInput)}`
      : type === "domain"
        ? `domains/${encodeURIComponent(normalizedInput)}`
        : type === "url"
          ? `urls/${vtUrlId(normalizedInput)}`
          : `files/${encodeURIComponent(normalizedInput)}`;
    const data = await fetchJson(`https://www.virustotal.com/api/v3/${vtPath}`, {
      headers: { "x-apikey": vtKey }
    }).catch((error) => ({ error: error.message }));
    const stats = data?.data?.attributes?.last_analysis_stats || {};
    feeds.push({
      provider: "VirusTotal",
      configured: true,
      malicious: Number(stats.malicious || 0),
      suspicious: Number(stats.suspicious || 0),
      harmless: Number(stats.harmless || 0),
      undetected: Number(stats.undetected || 0),
      reputation: data?.data?.attributes?.reputation ?? null,
      error: data.error || null
    });
  } else {
    feeds.push({ provider: "VirusTotal", configured: false, error: "VIRUSTOTAL_API_KEY is not configured." });
  }

  if (abuseIpdbKey && type === "ip") {
    const data = await fetchJson(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(normalizedInput)}&maxAgeInDays=90&verbose=true`, {
      headers: { Key: abuseIpdbKey, Accept: "application/json" }
    }).catch((error) => ({ error: error.message }));
    feeds.push({
      provider: "AbuseIPDB",
      configured: true,
      abuseConfidenceScore: data?.data?.abuseConfidenceScore ?? null,
      totalReports: data?.data?.totalReports ?? null,
      usageType: data?.data?.usageType || null,
      isp: data?.data?.isp || null,
      countryCode: data?.data?.countryCode || null,
      error: data.error || null
    });
  } else {
    feeds.push({ provider: "AbuseIPDB", configured: Boolean(abuseIpdbKey), error: type === "ip" ? "ABUSEIPDB_API_KEY is not configured." : "Applies to IP indicators only." });
  }

  if (otxKey && ["ip", "domain", "url"].includes(type)) {
    const otxType = type === "ip" ? "IPv4" : type === "domain" ? "domain" : "URL";
    const data = await fetchJson(`https://otx.alienvault.com/api/v1/indicators/${otxType}/${encodeURIComponent(normalizedInput)}/general`, {
      headers: { "X-OTX-API-KEY": otxKey }
    }).catch((error) => ({ error: error.message }));
    feeds.push({
      provider: "AlienVault OTX",
      configured: true,
      pulseCount: Number(data?.pulse_info?.count || 0),
      pulses: (data?.pulse_info?.pulses || []).slice(0, 5).map((pulse) => ({
        name: pulse.name,
        malwareFamilies: pulse.malware_families || [],
        tags: pulse.tags || []
      })),
      error: data.error || null
    });
  } else {
    feeds.push({ provider: "AlienVault OTX", configured: Boolean(otxKey), error: otxKey ? "Unsupported indicator type." : "OTX_API_KEY is not configured." });
  }

  return feeds;
}

async function buildThreatIntelEnrichment(input, type, normalizedInput) {
  const enrichment = {
    dns: null,
    http: null,
    tls: null,
    network: null
  };

  if (type === "ip") {
    const ipData = await fetchJson(`https://ipinfo.io/${encodeURIComponent(normalizedInput)}/json?token=${encodeURIComponent(process.env.IPINFO_TOKEN || "")}`).catch(() => null);
    enrichment.network = ipData ? {
      ip: ipData.ip || normalizedInput,
      hostname: ipData.hostname || null,
      org: parseAsnFromOrg(ipData.org).name || ipData.org || null,
      asn: parseAsnFromOrg(ipData.org).asn || null,
      city: ipData.city || null,
      region: ipData.region || null,
      country: ipData.country || null,
      timezone: ipData.timezone || null,
      postal: ipData.postal || null,
      coordinates: ipData.loc || null
    } : null;
    return enrichment;
  }

  if (type === "domain" || type === "url") {
    const targetDomain = type === "url" ? new URL(normalizedInput).hostname.replace(/^www\./i, "") : normalizedInput;
    const [dnsData, tlsData, domainRdap] = await Promise.all([
      fetchJson(`https://dns.google/resolve?name=${encodeURIComponent(targetDomain)}&type=A`).catch(() => null),
      fetchJson(`https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(targetDomain)}&all=done&fromCache=on`).catch(() => null),
      fetchDomainRdapWithFallback(targetDomain).catch(() => null)
    ]);

    const primaryIp = dnsData?.Answer?.[0]?.data || null;
    const ipProfile = primaryIp && process.env.IPINFO_TOKEN
      ? await fetchJson(`https://ipinfo.io/${encodeURIComponent(primaryIp)}/json?token=${encodeURIComponent(process.env.IPINFO_TOKEN)}`).catch(() => null)
      : null;

    enrichment.dns = dnsData ? {
      domain: targetDomain,
      addresses: [...new Set((dnsData.Answer || []).map((answer) => answer.data).filter(Boolean))]
    } : null;

    enrichment.network = domainRdap || ipProfile ? {
      registrar: getVcardField(getRdapEntityByRole(domainRdap, "registrar"), "fn") || null,
      nameservers: (domainRdap?.nameservers || []).map((item) => item.ldhName || item.unicodeName).filter(Boolean),
      primaryIp,
      org: ipProfile?.org || null,
      asn: parseAsnFromOrg(ipProfile?.org).asn || null,
      country: ipProfile?.country || null
    } : null;

    enrichment.tls = tlsData ? {
      status: tlsData.status || tlsData?.ssllabs?.status || null,
      issuer: tlsData?.endpoints?.[0]?.details?.cert?.issuerLabel || null
    } : null;

    if (type === "url") {
      const httpTrace = await fetchHttpTrace(normalizedInput).catch(() => null);
      enrichment.http = httpTrace ? {
        finalUrl: httpTrace.finalUrl,
        status: httpTrace.finalStatus,
        mimeType: httpTrace.mimeType,
        redirectChain: httpTrace.redirectChain,
        headers: httpTrace.headers
      } : null;
    }
  }

  return enrichment;
}

function scoreThreatIntel({ hits, enrichment }) {
  const threatScore = hits.reduce((max, item) => Math.max(max, item.confidence || 0, severityFromThreatType(item.threatType)), 0);
  let contextScore = 0;

  const orgText = `${enrichment?.network?.org || ""} ${enrichment?.network?.asn || ""}`.toLowerCase();
  if (isTrustedASN(orgText)) contextScore -= 10;
  if (/bulletproof|anonymous|offshore/.test(orgText)) contextScore += 10;
  if (!hits.length && !enrichment?.network?.asn) contextScore += 10;
  if (enrichment?.http?.status && [301, 302, 307, 308].includes(enrichment.http.status)) contextScore += 5;
  if (hits.some((item) => item.lastSeen && (Date.now() - new Date(item.lastSeen).getTime()) < 30 * 24 * 60 * 60 * 1000)) contextScore += 5;

  const finalScore = Math.max(0, Math.min(100, threatScore + contextScore));
  const band = finalScore >= 70 ? "high" : finalScore >= 30 ? "medium" : "low";
  const classification = hits.length
    ? "malicious"
    : isTrustedASN(orgText)
      ? "clean"
      : contextScore > 0
      ? "suspicious"
      : "clean";

  return { threat: threatScore, context: contextScore, final: finalScore, band, classification };
}

function buildThreatIntelSummary(hits, scoring) {
  const topHit = hits[0] || null;
  return {
    status: scoring.classification === "malicious"
      ? "MALICIOUS (Known Threat Intelligence)"
      : scoring.classification === "suspicious"
        ? "UNKNOWN / SUSPICIOUS"
        : "CLEAN (No Known Threat Intelligence)",
    threatType: topHit?.threatLabel || "No known threat classification",
    malwareFamily: topHit?.malware || null,
    confidenceScore: scoring.final,
    confidenceBand: scoring.band,
    source: hits.length ? "abuse.ch" : "No direct abuse.ch hit"
  };
}

function buildThreatIntelReputation(hits, enrichment) {
  if (hits.length) return "SUSPICIOUS";
  return isTrustedASN(enrichment?.network?.org || enrichment?.network?.asn) ? "TRUSTED" : "UNKNOWN";
}

function buildThreatIntelCacheKey(input, type) {
  return crypto.createHash("sha256").update(`${type}:${input}`).digest("hex");
}

function readThreatIntelCache(key) {
  const cached = threatIntelCache.get(key);
  if (!cached) return null;
  if (Date.now() > cached.expiresAt) {
    threatIntelCache.delete(key);
    return null;
  }
  return cached.value;
}

function writeThreatIntelCache(key, value) {
  threatIntelCache.set(key, {
    value,
    expiresAt: Date.now() + THREAT_INTEL_TTL_MS
  });
}

function buildThreatIntelExplanation({ input, type, hits, enrichment, scores, classification }) {
  const topHit = hits[0];
  if (classification === "malicious" && topHit) {
    return `${input} matched known abuse.ch intelligence with ${topHit.threatLabel || "threat activity"} context${topHit.malware ? ` tied to ${topHit.malware}` : ""}. Final score ${scores.final}/100 (${scores.band}).`;
  }

  if (isTrustedASN(enrichment?.network?.org || enrichment?.network?.asn)) {
    return `This entity belongs to ${enrichment?.network?.org || enrichment?.network?.asn}, a trusted infrastructure provider. No malicious activity was detected in abuse.ch and the current risk remains low.`;
  }

  if (classification === "suspicious") {
    return `${input} has no direct abuse.ch hit, but enrichment raised concern due to incomplete trust context or elevated infrastructure signals. Final score ${scores.final}/100 (${scores.band}).`;
  }

  const org = enrichment?.network?.org || enrichment?.network?.asn || "no strong provider context";
  return `${input} has no direct abuse.ch hits. Current enrichment points to ${org}, so the result is clean from known intelligence perspective, not proven safe. Final score ${scores.final}/100 (${scores.band}).`;
}

async function collectThreatHitsForIndicator(normalizedInput, type) {
  const iocs = new Set([normalizedInput]);

  if (type === "url") {
    try {
      const parsed = new URL(normalizedInput);
      iocs.add(parsed.hostname.replace(/^www\./i, ""));
    } catch {}
  }

  if (type === "domain") {
    const dnsData = await fetchJson(`https://dns.google/resolve?name=${encodeURIComponent(normalizedInput)}&type=A`).catch(() => null);
    (dnsData?.Answer || []).forEach((answer) => answer?.data && iocs.add(answer.data));
  }

  const hits = (
    await Promise.all(
      [...iocs].map((ioc) => (type === "hash" ? queryThreatFoxHash(ioc) : queryThreatFoxIoc(ioc)).catch(() => []))
    )
  ).flat();

  return hits
    .filter((item, index, arr) =>
      index === arr.findIndex((candidate) =>
        candidate.source === item.source &&
        candidate.ioc === item.ioc &&
        candidate.threatType === item.threatType &&
        candidate.malware === item.malware
      )
    )
    .sort((a, b) => (b.confidence || 0) - (a.confidence || 0));
}

function summarizeWatchSnapshot(indicator, type, enrichment, hits, scoring) {
  const network = enrichment?.network || {};
  const dnsInfo = enrichment?.dns || {};
  const http = enrichment?.http || {};
  const tls = enrichment?.tls || {};

  if (type === "domain") {
    return {
      label: "Domain snapshot",
      totalIps: (dnsInfo.addresses || []).length,
      ips: dnsInfo.addresses || [],
      nameservers: network.nameservers || [],
      registrar: network.registrar || null,
      org: network.org || null,
      asn: network.asn || null,
      country: network.country || null,
      secureDns: typeof network.secureDns === "boolean" ? network.secureDns : null,
      hitCount: hits.length,
      riskLevel: scoring.band.toUpperCase()
    };
  }

  if (type === "ip") {
    return {
      label: "IP snapshot",
      ip: network.ip || indicator,
      hostname: network.hostname || null,
      org: network.org || null,
      asn: network.asn || null,
      country: network.country || null,
      city: network.city || null,
      region: network.region || null,
      hitCount: hits.length,
      riskLevel: scoring.band.toUpperCase()
    };
  }

  if (type === "url") {
    return {
      label: "URL snapshot",
      finalUrl: http.finalUrl || indicator,
      finalStatus: http.status || null,
      mimeType: http.mimeType || null,
      redirectSteps: Array.isArray(http.redirectChain) ? http.redirectChain.length : 0,
      host: (() => {
        try {
          return new URL(indicator).hostname;
        } catch {
          return null;
        }
      })(),
      hitCount: hits.length,
      riskLevel: scoring.band.toUpperCase(),
      tlsIssuer: tls.issuer || null
    };
  }

  return {
    label: "Hash snapshot",
    hash: indicator,
    hitCount: hits.length,
    malware: hits[0]?.malware || null,
    riskLevel: scoring.band.toUpperCase()
  };
}

function compareWatchSnapshots(previous, current, type) {
  if (!previous) {
    return ["Initial monitoring baseline created."];
  }

  const changes = [];
  const prevSummary = previous.summary || {};
  const nextSummary = current.summary || {};
  const prevIntel = previous.intel || {};
  const nextIntel = current.intel || {};

  if (prevIntel.classification !== nextIntel.classification) {
    changes.push(`Classification changed from ${prevIntel.classification || "unknown"} to ${nextIntel.classification || "unknown"}.`);
  }
  if (prevIntel.hitCount !== nextIntel.hitCount) {
    changes.push(`Threat intel hit count changed from ${prevIntel.hitCount || 0} to ${nextIntel.hitCount || 0}.`);
  }
  if ((prevIntel.topMalware || null) !== (nextIntel.topMalware || null)) {
    changes.push(`Top malware attribution changed from ${prevIntel.topMalware || "none"} to ${nextIntel.topMalware || "none"}.`);
  }

  if (type === "domain") {
    if (!sameStringArray(prevSummary.ips, nextSummary.ips)) {
      changes.push("Resolved IP set changed.");
    }
    if (!sameStringArray(prevSummary.nameservers, nextSummary.nameservers)) {
      changes.push("Nameserver set changed.");
    }
    if ((prevSummary.registrar || null) !== (nextSummary.registrar || null)) {
      changes.push(`Registrar changed from ${prevSummary.registrar || "unknown"} to ${nextSummary.registrar || "unknown"}.`);
    }
  } else if (type === "ip") {
    if ((prevSummary.org || null) !== (nextSummary.org || null)) {
      changes.push(`Network organization changed from ${prevSummary.org || "unknown"} to ${nextSummary.org || "unknown"}.`);
    }
    if ((prevSummary.country || null) !== (nextSummary.country || null)) {
      changes.push(`Country changed from ${prevSummary.country || "unknown"} to ${nextSummary.country || "unknown"}.`);
    }
  } else if (type === "url") {
    if ((prevSummary.finalUrl || null) !== (nextSummary.finalUrl || null)) {
      changes.push("Final destination URL changed.");
    }
    if ((prevSummary.finalStatus || null) !== (nextSummary.finalStatus || null)) {
      changes.push(`HTTP status changed from ${prevSummary.finalStatus || "unknown"} to ${nextSummary.finalStatus || "unknown"}.`);
    }
    if ((prevSummary.redirectSteps || 0) !== (nextSummary.redirectSteps || 0)) {
      changes.push(`Redirect chain length changed from ${prevSummary.redirectSteps || 0} to ${nextSummary.redirectSteps || 0}.`);
    }
  } else if (type === "hash") {
    if ((prevSummary.malware || null) !== (nextSummary.malware || null)) {
      changes.push(`Malware association changed from ${prevSummary.malware || "none"} to ${nextSummary.malware || "none"}.`);
    }
  }

  return changes;
}

async function executeWatchCheck(watch) {
  const indicator = String(watch?.indicator || "").trim();
  const normalizedInput = normalizeThreatInput(indicator);
  const type = String(watch?.indicatorType || "").trim().toLowerCase() || detectThreatIntelType(normalizedInput);
  const checkedAt = new Date().toISOString();

  const hits = await collectThreatHitsForIndicator(normalizedInput, type).catch(() => []);
  const enrichment = await buildThreatIntelEnrichment(indicator, type, normalizedInput).catch(() => ({
    dns: null,
    http: null,
    tls: null,
    network: null
  }));
  const scoring = scoreThreatIntel({ hits, enrichment });
  const reputation = buildThreatIntelReputation(hits, enrichment);

  const snapshot = {
    checkedAt,
    type,
    intel: {
      hitCount: hits.length,
      classification: scoring.classification,
      reputation,
      riskLevel: scoring.band.toUpperCase(),
      topMalware: hits[0]?.malware || null,
      topThreat: hits[0]?.threatLabel || null
    },
    summary: summarizeWatchSnapshot(indicator, type, enrichment, hits, scoring)
  };

  const changes = compareWatchSnapshots(watch?.lastSnapshot || null, snapshot, type);
  const alertLevel = changes.length && changes[0] !== "Initial monitoring baseline created."
    ? (snapshot.intel.classification === "malicious" ? "high" : "medium")
    : "info";

  return {
    snapshot,
    changes,
    latestStatus: `${snapshot.intel.classification.toUpperCase()} | ${snapshot.intel.riskLevel}`,
    alertLevel
  };
}

function compactForAi(value, depth = 0) {
  if (value == null) return value;
  if (typeof value === "string") {
    return value.length > 800 ? `${value.slice(0, 800)}...` : value;
  }
  if (typeof value !== "object") return value;
  if (depth >= 4) {
    if (Array.isArray(value)) return value.slice(0, 5);
    return "[Truncated object]";
  }
  if (Array.isArray(value)) {
    return value.slice(0, 8).map((entry) => compactForAi(entry, depth + 1));
  }

  return Object.fromEntries(
    Object.entries(value)
      .slice(0, 20)
      .map(([key, entry]) => [key, compactForAi(entry, depth + 1)])
  );
}

function extractOpenAiText(payload) {
  if (typeof payload?.output_text === "string" && payload.output_text.trim()) {
    return payload.output_text.trim();
  }

  const messages = [];
  for (const item of payload?.output || []) {
    for (const content of item?.content || []) {
      if (typeof content?.text === "string" && content.text.trim()) {
        messages.push(content.text.trim());
      } else if (typeof content?.text?.value === "string" && content.text.value.trim()) {
        messages.push(content.text.value.trim());
      }
    }
  }

  return messages.join("\n\n").trim();
}

function extractGroqText(payload) {
  return payload?.choices?.[0]?.message?.content?.trim() || "";
}

async function requestOpenAiChat({ apiKey, model, page, question, reports, history, attachments }) {
  const safeReports = reports.map((report) => compactForAi(report));
  const safeAttachments = attachments.map((item) => compactForAi(item));
  const safeHistory = history
    .map((entry) => ({
      role: entry?.role === "assistant" ? "assistant" : "user",
      text: String(entry?.text || "").slice(0, 1000)
    }))
    .filter((entry) => entry.text);

  const inputText = [
    `Current page: ${page}`,
    `User question: ${question}`,
    safeAttachments.length ? `User attached image metadata:\n${JSON.stringify(safeAttachments, null, 2)}\nNote: image pixels are not processed by this text-only provider path unless a vision-capable model integration is added.` : "User attached image metadata: none",
    safeHistory.length ? `Recent chat history:\n${JSON.stringify(safeHistory, null, 2)}` : "Recent chat history: none",
    safeReports.length ? `Relevant CyberShield reports:\n${JSON.stringify(safeReports, null, 2)}` : "Relevant CyberShield reports: none"
  ].join("\n\n");

  const aiResponse = await fetchJson("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      model,
      store: false,
      instructions:
        "You are CyberShield AI, a cybersecurity assistant embedded in a learning-focused investigation dashboard. Use the provided report context first. Be concise, accurate, and practical. Do not invent facts that are not in the reports. If evidence is missing, say what is missing and suggest the next investigation step.",
      input: inputText
    })
  });

  return extractOpenAiText(aiResponse);
}

async function requestGroqChat({ apiKey, model, page, question, reports, history, attachments }) {
  const safeReports = reports.map((report) => compactForAi(report));
  const safeAttachments = attachments.map((item) => compactForAi(item));
  const messages = [
    {
      role: "system",
      content:
        "You are CyberShield AI, a cybersecurity assistant embedded in a learning-focused investigation dashboard. Use the provided report context first. Be concise, accurate, and practical. Do not invent facts that are not in the reports. If evidence is missing, say what is missing and suggest the next investigation step."
    },
    ...history
      .map((entry) => ({
        role: entry?.role === "assistant" ? "assistant" : "user",
        content: String(entry?.text || "").slice(0, 1000)
      }))
      .filter((entry) => entry.content),
    {
      role: "user",
      content: [
        `Current page: ${page}`,
        `User question: ${question}`,
        safeAttachments.length ? `User attached image metadata:\n${JSON.stringify(safeAttachments, null, 2)}\nNote: image pixels are not processed by this text-only provider path unless a vision-capable model integration is added.` : "User attached image metadata: none",
        safeReports.length ? `Relevant CyberShield reports:\n${JSON.stringify(safeReports, null, 2)}` : "Relevant CyberShield reports: none"
      ].join("\n\n")
    }
  ];

  const aiResponse = await fetchJson("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      model,
      messages,
      temperature: 0.2
    })
  });

  return extractGroqText(aiResponse);
}

function collectSeverities(cve) {
  const metrics = cve?.metrics || {};
  const severities = new Set();

  [
    ...(metrics.cvssMetricV40 || []).map((entry) => entry?.cvssData?.baseSeverity),
    ...(metrics.cvssMetricV31 || []).map((entry) => entry?.cvssData?.baseSeverity),
    ...(metrics.cvssMetricV30 || []).map((entry) => entry?.cvssData?.baseSeverity),
    ...(metrics.cvssMetricV3 || []).map((entry) => entry?.cvssData?.baseSeverity),
    ...(metrics.cvssMetricV2 || []).map((entry) => entry?.baseSeverity)
  ]
    .filter(Boolean)
    .forEach((severity) => severities.add(String(severity).toUpperCase()));

  return Array.from(severities);
}

function getPreferredSeverity(cve) {
  const ranking = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"];
  const severities = collectSeverities(cve);
  return severities.sort((a, b) => ranking.indexOf(a) - ranking.indexOf(b))[0] || "N/A";
}

function normalizeCve(item) {
  const cve = item?.cve || {};
  const englishDescription = (cve.descriptions || []).find((entry) => entry.lang === "en");

  return {
    id: cve.id,
    sourceIdentifier: cve.sourceIdentifier || null,
    published: cve.published || null,
    lastModified: cve.lastModified || null,
    severity: getPreferredSeverity(cve),
    severities: collectSeverities(cve),
    description: englishDescription?.value || "No description available.",
    url: cve.id ? `https://nvd.nist.gov/vuln/detail/${cve.id}` : null
  };
}

function sortCvesNewestFirst(items) {
  return [...items].sort((a, b) => {
    const aTime = a.published ? new Date(a.published).getTime() : 0;
    const bTime = b.published ? new Date(b.published).getTime() : 0;
    return bTime - aTime;
  });
}

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "cybershield-backend",
    timestamp: new Date().toISOString()
  });
});

app.get("/api/cves", async (req, res) => {
  const keyword = String(req.query.keyword || "").trim();
  const severity = String(req.query.severity || "").trim().toUpperCase();

  if (!keyword) {
    return badRequest(res, "Query parameter 'keyword' is required.");
  }

  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(keyword)}`;
    const data = await fetchJson(url);
    let items = (data.vulnerabilities || []).map(normalizeCve);

    if (severity) {
      items = items.filter((item) => item.severity.toUpperCase() === severity);
    }

    items = sortCvesNewestFirst(items);

    res.json({
      keyword,
      severity: severity || null,
      fetchedAt: new Date().toISOString(),
      total: items.length,
      items
    });
  } catch (error) {
    res.status(502).json({
      error: "Failed to fetch CVE data from NVD.",
      details: error.payload || error.message
    });
  }
});

app.get("/api/osint/whois", async (req, res) => {
  const domain = normalizeDomainInput(req.query.domain);

  if (!isLikelyDomain(domain)) {
    return badRequest(res, "A valid domain is required.");
  }

  try {
    const rdapData = await fetchDomainRdapWithFallback(domain);
    const rawWhois = await fetchRawWhoisWithReferral(domain).catch((error) => ({
      error: error.message
    }));
    const parsedData = mergeRawWhoisIntoParsed(parseWhoisFromRdap(rdapData), rawWhois);

    // Keep RDAP fields at the top level because the tools UI and analysis page
    // render entities, events, nameservers, and status directly.
    res.json({
      ...rdapData,
      query: domain,
      whoisData: parsedData,
      rawWhois,
      rawRdap: rdapData,
      source: "RDAP WHOIS"
    });
  } catch (error) {
    res.status(502).json({
      error: "Failed to fetch WHOIS/RDAP domain data.",
      details: error.payload || error.message
    });
  }
});

app.get("/api/osint/rdap", async (req, res) => {
  const query = String(req.query.query || "").trim();

  if (!query) {
    return badRequest(res, "Query parameter 'query' is required.");
  }

  const type = isLikelyIp(query) ? "ip" : "domain";

  try {
    const data = type === "domain"
      ? await fetchDomainRdapWithFallback(query)
      : await fetchJson(`https://rdap.org/${type}/${encodeURIComponent(query)}`);
    res.json({ type, query, data });
  } catch (error) {
    res.status(502).json({
      error: "Failed to fetch RDAP data.",
      details: error.payload || error.message
    });
  }
});

app.get("/api/osint/dns", async (req, res) => {
  const domain = String(req.query.domain || "").trim();
  const recordTypes = ["A", "AAAA", "MX", "TXT", "CNAME", "NS"];

  if (!isLikelyDomain(domain)) {
    return badRequest(res, "A valid domain is required.");
  }

  try {
    const lookups = await Promise.all(
      recordTypes.map(async (type) => {
        const data = await fetchJson(
          `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`
        );
        return { type, data };
      })
    );

    const records = lookups.flatMap(({ type, data }) =>
      (data.Answer || []).map((answer) => ({
        name: answer.name,
        ttl: answer.TTL,
        type,
        data: answer.data
      }))
    );

    res.json({
      domain,
      records,
      raw: Object.fromEntries(lookups.map(({ type, data }) => [type, data]))
    });
  } catch (error) {
    res.status(502).json({
      error: "Failed to fetch DNS data.",
      details: error.payload || error.message
    });
  }
});

app.get("/api/osint/uptime", async (req, res) => {
  const url = String(req.query.url || "").trim();

  try {
    const parsed = new URL(url);

    if (!/^https?:$/.test(parsed.protocol)) {
      return badRequest(res, "Only HTTP and HTTPS URLs are supported.");
    }
  } catch {
    return badRequest(res, "A valid URL is required.");
  }

  try {
    const response = await fetch(url, { method: "HEAD", redirect: "follow" });
    res.json({
      url,
      ok: response.ok,
      status: response.status,
      statusText: response.statusText
    });
  } catch (error) {
    res.status(502).json({
      error: "Failed to check uptime.",
      details: error.message
    });
  }
});

app.get("/api/threat/ip/:ip", async (req, res) => {
  const token = process.env.IPINFO_TOKEN;
  const ip = String(req.params.ip || "").trim();

  if (!isLikelyIp(ip)) {
    return badRequest(res, "A valid IP address is required.");
  }

  if (!token) {
    return res.status(500).json({ error: "IPINFO_TOKEN is not configured on the server." });
  }

  try {
    const data = await fetchJson(
      `https://ipinfo.io/${encodeURIComponent(ip)}/json?token=${encodeURIComponent(token)}`
    );

    res.json({
      ip: data.ip || ip,
      hostname: data.hostname || null,
      city: data.city || null,
      region: data.region || null,
      country: data.country || null,
      loc: data.loc || null,
      org: data.org || null,
      postal: data.postal || null,
      timezone: data.timezone || null
    });
  } catch (error) {
    res.status(502).json({
      error: "Failed to fetch IP intelligence.",
      details: error.payload || error.message
    });
  }
});

app.get("/api/threat/domain/resolve", async (req, res) => {
  const domain = String(req.query.domain || "").trim();

  if (!isLikelyDomain(domain)) {
    return badRequest(res, "A valid domain is required.");
  }

  try {
    const data = await fetchJson(
      `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`
    );
    const addresses = (data.Answer || []).map((answer) => answer.data);
    res.json({ domain, addresses });
  } catch (error) {
    res.status(502).json({
      error: "Failed to resolve domain.",
      details: error.payload || error.message
    });
  }
});

app.get("/api/threat/domain/asn", async (req, res) => {
  const token = process.env.IPINFO_TOKEN;
  const domain = String(req.query.domain || "").trim();

  if (!isLikelyDomain(domain)) {
    return badRequest(res, "A valid domain is required.");
  }

  if (!token) {
    return res.status(500).json({ error: "IPINFO_TOKEN is not configured on the server." });
  }

  try {
    const dnsData = await fetchJson(
      `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`
    );
    const ip = dnsData.Answer?.[0]?.data;

    if (!ip) {
      return res.status(404).json({ error: "No IPv4 address found for that domain." });
    }

    const ipData = await fetchJson(
      `https://ipinfo.io/${encodeURIComponent(ip)}/json?token=${encodeURIComponent(token)}`
    );

    res.json({
      domain,
      ip,
      org: ipData.org || null,
      hostname: ipData.hostname || null,
      city: ipData.city || null,
      region: ipData.region || null,
      country: ipData.country || null,
      timezone: ipData.timezone || null
    });
  } catch (error) {
    res.status(502).json({
      error: "Failed to fetch ASN details.",
      details: error.payload || error.message
    });
  }
});

app.get("/api/threat/domain/profile", async (req, res) => {
  const token = process.env.IPINFO_TOKEN;
  const domain = String(req.query.domain || "").trim().toLowerCase();

  if (!isLikelyDomain(domain)) {
    return badRequest(res, "A valid domain is required.");
  }

  if (!token) {
    return res.status(500).json({ error: "IPINFO_TOKEN is not configured on the server." });
  }

  try {
    const [dnsResult, rdapResult, nativeDnsResult] = await Promise.allSettled([
      fetchJson(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`),
      fetchDomainRdapWithFallback(domain),
      dns.resolve4(domain)
    ]);

    const dnsData = dnsResult.status === "fulfilled" ? dnsResult.value : null;
    const domainRdap = rdapResult.status === "fulfilled" ? rdapResult.value : null;
    const googleIps = (dnsData?.Answer || [])
      .filter((answer) => Number(answer.type) === 1 || String(answer.type).toUpperCase() === "A")
      .map((answer) => answer.data)
      .filter(Boolean);
    const nativeIps = nativeDnsResult.status === "fulfilled" ? nativeDnsResult.value : [];
    const ips = [...new Set([...googleIps, ...nativeIps].filter(Boolean))];

    if (!ips.length) {
      return res.status(404).json({
        error: "Unable to resolve domain.",
        details: "No live A records were returned by Google DNS or the local DNS resolver."
      });
    }

    const ipProfiles = await Promise.all(
      ips.map(async (ip) => {
        const [ipinfoResult, bgpResult, ipRdapResult] = await Promise.allSettled([
          fetchJson(`https://ipinfo.io/${encodeURIComponent(ip)}/json?token=${encodeURIComponent(token)}`),
          fetchJson(`https://api.bgpview.io/ip/${encodeURIComponent(ip)}`),
          fetchJson(`https://rdap.org/ip/${encodeURIComponent(ip)}`)
        ]);

        const ipinfo = ipinfoResult.status === "fulfilled" ? ipinfoResult.value : null;
        const bgp = bgpResult.status === "fulfilled" ? bgpResult.value?.data || null : null;
        const ipRdap = ipRdapResult.status === "fulfilled" ? ipRdapResult.value : null;
        const abuseEntity = getRdapEntityByRole(ipRdap, "abuse");
        const prefix =
          bgp?.prefixes?.[0] ||
          bgp?.ipv4_prefixes?.[0] ||
          bgp?.ipv6_prefixes?.[0] ||
          bgp?.prefix || null;
        const parsedOrg = parseAsnFromOrg(ipinfo?.org);
        const bgpAsn = prefix?.asn || bgp?.asn || bgp?.rir_allocation?.asn || null;
        const bgpAsnNumber = bgpAsn && typeof bgpAsn === "object" ? (bgpAsn.asn || bgpAsn.number || null) : bgpAsn;
        const bgpAsnName = bgpAsn && typeof bgpAsn === "object" ? (bgpAsn.name || bgpAsn.description_short || null) : null;
        const orgName = parsedOrg.name || bgpAsnName || ipinfo?.org || null;
        const route = prefix?.prefix || prefix?.cidr || bgp?.prefix || null;

        return {
          ip,
          hostname: ipinfo?.hostname || null,
          isp: orgName,
          org: orgName,
          city: ipinfo?.city || null,
          region: ipinfo?.region || null,
          country: ipinfo?.country || null,
          timezone: ipinfo?.timezone || null,
          postal: ipinfo?.postal || null,
          loc: ipinfo?.loc || null,
          asn: bgpAsnNumber ? `AS${String(bgpAsnNumber).replace(/^AS/i, "")}` : parsedOrg.asn,
          asnName: bgpAsnName || parsedOrg.name,
          asnDescription: prefix?.description || bgp?.description_short || null,
          prefix: route,
          abuseContact: getVcardField(abuseEntity, "email"),
          rdapHandle: ipRdap?.handle || null
        };
      })
    );

    res.json({
      domain,
      totalIps: ipProfiles.length,
      sources: {
        dns: dnsResult.status === "fulfilled" ? "available" : "unavailable",
        rdap: rdapResult.status === "fulfilled" ? "available" : "unavailable",
        ipinfo: "per-ip best effort",
        bgpview: "per-ip best effort"
      },
      nameservers: (domainRdap?.nameservers || []).map((entry) => entry.ldhName || entry.unicodeName).filter(Boolean),
      registrationDate: (domainRdap?.events || []).find((event) => event.eventAction === "registration")?.eventDate || null,
      lastChanged: (domainRdap?.events || []).find((event) => event.eventAction === "last changed")?.eventDate || null,
      secureDns: domainRdap?.secureDNS?.delegationSigned ?? null,
      registrar: domainRdap ? getVcardField(getRdapEntityByRole(domainRdap, "registrar"), "fn") : null,
      ips: ipProfiles
    });
  } catch (error) {
    res.status(502).json({
      error: "Failed to fetch domain profile intelligence.",
      details: error.payload || error.message
    });
  }
});

app.get("/api/infrastructure/exposure", async (req, res) => {
  const domain = String(req.query.domain || "").trim().toLowerCase();

  if (!isLikelyDomain(domain)) {
    return badRequest(res, "A valid domain is required.");
  }

  try {
    const exposure = await fetchInfrastructureExposure(domain);
    res.json(exposure);
  } catch (error) {
    res.status(502).json({
      error: "Failed to fetch infrastructure exposure intelligence.",
      details: error.payload || error.message
    });
  }
});

async function fetchTlsFull(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect(443, hostname, { servername: hostname, rejectUnauthorized: false, timeout: 8000 }, () => {
      const cert = socket.getPeerCertificate(true);
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();
      socket.end();
      const san = cert?.subjectaltname
        ? cert.subjectaltname.split(", ").map(s => s.replace(/^DNS:/, "").trim())
        : [];
      const chain = [];
      let c = cert;
      const seen = new Set();
      while (c && c.subject && !seen.has(c.fingerprint)) {
        seen.add(c.fingerprint);
        chain.push({
          subject: { CN: c.subject?.CN, O: c.subject?.O },
          issuerSubject: { CN: c.issuer?.CN, O: c.issuer?.O },
          issuerLabel: c.issuer?.CN || c.issuer?.O || null
        });
        c = c.issuerCertificate && c.issuerCertificate !== c ? c.issuerCertificate : null;
      }
      resolve({
        ok: true,
        subject: cert?.subject || {},
        issuer: cert?.issuer || {},
        issuerLabel: cert?.issuer?.CN || cert?.issuer?.O || null,
        validFrom: cert?.valid_from || null,
        validTo: cert?.valid_to || null,
        serialNumber: cert?.serialNumber || null,
        fingerprint256: cert?.fingerprint256 || null,
        san,
        chain,
        protocol,
        cipher: cipher?.name || null,
        cipherBits: cipher?.version || null,
        authorized: socket.authorized
      });
    });
    socket.on("error", (err) => resolve({ ok: false, error: err.message }));
    socket.on("timeout", () => { socket.destroy(); resolve({ ok: false, error: "TLS connection timed out" }); });
  });
}

async function fetchSecurityHeaders(hostname) {
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 6000);
    const res = await fetch(`https://${hostname}/`, { method: "HEAD", redirect: "follow", signal: controller.signal });
    clearTimeout(t);
    const h = (name) => res.headers.get(name);
    return {
      hsts: h("strict-transport-security"),
      csp: h("content-security-policy"),
      xframe: h("x-frame-options"),
      xcto: h("x-content-type-options"),
      referrer: h("referrer-policy"),
      server: h("server")
    };
  } catch { return {}; }
}

app.get("/api/security/ssl", async (req, res) => {
  const parsed = parseUserDomainInput(req.query.domain);
  const domain = parsed.hostname;

  if (!domain || !isLikelyDomain(domain)) {
    return badRequest(res, "A valid domain/hostname is required.");
  }

  try {
    const [tlsData, headers, crtRaw] = await Promise.allSettled([
      fetchTlsFull(domain),
      fetchSecurityHeaders(domain),
      fetchText(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, { timeoutMs: 8000 })
    ]);


    const tls_ = tlsData.status === "fulfilled" ? tlsData.value : { ok: false };
    const hdrs = headers.status === "fulfilled" ? headers.value : {};

    let crtData = [];
    if (crtRaw.status === "fulfilled") {
      try {
        const raw = crtRaw.value.trim();
        crtData = JSON.parse(raw.startsWith("[") ? raw : `[${raw.replace(/}\s*{/g, "},{")  }]`);
      } catch { crtData = []; }
    }

    const normalizedCerts = crtData
      .map(e => ({ issuerName: e.issuer_name || null, commonName: e.common_name || null, nameValue: e.name_value || null, entryTimestamp: e.entry_timestamp || null, notBefore: e.not_before || null, notAfter: e.not_after || null, serialNumber: e.serial_number || null }))
      .filter(e => e.commonName || e.nameValue || e.entryTimestamp);
    const certDates = normalizedCerts.flatMap(e => [e.entryTimestamp].filter(Boolean));
    const issueDates = normalizedCerts.flatMap(e => [e.notBefore].filter(Boolean));

    // Build SSL Labs-compatible shape so frontend rendering works unchanged
    const notBefore = tls_.validFrom ? new Date(tls_.validFrom).getTime() / 1000 : null;
    const notAfter = tls_.validTo ? new Date(tls_.validTo).getTime() / 1000 : null;
    const INSECURE_PROTOCOLS = ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"];
    const protocolVersion = tls_.protocol || "";
    const isInsecure = INSECURE_PROTOCOLS.some(p => protocolVersion.includes(p));
    const grade = !tls_.ok ? "" : isInsecure ? "C" : tls_.authorized ? "A" : "B";

    const fakeEndpoint = {
      grade,
      statusMessage: tls_.ok ? "Ready" : (tls_.error || "TLS scan failed"),
      details: {
        cert: {
          subject: tls_.subject,
          issuerSubject: tls_.issuer,
          issuerLabel: tls_.issuerLabel,
          commonNames: tls_.subject?.CN ? [tls_.subject.CN] : [],
          altNames: tls_.san || [],
          notBefore,
          notAfter,
          serialNumber: tls_.serialNumber,
          sha256Hash: tls_.fingerprint256,
          issues: tls_.authorized ? 0 : 1
        },
        protocols: tls_.protocol ? [{ name: protocolVersion.replace(/v/i, " "), id: protocolVersion.includes("1.3") ? 772 : protocolVersion.includes("1.2") ? 771 : 770 }] : [],
        suites: tls_.cipher ? [{ list: [{ name: tls_.cipher }] }] : [],
        chain: { certs: tls_.chain || [] },
        hstsPolicy: { status: hdrs.hsts ? "present" : "absent" },
        httpTransactions: [{ responseHeaders: [
          hdrs.hsts && { name: "strict-transport-security", value: hdrs.hsts },
          hdrs.csp && { name: "content-security-policy", value: hdrs.csp },
          hdrs.xframe && { name: "x-frame-options", value: hdrs.xframe },
          hdrs.xcto && { name: "x-content-type-options", value: hdrs.xcto },
          hdrs.referrer && { name: "referrer-policy", value: hdrs.referrer }
        ].filter(Boolean) }]
      }
    };

    res.json({
      domain,
      tlsDiagnostics: {
        ok: !!tls_.ok,
        source: "node_tls_socket",
        error: tls_.ok ? null : (tls_.error || "TLS scan failed")
      },
      ssllabs: {
        status: tls_.ok ? "READY" : "ERROR",
        statusMessage: tls_.ok ? "Ready" : (tls_.error || "TLS scan failed"),
        host: domain,
        port: 443,
        endpoints: [fakeEndpoint]
      },
      recentCertificates: normalizedCerts.slice(0, 20),
      summary: {
        recordCount: normalizedCerts.length,
        firstSeen: certDates.length ? certDates.sort()[0] : null,
        latestSeen: certDates.length ? certDates.sort().slice(-1)[0] : null,
        latestIssued: issueDates.length ? issueDates.sort().slice(-1)[0] : null,
        issuers: [...new Set(normalizedCerts.map(e => e.issuerName).filter(Boolean))].slice(0, 10)
      }
    });
  } catch (error) {
    res.status(502).json({ error: "Failed to fetch TLS data.", details: error.message });
  }
});

app.get("/api/url/intel", async (req, res) => {
  const url = String(req.query.url || "").trim();

  try {
    const parsed = new URL(url);
    if (!/^https?:$/.test(parsed.protocol)) {
      return badRequest(res, "Only HTTP and HTTPS URLs are supported.");
    }
  } catch {
    return badRequest(res, "A valid URL is required.");
  }

  try {
    const chain = [];
    const visited = new Set();
    let currentUrl = url;
    let finalStatus = null;

    for (let step = 0; step < 6; step += 1) {
      if (visited.has(currentUrl)) break;
      visited.add(currentUrl);

      const response = await fetchRedirectStep(currentUrl);
      const location = response.headers.get("location");
      const entry = {
        url: currentUrl,
        host: new URL(currentUrl).hostname,
        status: response.status,
        redirectedTo: null
      };

      if (location) {
        const nextUrl = new URL(location, currentUrl).toString();
        entry.redirectedTo = nextUrl;
        chain.push(entry);
        currentUrl = nextUrl;
        finalStatus = response.status;
        continue;
      }

      chain.push(entry);
      finalStatus = response.status;
      break;
    }

    res.json({
      inputUrl: url,
      finalUrl: currentUrl,
      finalHost: new URL(currentUrl).hostname,
      finalStatus,
      redirectCount: Math.max(chain.length - 1, 0),
      chain
    });
  } catch (error) {
    res.status(502).json({
      error: "Failed to inspect URL redirect intelligence.",
      details: error.message
    });
  }
});

app.post("/api/urlscan/scan", async (req, res) => {
  const url = String(req.body?.url || "").trim();
  const visibility = String(req.body?.visibility || "unlisted").trim().toLowerCase();
  const tags = normalizeStringArray(req.body?.tags);

  try {
    const parsed = new URL(url);
    if (!/^https?:$/.test(parsed.protocol)) {
      return badRequest(res, "Only HTTP and HTTPS URLs are supported.");
    }
  } catch {
    return badRequest(res, "A valid URL is required.");
  }

  try {
    const payload = await fetchUrlscanJson("https://urlscan.io/api/v1/scan/", {
      method: "POST",
      body: JSON.stringify({
        url,
        visibility,
        tags
      })
    });

    res.status(201).json({
      message: "Scan submitted successfully.",
      uuid: payload.uuid || null,
      result: payload.result || null,
      api: payload.api || null,
      visibility: payload.visibility || visibility,
      url: payload.url || url
    });
  } catch (error) {
    res.status(error.status || 502).json({
      error: extractUrlscanErrorMessage(error),
      details: error.payload || null
    });
  }
});

app.get("/api/urlscan/result/:uuid", async (req, res) => {
  const uuid = String(req.params.uuid || "").trim();
  if (!uuid) {
    return badRequest(res, "A scan UUID is required.");
  }

  try {
    const data = await fetchUrlscanJson(`https://urlscan.io/api/v1/result/${encodeURIComponent(uuid)}/`);
    const page = data.page || {};
    const task = data.task || {};
    const verdicts = data.verdicts || {};
    const lists = data.lists || {};
    const stats = data.stats || {};
    const meta = data.meta || {};
    const certificates = data.certificates || [];
    const rawData = data.data || {};
    const scanUrl = data.task?.uuid ? `https://urlscan.io/result/${data.task.uuid}/` : null;

    const enrichedRequests = Array.isArray(rawData.requests)
      ? await Promise.all(rawData.requests.slice(0, 120).map((entry) => enrichUrlscanRequestEntry(entry)))
      : [];

    res.json({
      uuid,
      scanUrl,
      screenshotUrl: task.screenshotURL || task.screenshotUrl || (task.uuid ? `https://urlscan.io/screenshots/${task.uuid}.png` : null),
      task: {
        uuid: task.uuid || uuid,
        url: task.url || null,
        visibility: task.visibility || null,
        time: task.time || null,
        source: task.source || null,
        method: task.method || null,
        tags: task.tags || []
      },
      page: {
        url: page.url || null,
        domain: page.domain || null,
        ip: page.ip || null,
        ptr: page.ptr || null,
        asn: page.asn || null,
        asnname: page.asnname || null,
        country: page.country || null,
        city: page.city || null,
        server: page.server || null,
        title: page.title || null,
        status: page.status || null,
        mimeType: page.mimeType || null,
        tlsIssuer: page.tlsIssuer || null,
        tlsAgeDays: page.tlsAgeDays || null,
        tlsValidDays: page.tlsValidDays || null
      },
      verdicts,
      stats,
      meta,
      lists: {
        ips: lists.ips || [],
        countries: lists.countries || [],
        asns: lists.asns || [],
        domains: lists.domains || [],
        links: lists.links || [],
        linkDomains: lists.linkDomains || [],
        urls: lists.urls || [],
        servers: lists.servers || lists.server || [],
        certificates: lists.certificates || [],
        hashes: lists.hashes || []
      },
      certificates: certificates.slice(0, 20),
      data: rawData,
      requests: enrichedRequests,
      linksData: Array.isArray(rawData.links) ? rawData.links.slice(0, 120) : [],
      cookies: Array.isArray(rawData.cookies) ? rawData.cookies.slice(0, 80) : [],
      consoleMessages: Array.isArray(rawData.console) ? rawData.console.slice(0, 80) : [],
      globals: Array.isArray(rawData.globals) ? rawData.globals.slice(0, 80) : [],
      storages: Array.isArray(rawData.storages) ? rawData.storages.slice(0, 40) : [],
      raw: data
    });
  } catch (error) {
    const status = error.status || 502;
    res.status(status).json({
      error: status === 404 ? "Scan result is not ready yet." : extractUrlscanErrorMessage(error),
      details: error.payload || null
    });
  }
});

app.get("/api/detonator/health", async (req, res) => {
  try {
    const data = await fetchJson(`${DETONATOR_SERVICE_URL}/health`);
    res.json({
      ok: true,
      upstream: DETONATOR_SERVICE_URL,
      service: data
    });
  } catch (error) {
    const details = error.payload || error.message;
    res.status(502).json({
      error: "Detonator microservice is unavailable.",
      details,
      hint: `Start the standalone detonator service on ${DETONATOR_SERVICE_URL}.`
    });
  }
});

app.post("/api/detonator/run", async (req, res) => {
  const url = String(req.body?.url || "").trim();
  const timeout = Number(req.body?.timeout || 15);
  const waitUntil = String(req.body?.waitUntil || "networkidle").trim();

  if (!url) {
    return badRequest(res, "A URL is required.");
  }

  try {
    const data = await fetchJson(`${DETONATOR_SERVICE_URL}/detonate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        timeout,
        wait_until: waitUntil
      })
    });
    res.json(data);
  } catch (error) {
    const details = error.payload || error.message;
    res.status(502).json({
      error: "Detonation request failed.",
      details,
      hint: `The Detonation Lab depends on the standalone microservice at ${DETONATOR_SERVICE_URL}. Make sure it is running before launching a detonation.`
    });
  }
});

app.post("/api/threat-intel/lookup", async (req, res) => {
  const input = String(req.body?.input || "").trim();
  const providedType = String(req.body?.type || "").trim().toLowerCase();
  const normalizedInput = normalizeThreatInput(input);
  const type = providedType || detectThreatIntelType(normalizedInput);

  if (!normalizedInput || type === "unknown") {
    return badRequest(res, "A valid IP, domain, URL, or hash is required.");
  }

  try {
    const cacheKey = buildThreatIntelCacheKey(normalizedInput, type);
    const cached = readThreatIntelCache(cacheKey);
    if (cached) {
      return res.json({ ...cached, cache: { hit: true, ttlSeconds: Math.round(THREAT_INTEL_TTL_MS / 1000) } });
    }

    const iocs = new Set([normalizedInput]);
    if (type === "url") {
      const parsed = new URL(normalizedInput);
      iocs.add(parsed.hostname.replace(/^www\./i, ""));
    }

    if (type === "domain") {
      const dnsData = await fetchJson(`https://dns.google/resolve?name=${encodeURIComponent(normalizedInput)}&type=A`).catch(() => null);
      (dnsData?.Answer || []).forEach((answer) => answer?.data && iocs.add(answer.data));
    }

    const iocList = [...iocs];
    const threatFoxHits = (
      await Promise.all(
        iocList.map((ioc) => (type === "hash" ? queryThreatFoxHash(ioc) : queryThreatFoxIoc(ioc)).catch(() => []))
      )
    ).flat();

    const dedupedHits = threatFoxHits.filter((item, index, arr) =>
      index === arr.findIndex((candidate) =>
        candidate.source === item.source &&
        candidate.ioc === item.ioc &&
        candidate.threatType === item.threatType &&
        candidate.malware === item.malware
      )
    ).sort((a, b) => (b.confidence || 0) - (a.confidence || 0));

    const enrichment = await buildThreatIntelEnrichment(input, type, normalizedInput);
    const externalFeeds = await queryOptionalExternalFeeds(input, type, normalizedInput);
    const externalRisk = externalFeeds.reduce((score, feed) => {
      if (feed.provider === "VirusTotal") return score + (feed.malicious > 0 ? 35 : feed.suspicious > 0 ? 15 : 0);
      if (feed.provider === "AbuseIPDB") return score + (Number(feed.abuseConfidenceScore || 0) >= 75 ? 35 : Number(feed.abuseConfidenceScore || 0) >= 25 ? 15 : 0);
      if (feed.provider === "AlienVault OTX") return score + (Number(feed.pulseCount || 0) > 0 ? 20 : 0);
      return score;
    }, 0);
    const scoring = scoreThreatIntel({ hits: dedupedHits, enrichment });
    scoring.final = Math.max(scoring.final, Math.min(100, scoring.final + externalRisk));
    scoring.band = scoring.final >= 70 ? "high" : scoring.final >= 30 ? "medium" : "low";
    scoring.classification = scoring.final >= 70 ? "malicious" : scoring.final >= 30 ? "suspicious" : scoring.classification;
    const summary = buildThreatIntelSummary(dedupedHits, scoring);
    const reputation = buildThreatIntelReputation(dedupedHits, enrichment);
    const entityType = classifyEntity(normalizedInput, enrichment?.network?.org || enrichment?.network?.asn);
    const behavior = {
      usage: dedupedHits.length ? "Potentially malicious" : isTrustedASN(enrichment?.network?.org || enrichment?.network?.asn) ? "Legitimate" : "Requires monitoring",
      stability: isTrustedASN(enrichment?.network?.org || enrichment?.network?.asn) ? "High" : "Unknown",
      role: entityType
    };
    const abusePotential = {
      summary: getAbusePotential(entityType),
      riskLevel: scoring.band.toUpperCase()
    };
    const finalVerdict = scoring.classification === "malicious"
      ? "Known malicious infrastructure. Escalation and containment recommended."
      : scoring.classification === "suspicious"
        ? "No direct threat intelligence hit, but the entity still requires monitoring."
        : "Trusted infrastructure with no known malicious activity. No action required.";
    const result = {
      input,
      normalizedInput,
      type,
      classification: scoring.classification,
      reputation,
      riskLevel: scoring.band.toUpperCase(),
      entityProfile: {
        org: enrichment?.network?.org || null,
        asn: enrichment?.network?.asn || null,
        type: entityType
      },
      confidence: {
        threat: dedupedHits.length ? Math.max(...dedupedHits.map((item) => item.confidence || 0)) : 0,
        data: enrichment?.network?.asn ? "HIGH" : "MEDIUM"
      },
      scores: {
        threat: scoring.threat,
        context: scoring.context,
        final: scoring.final,
        band: scoring.band
      },
      iocs: {
        all: iocList,
        ips: iocList.filter((ioc) => detectThreatIntelType(ioc) === "ip"),
        domains: iocList.filter((ioc) => detectThreatIntelType(ioc) === "domain"),
        urls: iocList.filter((ioc) => detectThreatIntelType(ioc) === "url"),
        hashes: iocList.filter((ioc) => detectThreatIntelType(ioc) === "hash")
      },
      intel: dedupedHits,
      enrichment: {
        ips: enrichment?.dns?.addresses || (type === "ip" ? [normalizedInput] : []),
        asn: enrichment?.network?.asn || null,
        org: enrichment?.network?.org || null,
        country: enrichment?.network?.country || null,
        dns: enrichment?.dns || null,
        http: enrichment?.http || null,
        tls: enrichment?.tls || null,
        network: enrichment?.network || null
      },
      behavior,
      abusePotential,
      externalFeeds,
      intelligenceAnalysis: {
        source: "abuse.ch + optional VirusTotal/AbuseIPDB/AlienVault OTX",
        summary: dedupedHits.length
          ? `${dedupedHits.length} intelligence hit(s) found.`
          : "No matches found in abuse.ch. No malware association or IOC correlation was returned."
      },
      explanation: buildThreatIntelExplanation({
        input,
        type,
        hits: dedupedHits,
        enrichment,
        scores: {
          final: scoring.final,
          band: scoring.band
        },
        classification: scoring.classification
      }),
      analystNote: dedupedHits.length
        ? "Indicators of compromise were detected and should be investigated immediately."
        : isTrustedASN(enrichment?.network?.org || enrichment?.network?.asn)
          ? "No indicators of compromise detected. Entity belongs to a trusted provider and appears safe for normal usage."
          : "No direct threat intelligence found. Continue monitoring and validate surrounding infrastructure.",
      finalVerdict,
      summary,
      fetchedAt: new Date().toISOString()
    };

    writeThreatIntelCache(cacheKey, result);
    res.json({ ...result, cache: { hit: false, ttlSeconds: Math.round(THREAT_INTEL_TTL_MS / 1000) } });
  } catch (error) {
    res.status(error.status || 502).json({
      error: error.message || "Failed to fetch threat intelligence.",
      details: error.payload || null
    });
  }
});

app.get("/api/cases", (req, res) => {
  const store = readWorkspaceStore();
  const indicator = String(req.query.indicator || "").trim().toLowerCase();
  const status = String(req.query.status || "").trim().toLowerCase();
  const verdict = String(req.query.verdict || "").trim().toLowerCase();

  let items = store.cases;

  if (indicator) {
    items = items.filter((item) => String(item.indicator || "").toLowerCase().includes(indicator));
  }

  if (status) {
    items = items.filter((item) => String(item.status || "").toLowerCase() === status);
  }

  if (verdict) {
    items = items.filter((item) => String(item.verdict || "").toLowerCase() === verdict);
  }

  res.json({
    total: items.length,
    items: items
      .sort((a, b) => new Date(b.updatedAt || b.createdAt || 0).getTime() - new Date(a.updatedAt || a.createdAt || 0).getTime())
      .map(buildCaseSnapshot)
  });
});

app.post("/api/cases", (req, res) => {
  const indicator = String(req.body?.indicator || "").trim();
  const indicatorType = String(req.body?.indicatorType || "unknown").trim().toLowerCase();

  if (!indicator) {
    return badRequest(res, "Case indicator is required.");
  }

  const store = readWorkspaceStore();
  const now = new Date().toISOString();
  const newCase = {
    id: makeId("case"),
    title: String(req.body?.title || indicator).trim().slice(0, 140) || indicator,
    indicator,
    indicatorType,
    verdict: String(req.body?.verdict || "under-review").trim().toLowerCase(),
    status: String(req.body?.status || "open").trim().toLowerCase(),
    priority: String(req.body?.priority || "medium").trim().toLowerCase(),
    tags: normalizeStringArray(req.body?.tags),
    notes: Array.isArray(req.body?.notes)
      ? req.body.notes.map((note) => ({
          id: makeId("note"),
          body: String(note?.body || "").trim(),
          author: String(note?.author || "Analyst").trim() || "Analyst",
          createdAt: now
        })).filter((note) => note.body)
      : [],
    comments: [],
    evidence: Array.isArray(req.body?.evidence)
      ? req.body.evidence.map((entry) => ({
          id: makeId("evidence"),
          label: String(entry?.label || "Initial Evidence").trim(),
          source: String(entry?.source || "analysis").trim(),
          capturedAt: String(entry?.capturedAt || now).trim() || now,
          data: entry?.data ?? null
        }))
      : [],
    locked: Boolean(req.body?.locked),
    watcherEnabled: Boolean(req.body?.watcherEnabled),
    watchTargets: normalizeStringArray(req.body?.watchTargets),
    createdAt: now,
    updatedAt: now,
    lastObservedAt: now,
    activity: [
      {
        id: makeId("activity"),
        type: "case_created",
        message: "Case created from analysis workspace.",
        createdAt: now
      }
    ]
  };

  store.cases.unshift(newCase);
  writeWorkspaceStore(store);
  res.status(201).json({ case: newCase, summary: buildCaseSnapshot(newCase) });
});

app.get("/api/cases/:id", (req, res) => {
  const store = readWorkspaceStore();
  const caseItem = store.cases.find((item) => item.id === req.params.id);

  if (!caseItem) {
    return res.status(404).json({ error: "Case not found." });
  }

  res.json({ case: caseItem });
});

app.patch("/api/cases/:id", (req, res) => {
  const store = readWorkspaceStore();
  const caseIndex = store.cases.findIndex((item) => item.id === req.params.id);

  if (caseIndex === -1) {
    return res.status(404).json({ error: "Case not found." });
  }

  const caseItem = store.cases[caseIndex];
  const now = new Date().toISOString();

  if (typeof req.body?.title === "string") {
    caseItem.title = req.body.title.trim().slice(0, 140) || caseItem.title;
  }
  if (typeof req.body?.verdict === "string") {
    caseItem.verdict = req.body.verdict.trim().toLowerCase() || caseItem.verdict;
  }
  if (typeof req.body?.status === "string") {
    caseItem.status = req.body.status.trim().toLowerCase() || caseItem.status;
  }
  if (typeof req.body?.priority === "string") {
    caseItem.priority = req.body.priority.trim().toLowerCase() || caseItem.priority;
  }
  if (Array.isArray(req.body?.tags)) {
    caseItem.tags = normalizeStringArray(req.body.tags);
  }
  if (typeof req.body?.locked === "boolean") {
    caseItem.locked = req.body.locked;
  }
  if (typeof req.body?.watcherEnabled === "boolean") {
    caseItem.watcherEnabled = req.body.watcherEnabled;
  }
  if (Array.isArray(req.body?.watchTargets)) {
    caseItem.watchTargets = normalizeStringArray(req.body.watchTargets);
  }
  if (typeof req.body?.lastObservedAt === "string" && req.body.lastObservedAt.trim()) {
    caseItem.lastObservedAt = req.body.lastObservedAt.trim();
  }

  caseItem.updatedAt = now;
  caseItem.activity = Array.isArray(caseItem.activity) ? caseItem.activity : [];
  caseItem.activity.unshift({
    id: makeId("activity"),
    type: "case_updated",
    message: "Case metadata updated.",
    createdAt: now
  });

  store.cases[caseIndex] = caseItem;
  writeWorkspaceStore(store);
  res.json({ case: caseItem, summary: buildCaseSnapshot(caseItem) });
});

app.post("/api/cases/:id/notes", (req, res) => {
  const store = readWorkspaceStore();
  const caseItem = store.cases.find((item) => item.id === req.params.id);
  const body = String(req.body?.body || "").trim();

  if (!caseItem) {
    return res.status(404).json({ error: "Case not found." });
  }
  if (!body) {
    return badRequest(res, "Note body is required.");
  }

  const note = {
    id: makeId("note"),
    body,
    author: String(req.body?.author || "Analyst").trim() || "Analyst",
    createdAt: new Date().toISOString()
  };

  caseItem.notes = Array.isArray(caseItem.notes) ? caseItem.notes : [];
  caseItem.notes.unshift(note);
  caseItem.updatedAt = note.createdAt;
  caseItem.activity = Array.isArray(caseItem.activity) ? caseItem.activity : [];
  caseItem.activity.unshift({
    id: makeId("activity"),
    type: "note_added",
    message: "Analyst note added to the case.",
    createdAt: note.createdAt
  });
  writeWorkspaceStore(store);

  res.status(201).json({ note, case: caseItem });
});

app.post("/api/cases/:id/comments", (req, res) => {
  const store = readWorkspaceStore();
  const caseItem = store.cases.find((item) => item.id === req.params.id);
  const body = String(req.body?.body || "").trim();

  if (!caseItem) {
    return res.status(404).json({ error: "Case not found." });
  }
  if (!body) {
    return badRequest(res, "Comment body is required.");
  }

  const comment = {
    id: makeId("comment"),
    body,
    author: String(req.body?.author || "Team Analyst").trim() || "Team Analyst",
    createdAt: new Date().toISOString()
  };

  caseItem.comments = Array.isArray(caseItem.comments) ? caseItem.comments : [];
  caseItem.comments.unshift(comment);
  caseItem.updatedAt = comment.createdAt;
  caseItem.activity = Array.isArray(caseItem.activity) ? caseItem.activity : [];
  caseItem.activity.unshift({
    id: makeId("activity"),
    type: "comment_added",
    message: "Team comment added to the case.",
    createdAt: comment.createdAt
  });
  writeWorkspaceStore(store);

  res.status(201).json({ comment, case: caseItem });
});

app.post("/api/cases/:id/evidence", (req, res) => {
  const store = readWorkspaceStore();
  const caseItem = store.cases.find((item) => item.id === req.params.id);

  if (!caseItem) {
    return res.status(404).json({ error: "Case not found." });
  }

  if (caseItem.locked) {
    return res.status(409).json({ error: "Evidence is locked for this case." });
  }

  const evidence = {
    id: makeId("evidence"),
    label: String(req.body?.label || "Evidence Snapshot").trim(),
    source: String(req.body?.source || "analysis").trim(),
    capturedAt: new Date().toISOString(),
    data: req.body?.data ?? null
  };

  caseItem.evidence = Array.isArray(caseItem.evidence) ? caseItem.evidence : [];
  caseItem.evidence.unshift(evidence);
  caseItem.updatedAt = evidence.capturedAt;
  caseItem.lastObservedAt = evidence.capturedAt;
  caseItem.activity = Array.isArray(caseItem.activity) ? caseItem.activity : [];
  caseItem.activity.unshift({
    id: makeId("activity"),
    type: "evidence_added",
    message: `${evidence.label} captured from live analysis.`,
    createdAt: evidence.capturedAt
  });
  writeWorkspaceStore(store);

  res.status(201).json({ evidence, case: caseItem, summary: buildCaseSnapshot(caseItem) });
});

app.delete("/api/cases/:id", (req, res) => {
  const store = readWorkspaceStore();
  const before = store.cases.length;
  store.cases = store.cases.filter((item) => item.id !== req.params.id);

  if (store.cases.length === before) {
    return res.status(404).json({ error: "Case not found." });
  }

  writeWorkspaceStore(store);
  res.json({ ok: true });
});

app.get("/api/watchlists", (req, res) => {
  const store = readWorkspaceStore();
  res.json({
    total: store.watchlists.length,
    items: store.watchlists
      .sort((a, b) => new Date(b.updatedAt || b.createdAt || 0).getTime() - new Date(a.updatedAt || a.createdAt || 0).getTime())
  });
});

app.post("/api/watchlists", (req, res) => {
  const indicator = String(req.body?.indicator || "").trim();
  if (!indicator) {
    return badRequest(res, "Watchlist indicator is required.");
  }

  const store = readWorkspaceStore();
  const existing = store.watchlists.find((item) => item.indicator === indicator);
  if (existing) {
    return res.json({ watch: existing, existed: true });
  }

  const now = new Date().toISOString();
  const watch = {
    id: makeId("watch"),
    indicator,
    indicatorType: String(req.body?.indicatorType || "unknown").trim().toLowerCase(),
    caseId: String(req.body?.caseId || "").trim() || null,
    scope: normalizeStringArray(req.body?.scope),
    status: "active",
    latestStatus: String(req.body?.latestStatus || "watching").trim(),
    alertLevel: "info",
    lastCheckedAt: null,
    lastSnapshot: null,
    lastChanges: [],
    history: [],
    createdAt: now,
    updatedAt: now
  };

  store.watchlists.unshift(watch);
  writeWorkspaceStore(store);
  res.status(201).json({ watch });
});

app.post("/api/watchlists/:id/check", async (req, res) => {
  const store = readWorkspaceStore();
  const watch = store.watchlists.find((item) => item.id === req.params.id);

  if (!watch) {
    return res.status(404).json({ error: "Watch target not found." });
  }

  try {
    const result = await executeWatchCheck(watch);
    const now = result.snapshot.checkedAt;

    watch.lastCheckedAt = now;
    watch.lastSnapshot = result.snapshot;
    watch.lastChanges = result.changes;
    watch.latestStatus = result.latestStatus;
    watch.alertLevel = result.alertLevel;
    watch.updatedAt = now;
    watch.history = Array.isArray(watch.history) ? watch.history : [];
    watch.history.unshift({
      id: makeId("watch-history"),
      checkedAt: now,
      latestStatus: result.latestStatus,
      alertLevel: result.alertLevel,
      changes: result.changes,
      snapshot: result.snapshot
    });
    watch.history = watch.history.slice(0, 10);

    writeWorkspaceStore(store);
    res.json({ watch, check: result });
  } catch (error) {
    res.status(error.status || 502).json({
      error: error.message || "Monitoring check failed.",
      details: error.payload || null
    });
  }
});

app.post("/api/watchlists/check-all", async (req, res) => {
  const store = readWorkspaceStore();
  const results = [];

  for (const watch of store.watchlists) {
    try {
      const result = await executeWatchCheck(watch);
      const now = result.snapshot.checkedAt;
      watch.lastCheckedAt = now;
      watch.lastSnapshot = result.snapshot;
      watch.lastChanges = result.changes;
      watch.latestStatus = result.latestStatus;
      watch.alertLevel = result.alertLevel;
      watch.updatedAt = now;
      watch.history = Array.isArray(watch.history) ? watch.history : [];
      watch.history.unshift({
        id: makeId("watch-history"),
        checkedAt: now,
        latestStatus: result.latestStatus,
        alertLevel: result.alertLevel,
        changes: result.changes,
        snapshot: result.snapshot
      });
      watch.history = watch.history.slice(0, 10);
      results.push({ id: watch.id, ok: true, latestStatus: result.latestStatus, changes: result.changes });
    } catch (error) {
      results.push({ id: watch.id, ok: false, error: error.message || "Monitoring check failed." });
    }
  }

  writeWorkspaceStore(store);
  res.json({ total: store.watchlists.length, results, items: store.watchlists });
});

app.post("/api/ai/chat", async (req, res) => {
  const provider = String(process.env.AI_PROVIDER || (process.env.GROQ_API_KEY ? "groq" : "openai")).trim().toLowerCase();
  const question = String(req.body?.question || "").trim();
  const page = String(req.body?.page || "unknown").trim();
  const reports = Array.isArray(req.body?.reports) ? req.body.reports.slice(0, 4) : [];
  const history = Array.isArray(req.body?.history) ? req.body.history.slice(-6) : [];
  const attachments = Array.isArray(req.body?.attachments)
    ? req.body.attachments.slice(0, 4).map((item) => ({
        name: String(item?.name || "image").slice(0, 160),
        type: String(item?.type || "image/*").slice(0, 80),
        size: Number(item?.size || 0)
      }))
    : [];

  if (!question) {
    return badRequest(res, "Question is required.");
  }

  try {
    let answer = "";
    let model = "";

    if (provider === "groq") {
      const apiKey = process.env.GROQ_API_KEY;
      model = String(process.env.GROQ_MODEL || "llama-3.3-70b-versatile").trim();
      if (!apiKey) {
        return res.status(500).json({ error: "GROQ_API_KEY is not configured on the server." });
      }
      answer = await requestGroqChat({ apiKey, model, page, question, reports, history, attachments });
    } else {
      const apiKey = process.env.OPENAI_API_KEY;
      model = String(process.env.OPENAI_MODEL || "gpt-5-mini").trim();
      if (!apiKey) {
        return res.status(500).json({ error: "OPENAI_API_KEY is not configured on the server." });
      }
      answer = await requestOpenAiChat({ apiKey, model, page, question, reports, history, attachments });
    }

    if (!answer) {
      return res.status(502).json({ error: "The AI service returned an empty response." });
    }

    res.json({
      answer,
      provider,
      model,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(502).json({
      error: "Failed to get an AI response.",
      details: error.payload || error.message
    });
  }
});

// ─── ASM: Attack Surface Management ────────────────────────────────────────

const ASM_RISK_KEYWORDS = ["vpn","admin","login","mail","owa","remote","internal","dev","staging","test","api","portal","secure","auth","sso","citrix","rdp","ftp","smtp"];

function asmRiskScore(subdomain) {
  const label = subdomain.split(".")[0].toLowerCase();
  if (ASM_RISK_KEYWORDS.some(kw => label === kw || label.startsWith(kw + "-") || label.endsWith("-" + kw))) return "high";
  if (label.startsWith("dev") || label.startsWith("test") || label.startsWith("staging")) return "medium";
  return "low";
}

async function runAsmScan(domainEntry) {
  const domain = domainEntry.domain;
  const certs = await fetchCertspotter(domain);
  const now = new Date().toISOString();

  const currentSubdomains = [...new Set(
    certs.flatMap(e => Array.isArray(e.dns_names) ? e.dns_names : [])
      .map(s => s.replace(/^\*\./, "").toLowerCase())
      .filter(s => s === domain || s.endsWith(`.${domain}`))
  )].sort();

  const previousSubdomains = new Set(domainEntry.subdomains || []);
  const newSubdomains = currentSubdomains.filter(s => !previousSubdomains.has(s));

  const brandAbuse = certs
    .flatMap(e => Array.isArray(e.dns_names) ? e.dns_names : [])
    .map(s => s.replace(/^\*\./, "").toLowerCase())
    .filter(s => s !== domain && !s.endsWith(`.${domain}`))
    .map(s => ({ name: s, abuse: detectCtBrandAbuse(s, domain) }))
    .filter(e => e.abuse !== null)
    .slice(0, 20);

  const alerts = [];

  for (const sub of newSubdomains) {
    const risk = asmRiskScore(sub);
    alerts.push({
      id: makeId("asm-alert"),
      type: "NEW_ASSET",
      domain,
      asset: sub,
      risk,
      firstSeen: now,
      message: `New subdomain detected: ${sub}`
    });
  }

  for (const { name, abuse } of brandAbuse) {
    alerts.push({
      id: makeId("asm-alert"),
      type: "BRAND_ABUSE",
      domain,
      asset: name,
      risk: "critical",
      firstSeen: now,
      similarity: abuse.similarity,
      abuseType: abuse.type,
      message: `Potential brand abuse: ${name} (${abuse.similarity}% match, ${abuse.type})`
    });
  }

  return { currentSubdomains, newSubdomains, alerts, scannedAt: now };
}

app.get("/api/asm/domains", (req, res) => {
  const store = readWorkspaceStore();
  res.json({ domains: store.ctMonitor.domains });
});

app.post("/api/asm/domains", (req, res) => {
  const domain = normalizeDomainInput(req.body?.domain);
  if (!isLikelyDomain(domain)) return badRequest(res, "A valid domain is required.");
  const store = readWorkspaceStore();
  if (store.ctMonitor.domains.find(d => d.domain === domain)) {
    return res.json({ existed: true, domain });
  }
  const entry = { id: makeId("asm"), domain, subdomains: [], addedAt: new Date().toISOString(), lastScannedAt: null };
  store.ctMonitor.domains.unshift(entry);
  writeWorkspaceStore(store);
  res.status(201).json({ entry });
});

app.delete("/api/asm/domains/:id", (req, res) => {
  const store = readWorkspaceStore();
  const before = store.ctMonitor.domains.length;
  store.ctMonitor.domains = store.ctMonitor.domains.filter(d => d.id !== req.params.id);
  if (store.ctMonitor.domains.length === before) return res.status(404).json({ error: "Domain not found." });
  writeWorkspaceStore(store);
  res.json({ ok: true });
});

app.post("/api/asm/scan", async (req, res) => {
  const domain = normalizeDomainInput(req.body?.domain);
  if (!isLikelyDomain(domain)) return badRequest(res, "A valid domain is required.");
  const store = readWorkspaceStore();
  const entry = store.ctMonitor.domains.find(d => d.domain === domain);
  if (!entry) return res.status(404).json({ error: "Domain not monitored. Add it first." });
  try {
    const result = await runAsmScan(entry);
    entry.subdomains = result.currentSubdomains;
    entry.lastScannedAt = result.scannedAt;
    // Deduplicate alerts by asset+type before storing
    const existingKeys = new Set(store.ctMonitor.alerts.map(a => `${a.type}:${a.asset}`));
    const fresh = result.alerts.filter(a => !existingKeys.has(`${a.type}:${a.asset}`));
    store.ctMonitor.alerts.unshift(...fresh);
    store.ctMonitor.alerts = store.ctMonitor.alerts.slice(0, 500);
    writeWorkspaceStore(store);
    res.json({ domain, newSubdomains: result.newSubdomains, newAlerts: fresh.length, subdomainCount: result.currentSubdomains.length, scannedAt: result.scannedAt });
  } catch (err) {
    res.status(502).json({ error: err.message || "Scan failed." });
  }
});

app.post("/api/asm/scan-all", async (req, res) => {
  const store = readWorkspaceStore();
  const results = [];
  for (const entry of store.ctMonitor.domains) {
    try {
      const result = await runAsmScan(entry);
      entry.subdomains = result.currentSubdomains;
      entry.lastScannedAt = result.scannedAt;
      const existingKeys = new Set(store.ctMonitor.alerts.map(a => `${a.type}:${a.asset}`));
      const fresh = result.alerts.filter(a => !existingKeys.has(`${a.type}:${a.asset}`));
      store.ctMonitor.alerts.unshift(...fresh);
      results.push({ domain: entry.domain, ok: true, newAlerts: fresh.length });
    } catch (err) {
      results.push({ domain: entry.domain, ok: false, error: err.message });
    }
  }
  store.ctMonitor.alerts = store.ctMonitor.alerts.slice(0, 500);
  writeWorkspaceStore(store);
  res.json({ results });
});

app.get("/api/asm/alerts", (req, res) => {
  const store = readWorkspaceStore();
  const domain = String(req.query.domain || "").trim().toLowerCase();
  let alerts = store.ctMonitor.alerts;
  if (domain) alerts = alerts.filter(a => a.domain === domain);
  res.json({ total: alerts.length, alerts: alerts.slice(0, 100) });
});

app.delete("/api/asm/alerts/:id", (req, res) => {
  const store = readWorkspaceStore();
  store.ctMonitor.alerts = store.ctMonitor.alerts.filter(a => a.id !== req.params.id);
  writeWorkspaceStore(store);
  res.json({ ok: true });
});

// ─── CT Monitor — Certspotter API (free, no auth, reliable) ─────────────────
// CT Monitor — Certspotter API (free, no auth, reliable)
const https = require("https");

function fetchCertspotter(domain) {
  return new Promise((resolve, reject) => {
    const results = [];
    let afterId = null;
    let pages = 0;
    const MAX_PAGES = 10;

    function fetchPage() {
      if (pages >= MAX_PAGES) return resolve(results);
      pages++;
      // Note: no expand=cert — reduces payload size significantly
      const qs = "domain=" + encodeURIComponent(domain) +
        "&include_subdomains=true&expand=dns_names&expand=issuer" +
        (afterId ? "&after=" + encodeURIComponent(afterId) : "");
      const url = "https://api.certspotter.com/v1/issuances?" + qs;
      let settled = false;
      const done = (fn) => { if (!settled) { settled = true; clearTimeout(wc); fn(); } };
      const wc = setTimeout(() => { req.destroy(); done(() => reject(new Error("CT lookup timed out. Try again in a moment."))); }, 20000);
      const req = https.get(url, { headers: { "User-Agent": "CyberShield/1.0" } }, (res) => {
        let data = "";
        res.on("data", c => { data += c; });
        res.on("end", () => done(() => {
          // Check status BEFORE attempting JSON parse
          if (res.statusCode === 429) return reject(new Error("CT source rate limit reached. Wait 60 seconds and try again."));
          if (res.statusCode === 401 || res.statusCode === 403) return reject(new Error("CT source requires authentication for this domain. Try a smaller or less popular domain."));
          if (res.statusCode !== 200) return reject(new Error("CT source returned HTTP " + res.statusCode + ". Try again shortly."));
          // Guard against HTML responses (rate limit pages, error pages)
          const trimmed = data.trim();
          if (!trimmed.startsWith("[") && !trimmed.startsWith("{")) {
            return reject(new Error("CT source returned an unexpected response (not JSON). The service may be temporarily unavailable."));
          }
          try {
            const page = JSON.parse(trimmed);
            if (!Array.isArray(page) || page.length === 0) return resolve(results);
            results.push(...page);
            afterId = page[page.length - 1].id;
            if (page.length < 100) return resolve(results);
            fetchPage();
          } catch(e) { reject(new Error("CT response parse failed: " + e.message)); }
        }));
      });
      req.on("error", (e) => done(() => reject(new Error("CT lookup failed: " + e.message))));
    }
    fetchPage();
  });
}

// CT Monitor helpers
const KNOWN_BRANDS_CT = ["google","youtube","gmail","microsoft","azure","office","outlook","amazon","aws","apple","icloud","facebook","instagram","whatsapp","meta","twitter","github","paypal","stripe","netflix","cloudflare","openai","chatgpt","linkedin","dropbox","salesforce","adobe","zoom","slack","shopify"];

function ctLevenshtein(a, b) {
  const dp = Array.from({length: a.length+1}, (_,i) => Array.from({length: b.length+1}, (_,j) => i===0?j:j===0?i:0));
  for (let i=1;i<=a.length;i++) for (let j=1;j<=b.length;j++)
    dp[i][j] = a[i-1]===b[j-1] ? dp[i-1][j-1] : 1+Math.min(dp[i-1][j],dp[i][j-1],dp[i-1][j-1]);
  return dp[a.length][b.length];
}

function detectCtBrandAbuse(name, queryDomain) {
  const clean = name.replace(/^\*\./, "").toLowerCase();
  if (clean === queryDomain || clean.endsWith(`.${queryDomain}`)) return null;
  const queryBase = queryDomain.split(".")[0];
  for (const brand of KNOWN_BRANDS_CT) {
    if (!clean.includes(brand)) continue;
    const part = clean.split(".")[0];
    const dist = ctLevenshtein(part, brand);
    const sim = Math.round((1 - dist / Math.max(part.length, brand.length)) * 100);
    if (sim >= 70) return { brand, similarity: sim, type: dist === 0 ? "impersonation" : "typosquatting" };
  }
  const part = clean.split(".")[0];
  const dist = ctLevenshtein(part, queryBase);
  const sim = Math.round((1 - dist / Math.max(part.length, queryBase.length)) * 100);
  if (sim >= 80 && sim < 100) return { brand: queryDomain, similarity: sim, type: "typosquatting" };
  return null;
}

app.get("/api/cert-monitor/check", async (req, res) => {
  const domain = String(req.query.domain || "").trim().toLowerCase();
  if (!isLikelyDomain(domain)) return badRequest(res, "A valid domain is required.");

  let certs = [];
  let source = "certspotter";
  let lastErr = null;

  try {
    certs = await fetchCertspotter(domain);
  } catch (err) {
    lastErr = err.message;
  }

  if (!certs.length) {
    const isTimeout = lastErr && lastErr.includes("timed out");
    const isRateLimit = lastErr && lastErr.includes("rate limit");
    return res.status(502).json({
      error: isTimeout
        ? "CT lookup timed out. Wait a few seconds and try again."
        : isRateLimit
          ? lastErr
          : lastErr
            ? lastErr
            : `No CT records found for ${domain}. The domain may have no certificates logged yet.`
    });
  }

  const now = Date.now();
  const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;

  const normalized = certs.map(e => {
    const dnsNames = Array.isArray(e.dns_names) ? e.dns_names : [];
    const isWildcard = dnsNames.some(s => s.startsWith("*."));
    const isOwned = dnsNames.some(s => {
      const sc = s.replace(/^\*\./, "").toLowerCase();
      return sc === domain || sc.endsWith(`.${domain}`);
    });
    const isNew = !!(e.not_before && (now - new Date(e.not_before).getTime()) < sevenDaysMs);
    const isExpired = !!(e.not_after && new Date(e.not_after).getTime() < now);
    const issuerLabel = e.issuer ? (e.issuer.organization || e.issuer.common_name || null) : null;
    const commonName = dnsNames[0] || null;
    const brandAbuse = !isOwned ? detectCtBrandAbuse(commonName || "", domain) : null;
    return {
      issuer: issuerLabel,
      commonName,
      sans: dnsNames,
      notBefore: e.not_before || null,
      notAfter: e.not_after || null,
      loggedAt: e.not_before || null,
      serialNumber: e.tbs_sha256 || null,
      revoked: e.revoked || false,
      isWildcard,
      isOwned,
      isNew,
      isExpired,
      brandAbuse
    };
  })
  .filter(e => e.commonName || e.sans.length)
  .sort((a, b) => new Date(b.loggedAt || 0) - new Date(a.loggedAt || 0));

  // Extract unique subdomains from dns_names
  const subdomains = [...new Set(
    normalized.flatMap(e => e.sans)
      .map(s => s.replace(/^\*\./, "").toLowerCase())
      .filter(s => s.endsWith(`.${domain}`) || s === domain)
  )].sort();

  const newCerts = normalized.filter(e => e.isNew);
  const wildcardCerts = normalized.filter(e => e.isWildcard && e.isOwned);
  const brandAbuseCerts = normalized.filter(e => e.brandAbuse);
  const suspiciousCerts = normalized.filter(e => !e.isOwned && !e.brandAbuse && !e.isExpired);
  const issuers = [...new Set(normalized.map(e => e.issuer).filter(Boolean))];

  // Certificate timeline by year
  const timelineByYear = {};
  for (const c of normalized) {
    const yr = c.notBefore ? new Date(c.notBefore).getFullYear() : null;
    if (yr && yr > 2000) timelineByYear[yr] = (timelineByYear[yr] || 0) + 1;
  }

  // CA distribution (top 5) — issuer is already a clean string from Certspotter
  const caCount = {};
  for (const c of normalized) {
    if (!c.issuer) continue;
    const ca = c.issuer.slice(0, 60);
    caCount[ca] = (caCount[ca] || 0) + 1;
  }
  const caDistribution = Object.entries(caCount)
    .sort((a, b) => b[1] - a[1]).slice(0, 5)
    .map(([ca, count]) => ({ ca, count, pct: Math.round(count / normalized.length * 100) }));

  // Suspicious subdomain keywords (attack surface)
  const SUSPICIOUS_KEYWORDS = ["vpn","admin","login","mail","owa","remote","internal","dev","staging","test","api","portal","secure","auth","sso","citrix","rdp","ftp","smtp"];
  const suspiciousSubdomains = subdomains.filter(s => {
    const label = s.split(".")[0];
    return SUSPICIOUS_KEYWORDS.some(kw => label === kw || label.startsWith(kw + "-") || label.endsWith("-" + kw));
  });

  // Certificate hygiene score (0-100)
  const expiredCount = normalized.filter(e => e.isExpired).length;
  const hasWeakIssuer = normalized.some(e => e.issuer && /startssl|wosign|symantec/i.test(e.issuer));
  let hygieneScore = 100;
  if (expiredCount > 0) hygieneScore -= Math.min(30, expiredCount * 5);
  if (brandAbuseCerts.length > 0) hygieneScore -= 40;
  if (hasWeakIssuer) hygieneScore -= 20;
  if (wildcardCerts.length > 5) hygieneScore -= 10;
  hygieneScore = Math.max(0, hygieneScore);

  const firstSeen = normalized.map(e => e.notBefore).filter(Boolean).sort()[0] || null;
  const lastSeen = normalized.map(e => e.loggedAt || e.notBefore).filter(Boolean).sort().slice(-1)[0] || null;

  const alertLevel = brandAbuseCerts.length > 0 ? "high" : newCerts.length > 0 ? "medium" : "low";
  const alert = brandAbuseCerts.length > 0
    ? `${brandAbuseCerts.length} certificate(s) show brand abuse targeting ${domain}.`
    : newCerts.length > 0
      ? `${newCerts.length} new certificate(s) issued for ${domain} in the last 7 days.`
      : `No new certificates detected for ${domain} in the last 7 days.`;

  res.json({
    domain,
    source,
    checkedAt: new Date().toISOString(),
    totalCerts: normalized.length,
    alert,
    alertLevel,
    firstSeen,
    lastSeen,
    hygieneScore,
    summary: {
      total: normalized.length,
      newCount: newCerts.length,
      wildcard: wildcardCerts.length,
      brandAbuse: brandAbuseCerts.length,
      suspicious: suspiciousCerts.length,
      expired: expiredCount,
      uniqueIssuers: issuers.length,
      subdomainCount: subdomains.length,
      suspiciousSubdomainCount: suspiciousSubdomains.length
    },
    subdomains: subdomains.slice(0, 50),
    suspiciousSubdomains: suspiciousSubdomains.slice(0, 20),
    issuers: issuers.slice(0, 10),
    caDistribution,
    timelineByYear,
    newCerts: newCerts.slice(0, 10),
    wildcardCerts: wildcardCerts.slice(0, 10),
    brandAbuseCerts: brandAbuseCerts.slice(0, 10),
    suspiciousCerts: suspiciousCerts.slice(0, 10),
    recentCerts: normalized.slice(0, 15)
  });
});

app.get("/", (req, res) => {
  res.sendFile(path.resolve(__dirname, "home2.html"));
});

app.use(express.static(path.resolve(__dirname), {
  index: false,
  etag: false,
  lastModified: false,
  setHeaders(res, filePath) {
    if (/\.(css|js|html)$/i.test(filePath)) {
      res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
      res.setHeader("Pragma", "no-cache");
      res.setHeader("Expires", "0");
      res.setHeader("Surrogate-Control", "no-store");
    }
  }
}));

app.use((error, req, res, next) => {
  if (error?.type === "entity.too.large") {
    return res.status(413).json({
      error: "AI request payload was too large. Please retry with fewer saved reports or shorter chat history."
    });
  }
  return next(error);
});

app.use((req, res) => {
  res.status(404).json({ error: "Route not found." });
});

function startAsmScheduler() {
  const INTERVAL_MS = 60 * 60 * 1000;
  setInterval(async () => {
    const store = readWorkspaceStore();
    if (!store.ctMonitor.domains.length) return;
    console.log(`[ASM Scheduler] Running hourly scan for ${store.ctMonitor.domains.length} domain(s)...`);
    for (const entry of store.ctMonitor.domains) {
      try {
        const result = await runAsmScan(entry);
        entry.subdomains = result.currentSubdomains;
        entry.lastScannedAt = result.scannedAt;
        const existingKeys = new Set(store.ctMonitor.alerts.map(a => `${a.type}:${a.asset}`));
        const fresh = result.alerts.filter(a => !existingKeys.has(`${a.type}:${a.asset}`));
        store.ctMonitor.alerts.unshift(...fresh);
        if (fresh.length) console.log(`[ASM Scheduler] ${entry.domain}: ${fresh.length} new alert(s)`);
      } catch (err) {
        console.error(`[ASM Scheduler] ${entry.domain} scan failed: ${err.message}`);
      }
    }
    store.ctMonitor.alerts = store.ctMonitor.alerts.slice(0, 500);
    writeWorkspaceStore(store);
  }, INTERVAL_MS);
}

function startServer() {
  ensureWorkspaceStore();
  startAsmScheduler();
  return app.listen(PORT, () => {
    console.log(`CyberShield backend running at http://localhost:${PORT}`);
  });
}

if (require.main === module) {
  startServer();
}

module.exports = {
  app,
  startServer
};
