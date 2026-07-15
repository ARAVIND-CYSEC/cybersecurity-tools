// Strict (non-simulated) TLS intelligence helpers for CyberShield
// Designed to be used from server.js. No fabricated SSL-Labs wrappers.

const tls = require("tls");

function parseStrictTransportSecurity(hstsRaw) {
  const raw = String(hstsRaw || "").trim();
  if (!raw) return { present: false, value: null, maxAge: null, includeSubDomains: false, preload: false, otherDirectives: [] };

  const directives = raw.split(";").map(s => s.trim()).filter(Boolean);
  const maxAgeDir = directives.find(d => /^max-age\s*=\s*\d+/i.test(d));
  const maxAge = maxAgeDir ? Number((maxAgeDir.match(/\d+/)?.[0] || "0")) : null;

  const includeSubDomains = directives.some(d => /^includeSubDomains$/i.test(d));
  const preload = directives.some(d => /^preload$/i.test(d));

  const otherDirectives = directives.filter(d => !/^max-age\s*=/i.test(d) && !/^includeSubDomains$/i.test(d) && !/^preload$/i.test(d));

  return {
    present: true,
    value: raw,
    maxAge,
    includeSubDomains,
    preload,
    otherDirectives
  };
}

function parseContentSecurityPolicy(cspRaw) {
  const raw = String(cspRaw || "").trim();
  if (!raw) return { present: false, value: null, directives: [], otherDirectives: {} };

  // Best-effort parsing (do not claim semantic correctness; just structure)
  const parts = raw.split(";").map(s => s.trim()).filter(Boolean);
  const directives = parts.map(part => {
    const [name, ...rest] = part.split(/\s+/);
    return { name: name || null, values: rest || [] };
  }).filter(d => d.name);

  const otherDirectives = {};
  for (const d of directives) otherDirectives[d.name] = d.values;

  return { present: true, value: raw, directives, otherDirectives };
}

async function tlsHandshakeWithVersion({ hostname, port, servername, minVersion, maxVersion, timeoutMs }) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: hostname,
      port: port || 443,
      servername: servername || hostname,
      rejectUnauthorized: false,
      timeout: timeoutMs || 8000,
      minVersion,
      maxVersion
    }, () => {
      try {
        const cert = socket.getPeerCertificate(true);
        const negotiatedProtocol = socket.getProtocol ? socket.getProtocol() : null;
        const cipher = socket.getCipher ? socket.getCipher() : null;

        const san = cert?.subjectaltname
          ? String(cert.subjectaltname)
              .split(",")
              .map(s => s.replace(/^DNS:/i, "").trim())
              .filter(Boolean)
          : [];

        // Chain is not guaranteed through getPeerCertificate in Node; this is best-effort.
        const chain = [];
        let c = cert;
        const seen = new Set();
        while (c && c.subject && c.fingerprint && !seen.has(c.fingerprint)) {
          seen.add(c.fingerprint);
          chain.push({
            subject: { CN: c.subject?.CN || null, O: c.subject?.O || null },
            issuerSubject: { CN: c.issuer?.CN || null, O: c.issuer?.O || null },
            issuerLabel: c.issuer?.CN || c.issuer?.O || null,
            fingerprint256: c.fingerprint256 || null
          });
          c = c.issuerCertificate && c.issuerCertificate !== c ? c.issuerCertificate : null;
        }

        resolve({
          ok: true,
          negotiated: {
            protocol: negotiatedProtocol,
            cipher: cipher?.name || null,
            cipherBits: cipher?.version || null
          },
          certificate: {
            subject: cert?.subject || null,
            issuer: cert?.issuer || null,
            issuerLabel: cert?.issuer?.CN || cert?.issuer?.O || null,
            validFrom: cert?.valid_from || null,
            validTo: cert?.valid_to || null,
            serialNumber: cert?.serialNumber || null,
            fingerprint256: cert?.fingerprint256 || cert?.fingerprint || null,
            san
          },
          chain
        });
      } catch (e) {
        resolve({ ok: false, error: e?.message || "TLS parsing failed" });
      } finally {
        socket.end();
      }
    });

    socket.on("error", (err) => {
      resolve({ ok: false, error: err?.message || "TLS handshake error" });
    });

    socket.on("timeout", () => {
      socket.destroy();
      resolve({ ok: false, error: `TLS handshake timed out after ${timeoutMs || 8000}ms` });
    });
  });
}

async function probeTlsSupport(hostname) {
  const versions = [
    { label: "TLSv1.0", min: "TLSv1", max: "TLSv1" },
    { label: "TLSv1.1", min: "TLSv1.1", max: "TLSv1.1" },
    { label: "TLSv1.2", min: "TLSv1.2", max: "TLSv1.2" },
    { label: "TLSv1.3", min: "TLSv1.3", max: "TLSv1.3" }
  ];

  const tlsVersionMap = {
    "TLSv1": "TLSv1",
    "TLSv1.1": "TLSv1.1",
    "TLSv1.2": "TLSv1.2",
    "TLSv1.3": "TLSv1.3"
  };

  const results = {};
  for (const v of versions) {
    try {
      const res = await tlsHandshakeWithVersion({
        hostname,
        port: 443,
        servername: hostname,
        minVersion: tlsVersionMap[v.min],
        maxVersion: tlsVersionMap[v.max],
        timeoutMs: 8000
      });
      results[v.label] = res.ok ? { supported: true, ...res } : { supported: false, error: res.error };
    } catch (e) {
      results[v.label] = { supported: false, error: e?.message || "Unknown error" };
    }
  }

  // Pick the first supported version for convenience
  const supportedOrder = versions.map(v => v.label);
  const firstSupported = supportedOrder.find(lbl => results[lbl]?.supported);

  return { supported: firstSupported || null, probes: results };
}

module.exports = {
  parseStrictTransportSecurity,
  parseContentSecurityPolicy,
  probeTlsSupport
};

