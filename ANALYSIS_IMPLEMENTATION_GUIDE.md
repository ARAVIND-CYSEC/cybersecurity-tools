# Analysis.html Intelligence Output Implementation Guide

## Overview
Transform analysis.html to match the enterprise domain/URL intelligence model with structured sections.

## Key Changes Required

### 1. DOMAIN OVERVIEW Section
**Location**: Replace/enhance `renderDomainInfraOverview()` function
**Add fields**:
```javascript
{
  domain: string,
  type: "Domain" | "Subdomain",
  status: "Active" | "Inactive",
  registrationDate: string,
  expirationDate: string,
  registrar: string,
  organization: string
}
```

### 2. INFRASTRUCTURE PROFILE Section
**Location**: Enhance existing IP stream rendering
**Structure**:
```javascript
{
  primaryIP: string,
  resolvedIPs: string[],
  asn: string,
  hostingProvider: string,
  cdnProvider: string | null,
  cloudProvider: string | null,
  geolocation: { city, country, coordinates }
}
```

### 3. DNS ANALYSIS Section
**Location**: Already exists in `tab === 'dns'`
**Enhance to show**:
- A Records
- AAAA Records
- MX Records
- NS Records
- TXT Records
- CNAME Records

### 4. TLS & CERTIFICATE ANALYSIS
**Location**: Already exists in `renderTlsIntelligencePanel()`
**Add fields**:
- Certificate Status: "Valid" | "Expired" | "Self-Signed"
- Issuer: string
- Expiration: date
- Validity: days remaining
- Certificate Chain: issuer hierarchy

### 5. ATTACK SURFACE ANALYSIS
**Location**: Already exists in `renderPortsServicesPanel()`
**Add**:
- Open Ports (already exists)
- Observed Services (already exists)
- Service Banners (already exists)
- Technology Fingerprints (link to tech stack)

### 6. TECHNOLOGY STACK
**Location**: Already exists in `renderTechnologyStackPanel()`
**Current fields are good, add**:
- Web Server
- Framework
- CDN
- JavaScript Libraries
- Analytics
- Security Headers

### 7. INFRASTRUCTURE RELATIONSHIPS
**Location**: Already exists in `renderRelationshipGraph()`
**Enhance to show**:
- Domain → IP
- IP → ASN
- ASN → Organization
- Certificate → Domains (SAN list)

### 8. REPUTATION SUMMARY
**NEW SECTION** - Add after Infrastructure Profile
```javascript
function renderReputationSummary(profile, exposure) {
  return `
    <section class="glass rounded-[1.5rem] p-5">
      <p class="section-label m-0">Reputation Summary</p>
      <div class="mt-4 grid md:grid-cols-3 gap-4">
        <div class="insight-card">
          <p class="section-label m-0">Infrastructure Reputation</p>
          <p class="mt-3 mb-0 text-lg font-semibold">${calculateInfraReputation(profile)}</p>
        </div>
        <div class="insight-card">
          <p class="section-label m-0">Hosting Reputation</p>
          <p class="mt-3 mb-0 text-lg font-semibold">${calculateHostingReputation(profile)}</p>
        </div>
        <div class="insight-card">
          <p class="section-label m-0">ASN Reputation</p>
          <p class="mt-3 mb-0 text-lg font-semibold">${calculateASNReputation(profile)}</p>
        </div>
      </div>
      <p class="mt-4 text-sm text-slate-500 dark:text-slate-400">
        Note: Reputation scores provide context but are not threat intelligence indicators.
      </p>
    </section>
  `;
}

function calculateInfraReputation(profile) {
  const ip = profile?.ips?.[0] || {};
  if (classifyProvider(ip.org) === "Cloud Provider") return "Trusted";
  if (classifyProvider(ip.org) === "Consumer ISP") return "Unknown";
  return "Standard";
}

function calculateHostingReputation(profile) {
  const infraType = detectInfraType(profile?.ips?.[0] || {});
  if (infraType === "CDN Edge Node") return "High Trust";
  if (infraType === "Cloud Hosted") return "Trusted";
  if (infraType === "Consumer ISP") return "Low Trust";
  return "Standard";
}

function calculateASNReputation(profile) {
  const asn = profile?.ips?.[0]?.asn;
  if (!asn) return "Unknown";
  // Could integrate with ASN reputation databases
  return "Standard";
}
```

### 9. OBSERVATION SUMMARY
**NEW SECTION** - Add key findings with checkmarks
```javascript
function renderObservationSummary(profile, exposure, tls) {
  const findings = [];
  
  if (classifyProvider(profile?.ips?.[0]?.org) === "Cloud Provider") {
    findings.push("✓ Enterprise Infrastructure");
  }
  if (tls?.ssllabs?.status === "READY" || exposure?.tls?.enabled) {
    findings.push("✓ TLS Enabled");
  }
  if ((getExposureServices(exposure) || []).length === 0) {
    findings.push("✓ No Exposed Services");
  }
  if ((profile?.ips || []).length > 1) {
    findings.push("✓ Multiple IPs Detected");
  }
  if (detectInfraType(profile?.ips?.[0] || {}) === "CDN Edge Node") {
    findings.push("✓ Global CDN Present");
  }
  
  return `
    <section class="glass rounded-[1.5rem] p-5">
      <p class="section-label m-0">Key Findings</p>
      <div class="mt-4 grid md:grid-cols-2 gap-3">
        ${findings.map(f => `<div class="insight-card text-emerald-400 font-semibold">${escapeHtml(f)}</div>`).join("")}
      </div>
    </section>
  `;
}
```

### 10. INFRASTRUCTURE ASSESSMENT
**NEW SECTION** - Add infrastructure quality scoring
```javascript
function renderInfrastructureAssessment(profile, exposure) {
  const ownershipConfidence = profile?.registrar ? "High" : "Unknown";
  const exposureLevel = (exposure?.exposure?.score || 0) >= 60 ? "High" : 
                        (exposure?.exposure?.score || 0) >= 30 ? "Medium" : "Low";
  const maturity = profile?.registrationDate ? calculateMaturity(profile.registrationDate) : "Unknown";
  
  return `
    <section class="glass rounded-[1.5rem] p-5">
      <p class="section-label m-0">Infrastructure Assessment</p>
      <div class="mt-4 grid md:grid-cols-4 gap-4">
        <div class="insight-card">
          <p class="section-label m-0">Infrastructure Type</p>
          <p class="mt-3 mb-0 text-lg font-semibold">${escapeHtml(detectInfraType(profile?.ips?.[0] || {}))}</p>
        </div>
        <div class="insight-card">
          <p class="section-label m-0">Ownership Confidence</p>
          <p class="mt-3 mb-0 text-lg font-semibold">${escapeHtml(ownershipConfidence)}</p>
        </div>
        <div class="insight-card">
          <p class="section-label m-0">Exposure Level</p>
          <p class="mt-3 mb-0 text-lg font-semibold">${escapeHtml(exposureLevel)}</p>
        </div>
        <div class="insight-card">
          <p class="section-label m-0">Operational Maturity</p>
          <p class="mt-3 mb-0 text-lg font-semibold">${escapeHtml(maturity)}</p>
        </div>
      </div>
    </section>
  `;
}

function calculateMaturity(registrationDate) {
  if (!registrationDate) return "Unknown";
  const age = Date.now() - new Date(registrationDate).getTime();
  const years = age / (1000 * 60 * 60 * 24 * 365);
  if (years >= 5) return "Mature";
  if (years >= 1) return "Established";
  return "New";
}
```

### 11. ANALYST OBSERVATIONS
**NEW SECTION** - Add contextual analyst notes
```javascript
function generateAnalystObservations(profile, exposure, tls) {
  const org = profile?.ips?.[0]?.org || profile?.registrar || "Unknown organization";
  const asn = profile?.ips?.[0]?.asn || "Unknown ASN";
  const ipCount = (profile?.ips || []).length;
  const tlsStatus = tls?.ssllabs?.status === "READY" || exposure?.tls?.enabled;
  const serviceCount = (getExposureServices(exposure) || []).length;
  
  let observation = `Infrastructure is attributed to ${org} and hosted within ${asn} ASN space. `;
  
  if (ipCount > 1) {
    observation += `Multiple A records (${ipCount}) provide redundancy and availability. `;
  }
  
  if (tlsStatus) {
    observation += `TLS is enabled and certificate validation was successful. `;
  }
  
  if (serviceCount === 0) {
    observation += `No externally observable services were identified from current data sources.`;
  } else {
    observation += `${serviceCount} exposed service(s) detected on public-facing infrastructure.`;
  }
  
  return `
    <section class="glass rounded-[1.5rem] p-5">
      <p class="section-label m-0">Analyst Observations</p>
      <p class="mt-4 mb-0 text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
        ${escapeHtml(observation)}
      </p>
    </section>
  `;
}
```

### 12. EXECUTIVE SUMMARY
**NEW SECTION** - Add at the top of overview tab
```javascript
function renderExecutiveSummary(profile, exposure, tls) {
  const whoOwns = profile?.registrar || profile?.ips?.[0]?.org || "Unknown organization";
  const howHosted = detectInfraType(profile?.ips?.[0] || {});
  const whatExposed = (getExposureServices(exposure) || []).length > 0 
    ? `${(getExposureServices(exposure) || []).length} exposed services` 
    : "No exposed services";
  const analystNote = `${howHosted} infrastructure with ${exposure?.tls?.enabled ? "TLS enabled" : "no TLS observed"}`;
  
  return `
    <section class="situation-shell">
      <div class="situation-hero">
        <p class="section-label m-0">Executive Summary</p>
        <div class="mt-4 space-y-4">
          <div>
            <p class="text-sm text-slate-500 dark:text-slate-400">Who owns it?</p>
            <p class="mt-1 text-xl font-bold">${escapeHtml(whoOwns)}</p>
          </div>
          <div>
            <p class="text-sm text-slate-500 dark:text-slate-400">How is it hosted?</p>
            <p class="mt-1 text-xl font-bold">${escapeHtml(howHosted)}</p>
          </div>
          <div>
            <p class="text-sm text-slate-500 dark:text-slate-400">What is exposed?</p>
            <p class="mt-1 text-xl font-bold">${escapeHtml(whatExposed)}</p>
          </div>
          <div>
            <p class="text-sm text-slate-500 dark:text-slate-400">What should analysts know?</p>
            <p class="mt-1 text-base text-slate-600 dark:text-slate-300">${escapeHtml(analystNote)}</p>
          </div>
        </div>
      </div>
    </section>
  `;
}
```

## Implementation Steps

1. **Add new helper functions** at the top of the script section (after existing helpers)
2. **Modify the overview tab rendering** in `renderContent()` for domain type:
```javascript
if (tab === "overview") {
  root.innerHTML = `
    ${renderExecutiveSummary(profile, exposure, data.tls)}
    ${renderExposureOverview(profile, exposure, data.tls)}
    ${renderDomainInfraOverview(profile, exposure)}
    ${renderReputationSummary(profile, exposure)}
    ${renderObservationSummary(profile, exposure, data.tls)}
    ${renderInfrastructureAssessment(profile, exposure)}
    ${generateAnalystObservations(profile, exposure, data.tls)}
  `;
  return;
}
```

3. **Enhance existing sections** with additional fields as specified above

## Testing
- Test with: `google.com`, `cloudflare.com`, `example.com`
- Verify all sections render properly
- Check that data flows correctly from API to UI

## Notes
- Keep existing functionality intact
- Add new sections progressively
- Ensure responsive design maintained
- Follow existing code style
