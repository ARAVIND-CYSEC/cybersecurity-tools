# TLS v2 Scanner - Direct Implementation Plan

## Information Gathered

### Frontend (`tls-v2.html`)
- POSTs to `/api/tls/v2/scan` with `{ domain, port: 443, timeout: 8 }`
- Expects a response with 11 modules: `dns`, `tls_protocol`, `cipher_suites`, `alpn`, `tls_features`, `performance`, `certificate`, `certificate_chain`, `certificate_transparency`, `ocsp`, `compliance`
- Each module has `findings`, `status`, `duration_ms`, `warnings`, `errors`
- Also expects `target`, `scan_duration_ms`, `summary` at top level
- Also calls `/api/tls/v2/health` and `/api/tls/v2/modules`

### Backend (`server.js`) - CURRENT
- Line ~2930: Simple proxy route forwarding to `TLS_V2_SERVICE_URL` (Python microservice)
- When Python service is down, returns 502 error
- The proxy doesn't add value - just forwards

### Available Node.js modules (`tls_intel_scanner.js`)
- `probeTlsSupport(hostname)` - Probes TLSv1.0 through TLSv1.3 support
- `parseStrictTransportSecurity(hstsRaw)`
- `parseContentSecurityPolicy(cspRaw)`
- Uses Node.js built-in `tls` module

### Python Backend (`tls_scanner_service/`)
- Full 11-module scanner at `api/v2.py`
- Runs on port 8060
- Has scanner modules for DNS, TLS protocol, cipher, ALPN, features, performance, cert parsing, chain validation, CT, OCSP, compliance

## Plan

### Option A (Recommended): Keep Proxy + Add Direct Fallback
1. Keep the existing proxy to Python service (best performance, all 11 modules)
2. When Python service is unavailable, fall back to direct Node.js TLS scan (basic 4-5 modules)
3. This ensures `tls-v2.html` always gets a response

### Option B: Full Direct Node.js Implementation
1. Replace proxy with direct implementation using Node.js `tls`, `dns`, `crypto`, `https` modules
2. Implement all 11 modules natively in `server.js`
3. Eliminate dependency on Python service

**Recommendation: Option A** - Keep the Python service for full scans, fall back to Node.js when unavailable.

