# TODO: Strict (non-simulated) TLS intelligence pipeline

- [ ] Inspect current `/api/security/ssl` response schema expectations in frontend (find where it’s rendered)
- [ ] Implement new endpoint (keep `/api/security/ssl` unchanged): `POST /api/security/tls-intel` (or `GET /api/security/tls-intel?domain=`)
- [ ] In new endpoint, replace any fabricated/SSL-Labs-like structures with **raw live socket-derived TLS intelligence**
- [ ] Add TLS protocol probing (TLSv1.0–TLSv1.3) with best-effort handshakes via Node `tls` forced min/max versions
- [ ] Parse live X.509 certificate fields (SAN, validity bounds, CN/SAN, serial, SHA-256 fingerprint)
- [ ] Add HTTP header auditing (Strict-Transport-Security parsing into structured values; CSP raw + best-effort directive list; XFO/XCTO/Referrer-Policy presence)
- [ ] Add CT log client (crt.sh JSON API) and compute firstSeen/latestSeen + issuers + recordCount
- [ ] Return output JSON matching the requested schema: `scan_metadata / transport_layer / certificate_authority / security_headers / certificate_transparency`
- [ ] Add minimal integration in UI (only if needed): add fetch call to new endpoint and render results
- [ ] Smoke test against `google.com`, `cloudflare.com`, `example.com`

