# CyberShield Backend

This project now includes a lightweight `Node.js + Express` backend so third-party API calls can move off the browser and API keys can stay in server-side environment variables.

## Why this stack

- It matches the current project shape: plain HTML pages with JavaScript.
- It is easy to run locally with very little setup.
- It can serve the static files and backend routes from one process.
- It keeps secrets like `IPINFO_TOKEN` out of client-side code.

## Routes

- `GET /api/health`
  Returns a simple health response.

- `GET /api/cves?keyword=nginx&severity=HIGH`
  Proxies NVD CVE search and returns simplified CVE objects.

- `GET /api/osint/whois?domain=example.com`
  Returns RDAP domain data for a domain lookup.

- `GET /api/osint/rdap?query=example.com`
  Returns RDAP data for either a domain or IP.

- `GET /api/osint/dns?domain=example.com`
  Returns combined DNS lookups for `A`, `AAAA`, `MX`, `TXT`, `CNAME`, and `NS`.

- `GET /api/osint/uptime?url=https://example.com`
  Performs a server-side uptime check using a `HEAD` request.

- `GET /api/threat/ip/8.8.8.8`
  Returns IP intelligence from ipinfo using the server-side token.

- `GET /api/threat/domain/resolve?domain=example.com`
  Resolves a domain to IPv4 addresses using Google DNS.

- `GET /api/threat/domain/asn?domain=example.com`
  Resolves the domain and fetches ASN/org details through ipinfo.

- `GET /api/infrastructure/exposure?domain=example.com`
  Resolves the domain, enriches resolved IPs with Shodan host intelligence when `SHODAN_API_KEY` is configured, and returns open ports, exposed services, service banners, protocol fingerprints, TLS/certificate metadata, software/CPE/component fingerprints, ASN/hosting attribution, geolocation, operating systems, service risk analysis, protocol distribution, timeline events, service-to-infrastructure mappings, and exposure severity.

- `GET /api/security/ssl?domain=example.com`
  Returns SSL Labs data and recent certificate transparency entries.

## Environment setup

1. Copy `.env.example` to `.env`
2. Fill in your real values

Example:

```env
PORT=3000
IPINFO_TOKEN=your_real_token_here
SHODAN_API_KEY=your_real_shodan_key_here
```

## Install and run

```powershell
npm install
npm start
```

Then open:

```text
http://localhost:3000/
```

## Frontend migration plan

Update the HTML pages to call your own backend instead of third-party URLs directly:

- Replace NVD calls with `/api/cves`
- Replace RDAP calls with `/api/osint/whois` or `/api/osint/rdap`
- Replace Google DNS calls with `/api/osint/dns` or `/api/threat/domain/resolve`
- Replace `ipinfo.io` calls with `/api/threat/ip/:ip` and `/api/threat/domain/asn`
- Replace Shodan browser calls with `/api/infrastructure/exposure`
- Replace SSL Labs and `crt.sh` browser calls with `/api/security/ssl`

## Security notes

- Do not commit `.env`
- Do not hardcode tokens in HTML or browser JavaScript
- Keep using server-side validation before proxying user input upstream
- Add stronger rate limiting and caching before public deployment
