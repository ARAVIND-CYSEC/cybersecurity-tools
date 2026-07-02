# CyberShield URL Detonation Microservice

This service is a standalone URL detonation engine for CyberShield. It safely opens a suspicious URL in a headless browser, records what happens, collects artifacts, enriches the result, and returns a JSON security report.

## What it does

- validates and normalizes an input URL
- blocks private or local-network targets
- opens the URL inside Playwright Chromium
- waits for the page to render and delayed scripts to fire
- captures:
  - full-page screenshot
  - rendered HTML
  - request/response activity
  - redirect chain
  - final resolved IPs
- enriches with:
  - DNS resolution
  - TLS metadata
  - optional IP geolocation via `ipinfo`
  - optional threat hits via `abuse.ch`
- calculates a deterministic risk score
- caches recent reports in memory

## Folder structure

- `app.py` - FastAPI service and detonation pipeline
- `requirements.txt` - Python dependencies
- `.env.example` - optional service configuration
- `artifacts/` - screenshots and DOM dumps

## Local setup

Create a Python virtual environment, then install the dependencies:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
playwright install
```

Copy the example environment file if you want optional enrichment:

```powershell
Copy-Item .env.example .env
```

## Run the service

```powershell
uvicorn app:app --host 0.0.0.0 --port 8010 --reload
```

Open:

```text
http://localhost:8010/health
```

## API

### `POST /detonate`

Body:

```json
{
  "url": "https://example.com/login",
  "timeout": 15,
  "wait_until": "networkidle"
}
```

### Example response shape

```json
{
  "input": "https://example.com/login",
  "type": "url",
  "host": "example.com",
  "http": {
    "status": 200,
    "final_url": "https://example.com/login",
    "content_type": "text/html",
    "redirect_chain": []
  },
  "tls": {
    "issuer": {
      "organizationName": "Let's Encrypt"
    }
  },
  "detonation": {
    "page": {
      "title": "Example Login",
      "screenshot_path": "artifacts/abc123/snapshot.png",
      "dom_path": "artifacts/abc123/rendered.html",
      "phishing_indicators": ["password_form"]
    }
  },
  "risk": {
    "score": 35,
    "band": "medium",
    "reasons": [
      "Rendered page contained phishing-oriented indicators."
    ]
  }
}
```

## Safety notes

This service is designed as a safer detonation helper, but it is still opening suspicious content. For stronger isolation:

- run it inside Docker
- dedicate a separate VM or sandbox host
- avoid running it directly on your primary workstation long term

## How to integrate with CyberShield later

Once this service is running, CyberShield can call it from the Node backend:

- submit a suspicious URL from `analysis.html`
- poll or wait for the JSON result
- store the artifact ID in a case
- attach the screenshot and rendered evidence to reports
