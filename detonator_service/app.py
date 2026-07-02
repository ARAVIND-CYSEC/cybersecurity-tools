import asyncio
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator


APP_ROOT = Path(__file__).resolve().parent
ARTIFACT_ROOT = APP_ROOT / "artifacts"
ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)

DEFAULT_TIMEOUT = int(os.getenv("DETONATOR_DEFAULT_TIMEOUT", "15"))
CACHE_TTL_SECONDS = int(os.getenv("DETONATOR_CACHE_TTL", "3600"))
USER_AGENT = os.getenv(
    "DETONATOR_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
ABUSECH_API_URL = os.getenv("ABUSECH_API_URL", "https://threatfox-api.abuse.ch/api/v1/")
ABUSECH_API_KEY = os.getenv("ABUSECH_API_KEY", "").strip()
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "").strip()
MAX_REDIRECTS = int(os.getenv("DETONATOR_MAX_REDIRECTS", "10"))

_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def ensure_http_url(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        raise ValueError("URL is required.")
    if not candidate.lower().startswith(("http://", "https://")):
        candidate = f"http://{candidate}"
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.hostname:
        raise ValueError("URL hostname is missing.")
    return candidate


def is_hash(value: str) -> bool:
    lowered = value.lower()
    return len(lowered) in {32, 40, 64} and all(ch in "0123456789abcdef" for ch in lowered)


def detect_input_type(value: str) -> str:
    with suppress(ValueError):
        ipaddress.ip_address(value)
        return "ip"
    if is_hash(value):
        return "hash"
    parsed = urlparse(value if "://" in value else f"http://{value}")
    if parsed.scheme in {"http", "https"} and parsed.hostname and parsed.path not in {"", "/"}:
        return "url"
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        return "url"
    return "domain"


async def resolve_host_ips(hostname: str) -> List[str]:
    def _resolve() -> List[str]:
        results = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        ips = []
        for entry in results:
            ip = entry[4][0]
            if ip not in ips:
                ips.append(ip)
        return ips

    try:
        return await asyncio.to_thread(_resolve)
    except socket.gaierror:
        return []


def is_forbidden_ip(ip_text: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except ValueError:
        return True

    return any(
        [
            ip_obj.is_private,
            ip_obj.is_loopback,
            ip_obj.is_link_local,
            ip_obj.is_multicast,
            ip_obj.is_reserved,
            ip_obj.is_unspecified,
        ]
    )


async def assert_public_target(hostname: str) -> List[str]:
    ips = await resolve_host_ips(hostname)
    if not ips:
        raise HTTPException(status_code=400, detail="Unable to resolve target hostname.")
    blocked = [ip for ip in ips if is_forbidden_ip(ip)]
    if blocked:
        raise HTTPException(status_code=400, detail="Target resolves to a private or restricted IP range.")
    return ips


async def fetch_ipinfo(ip_value: str) -> Optional[Dict[str, Any]]:
    if not IPINFO_TOKEN:
        return None
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
        response = await client.get(
            f"https://ipinfo.io/{ip_value}/json",
            params={"token": IPINFO_TOKEN},
        )
        response.raise_for_status()
        return response.json()


async def fetch_threatfox_hits(terms: List[str]) -> List[Dict[str, Any]]:
    if not terms:
        return []

    headers = {"User-Agent": "CyberShield URL Detonator"}
    if ABUSECH_API_KEY:
        headers["Auth-Key"] = ABUSECH_API_KEY

    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, headers=headers) as client:
        all_hits: List[Dict[str, Any]] = []
        for term in terms:
            payload = {
                "query": "search_hash" if is_hash(term) else "search_ioc",
                "search_term": term,
            }
            try:
                response = await client.post(ABUSECH_API_URL, json=payload)
                response.raise_for_status()
                body = response.json()
            except Exception:
                continue

            if body.get("query_status") != "ok":
                continue

            for item in body.get("data", []):
                all_hits.append(
                    {
                        "source": "abuse.ch",
                        "ioc": item.get("ioc") or item.get("md5_hash") or term,
                        "threat_type": item.get("threat_type") or "other",
                        "malware": item.get("malware") or item.get("malware_alias"),
                        "confidence": int(item.get("confidence_level") or 0),
                        "first_seen": item.get("first_seen"),
                        "last_seen": item.get("last_seen"),
                        "reference": item.get("reference"),
                    }
                )

        deduped: Dict[str, Dict[str, Any]] = {}
        for hit in all_hits:
            key = f"{hit['ioc']}:{hit['threat_type']}:{hit.get('malware')}"
            existing = deduped.get(key)
            if not existing or hit["confidence"] > existing["confidence"]:
                deduped[key] = hit
        return list(deduped.values())


async def probe_http(url: str, timeout: int) -> Dict[str, Any]:
    async with httpx.AsyncClient(
        timeout=min(max(timeout, 5), 20),
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        chain: List[Dict[str, Any]] = []
        current = url
        for _ in range(MAX_REDIRECTS):
            response = await client.get(current)
            host = urlparse(current).hostname or ""
            ips = await resolve_host_ips(host) if host else []
            if any(is_forbidden_ip(ip) for ip in ips):
                raise HTTPException(status_code=400, detail="Redirect chain reached a restricted IP target.")

            chain.append(
                {
                    "url": current,
                    "status": response.status_code,
                    "location": response.headers.get("location"),
                    "ip": ips[0] if ips else None,
                }
            )

            if response.status_code not in {301, 302, 303, 307, 308}:
                return {
                    "status": response.status_code,
                    "final_url": str(response.url),
                    "content_type": response.headers.get("content-type"),
                    "server": response.headers.get("server"),
                    "headers": {
                        "content-security-policy": response.headers.get("content-security-policy"),
                        "strict-transport-security": response.headers.get("strict-transport-security"),
                        "x-frame-options": response.headers.get("x-frame-options"),
                        "x-content-type-options": response.headers.get("x-content-type-options"),
                    },
                    "redirect_chain": chain,
                }

            location = response.headers.get("location")
            if not location:
                break
            current = httpx.URL(current).join(location).unicode_string()

    return {
        "status": None,
        "final_url": url,
        "content_type": None,
        "server": None,
        "headers": {},
        "redirect_chain": chain,
    }


async def fetch_tls_metadata(hostname: str) -> Optional[Dict[str, Any]]:
    def _worker() -> Optional[Dict[str, Any]]:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as wrapped:
                cert = wrapped.getpeercert()
                return {
                    "issuer": dict(x[0] for x in cert.get("issuer", [])) if cert.get("issuer") else None,
                    "subject": dict(x[0] for x in cert.get("subject", [])) if cert.get("subject") else None,
                    "valid_from": cert.get("notBefore"),
                    "valid_to": cert.get("notAfter"),
                    "version": wrapped.version(),
                }

    try:
        return await asyncio.to_thread(_worker)
    except Exception:
        return None


def compute_risk(report: Dict[str, Any]) -> Dict[str, Any]:
    score = 0
    reasons: List[str] = []
    redirect_steps = len(report["http"].get("redirect_chain", []))
    final_country = report.get("geo", {}).get("country")
    hits = report.get("threat_intel", [])

    if redirect_steps > 3:
        score += 20
        reasons.append("Redirect chain exceeded three hops.")
    if hits:
        top = max(hit.get("confidence", 0) for hit in hits)
        score += min(top, 60)
        reasons.append("Threat intelligence source returned known IOC matches.")
    if final_country and final_country.upper() in {"RU", "KP", "IR"}:
        score += 30
        reasons.append("Final destination resolved to a high-risk geography.")
    if report.get("behavior", {}).get("suspicious_domains"):
        score += 20
        reasons.append("Third-party requests touched suspicious or newly observed domains.")
    if report.get("page", {}).get("phishing_indicators"):
        score += 15
        reasons.append("Rendered page contained phishing-oriented indicators.")

    score = max(0, min(score, 100))
    band = "high" if score >= 70 else "medium" if score >= 30 else "low"
    return {
        "score": score,
        "band": band,
        "reasons": reasons,
    }


@dataclass
class CacheEntry:
    expires_at: float
    payload: Dict[str, Any]


def read_cache(key: str) -> Optional[Dict[str, Any]]:
    entry = _CACHE.get(key)
    if not entry:
        return None
    expires_at, payload = entry
    if expires_at < time.time():
        _CACHE.pop(key, None)
        return None
    return payload


def write_cache(key: str, payload: Dict[str, Any]) -> None:
    _CACHE[key] = (time.time() + CACHE_TTL_SECONDS, payload)


class DetonateRequest(BaseModel):
    url: str = Field(..., description="Suspicious URL to detonate.")
    timeout: int = Field(DEFAULT_TIMEOUT, ge=5, le=60)
    wait_until: str = Field("networkidle", description="Playwright navigation readiness event.")

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return ensure_http_url(value)

    @field_validator("wait_until")
    @classmethod
    def validate_wait_until(cls, value: str) -> str:
        allowed = {"load", "domcontentloaded", "networkidle"}
        if value not in allowed:
            raise ValueError(f"wait_until must be one of {', '.join(sorted(allowed))}")
        return value


async def detonate_with_playwright(target_url: str, timeout: int, wait_until: str) -> Dict[str, Any]:
    try:
        from playwright.async_api import async_playwright
        from PIL import Image  # noqa: F401
    except ImportError as exc:
        raise HTTPException(
            status_code=500,
            detail="Playwright service dependencies are not installed. Run pip install -r requirements.txt and playwright install.",
        ) from exc

    artifact_id = sha256_text(f"{target_url}:{utc_now()}")[:16]
    run_dir = ARTIFACT_ROOT / artifact_id
    run_dir.mkdir(parents=True, exist_ok=True)
    screenshot_path = run_dir / "snapshot.png"
    dom_path = run_dir / "rendered.html"

    requests: List[Dict[str, Any]] = []
    responses: List[Dict[str, Any]] = []
    console_messages: List[str] = []

    parsed = urlparse(target_url)
    if parsed.hostname:
        await assert_public_target(parsed.hostname)

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        context = await browser.new_context(
            user_agent=USER_AGENT,
            ignore_https_errors=True,
            java_script_enabled=True,
            viewport={"width": 1440, "height": 960},
        )

        async def guard_route(route):
            request = route.request
            host = urlparse(request.url).hostname or ""
            if host:
                ips = await resolve_host_ips(host)
                if any(is_forbidden_ip(ip) for ip in ips):
                    await route.abort()
                    return
            await route.continue_()

        await context.route("**/*", guard_route)
        page = await context.new_page()

        page.on(
            "request",
            lambda request: requests.append(
                {
                    "url": request.url,
                    "method": request.method,
                    "resource_type": request.resource_type,
                    "headers": dict(request.headers),
                }
            ),
        )
        page.on(
            "response",
            lambda response: responses.append(
                {
                    "url": response.url,
                    "status": response.status,
                    "headers": dict(response.headers),
                }
            ),
        )
        page.on("console", lambda msg: console_messages.append(f"{msg.type}: {msg.text}"))

        await page.goto(target_url, wait_until=wait_until, timeout=timeout * 1000)
        await page.wait_for_timeout(min(timeout, 15) * 1000)
        await page.screenshot(path=str(screenshot_path), full_page=True)
        rendered_html = await page.content()
        dom_path.write_text(rendered_html, encoding="utf-8")

        title = await page.title()
        final_url = page.url

        await context.close()
        await browser.close()

    final_host = urlparse(final_url).hostname or urlparse(target_url).hostname or ""
    final_ips = await resolve_host_ips(final_host) if final_host else []
    page_signals = {
        "title": title,
        "final_url": final_url,
        "screenshot_path": str(screenshot_path.relative_to(APP_ROOT)),
        "dom_path": str(dom_path.relative_to(APP_ROOT)),
        "phishing_indicators": detect_phishing_indicators(rendered_html),
    }
    behavior = {
        "console_messages": console_messages[:30],
        "request_count": len(requests),
        "response_count": len(responses),
        "suspicious_domains": detect_suspicious_domains(requests),
    }

    return {
        "artifact_id": artifact_id,
        "page": page_signals,
        "network": {
            "requests": requests,
            "responses": responses,
            "final_ips": final_ips,
        },
        "behavior": behavior,
    }


def detect_suspicious_domains(requests: List[Dict[str, Any]]) -> List[str]:
    suspicious = []
    for request in requests:
        host = urlparse(request.get("url", "")).hostname
        if not host:
            continue
        lowered = host.lower()
        if any(flag in lowered for flag in ["track", "telemetry", "pixel", "login", "verify", "auth"]):
            if host not in suspicious:
                suspicious.append(host)
    return suspicious[:20]


def detect_phishing_indicators(html: str) -> List[str]:
    lowered = html.lower()
    indicators = []
    checks = {
        "password_form": "type=\"password\"",
        "credential_keywords": any(word in lowered for word in ["verify your account", "signin", "login", "otp", "bank"]),
        "hidden_iframe": "<iframe" in lowered and "display:none" in lowered,
        "suspicious_submit": any(word in lowered for word in ["confirm identity", "unlock account", "validate account"]),
    }
    for key, present in checks.items():
        if present:
            indicators.append(key)
    return indicators


app = FastAPI(title="CyberShield URL Detonator", version="0.1.0")


@app.get("/health")
async def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "url-detonator",
        "fetched_at": utc_now(),
    }


@app.post("/detonate")
async def detonate(request: DetonateRequest) -> Dict[str, Any]:
    normalized = request.url
    cache_key = sha256_text(f"{normalized}:{request.timeout}:{request.wait_until}")
    cached = read_cache(cache_key)
    if cached:
        return {
            **cached,
            "cache": {"hit": True, "ttl_seconds": CACHE_TTL_SECONDS},
        }

    parsed = urlparse(normalized)
    hostname = parsed.hostname or ""
    ips = await assert_public_target(hostname)

    http_probe_task = asyncio.create_task(probe_http(normalized, request.timeout))
    tls_task = asyncio.create_task(fetch_tls_metadata(hostname) if parsed.scheme == "https" else asyncio.sleep(0, result=None))
    detonation_task = asyncio.create_task(detonate_with_playwright(normalized, request.timeout, request.wait_until))

    intel_terms = [normalized, hostname, *ips]
    threatfox_task = asyncio.create_task(fetch_threatfox_hits(intel_terms))
    geo_task = asyncio.create_task(fetch_ipinfo(ips[0])) if ips else asyncio.create_task(asyncio.sleep(0, result=None))

    http_probe, tls_meta, detonation, threat_hits, geo = await asyncio.gather(
        http_probe_task,
        tls_task,
        detonation_task,
        threatfox_task,
        geo_task,
    )

    result = {
        "input": normalized,
        "type": "url",
        "fetched_at": utc_now(),
        "host": hostname,
        "pre_resolution": {
            "ips": ips,
            "source": "dns_resolution",
        },
        "http": http_probe,
        "tls": tls_meta,
        "geo": geo or {},
        "threat_intel": threat_hits,
        "detonation": detonation,
    }
    result["risk"] = compute_risk(result)
    result["summary"] = {
        "final_url": detonation["page"]["final_url"],
        "final_ips": detonation["network"]["final_ips"],
        "redirect_hops": len(http_probe.get("redirect_chain", [])),
        "threat_hits": len(threat_hits),
        "phishing_indicators": detonation["page"]["phishing_indicators"],
    }

    write_cache(cache_key, result)
    return {
        **result,
        "cache": {"hit": False, "ttl_seconds": CACHE_TTL_SECONDS},
    }
