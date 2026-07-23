"""DNS Intelligence Module - resolves all record types and CDN/ASN detection."""

import socket
from typing import Optional

from ..core.base_scanner import BaseScanner
from ..core.models import ModuleResult, ScanTarget
from ..core.registry import register_scanner
from ..utils.cache import dns_cache, geo_cache, asn_cache


try:
    import dns.resolver
    import dns.reversename
    import dns.name
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


def _resolve_with_cache(domain: str, record_type: str, resolver=None) -> list:
    """Resolve DNS records with caching."""
    cache_key = f"{domain}:{record_type}"
    cached = dns_cache.get(cache_key)
    if cached is not None:
        return cached

    records = []
    if not HAS_DNSPYTHON:
        # Fallback to socket-based resolution
        try:
            if record_type == "A":
                records = list(set(socket.gethostbyname_ex(domain)[2]))
            elif record_type == "AAAA":
                records = list(set(
                    addr[4][0] for addr in socket.getaddrinfo(domain, None, socket.AF_INET6)
                ))
        except Exception:
            pass
        dns_cache.set(cache_key, records, ttl=120)
        return records

    try:
        r = resolver or dns.resolver.Resolver()
        answers = r.resolve(domain, record_type, lifetime=4)
        for ans in answers:
            if record_type == "MX":
                records.append(str(ans.exchange).rstrip("."))
            else:
                records.append(str(ans).rstrip("."))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.name.EmptyLabel):
        pass
    except Exception:
        pass

    dns_cache.set(cache_key, records, ttl=300)
    return records


def _detect_cdn(domain: str, ips: list, cname: str) -> Optional[str]:
    """Identify CDN provider from IPs and CNAME patterns."""
    combined = " ".join([cname or "", *ips]).lower()
    if any(x in combined for x in ["cloudflare", "cf-"]):
        return "Cloudflare"
    if "cloudfront" in combined or ".cloudfront.net" in combined:
        return "Amazon CloudFront"
    if "akamaiedge" in combined or "akamai" in combined:
        return "Akamai"
    if "fastly" in combined:
        return "Fastly"
    if "azure" in combined or "azureedge" in combined:
        return "Azure CDN"
    if "google" in combined or "googlesyndication" in combined:
        return "Google Cloud CDN"
    if "stackpath" in combined:
        return "StackPath"
    if "keycdn" in combined:
        return "KeyCDN"
    if "bunnycdn" in combined:
        return "Bunny CDN"
    return None


def _reverse_dns(ip: str) -> Optional[str]:
    """Reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _get_geo_info(ip: str) -> dict:
    """Get geo-location via ipinfo.io (best-effort)."""
    cache_key = f"geo:{ip}"
    cached = geo_cache.get(cache_key)
    if cached:
        return cached

    info = {}
    try:
        import urllib.request
        import json
        token = __import__('os').environ.get("IPINFO_TOKEN", "")
        if token:
            url = f"https://ipinfo.io/{ip}/json?token={token}"
            req = urllib.request.Request(url, headers={"User-Agent": "CyberIntelTLS/1.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode())
                info = {
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country": data.get("country"),
                    "org": data.get("org"),
                    "loc": data.get("loc"),
                    "timezone": data.get("timezone"),
                }
    except Exception:
        pass

    geo_cache.set(cache_key, info, ttl=900)
    return info


@register_scanner
class DNSScanner(BaseScanner):
    """Comprehensive DNS intelligence scanner."""

    @property
    def module_name(self) -> str:
        return "dns"

    def scan(self, target: ScanTarget) -> ModuleResult:
        result = ModuleResult(module=self.module_name)
        domain = target.hostname

        resolver = dns.resolver.Resolver() if HAS_DNSPYTHON else None

        # Resolve all record types in parallel (using simple sequential for reliability)
        a_records = _resolve_with_cache(domain, "A", resolver)
        aaaa_records = _resolve_with_cache(domain, "AAAA", resolver)
        mx_records = _resolve_with_cache(domain, "MX", resolver)
        ns_records = _resolve_with_cache(domain, "NS", resolver)
        txt_records = _resolve_with_cache(domain, "TXT", resolver)

        # CNAME resolution
        cname = None
        if HAS_DNSPYTHON:
            try:
                cname_answers = resolver.resolve(domain, "CNAME", lifetime=4)
                cname = str(cname_answers[0]).rstrip(".") if cname_answers else None
            except Exception:
                pass

        # SOA record
        soa = None
        if HAS_DNSPYTHON:
            try:
                soa_answers = resolver.resolve(domain, "SOA", lifetime=4)
                if soa_answers:
                    soa = str(soa_answers[0]).strip()
            except Exception:
                pass

        # DNSSEC detection
        dnssec = False
        if HAS_DNSPYTHON:
            try:
                _ = resolver.resolve(domain, "DNSKEY", lifetime=4)
                dnssec = True
            except Exception:
                pass

        # CDN detection
        all_ips = list(set(a_records + aaaa_records))
        cdn_provider = _detect_cdn(domain, all_ips, cname)

        # Reverse DNS on primary IP
        primary_ip = a_records[0] if a_records else (aaaa_records[0] if aaaa_records else None)
        ptr = _reverse_dns(primary_ip) if primary_ip else None

        # ASN / Geo info on primary IP
        asn_info = {}
        geo_info = {}
        if primary_ip:
            geo_info = _get_geo_info(primary_ip)
            org = geo_info.get("org", "")
            if org:
                parts = org.split(" ", 1)
                asn_info = {
                    "asn": parts[0] if parts[0].upper().startswith("AS") else None,
                    "organisation": parts[1] if len(parts) > 1 else org
                }

        findings = {
            "domain": domain,
            "a_records": a_records,
            "aaaa_records": aaaa_records,
            "mx_records": mx_records,
            "ns_records": ns_records,
            "txt_records": txt_records,
            "cname": cname,
            "soa": soa,
            "dnssec": dnssec,
            "cdn_provider": cdn_provider,
            "primary_ip": primary_ip,
            "ipv4_count": len(a_records),
            "ipv6_count": len(aaaa_records),
            "reverse_dns": ptr,
        }

        if asn_info:
            findings["asn"] = asn_info
        if geo_info:
            findings["geo"] = geo_info

        result.mark_success(findings)

        if not a_records and not aaaa_records:
            result.mark_partial("No A or AAAA records resolved.")

        return result

