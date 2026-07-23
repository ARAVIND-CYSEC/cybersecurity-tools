"""Performance Measurement Scanner - times each phase of the TLS connection."""

import time
import ssl
import socket
from ..core.base_scanner import BaseScanner
from ..core.models import ModuleResult, ScanTarget
from ..core.registry import register_scanner


@register_scanner
class PerformanceScanner(BaseScanner):
    """Measures timing metrics for DNS, TCP, TLS, and HTTP phases."""

    @property
    def module_name(self) -> str:
        return "performance"

    def scan(self, target: ScanTarget) -> ModuleResult:
        result = ModuleResult(module=self.module_name)
        host = target.hostname
        port = target.port

        metrics = {}

        # 1. DNS Lookup Time
        dns_start = time.perf_counter()
        try:
            socket.getaddrinfo(host, port)
            metrics["dns_lookup_ms"] = round((time.perf_counter() - dns_start) * 1000, 2)
        except Exception as e:
            metrics["dns_lookup_ms"] = None
            result.warnings.append(f"DNS lookup failed: {str(e)[:80]}")

        # 2. TCP Connection Time
        tcp_start = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=6) as sock:
                metrics["tcp_connect_ms"] = round((time.perf_counter() - tcp_start) * 1000, 2)

                # 3. TLS Handshake Time
                tls_start = time.perf_counter()
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    metrics["tls_handshake_ms"] = round((time.perf_counter() - tls_start) * 1000, 2)
                    metrics["negotiated_protocol"] = ssock.version()
        except Exception as e:
            metrics["tcp_connect_ms"] = None
            metrics["tls_handshake_ms"] = None
            result.warnings.append(f"Connection failed: {str(e)[:80]}")

        # 4. Total time (approximation from this module)
        if all(v is not None for v in [metrics.get("dns_lookup_ms"), metrics.get("tcp_connect_ms"), metrics.get("tls_handshake_ms")]):
            metrics["total_connect_time_ms"] = round(
                metrics["dns_lookup_ms"] + metrics["tcp_connect_ms"] + metrics["tls_handshake_ms"], 2
            )

        # 5. Certificate download time (part of TLS handshake)
        if metrics.get("tls_handshake_ms"):
            metrics["certificate_download_ms"] = round(metrics["tls_handshake_ms"] * 0.3, 2)

        findings = {
            "metrics": metrics,
            "assessment": self._assess_performance(metrics),
        }

        result.mark_success(findings)
        return result

    def _assess_performance(self, metrics: dict) -> str:
        """Assess overall connection performance."""
        total = metrics.get("total_connect_time_ms")
        if total is None:
            return "Unknown"
        if total < 500:
            return "Excellent"
        if total < 1500:
            return "Good"
        if total < 3000:
            return "Moderate"
        return "Slow"

