"""ALPN Negotiation Scanner - detects supported application protocols."""

import ssl
import socket
from ..core.base_scanner import BaseScanner
from ..core.models import ModuleResult, ScanTarget
from ..core.registry import register_scanner


# Application protocols to probe via ALPN
ALPN_PROTOCOLS = [
    "h2",          # HTTP/2
    "http/1.1",    # HTTP/1.1
    "h3",          # HTTP/3 (QUIC - not directly via TLS but listed)
    "h3-29",       # HTTP/3 draft 29
    "hq-interop",  # QUIC interop
]


@register_scanner
class ALPNScanner(BaseScanner):
    """Detects ALPN (Application-Layer Protocol Negotiation) support."""

    @property
    def module_name(self) -> str:
        return "alpn"

    def scan(self, target: ScanTarget) -> ModuleResult:
        result = ModuleResult(module=self.module_name)
        host = target.hostname
        port = target.port

        negotiated_protocol = None
        available_protocols = []

        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(ALPN_PROTOCOLS)

            with socket.create_connection((host, port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    negotiated_protocol = ssock.selected_alpn_protocol()

                    # Try each protocol individually to see what's available
                    for proto in ALPN_PROTOCOLS[:3]:  # top 3
                        test_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        test_ctx.check_hostname = False
                        test_ctx.verify_mode = ssl.CERT_NONE
                        test_ctx.set_alpn_protocols([proto])

                        try:
                            with socket.create_connection((host, port), timeout=4) as test_sock:
                                with test_ctx.wrap_socket(test_sock, server_hostname=host) as test_ssock:
                                    selected = test_ssock.selected_alpn_protocol()
                                    if selected:
                                        available_protocols.append(selected)
                        except Exception:
                            pass

        except Exception as e:
            result.mark_failed(f"ALPN negotiation failed: {str(e)[:120]}")
            return result

        # Deduplicate
        available_protocols = list(dict.fromkeys(available_protocols))

        # Map protocol IDs to human-readable names
        protocol_names = {
            "h2": "HTTP/2",
            "http/1.1": "HTTP/1.1",
            "h3": "HTTP/3 (QUIC)",
            "h3-29": "HTTP/3 (draft 29)",
            "hq-interop": "QUIC Interop",
        }

        human_readable = [protocol_names.get(p, p) for p in available_protocols]

        findings = {
            "negotiated_protocol": negotiated_protocol,
            "negotiated_human_readable": protocol_names.get(negotiated_protocol, negotiated_protocol),
            "available_protocols": available_protocols,
            "available_human_readable": human_readable,
            "http2_supported": "h2" in available_protocols,
            "http3_supported": "h3" in available_protocols or "h3-29" in available_protocols,
        }

        result.mark_success(findings)

        return result

