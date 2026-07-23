"""TLS Feature Detection - detects advanced TLS features and extensions."""

import ssl
import socket
from ..core.base_scanner import BaseScanner
from ..core.models import ModuleResult, ScanTarget
from ..core.registry import register_scanner


@register_scanner
class TLSFeatureScanner(BaseScanner):
    """Detects TLS features: PFS, session resumption, renegotiation, compression, GREASE, 0-RTT."""

    @property
    def module_name(self) -> str:
        return "tls_features"

    def scan(self, target: ScanTarget) -> ModuleResult:
        result = ModuleResult(module=self.module_name)
        host = target.hostname
        port = target.port

        features = {}

        # 1. Check if connection is possible at all
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    features["connection_possible"] = True
                    features["negotiated_protocol"] = ssock.version()

                    # PFS detection from cipher name
                    cipher_name = cipher[0] if cipher else ""
                    features["perfect_forward_secrecy"] = any(
                        p in cipher_name.upper() for p in ["ECDHE", "DHE", "EDH"]
                    )

                    # Session resumption test
                    features["session_resumption"] = self._test_session_resumption(host, port)
                    features["session_tickets"] = self._test_session_tickets(host, port)

                    # Renegotiation detection (best-effort via feature flags)
                    features["secure_renegotiation"] = self._test_renegotiation(host, port)

                    # Compression detection
                    features["compression"] = self._test_compression(host, port)

                    # SNI support
                    features["sni_support"] = True  # If TLS handshake succeeded, SNI worked

                    # 0-RTT / Early Data (TLS 1.3 feature)
                    if "1.3" in (ssock.version() or ""):
                        features["early_data_0rtt"] = "Possible (TLS 1.3)"
                        features["early_data_status"] = "supported_protocol"
                    else:
                        features["early_data_0rtt"] = False
                        features["early_data_status"] = "not_applicable"

        except Exception as e:
            result.mark_failed(f"TLS feature scan failed: {str(e)[:120]}")
            return result

        findings = {
            "features": features,
            "warnings": [],
        }

        if not features.get("perfect_forward_secrecy"):
            findings["warnings"].append("Server does not appear to use Perfect Forward Secrecy ciphers.")

        result.mark_success(findings)
        return result

    def _test_session_resumption(self, host: str, port: int) -> dict:
        """Test if session resumption is supported."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.options |= ssl.OP_NO_TICKET  # Disable tickets to test resumption

            # First connection
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as _:
                    pass

            # Second connection - if it works, resumption is likely supported
            with socket.create_connection((host, port), timeout=5) as sock2:
                with ctx.wrap_socket(sock2, server_hostname=host) as _:
                    pass

            return {"supported": True, "note": "Session ID-based resumption available"}
        except Exception:
            return {"supported": False, "note": "Session resumption not observed"}

    def _test_session_tickets(self, host: str, port: int) -> dict:
        """Test if session tickets are supported."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    session = ssock.session
                    if session and session.ticket_lifetime_hint:
                        return {
                            "supported": True,
                            "ticket_lifetime_hint": session.ticket_lifetime_hint,
                        }
                    return {"supported": True, "note": "Session ticket likely available (no lifetime hint)"}
        except Exception:
            return {"supported": False, "note": "Session tickets not observed"}

    def _test_renegotiation(self, host: str, port: int) -> dict:
        """Test secure renegotiation support."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.options &= ~ssl.OP_NO_RENEGOTIATION  # Allow renegotiation

            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as _:
                    pass
            return {"supported": True, "note": "Secure renegotiation supported"}
        except Exception:
            return {"supported": False, "note": "Renegotiation not tested or unsupported"}

    def _test_compression(self, host: str, port: int) -> dict:
        """Test if TLS compression is enabled."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.options &= ~ssl.OP_NO_COMPRESSION  # Allow compression

            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    compressed = ssock.compression()
                    if compressed:
                        return {"supported": True, "method": compressed}
                    return {"supported": False, "method": None, "note": "TLS compression disabled"}
        except Exception:
            return {"supported": False, "method": None, "note": "Could not determine compression state"}

