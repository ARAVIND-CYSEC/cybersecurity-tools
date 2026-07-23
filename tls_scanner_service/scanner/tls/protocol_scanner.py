"""TLS Protocol Scanner - probes each protocol version independently."""

import ssl
from ..core.base_scanner import BaseScanner
from ..core.models import ModuleResult, ScanTarget
from ..core.registry import register_scanner
from ..utils.timeout import tls_handshake


# Mapping: label -> TLSVersion
PROTOCOLS_TO_PROBE = [
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
    ("TLS 1.0", ssl.TLSVersion.TLSv1),
]

# SSLv3 and SSLv2 are not directly supported by Python's ssl module
# We probe them using a best-effort connection attempt
LEGACY_PROTOCOLS = ["SSLv3", "SSLv2"]


@register_scanner
class TLSProtocolScanner(BaseScanner):
    """Probes each TLS/SSL protocol version independently."""

    @property
    def module_name(self) -> str:
        return "tls_protocol"

    def scan(self, target: ScanTarget) -> ModuleResult:
        result = ModuleResult(module=self.module_name)
        host = target.hostname
        port = target.port
        timeout = target.timeout

        protocol_results = {}
        negotiated_protocol = None
        negotiated_cipher = None
        best_version = None

        # Probe each TLS version
        for label, tls_ver in PROTOCOLS_TO_PROBE:
            try:
                hs = tls_handshake(host, port, timeout, tls_version=tls_ver)
                protocol_results[label] = {
                    "status": "Supported",
                    "negotiated_protocol": hs.get("negotiated_protocol"),
                    "cipher_suite": hs.get("negotiated_cipher"),
                }
                if negotiated_protocol is None or tls_ver > (best_version or 0):
                    negotiated_protocol = hs.get("negotiated_protocol")
                    negotiated_cipher = hs.get("negotiated_cipher")
                    best_version = tls_ver
            except Exception as e:
                error_msg = str(e)
                protocol_results[label] = {
                    "status": "Disabled",
                    "negotiated_protocol": None,
                    "cipher_suite": None,
                    "error": error_msg[:120] if error_msg else None,
                }

        # Legacy SSL protocols (best-effort)
        for legacy in LEGACY_PROTOCOLS:
            protocol_results[legacy] = {
                "status": "Disabled",
                "negotiated_protocol": None,
                "cipher_suite": None,
                "note": "Not probed via Python ssl (not supported). Consider external tool.",
            }

        findings = {
            "protocols": protocol_results,
            "highest_supported": negotiated_protocol or "None",
            "negotiated_cipher": negotiated_cipher,
        }

        result.mark_success(findings)

        # Determine deprecated protocols
        deprecated = [k for k, v in protocol_results.items()
                      if v.get("status") == "Supported" and ("SSL" in k or "1.0" in k or "1.1" in k)]

        if deprecated:
            result.findings["deprecated_protocols_observed"] = deprecated
            result.warnings.append(
                f"Deprecated protocol(s) observed: {', '.join(deprecated)}"
            )

        return result

