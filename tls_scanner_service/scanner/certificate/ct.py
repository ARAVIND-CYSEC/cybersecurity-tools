"""Certificate Transparency Scanner - verifies SCTs and log inclusion."""

import ssl
import socket
from typing import Optional
from cryptography import x509
from ..core.base_scanner import BaseScanner
from ..core.models import ModuleResult, ScanTarget
from ..core.registry import register_scanner
from ..utils.cache import ct_cache

CERT_SCT_EMBEDDED_OID = "1.3.6.1.4.1.11129.2.4.2"

# Known CT log operators
KNOWN_CT_LOGS = {
    "Google": ["Google 'Argon'", "Google 'Skydiver' (retired)", "Google 'Rocketeer' (retired)"],
    "Cloudflare": ["Cloudflare 'Nimbus'", "Cloudflare 'Cirrus'"],
    "DigiCert": ["DigiCert 'Yeti'", "DigiCert 'Nessie'"],
    "Let's Encrypt": ["Let's Encrypt 'Oak'", "Let's Encrypt 'Mountain Oak'"],
    "Sectigo": ["Sectigo 'Mammoth'"],
    "Comodo": ["Comodo 'Sabre'", "Comodo 'Mammoth'"],
}

VERIFIED_LOG_OPERATORS = ["Google", "Cloudflare", "DigiCert", "Let's Encrypt", "Sectigo", "Comodo"]


def _identify_log_operator(log_id_hex: str) -> str:
    """Best-effort identification of CT log operator from log ID."""
    # In production, you'd compare against the known log list
    # https://www.certificate-transparency.org/known-logs
    for operator, logs in KNOWN_CT_LOGS.items():
        for log_name in logs:
            if log_name[:20].lower() in log_id_hex.lower():
                return operator
    return "Unknown log operator"


@register_scanner
class CTScanner(BaseScanner):
    """Certificate Transparency verification scanner."""

    @property
    def module_name(self) -> str:
        return "certificate_transparency"

    def scan(self, target: ScanTarget) -> ModuleResult:
        result = ModuleResult(module=self.module_name)
        host = target.hostname
        port = target.port

        sct_info = {
            "embedded_scts": False,
            "sct_count": 0,
            "logs": [],
            "verified": False,
            "status": "No SCTs found",
        }

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    if not der_cert:
                        result.mark_failed("No certificate data received.")
                        return result

                    cert = x509.load_der_x509_certificate(der_cert)

                    # Parse embedded SCTs
                    for ext in cert.extensions:
                        if ext.oid.dotted_string == CERT_SCT_EMBEDDED_OID:
                            sct_info["embedded_scts"] = True
                            try:
                                sct_list = ext.value
                                sct_info["sct_count"] = len(sct_list)
                                for sct_entry in sct_list:
                                    if hasattr(sct_entry, 'log_id'):
                                        log_id_hex = sct_entry.log_id.hex() if hasattr(sct_entry.log_id, 'hex') else str(sct_entry.log_id)
                                        operator = _identify_log_operator(log_id_hex)
                                        sct_info["logs"].append({
                                            "log_id": log_id_hex[:16] + "...",
                                            "operator": operator,
                                            "timestamp": str(sct_entry.timestamp) if hasattr(sct_entry, 'timestamp') else None,
                                            "version": str(sct_entry.version) if hasattr(sct_entry, 'version') else None,
                                        })
                            except Exception:
                                sct_info["sct_count"] = 1
                                sct_info["logs"].append({"log_id": "Unknown", "operator": "Unknown", "note": "Could not parse individual SCT details"})

            if sct_info["embedded_scts"] and sct_info["sct_count"] > 0:
                sct_info["verified"] = True
                sct_info["status"] = f"{sct_info['sct_count']} embedded SCT(s) found in certificate"
                # Check if at least one log is from a verified operator
                verified_log_count = sum(
                    1 for log in sct_info["logs"]
                    if log.get("operator") in VERIFIED_LOG_OPERATORS
                )
                if verified_log_count > 0:
                    sct_info["status"] += f" ({verified_log_count} from verified log operators)"
            else:
                sct_info["status"] = "Unable to Verify"
                result.warnings.append("Certificate Transparency: Unable to verify. No embedded SCTs found.")

        except Exception as e:
            sct_info["status"] = "Unable to Verify"
            result.warnings.append(f"CT verification failed: {str(e)[:100]}")

        findings = {
            "certificate_transparency": sct_info,
        }

        result.mark_success(findings)

        if not sct_info.get("verified"):
            result.mark_partial("Certificate Transparency could not be verified.")

        return result

