"""Cipher Suite Enumeration - enumerates and analyses supported ciphers."""

import ssl
import socket
from ..core.base_scanner import BaseScanner
from ..core.models import ModuleResult, ScanTarget
from ..core.registry import register_scanner
from ..utils.timeout import create_socket_connection

# Cipher strength classification
CIPHER_STRENGTH = {
    "TLS_AES_256_GCM_SHA384": {"strength": "Strong", "pfs": True, "key_exchange": "ECDHE", "bits": 256, "auth": "AEAD"},
    "TLS_AES_128_GCM_SHA256": {"strength": "Strong", "pfs": True, "key_exchange": "ECDHE", "bits": 128, "auth": "AEAD"},
    "TLS_CHACHA20_POLY1305_SHA256": {"strength": "Strong", "pfs": True, "key_exchange": "ECDHE", "bits": 256, "auth": "AEAD"},
}

# Default cipher sets to try per TLS version
CIPHER_SETS = {
    "TLSv1_3": [
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
    ],
    "TLSv1_2": [
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-AES256-SHA384",
        "ECDHE-RSA-AES256-SHA384",
        "ECDHE-ECDSA-AES128-SHA256",
        "ECDHE-RSA-AES128-SHA256",
        "ECDHE-ECDSA-AES256-SHA",
        "ECDHE-RSA-AES256-SHA",
        "ECDHE-ECDSA-AES128-SHA",
        "ECDHE-RSA-AES128-SHA",
        "AES256-GCM-SHA384",
        "AES128-GCM-SHA256",
        "AES256-SHA256",
        "AES128-SHA256",
        "AES256-SHA",
        "AES128-SHA",
    ],
}

PFS_CIPHERS = {"ECDHE", "DHE", "EDH"}
WEAK_CIPHERS = {"RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "anon", "PSK"}
WEAK_EXCHANGES = {"RSA", "DH"}


@register_scanner
class CipherScanner(BaseScanner):
    """Enumerates supported cipher suites per TLS version."""

    @property
    def module_name(self) -> str:
        return "cipher_suites"

    def _try_cipher(self, host: str, port: int, cipher: str, tls_version) -> dict:
        """Try to negotiate a specific cipher suite."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers(cipher)
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version

            with socket.create_connection((host, port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    negotiated = ssock.cipher()
                    return {
                        "supported": True,
                        "negotiated_cipher": negotiated[0] if negotiated else None,
                        "negotiated_bits": negotiated[1] if negotiated else None,
                    }
        except Exception:
            return {"supported": False, "negotiated_cipher": None, "negotiated_bits": None}

    def _analyse_cipher(self, cipher_name: str) -> dict:
        """Analyse a cipher suite's security properties."""
        name = cipher_name or ""
        upper = name.upper()

        # PFS detection
        pfs = any(p in upper for p in ["ECDHE", "DHE", "EDH"]) if name else False

        # Strength estimation
        if "AES_256" in upper or "AES256" in upper:
            strength = "Strong"
            bits = 256
        elif "AES_128" in upper or "AES128" in upper:
            strength = "Strong"
            bits = 128
        elif "CHACHA20" in upper:
            strength = "Strong"
            bits = 256
        elif any(w in upper for w in WEAK_CIPHERS):
            strength = "Weak"
            bits = 0
        else:
            strength = "Medium"
            bits = 128

        # Key exchange
        if "ECDHE" in upper:
            key_exchange = "ECDHE"
        elif "DHE" in upper or "EDH" in upper:
            key_exchange = "DHE"
        elif "ECDH" in upper:
            key_exchange = "ECDH"
        elif "DH" in upper:
            key_exchange = "DH"
        elif "RSA" in upper:
            key_exchange = "RSA"
        elif "PSK" in upper:
            key_exchange = "PSK"
        else:
            key_exchange = "Unknown"

        return {
            "cipher": cipher_name,
            "strength": strength,
            "forward_secrecy": pfs,
            "key_exchange": key_exchange,
            "bits": bits,
        }

    def scan(self, target: ScanTarget) -> ModuleResult:
        result = ModuleResult(module=self.module_name)
        host = target.hostname
        port = target.port

        supported_ciphers = []

        # Probe TLS 1.3 ciphers (these are fixed by RFC)
        for cipher in CIPHER_SETS["TLSv1_3"]:
            res = self._try_cipher(host, port, cipher, ssl.TLSVersion.TLSv1_3)
            if res["supported"]:
                analysis = self._analyse_cipher(cipher)
                analysis["protocol"] = "TLS 1.3"
                analysis["tested"] = cipher
                supported_ciphers.append(analysis)

        # Probe TLS 1.2 ciphers
        for cipher in CIPHER_SETS["TLSv1_2"]:
            res = self._try_cipher(host, port, cipher, ssl.TLSVersion.TLSv1_2)
            if res["supported"]:
                analysis = self._analyse_cipher(cipher)
                analysis["protocol"] = "TLS 1.2"
                analysis["tested"] = cipher
                supported_ciphers.append(analysis)

        # Count security properties
        strong_count = sum(1 for c in supported_ciphers if c["strength"] == "Strong")
        pfs_count = sum(1 for c in supported_ciphers if c["forward_secrecy"])
        weak_count = sum(1 for c in supported_ciphers if c["strength"] == "Weak")

        findings = {
            "total_supported": len(supported_ciphers),
            "strong_ciphers": strong_count,
            "pfs_ciphers": pfs_count,
            "weak_ciphers": weak_count,
            "all_supported": supported_ciphers,
            "has_forward_secrecy": pfs_count > 0,
            "has_weak_ciphers": weak_count > 0,
        }

        result.mark_success(findings)

        if weak_count > 0:
            result.warnings.append(f"{weak_count} weak cipher(s) detected.")
        if pfs_count == 0 and supported_ciphers:
            result.warnings.append("No Perfect Forward Secrecy ciphers available.")

        return result

